//! Hysteria2's negotiated Brutal congestion controller.
//!
//! Hysteria2 authenticates over HTTP/3, after QUIC has already constructed its
//! congestion controller. Quinn 0.11 intentionally exposes controller selection
//! only through [`quinn::TransportConfig`], not as a mutable per-connection API.
//! [`BrutalConfig`] therefore builds a switchable controller for every connection:
//! it behaves as BBR during the QUIC and HTTP/3 handshake, then [`activate`] flips
//! only that connection to Brutal after its `Hysteria-CC-RX` header is accepted.
//!
//! The switch is held in an `Arc` shared by `clone_box`. That detail matters twice:
//! `Connection::congestion_state` returns a clone (which is how [`activate`] obtains
//! the handle), and Quinn clones a controller when a connection migrates to a new
//! path. Both clones must continue to name the same negotiation, while controllers
//! built for other connections must not.
//!
//! # Quinn-specific approximation
//!
//! sing-quic exposes pacing and congestion-window controls separately. Quinn's
//! built-in pacer instead derives its rate as `1.25 * window / RTT`, so this
//! implementation uses a `0.8 * compensated_rate * RTT` window to preserve the
//! negotiated wire rate. That necessarily gives less flight headroom than Go's
//! two-BDP window. Quinn also reports lost bytes rather than lost packet records;
//! loss sampling therefore uses a safe lower-bound packet estimate.

use std::any::Any;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use quinn::congestion::{BbrConfig, Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;

/// Decimal megabits per second to bytes per second.
///
/// This is the constant used by sing-quic (`hysteria.MbpsToBps`). The Hysteria2
/// HTTP header carries bytes per second, not the human-facing Mbps value.
pub const MBPS_TO_BYTES_PER_SECOND: u64 = 125_000;

const SAMPLE_SECONDS: usize = 5;
const MIN_SAMPLE_PACKETS: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
/// Quinn's built-in pacer refills at 5/4 of one congestion window per RTT.
/// Scale the window by the reciprocal so that its wire pacing rate is Brutal's
/// compensated target rather than 1.25 times that target.
const QUINN_PACING_RECIPROCAL: f64 = 4.0 / 5.0;
/// Quinn's strict send-window check needs room for two full datagrams plus the
/// next-datagram boundary. Two datagrams are the receiver's normal immediate-ACK
/// threshold; allowing only one falls onto the delayed-ACK timer.
const MIN_CONGESTION_WINDOW_PACKETS: u64 = 3;

/// Convert a configured Mbps value to Hysteria2's bytes-per-second wire unit.
#[inline]
pub fn mbps_to_bytes_per_second(mbps: u64) -> u64 {
    mbps.saturating_mul(MBPS_TO_BYTES_PER_SECOND)
}

/// Select the server-to-client Brutal rate for one authenticated connection.
///
/// `client_receive_bps == 0` means the client supplied no fixed receive rate and
/// asks for bandwidth detection (BBR). A non-zero server value is an upper bound;
/// zero leaves the client's declaration uncapped, matching sing-quic.
#[inline]
pub fn negotiated_send_bps(client_receive_bps: u64, server_up_mbps: u64) -> Option<u64> {
    if client_receive_bps == 0 {
        return None;
    }

    let server_cap = mbps_to_bytes_per_second(server_up_mbps);
    Some(if server_cap == 0 {
        client_receive_bps
    } else {
        client_receive_bps.min(server_cap)
    })
}

/// The server receive rate advertised to the client in `Hysteria-CC-RX`.
#[inline]
pub fn advertised_receive_bps(server_down_mbps: u64) -> u64 {
    mbps_to_bytes_per_second(server_down_mbps)
}

/// Value written to the server's `Hysteria-CC-RX` response header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvertisedReceive {
    /// Ask the client to retain bandwidth detection (BBR).
    Auto,
    /// A fixed receive rate in bytes per second. Zero means uncapped.
    BytesPerSecond(u64),
}

impl AdvertisedReceive {
    pub fn header_value(self) -> String {
        match self {
            Self::Auto => "auto".to_string(),
            Self::BytesPerSecond(rate) => rate.to_string(),
        }
    }
}

/// Both directions negotiated by a Hysteria2 server for one auth request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerNegotiation {
    /// Controller for packets sent by the server. `None` retains BBR.
    pub send_bps: Option<u64>,
    /// Instruction for the controller sending packets toward the server.
    pub advertised_receive: AdvertisedReceive,
}

/// Negotiate Hysteria2 congestion control for one authenticated connection.
///
/// With `ignore_client_bandwidth=false`, a non-zero client declaration keeps the
/// two directions independent: the server caps its Brutal sender with `up_mbps`
/// and advertises `down_mbps` numerically. A zero declaration keeps both halves on
/// bandwidth detection and returns the literal `auto`, matching the sing-quic
/// service embedded by the Go node agent.
///
/// With `ignore_client_bandwidth=true`, the client's declaration is ignored, both
/// sides are instructed to retain bandwidth detection, and `up_mbps`/`down_mbps`
/// do not participate in the exchange.
pub fn negotiate_server(
    client_receive_bps: u64,
    server_up_mbps: u64,
    server_down_mbps: u64,
    ignore_client_bandwidth: bool,
) -> ServerNegotiation {
    if ignore_client_bandwidth {
        ServerNegotiation {
            send_bps: None,
            advertised_receive: AdvertisedReceive::Auto,
        }
    } else if let Some(send_bps) = negotiated_send_bps(client_receive_bps, server_up_mbps) {
        ServerNegotiation {
            send_bps: Some(send_bps),
            advertised_receive: AdvertisedReceive::BytesPerSecond(advertised_receive_bps(
                server_down_mbps,
            )),
        }
    } else {
        ServerNegotiation {
            send_bps: None,
            advertised_receive: AdvertisedReceive::Auto,
        }
    }
}

/// Factory installed on every Hysteria2 endpoint.
///
/// A fresh negotiation state is allocated by every call to `build`, so activating
/// one connection cannot change another connection's controller.
#[derive(Debug, Default)]
pub struct BrutalConfig;

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let fallback_factory = Arc::new(BbrConfig::default());
        Box::new(NegotiatedBrutal {
            fallback: fallback_factory.build(now, current_mtu),
            negotiation: Arc::new(Negotiation::default()),
            current_mtu: u64::from(current_mtu),
            samples: PacketSamples::new(now),
        })
    }
}

/// Switch the congestion controller belonging to `connection` from BBR to Brutal.
///
/// Quinn returns a cloned controller from `congestion_state`; the clone shares only
/// this connection's [`Negotiation`], so publishing the target here changes the live
/// controller without a global registry or connection-order assumptions.
pub fn activate(connection: &quinn::Connection, bytes_per_second: u64) -> io::Result<()> {
    if bytes_per_second == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a Brutal rate must be non-zero",
        ));
    }

    let controller = connection
        .congestion_state()
        .into_any()
        .downcast::<NegotiatedBrutal>()
        .map_err(|_| {
            io::Error::other(
                "Hysteria2 connection was not constructed with the Brutal controller factory",
            )
        })?;
    controller.activate(bytes_per_second, connection.rtt());
    Ok(())
}

#[derive(Debug, Default)]
struct Negotiation {
    /// Zero means the connection is still using BBR.
    bytes_per_second: AtomicU64,
    /// RTT published by authentication and refreshed from controller callbacks.
    rtt_micros: AtomicU64,
}

impl Negotiation {
    fn activate(&self, bytes_per_second: u64, rtt: Duration) {
        // Publish the RTT first; the release store of the rate makes it visible to
        // the live controller the first time it observes activation.
        self.rtt_micros
            .store(duration_micros(rtt), Ordering::Relaxed);
        self.bytes_per_second
            .store(bytes_per_second, Ordering::Release);
    }

    #[inline]
    fn rate(&self) -> Option<u64> {
        match self.bytes_per_second.load(Ordering::Acquire) {
            0 => None,
            rate => Some(rate),
        }
    }

    fn set_rtt(&self, rtt: Duration) {
        self.rtt_micros
            .store(duration_micros(rtt), Ordering::Relaxed);
    }

    fn rtt(&self) -> Duration {
        Duration::from_micros(self.rtt_micros.load(Ordering::Relaxed).max(1))
    }
}

fn duration_micros(duration: Duration) -> u64 {
    duration.as_micros().try_into().unwrap_or(u64::MAX).max(1)
}

struct NegotiatedBrutal {
    fallback: Box<dyn Controller>,
    negotiation: Arc<Negotiation>,
    current_mtu: u64,
    samples: PacketSamples,
}

impl NegotiatedBrutal {
    fn activate(&self, bytes_per_second: u64, rtt: Duration) {
        self.negotiation.activate(bytes_per_second, rtt);
    }

    fn brutal_window(&self, rate: u64) -> u64 {
        let compensated_rate = rate as f64 / self.samples.ack_rate;
        let pacing_window =
            compensated_rate * self.negotiation.rtt().as_secs_f64() * QUINN_PACING_RECIPROCAL;

        // Quinn blocks when `in_flight + next_datagram >= window`. A 2-MTU
        // window therefore admits only one full datagram, while QUIC normally
        // sends an immediate ACK after the second. The sender would otherwise
        // fall back to one packet per delayed-ACK timeout on low-RTT paths.
        // Three MTUs are the smallest window that admits two full datagrams.
        //
        // Quinn's pacer refills at 5/4 window per RTT, hence the 4/5 above.
        // sing-quic can set its pacer independently and keeps two BDPs of flight
        // headroom; Quinn couples both knobs to `window`, so exact pacing leaves
        // only 0.8 BDP of headroom. On a high-BDP path this can become ACK-clock
        // constrained, but preserving the negotiated fixed rate is safer than
        // silently sending 1.25x or 2.5x it.
        (pacing_window as u64).max(
            self.current_mtu
                .saturating_mul(MIN_CONGESTION_WINDOW_PACKETS),
        )
    }
}

impl Controller for NegotiatedBrutal {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        if self.negotiation.rate().is_none() {
            self.fallback.on_sent(now, bytes, last_packet_number);
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        if self.negotiation.rate().is_some() {
            self.negotiation.set_rtt(rtt.get());
            self.samples.record(now, 1, 0);
        } else {
            self.fallback.on_ack(now, sent, bytes, app_limited, rtt);
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        if self.negotiation.rate().is_none() {
            self.fallback
                .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        if self.negotiation.rate().is_some() {
            // Quinn reports a batch's bytes rather than sing-quic's packet list.
            // Dividing by the current MTU gives a lower-bound packet estimate:
            // it may under-compensate mixed small packets, but cannot invent loss
            // and overdrive the negotiated rate from an unknowable packet count.
            let lost_packets = lost_bytes.saturating_add(self.current_mtu.saturating_sub(1))
                / self.current_mtu.max(1);
            if lost_packets != 0 {
                self.samples.record(now, 0, lost_packets);
            }
        } else {
            self.fallback
                .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = u64::from(new_mtu);
        self.fallback.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        match self.negotiation.rate() {
            Some(rate) => self.brutal_window(rate),
            None => self.fallback.window(),
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        let Some(rate) = self.negotiation.rate() else {
            return self.fallback.metrics();
        };

        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.brutal_window(rate);
        metrics.pacing_rate =
            Some(((rate as f64 / self.samples.ack_rate) * 8.0).min(u64::MAX as f64) as u64);
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            fallback: self.fallback.clone_box(),
            negotiation: Arc::clone(&self.negotiation),
            current_mtu: self.current_mtu,
            samples: self.samples.clone(),
        })
    }

    fn initial_window(&self) -> u64 {
        self.fallback.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PacketSample {
    second: Option<u64>,
    acked: u64,
    lost: u64,
}

#[derive(Debug, Clone)]
struct PacketSamples {
    epoch: Instant,
    slots: [PacketSample; SAMPLE_SECONDS],
    ack_rate: f64,
}

impl PacketSamples {
    fn new(epoch: Instant) -> Self {
        Self {
            epoch,
            slots: [PacketSample::default(); SAMPLE_SECONDS],
            ack_rate: 1.0,
        }
    }

    fn record(&mut self, now: Instant, acked: u64, lost: u64) {
        let second = now.saturating_duration_since(self.epoch).as_secs();
        let slot = second as usize % SAMPLE_SECONDS;
        let sample = &mut self.slots[slot];
        if sample.second == Some(second) {
            sample.acked = sample.acked.saturating_add(acked);
            sample.lost = sample.lost.saturating_add(lost);
        } else {
            *sample = PacketSample {
                second: Some(second),
                acked,
                lost,
            };
        }
        self.update(second);
    }

    fn update(&mut self, current_second: u64) {
        let oldest = current_second.saturating_sub(SAMPLE_SECONDS as u64);
        let (acked, lost) = self
            .slots
            .iter()
            .filter(|sample| sample.second.is_some_and(|second| second >= oldest))
            .fold((0u64, 0u64), |(acked, lost), sample| {
                (
                    acked.saturating_add(sample.acked),
                    lost.saturating_add(sample.lost),
                )
            });
        let total = acked.saturating_add(lost);
        self.ack_rate = if total < MIN_SAMPLE_PACKETS {
            1.0
        } else {
            (acked as f64 / total as f64).max(MIN_ACK_RATE)
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_rates_use_decimal_megabits_and_saturate() {
        assert_eq!(mbps_to_bytes_per_second(1), 125_000);
        assert_eq!(advertised_receive_bps(200), 25_000_000);
        assert_eq!(mbps_to_bytes_per_second(u64::MAX), u64::MAX);
    }

    #[test]
    fn server_rate_is_negotiated_independently_from_advertised_receive_rate() {
        assert_eq!(negotiated_send_bps(0, 100), None);
        assert_eq!(negotiated_send_bps(8_000_000, 0), Some(8_000_000));
        assert_eq!(negotiated_send_bps(8_000_000, 100), Some(8_000_000));
        assert_eq!(negotiated_send_bps(20_000_000, 100), Some(12_500_000));

        // The opposite direction is not part of that minimum calculation.
        assert_eq!(advertised_receive_bps(0), 0);
        assert_eq!(advertised_receive_bps(37), 4_625_000);
    }

    #[test]
    fn server_negotiation_matches_sing_quic_for_zero_client_receive_rate() {
        assert_eq!(
            negotiate_server(0, 100, 200, false),
            ServerNegotiation {
                send_bps: None,
                advertised_receive: AdvertisedReceive::Auto,
            },
            "an RX=0 request keeps BBR in both directions"
        );
        assert_eq!(
            negotiate_server(8_000_000, 0, 37, false),
            ServerNegotiation {
                send_bps: Some(8_000_000),
                advertised_receive: AdvertisedReceive::BytesPerSecond(4_625_000),
            },
            "an absent server upload cap leaves the client's rate intact"
        );
        assert_eq!(
            negotiate_server(20_000_000, 100, 0, false),
            ServerNegotiation {
                send_bps: Some(12_500_000),
                advertised_receive: AdvertisedReceive::BytesPerSecond(0),
            },
            "the upload cap and numeric zero in the opposite direction are independent"
        );
        assert_eq!(
            negotiate_server(8_000_000, 100, 200, false)
                .advertised_receive
                .header_value(),
            "25000000"
        );
        assert_eq!(
            negotiate_server(0, 100, 200, false)
                .advertised_receive
                .header_value(),
            "auto"
        );
        assert_eq!(
            negotiate_server(8_000_000, 100, 200, true),
            ServerNegotiation {
                send_bps: None,
                advertised_receive: AdvertisedReceive::Auto,
            },
            "ignoring client bandwidth keeps both directions on bandwidth detection"
        );
    }

    #[test]
    fn loss_compensation_matches_the_go_sampling_rules() {
        let epoch = Instant::now();
        let mut samples = PacketSamples::new(epoch);

        for _ in 0..39 {
            samples.record(epoch, 1, 0);
        }
        samples.record(epoch, 0, 10);
        assert_eq!(samples.ack_rate, 1.0, "49 samples are not enough");

        samples.record(epoch, 1, 0);
        assert_eq!(samples.ack_rate, 0.8, "40/50 is the minimum ACK rate");

        // A still worse path is clamped so compensation cannot run away.
        samples.record(epoch, 0, 50);
        assert_eq!(samples.ack_rate, MIN_ACK_RATE);

        // Five rotating slots forget the old burst once time advances far enough.
        samples.record(epoch + Duration::from_secs(6), 1, 0);
        assert_eq!(samples.ack_rate, 1.0);
    }

    #[test]
    fn controller_builds_get_connection_local_negotiations() {
        let factory = Arc::new(BrutalConfig);
        let now = Instant::now();
        let first = factory.clone().build(now, 1200);
        let second = factory.build(now, 1200);

        let first_handle = first
            .clone_box()
            .into_any()
            .downcast::<NegotiatedBrutal>()
            .expect("factory must build the negotiated controller");
        first_handle.activate(1_000_000, Duration::from_millis(100));

        assert_eq!(first.window(), 80_000);
        assert_ne!(
            second.window(),
            first.window(),
            "activating one connection must not alter another"
        );
    }

    #[test]
    fn brutal_window_compensates_loss_and_avoids_the_delayed_ack_deadlock() {
        let factory = Arc::new(BrutalConfig);
        let now = Instant::now();
        let controller = factory.build(now, 1200);
        let handle = controller
            .clone_box()
            .into_any()
            .downcast::<NegotiatedBrutal>()
            .unwrap();
        handle.activate(1_000_000, Duration::from_millis(100));
        assert_eq!(controller.window(), 80_000);

        let negotiated = controller
            .into_any()
            .downcast::<NegotiatedBrutal>()
            .unwrap();
        let mut negotiated = *negotiated;
        for _ in 0..80 {
            negotiated.samples.record(now, 1, 0);
        }
        negotiated.samples.record(now, 0, 20);
        assert_eq!(negotiated.samples.ack_rate, 0.8);
        assert_eq!(negotiated.window(), 100_000);

        negotiated.activate(1, Duration::from_micros(1));
        assert_eq!(negotiated.window(), 3600);
        assert!(
            2 * negotiated.current_mtu < negotiated.window(),
            "Quinn's strict boundary must admit two full datagrams"
        );
    }

    #[test]
    fn quinns_five_quarters_pacer_derives_the_negotiated_wire_rate() {
        let factory = Arc::new(BrutalConfig);
        let now = Instant::now();
        let controller = factory.build(now, 1200);
        let handle = controller
            .clone_box()
            .into_any()
            .downcast::<NegotiatedBrutal>()
            .unwrap();
        let rtt = Duration::from_millis(100);
        handle.activate(1_000_000, rtt);

        let derived_pacing_rate = controller.window() as f64 * 1.25 / rtt.as_secs_f64();
        assert_eq!(derived_pacing_rate, 1_000_000.0);

        // At the minimum 80% ACK rate Brutal sends 1.25x on the wire, leaving the
        // negotiated delivery rate after loss.
        let negotiated = controller
            .into_any()
            .downcast::<NegotiatedBrutal>()
            .unwrap();
        let mut negotiated = *negotiated;
        for _ in 0..80 {
            negotiated.samples.record(now, 1, 0);
        }
        negotiated.samples.record(now, 0, 20);
        let compensated_pacing = negotiated.window() as f64 * 1.25 / rtt.as_secs_f64();
        assert_eq!(compensated_pacing, 1_250_000.0);
        assert_eq!(
            compensated_pacing * negotiated.samples.ack_rate,
            1_000_000.0
        );
    }
}
