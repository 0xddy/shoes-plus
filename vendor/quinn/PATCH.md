# Local Quinn ingress admission patch

Source: crates.io `quinn` 0.11.11, upstream revision
`a7499b8439e393a6299330111d9c8564cd96c464` (`quinn/` in
<https://github.com/quinn-rs/quinn>). The original MIT and Apache-2.0 licenses
are retained. `Cargo.toml` is the standalone normalized crate manifest.

The upstream endpoint routes network packets into an unbounded channel for each
connection before that connection decrypts and validates them. Stream receive
windows do not limit packets still waiting in this channel. Sustained ingress
faster than processing can therefore retain unbounded packet buffers.

This patch adds a private event queue with a per-connection budget of 256 pending
network datagrams, matching quic-go's `MaxConnUnprocessedPackets` policy. Full
packet queues discard subsequent datagrams without blocking the shared endpoint;
QUIC loss recovery recovers reliable stream/control data; DATAGRAM payloads
retain best-effort semantics. The permit is released at dequeue, on send failure,
or when the receiver is dropped. There can additionally be one event currently
being processed by the connection driver.

Only `DatagramEvent::ConnectionEvent` consumes packet admission. Locally generated
`Close`, `Rebind`, and protocol control events continue through the reliable
channel without using the packet budget. No public API, bandwidth policy,
congestion controller, or wire format is changed. The underlying channel still
provides Tokio's cooperative polling behavior.

Deterministic unit tests in `src/connection_events.rs` verify queue saturation,
dequeue and close release, failed-send release, connection isolation, and control
event delivery with a saturated packet budget.

The upstream examples and tests are included so the normalized crate manifest
continues to be valid and its existing transport tests remain available.
