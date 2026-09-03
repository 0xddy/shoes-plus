# Local Quinn transport patches

Source: crates.io `quinn` 0.11.11, upstream revision
`a7499b8439e393a6299330111d9c8564cd96c464` (`quinn/` in
<https://github.com/quinn-rs/quinn>). The original MIT and Apache-2.0 licenses
are retained. `Cargo.toml` is the standalone normalized crate manifest.
Its protocol dependency also points to the adjacent patched `../quinn-proto`;
the standalone `Cargo.lock` keeps the vendor library test gate reproducible.

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

## Fatal local UDP I/O cleanup

`ConnectionDriver::poll` used to return immediately through
`drive_transmit(cx)?` when a socket operation returned a fatal I/O error. Dropping
the driver does not drop connection state while application connection/stream
handles remain alive. Consequently blocked reads, writes, and `closed()` could
remain pending, with the endpoint retaining the connection and its routing.
The same early return is present in the reviewed
[upstream Quinn revision](https://github.com/quinn-rs/quinn/blob/31c0f7de25730d95b6eb272db63831c095adf36f/quinn/src/connection.rs).
By comparison, the reviewed
[quic-go connection loop](https://github.com/quic-go/quic-go/blob/c2877d14c1382829f78966ccb4bde09a8ec487c9/connection.go)
routes send-queue failures through connection destruction, closes the stream and
datagram queues with the error, cancels the connection context, and removes
connection IDs during immediate cleanup.

Before returning the original I/O error for driver logging, this patch closes
the local protocol state, wakes all connection waiters, clears driver timers and
pending transmit state, closes/drains the ingress queue, and notifies the endpoint
that this connection is drained. A flag prevents a second `Drained` event when
application handles are later dropped; a reused endpoint connection handle must
not be removed by stale cleanup. An existing application-visible close reason is
preserved. Otherwise, because the public `ConnectionError` has no I/O variant,
waiters receive `TransportError(INTERNAL_ERROR)` with the local I/O kind and
message. The failed socket is not used to attempt a graceful wire close.

This is a cleanup guarantee for errors actually returned by the socket adapter,
not evidence that such an error caused the observed WAN Speedtest failure.
The default Tokio adapter in `src/runtime/tokio.rs` calls
`quinn_udp::UdpSocketState::send`, not its raw `try_send` method. In the resolved
quinn-udp 0.5.15 Unix implementation, `send` only returns `WouldBlock`; `EMSGSIZE`
is ignored for MTU probing and other send errors are logged then treated as
successful submission. `WouldBlock` keeps its existing retry behavior. A custom
`AsyncUdpSocket` or an error from Tokio's readiness/registration layer can still
reach the fatal driver path. The loopback fault adapter deliberately injects
`PermissionDenied` at that abstraction boundary; it does not simulate normal
Unix `sendmsg` error filtering or identify a production network root cause.

`src/tests/io_error.rs` establishes a normal loopback QUIC connection before
injecting one `try_send` or `poll_writable` failure. Tests require an already
pending reader, writer, and `closed()` waiter to receive the error, require
`wait_idle()` to complete while application handles remain alive, then reconnect
on the same endpoint and drop the old handles without removing the new
connection. Another case preserves an existing local closure. These tests timed
out with the original early-return path. The ingress queue test also verifies
immediate allocation/permit release and refusal of new events after abort.

Validation: `cargo test --offline --locked --manifest-path vendor/quinn/Cargo.toml --lib`
(26 passed, 3 upstream stress tests ignored).
