# Quinn transport corrections

Base: crates.io `quinn-proto` 0.11.17, unchanged MIT / Apache-2.0 licensing.
The original normalized manifest, source and embedded tests are retained.

This backports the assembler correction from upstream
[PR #2814](https://github.com/quinn-rs/quinn/pull/2814), merged on 2026-09-03
as `c3f8b0984cc8aa0da0243b3ff29f7ad169951fa8`. The upstream `main` branch uses
a deque; this copy retains the 0.11.17 binary heap and applies only the
chunk-coalescing change. The diagnosis is also recorded in
[issue #2809](https://github.com/quinn-rs/quinn/issues/2809).

Previously, 2,049 high-utilization contiguous STREAM buffers could produce
`INTERNAL_ERROR: too many gaps in stream buffer`, closing the entire QUIC
connection even with no actual gaps. A slow application reader or one missing
prefix byte can produce this backlog during an ordinary upload.

Compaction now coalesces contiguous chunks smaller than
`max(ceil(buffered_bytes / 1024), 128)` even if their allocations are already
efficient. Larger chunks remain in place to avoid repeatedly copying them.
The existing 1,024 post-compaction chunk limit, 2,048 compaction trigger,
duplicate handling, allocation accounting, and transport flow-control limits
remain in force. This is not a bandwidth or receive-window increase.

Additional regressions cover lossless contiguous data, a nearly 7 MiB backlog
of full-sized packets with a paused reader, the same backlog behind one missing
prefix byte, byte-exact partial readback, threshold rounding, and preservation
of the true disjoint-span limit. Existing duplicate, overlap, unordered-read
and allocation tests are retained.

Remove this vendor override when a compatible published Quinn release includes
PR #2814 (or an equivalent fix), then run the assembler and HY2 upload
regressions against that release. Do not remove the resource limits or downgrade
to an older release without the 0.11.17 security fixes.

## DATAGRAM storage accounting

The resource-control audit also corrects three local 0.11.17 accounting defects:

- Removing an outgoing datagram already subtracts its payload in `pop_front`;
  the drop-to-make-space path must not subtract it a second time.
- Blocking sends and `send_buffer_space` must count metadata for every queued
  datagram, including empty payloads, rather than just one metadata entry.
- Received frame slices are copied into payload-sized storage before queueing.
  Otherwise a tiny frame could retain the complete decrypted UDP/GRO allocation
  while the receive budget only counted its visible payload length.

This retains oldest-first eviction and the 0.11.17 dropping-send allowance of
one final datagram beyond the configured send window. The receive byte budget
covers owned payload plus occupied entry metadata, not allocator overhead or
spare `VecDeque` capacity. Copying received payloads adds a bounded copy per
DATAGRAM; it does not copy STREAM traffic. Application-level HY2 fragment and
forwarding queues have their own ownership/accounting boundaries.

Run the private-module regressions with:

```sh
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked --lib connection::datagrams::tests
```

The standalone lockfile is committed solely to make these vendor unit tests
reproducible. Production builds continue to use their workspace root lockfile.

## BBR application-limited STARTUP and bandwidth sample admission

Backport the two arithmetic/admission corrections proposed in upstream
[PR #2798](https://github.com/quinn-rs/quinn/pull/2798), head
`fd3881f93ede58f4a4daf524cf39e1dc1ac9364b` (open and unmerged when reviewed on
2026-09-03). The upstream issue and local regressions demonstrate defects in
the vendored 0.11.17 BBR implementation:

- STARTUP compared a dimensionless congestion-window gain with a target byte
  count, effectively growing the window with cumulative acknowledged traffic
  when an application-limited tunnel remained in STARTUP. Compare the actual
  congestion window with the target instead.
- Admit positive non-application-limited delivery samples even when they are
  lower than the current maximum, allowing the ten-round filter to expire old
  peaks. Application-limited samples may raise the estimate, but not lower it.
  Rejecting all such samples left a newly application-limited connection with
  no bandwidth estimate and unbounded ACK-aggregation growth.

Deterministic regressions cover application-limited STARTUP with and without
a seeded estimate, expiration after delivery falls below a historical peak,
and continued STARTUP growth toward a genuinely larger target. Before the
fixes, both bounded-window tests grew to approximately 20 MB after about 20 MB
of acknowledged traffic, and the bandwidth estimate stayed at 1,200,000 B/s
after delivery fell to 120,000 B/s for more than ten rounds. Those three tests
failed; the normal growth test passed. All four pass with the corrections.

These fixes do not replace Quinn's experimental BBR algorithm, change its
external pacer, or establish the cause of a particular WAN Speedtest stall.
Download-to-upload transitions still need connection-level interoperability
validation with ACK, flow-control, loss and pacing observations.

```sh
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked --lib congestion::bbr
```

## Acknowledge reverse traffic while outgoing data is blocked

When STREAM or ACK-eliciting control frames were pending, `poll_transmit`
treated their packet space as congestion controlled before assembling frames.
If the congestion window or pacer blocked those frames, it also skipped ACKs
that were already due. Download traffic could consequently delay acknowledgement
of a peer's simultaneous upload. Go's corresponding sender explicitly calls
`maybeSendAckOnlyPacket` in its `SendAck` and `SendPacingLimited` paths:
[quic-go v0.61.0](https://github.com/quic-go/quic-go/blob/v0.61.0/connection.go).

On these blocked paths, fall back to emitting the due ACK alone. Keep queued
STREAM, FIN and flow-control updates pending, and preserve the pacing wakeup.
Anti-amplification checks still run first. Initial packet size rules and the
existing optional `pad_to_mtu` policy (including accounting padding as in-flight
bytes) are preserved. This changes ACK scheduling, not the configured congestion
algorithm or the application's bandwidth limits.

Four in-memory connection regressions cover congestion-window and pacing
blocks, each with MTU padding enabled and disabled. They decrypt the ACK packet,
verify that no queued STREAM/MAX_DATA bypasses congestion control, then release
the outstanding traffic and verify the complete 1 MiB payload, FIN and saved
MAX_DATA update. Both unpadded tests fail without the correction. All four pass
with it; the complete vendored library suite has 286 passing tests.

This establishes a transport scheduling defect, not the cause of a particular
WAN outage. Node-agent's direction-switch interoperability suite additionally
tests large ordinary transfers on one existing HY2 connection.

Run all vendor transport regressions (also used in CI):

```sh
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked --lib
```
