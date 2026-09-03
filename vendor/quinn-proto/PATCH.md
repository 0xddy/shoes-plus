# Quinn stream reassembly backport

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
