# nndsk-ro-proton

Linux runtime for Ragnarok Online, derived from pinned Proton-CachyOS and Wine.
The first milestone is an **experimental preservation build**, not a stable
release or a universal replacement for Wine 7.16.

This repository preserves three general Wine compatibility changes recovered
from the runner that passed the HoneyRO PE32 launch and 20-minute Prontera test:

1. Certificate SHA-256 context property (`crypt32`).
2. Named ECDSA-P256 Software-KSP persistence (`ncrypt`).
3. Actual private copy-on-write tracking for memory queries (`ntdll`).

No client/protection patches, no native Windows DLLs, no fabricated trust or
security-check results. The Windows/DOS launch path is a separate integration
requirement, not a runtime patch.

## Source and build identity

- Proton-CachyOS `cachyos-11.0-20260702-slr`:
  `3edf6fbb8af940de5c65b9dd0fbf366b51a218a8`.
- Wine-CachyOS: `b5f2dc7b5906ef864f83df8fef94c9f539eaad2d`.
- Runtime version: `0.1.0-dev.1`; patchset revision: `1`.
- `patches/series` defines the exact behavior patch order.
- `upstream.lock.json` pins the binary base and source revisions.

The preservation recipe rebuilds the six modified modules from a fresh Wine
checkout and overlays them on a verified official binary archive. It does **not**
claim to rebuild the remaining Proton distribution from source. Debug paths and
the host toolchain also prevent a present claim of bit-identical module builds
across hosts. Deterministic packaging is a separate property.

See [build instructions](docs/BUILD.md), [risks](docs/RISKS.md),
[launch topology](docs/LAUNCH.md), and [redistribution status](docs/LICENSING.md).
Nothing is published remotely or integrated into launcher defaults.
