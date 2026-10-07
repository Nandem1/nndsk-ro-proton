# Launcher delivery

The primary runtime is `nndsk-ro-proton` (`0.1.0-dev.1`, patchset 1). Wine 7.16
old-WoW64 remains a separate per-server backward-compatibility profile. Do not
migrate a Wine 7.16 or previous CachyOS prefix into this runtime.

The GitHub repository is a native fork of `CachyOS/proton-cachyos`. Its default
`ro-runtime` branch preserves the existing maintainer history and three separate
behavior commits. The inherited upstream branches are not force-pushed. The
exact pinned base is still the lock's commit, not the current upstream branch tip.
No GitHub binary release or tag is created by this delivery.

## Accepted archive

- Name: `nndsk-ro-proton-0.1.0-dev.1-linux-x86_64.tar.zst`
- Bytes: `398862860`
- SHA-256: `75b0c916ccf6e7fcd64ed2afe576c2c0bc6a75ef63a8d74ad6dd9bee629d4d9f`
- Binary source snapshot commit: `93bda981a6e8b7bdadb46fa3497f84df8dfc6fe2`
- Archive root: `nndsk-ro-proton`
- Launcher catalog identity: `nndsk-ro-proton-0.1.0-dev.1`

The launcher local-import workflow accepts only that checksum-pinned artifact,
validates `nndsk-runtime.json` and the six modified modules, and installs it under
its own managed runtime root. Receipts explicitly describe a local source
snapshot rather than an imaginary GitHub download. Existing unknown or damaged
destinations are preserved, not overwritten.

Selecting the imported runtime is an explicit global setting change; a nonempty
server runner override still wins. Game/patcher/setup Proton invocations convert
the executable through the actual prefix DOS drive mappings, check its round-trip
identity, and retain CWD and the remaining arguments. Wine 7.16 launch arguments
are unchanged.

Public automatic download remains pending the inherited source/license audit and
an explicitly approved binary release. The source fork alone is not a complete
corresponding-source offer for every inherited binary component. Do not advertise
an absent release or present this experimental build as upstream-ready.
