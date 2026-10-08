# Launcher delivery

The primary runtime is `nndsk-ro-proton` (`0.1.0-dev.2`, patchset 1). Wine 7.16
old-WoW64 remains a separate per-server backward-compatibility profile. Do not
migrate a Wine 7.16 or previous CachyOS prefix into this runtime.

The GitHub repository is a native fork of `CachyOS/proton-cachyos`. Its default
`ro-runtime` branch preserves the existing maintainer history and three separate
behavior commits. The inherited upstream branches are not force-pushed. The
exact pinned base is still the lock's commit, not the current upstream branch tip.
The published `v0.1.0-dev.2` tag preserves the publication recipe commit;
subsequent documentation commits do not move that tag.

## Published archive (notice/metadata-only revision)

- Name: `nndsk-ro-proton-0.1.0-dev.2-linux-x86_64.tar.zst`
- Bytes: `399605131`
- SHA-256: `208e6d4735c9a25c4f14b6465712a1069ce53aaf4d5a12eb5a3967abe962ead4`
- Binary source snapshot commit: `93bda981a6e8b7bdadb46fa3497f84df8dfc6fe2`
- Archive root: `nndsk-ro-proton`
- Launcher catalog identity: `nndsk-ro-proton-0.1.0-dev.2`

The launcher downloads this versioned package on demand, pins its size/SHA-256,
validates `nndsk-runtime.json` and the six modified modules, and installs it under
its own managed runtime root. Receipts bind the exact versioned HTTPS source.
Offline import accepts the original dev.1 or published dev.2 archive, with
distinct receipts/identities; no arbitrary archives are accepted. Existing unknown or damaged
destinations are preserved, not overwritten.

Selecting the imported runtime is an explicit global setting change; a nonempty
server runner override still wins. Game/patcher/setup Proton invocations convert
the executable through the actual prefix DOS drive mappings, check its round-trip
identity, and retain CWD and the remaining arguments. Wine 7.16 launch arguments
are unchanged.

Sources/notices, manifest, preservation inventory and checksums accompany the
binary on the same [release page](https://github.com/Nandem1/nndsk-ro-proton/releases/tag/v0.1.0-dev.2).
The source fork alone is not treated as the complete corresponding-source offer.
The final GUI download/game test is assigned to the user. Existing global/server
selections and prefixes stay unchanged; selecting dev.2 explicitly creates its
own prefix. This experimental runtime is not advertised as upstream-ready.
