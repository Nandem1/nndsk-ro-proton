# nndsk-ro-proton 0.1.0-dev.2

Experimental Linux x86_64 runtime for Ragnarok Online, preserving the accepted
Proton-CachyOS 11 runtime and three general Wine compatibility changes:

- crypt32: SHA-256 certificate context property.
- ncrypt: named Software-KSP ECDSA-P256 persistence and lifecycle.
- ntdll: private COW state observed through VirtualQuery.

This release changes **only notices/source-access metadata and packaging identity**
relative to the accepted dev.1 build. Runtime code/data and all six modified
module hashes are identical. It is not an upstream-ready or universal-compatibility
claim. Wine 7.16 remains the launcher's independent per-server fallback.

Binary: `nndsk-ro-proton-0.1.0-dev.2-linux-x86_64.tar.zst`

SHA256: `208e6d4735c9a25c4f14b6465712a1069ce53aaf4d5a12eb5a3967abe962ead4`

Sources/notices: `nndsk-ro-proton-0.1.0-dev.2-sources.tar.zst`, with original Wine
modifications/build recipe, pinned Proton/component sources and supplemental
dependency source/notices. `source-index.json` describes custody and explicit
limitations; `preservation.json` records unchanged accepted files/modules.
Verify every download against the accompanying `SHA256SUMS`.

Publication recipe/tag commit: `2dbf7cf1c2c6856ecac6f65cb6742ffc61d49d2a`.
Original module source commit: `93bda981a6e8b7bdadb46fa3497f84df8dfc6fe2`.

Validated: identical accepted runtime code/data, two deterministic packages,
archive integrity, inner source checksums and real isolated launcher import.
HoneyRO's earlier stability result is accepted; the final public-package GUI
download/game test remains assigned to the user. No guest/client/protection
files were changed.

COW requires 4096-byte host pages and the documented Linux userfaultfd/pagemap
features. Software-KSP persistence uses Wine/DPAPI, not TPM or Windows-equivalent
isolation. Upstream compilation bit-reproducibility and a complete SPDX SBOM are
not claimed. The historical checksum/commit of the mutable Piper phonemizer
download remains unknown; see the [artifact-specific review](https://github.com/Nandem1/nndsk-ro-proton/blob/2dbf7cf1c2c6856ecac6f65cb6742ffc61d49d2a/docs/PUBLICATION-20261008.md).

Existing runner selections and prefixes must not be migrated silently.
Use the launcher's verified Windows/DOS launch topology, not an arbitrary Unix
game path through the Windows-visible UMU shim.

## Publication custody

Published on 2026-10-08 after verifying all six remote assets as `uploaded`, with
GitHub-reported sizes and SHA-256 digests matching their local counterparts.
Release ID: `406420296`; `draft=false`, `prerelease=true`. The tag points directly
to the publication recipe commit above and is not moved by documentation updates.

| Asset | Bytes | SHA-256 |
| --- | ---: | --- |
| Binary archive | 399605131 | `208e6d4735c9a25c4f14b6465712a1069ce53aaf4d5a12eb5a3967abe962ead4` |
| Source archive | 1401592274 | `846a3de09d64e37dbf02b17ee1da5199e8e8600eebbbe1cc63aef99387a87d68` |
| manifest.json | 3185 | `46622ca2641c89bdddf822f94b42eeb64a4feb5c07f6f2ac35a933b940132b8d` |
| source-index.json | 286366 | `96366bba42af2a8c2456b5f1c0315675870645b0bded725621b9140306d5d3a8` |
| preservation.json | 517333 | `78f6f7e33d6e1b20c2b88ae006b7cde21ecee46054d569e912b79117145dd113` |
| SHA256SUMS | 473 | `04133407e029c74b3788bd539a05e0ccc35c3b9021917578f61ec275426aae40` |

Runtime recipe tests: 70 tests, OK, one explicitly skipped game test. Both actual
dev.1 and dev.2 archives passed the launcher's isolated import regression. No
Wine or game process was started by those import tests.
