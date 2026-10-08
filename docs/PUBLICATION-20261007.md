# Publication review, 2026-10-07

Status: **full-runtime binary publication remains blocked**. This review does not
change the accepted archive, modules, patchset, runner or guest software.
It narrows a previously general source-audit item to a specific unresolved input.

## Verified custody

The official release API currently reports the pinned x86_64 archive SHA-256
`428d7a47b29519856e5bad50eb7e0f0123ec2431e2d37c31cebef2703f24f253`, size
`328233608`, published 2026-07-12. This matches the preserved base archive.
[Upstream release](https://github.com/CachyOS/proton-cachyos/releases/tag/cachyos-11.0-20260702-slr).

The accepted modified archive remains SHA-256
`75b0c916ccf6e7fcd64ed2afe576c2c0bc6a75ef63a8d74ad6dd9bee629d4d9f`.
Existing source snapshots and all 50 gitlinks remain as documented in
[DISTRIBUTION.md](DISTRIBUTION.md). A list of pinned submodules alone does not
cover downloads inside their build rules.

## Concrete first unresolved transitive source

Pinned Proton `3edf6fbb8af940de5c65b9dd0fbf366b51a218a8` records Piper at
`9d06b74959570772e8bcbe7a3f696664d2421167`. The Piper
[committed CMakeLists.txt](https://github.com/shaunren/piper/blob/9d06b74959570772e8bcbe7a3f696664d2421167/CMakeLists.txt)
(Git blob `6e41c83e97029319e71802d56d23b5fd93a505b8`) defines, unless overridden:

```text
ExternalProject_Add(piper_phonemize_external
  URL https://github.com/shaunren/piper-phonemize/archive/refs/heads/pic.zip
  ...)
```

There is no URL_HASH or fixed phonemizer commit in this dependency declaration.
The pinned Proton Makefile.in's Piper post-build rule copies that dependency's
libraries, `espeak-ng-data` and `libtashkeel_model.ort` into the runtime.
The accepted binary inventory contains:

| Payload | SHA-256 | Bytes |
| --- | --- | ---: |
| `files/lib/x86_64-linux-gnu/libpiper.so` | `b4f50d04a7898c6a3c33bf8193a78724a158571f96fc3c182e50f337fd0b71cf` | 667928 |
| `files/lib/x86_64-linux-gnu/libpiper_phonemize.so.1.2.0` | `42deaa48eb60b246220304e11a35f7e13bad6f2e68423f5129053aea80e6cf66` | 444968 |
| `files/lib/x86_64-linux-gnu/libespeak-ng.so.1.52.0.1` | `ff983fef81d6b241545a8b87e2ee0a06cb49fbd76f1142ec045117a3ff30893c` | 578792 |
| `files/share/libtashkeel_model.ort` | `9f27090af3e0f661913af048a739632a3f577b3233512551d8c90580ccad4aa8` | 10261536 |

The currently observed `pic` branch resolves to
`5ecbb9b59abcffe03a9775ae82491c9ac5037f4d` (committer date 2024-11-26).
That date makes historical correspondence plausible; it does **not** prove which
archive the original build fetched, whether a cached/overridden dependency was
used, or that the branch was never moved. It is not yet promoted to a verified
historical source identity.

The current branch's CMake file declares an ONNX Runtime 1.14.1 binary download,
eSpeak at `0f65aa301e0d6bae5e172cc74197d32a6182200f`, and a checked-in model.
These are leads for narrowing the source/notices inventory, not proof about the
historical build. Exact downloaded content, associated notices and SDK-supplied
libraries remain to be reconciled. No license is inferred solely from filenames.

## Publication decision

Do not create a public full-runtime binary release, fabricate a source-complete
manifest or change LocalOnly launcher registration on this evidence alone.
This is an evidence/maintainer acceptance gate, not a legal conclusion that
Proton cannot be redistributed. No legal clearance is claimed.

Two possible distribution designs remain distinct:

1. Preserve the requested full tar.zst package and finish the inherited-component
   source/notices audit, using historical build cache/logs where necessary.
2. Publish only our six general Wine modules with complete corresponding Wine
   source/build inputs, and let a separately designed transactional installer
   combine them with the checksum-pinned official base downloaded from upstream.
   This would avoid us redistributing the inherited bundle; it would change the
   package/installer contract and therefore requires an explicit user decision.

Neither alternative changes a guest protection or is a new Wine fix. Option 2
has **not** been implemented or treated as blanket legal clearance. The existing
runtime remains usable through the accepted local importer.

The next highest-information source test is to recover the original build's
phonemizer archive/cache or input record and compare it to the historical candidate
tree. No external issue/message was submitted on the user's behalf.
