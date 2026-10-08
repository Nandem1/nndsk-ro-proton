# Distribution preparation

HoneyRO compatibility/stability is **accepted PASS** for the identified new
artifact. Additional game tests were stopped by the user; see
[the acceptance record](ACCEPTANCE-20261006.md). No new runtime behavior is being
introduced during this step.

## Already available locally

- Binary: `dist/nndsk-ro-proton-0.1.0-dev.1-linux-x86_64.tar.zst`, manifest and
  checksums. Entrypoints, source/base commits, architectures and COW capability
  requirements are identified.
- Exact modified Wine and original build-recipe source snapshot:
  `dist/source/nndsk-ro-proton-0.1.0-dev.1-source.tar.zst`.
- Supplemental exact top-level Proton source:
  `dist/source/proton-cachyos-3edf6fbb8af9-source.tar.zst`.
  Size: 74376102 bytes; SHA256:
  `d7832130e4da8b1e9a79c966b2b65dd2b7cf09bcd287aab5d63a1bf89c1f4d85`.
  Companion: `proton-source-manifest.json` and `proton-source.SHA256SUMS`.

The supplemental archive contains all 3763 tracked blobs from the pinned
Proton commit, including wrapper/helper code, patches, fonts, build rules and
notices. Streamed content and Git modes match the committed tree. It contains
no working-tree modifications, prefixes or client files. Gitlinks are **not**
submodule payloads: this archive alone does not provide complete inherited
component sources.

## Static component inventory

[proton-components.json](../provenance/proton-components.json) records all 50
upstream gitlinks and exact URLs/commits, the committed metadata blob hashes,
embedded version records, and payload-path groups from the 9432-entry binary
inventory. It is a source-reference inventory, **not a complete SBOM**.

The shipped DXVK, vkd3d-proton and vkd3d version records name the same commits
as the pinned source tree. This is useful corroboration, not proof that every
binary byte was built from unmodified source. SDK-supplied libraries, nested
dependencies, download-only inputs and model/data components still need review.
No license is guessed from a library name or gitlink.

The Wine-specific source snapshot and newly archived Proton root close those
local source-custody tasks. Publication remains blocked while inherited-source
and notices completeness are unresolved. An earlier aggregate LICENSE or a
generic homepage does not resolve the inventory.

## Next distribution work, in order

1. Recover exact source/notices for shipped components using pinned commits,
   shipped version records and build rules. Include upstream build-time patches
   and nested/downloaded inputs; do not substitute a current branch tip.
2. Resolve the historical Piper/eSpeak/phonemizer/model inputs and SDK-supplied
   library provenance. The SDK's historical immutable digest has now been
   recovered from the exact upstream build logs; associated source/notices
   and all transitive inputs are not yet reconciled. See
   [the publication review](PUBLICATION-20261007.md).
3. Complete a per-file/component source/license map and review the proposed
   source-access mechanism. Keep publication flags false until this closes.
4. Prepare release URLs and launcher runtime registration only after explicit
   publication/integration authorization. DOS launch topology and isolated
   prefix ownership remain integration requirements.

Do not remove unused components, change graphics, rebuild a different base,
add a Wine fix or rewrite the accepted artifact just to simplify this audit.
That would create another runtime rather than preserve the accepted one.

## Reproducing the supplemental source archive

Use a checkout/object database of the pinned repository as the explicit source
input. The destination must not already exist; zstd refuses overwrite:

```sh
set -o pipefail
env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC \
  git -c tar.umask=0022 -C /absolute/proton-cachyos \
  archive --format=tar --prefix=proton-cachyos-source/ \
  3edf6fbb8af940de5c65b9dd0fbf366b51a218a8 \
  | env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC \
    zstd -q -19 -T1 -o /absolute/new-output.tar.zst
```

Compression-tool versions can affect this supplemental compressed checksum;
the Git commit and verified complete blob/mode set are its source identity.
The recorded packaging tools were Git 2.55.0 and zstd 1.5.7.
This command is packaging, not compilation or a runtime test. No game, Wine,
installer or remote publication is invoked.
