# Prerelease distribution review — 2026-10-08

This supersedes the blocked distribution status in the historical 2026-10-07
review. It authorizes **maintainer acceptance for a prerelease**, not a legal
opinion, an upstream-ready claim, a complete SPDX SBOM, or bit-reproducibility
of upstream's entire binary compilation.

## Preservation and source access

`0.1.0-dev.2` is a **notice/metadata-only packaging revision** of the accepted
`0.1.0-dev.1` build (SHA256
`75b0c916ccf6e7fcd64ed2afe576c2c0bc6a75ef63a8d74ad6dd9bee629d4d9f`).
Every existing binary, script, model, font, template, symlink and file mode stays
identical. Only `nndsk-runtime.json` changes; new source-access and notice files
are added. Patchset revision stays 1; the six module hashes remain identical.
The original archive is preserved. No game, protection, prefix or Wine code is
changed during publication.

The binary release is accompanied on the **same release page** by the source
bundle, checksum-pinned source index, preservation inventory, manifest and
SHA256SUMS. The bundle includes the exact modified Wine and original module
build recipe, pinned Proton root including upstream patches/build rules, all
49 other pinned submodule archives, supplemental dependency sources, and the
committed publication recipe. Rust registry archives match Cargo.lock checksums;
git dependencies are pinned to full commits, not branch selectors. Supplemental
download receipts record their own URL, size and SHA256. Official binaries used
only for read-only custody comparison are excluded from the source bundle.

## Review of inherited distributions

| Distributed family | Material preserved and interpretation |
| --- | --- |
| Wine, wrapper/helpers, graphics, codecs and translation layers | Modified Wine snapshot and pinned Proton/component trees, upstream build patches and license texts. LGPL versions and exceptions stay component-specific. No native proprietary Windows DLL was added. |
| FFmpeg | Its packaged library declares LGPL 2.1-or-later; embedded configuration has neither `--enable-gpl` nor `--enable-nonfree`. Exact pinned tree/build flags are available. This is not a claim about optional codecs in other builds. |
| Wine Mono 11.2.0 | All 2,790 included files match the official binary archive. Full release source (including vendored dependencies), COPYING and constituent notices accompany the release. Do not describe all Mono as one license. |
| Wine Gecko 2.47.4 | Full release source including Mozilla/vendor notices and `toolkit/content/license.html` accompany the release. Component MPL/BSD/LGPL terms remain intact. |
| Piper/eSpeak/ONNX/model | Pinned Piper, historically observed eSpeak source and GPL3 text, exact ONNX 1.14.1 source and binary ThirdPartyNotices, fmt/spdlog and uni-algo notices. Packaged ONNX matches the official binary byte for byte. |
| Model | SHA256 `9f27090af3e0f661913af048a739632a3f577b3233512551d8c90580ccad4aa8` matches the committed phonemizer model. MIT notices for its carrier and libtashkeel origin are retained; no TPM or proprietary-model provenance is inferred. |
| Protonfixes utilities | Exact libmspack/cabextract, procps, Winetricks, UMU database, Info-ZIP 6.0 and Debian 6.0-29 patch sources/notices. Recovery of the Debian source archive is checksum-verified against its original .dsc. No utility or installer is executed by this audit. |
| Zenity 0.2.8 | Packaged executable matches its pinned upstream SHA256; MIT source and Cargo.lock dependency sources/notices retained. Embedded Cantarell is separately OFL1.1, with its own copyright (not Liberation's). |
| Xalia 0.4.9 | Its 13 dependency DLLs match the official release. Twelve managed DLLs also match exact NuGet payload members, recorded in source-index.json; SDL3 3.4.0 has its own pinned source/zlib notice. Xalia and SDL3-CS notices retained. **Superpower is Apache-2.0, not MIT**; Tmds is MIT and .NET packages retain their notices/metadata. |
| Fonts and ICU | Original Proton font notices (Noto, Source Han, Ume), Liberation OFL and ICU release-68-2 notices retained. Six ICU DLL hashes are listed in the pinned Proton icu/README.md; the corresponding release tree is provided, not a current-license substitution. |

Original notice bytes are read from immutable source/distribution archives, not
rewritten under a blanket project license. Where a published crate omits a
separate LICENSE file, its original package license metadata and existing
copyright/SPDX headers are retained as well. The source bundle deliberately
includes optional/build-only dependencies; inclusion is **not** proof that every
such dependency is linked into the runtime.

## Explicit custody limitations

The historical Piper phonemizer download used a mutable `pic.zip` without a
checksum. Its original archive checksum/commit has not been recovered. The
candidate tree `5ecbb9b59abcffe03a9775ae82491c9ac5037f4d`, its MIT notice,
historically corroborated eSpeak/ONNX/fmt/spdlog inputs and byte-identical model
are preserved, but that tree is **not promoted to historical proof**. The
libtashkeel tree is an origin/license reference, not proof of a model-training
revision. MIT does not itself impose a corresponding-source distribution
condition; this uncertainty is retained as a supply-chain/rebuild limitation.

The historical Steam Runtime SDK digest is preserved in
`provenance/upstream-build-observations.json`. Host/SDK dependencies that remain
external are not bundled or claimed as our binary payload. Included i386
FLAC/WebP/Speex/XZ/PCAP/XML/XKB libraries have pinned `steamrtdeps` sources and
build rules. This review is about the identified artifact, not any newer
CachyOS build or arbitrary SDK configuration.

## Reproduction and acceptance gates

```sh
python3 -m unittest discover -s tests
python3 scripts/collect_component_sources.py --publication-lock
python3 scripts/publication_materials.py --output work/publication-materials-20261008-v3
python3 scripts/publication_package.py --repeat-package
```

The previously documented source/module build and accepted staging are required
inputs. Outputs must be new; historical receipts/artifacts are never overwritten.
For rebuilding from downloaded publication sources, use their included
source-index/SHA256SUMS instead of trusting a newly fetched archive's checksum.
The original build lock's false publication flags are historical and intentionally
unchanged; `publication-review.json` is the separate distribution gate.

Packaging checks require all existing records to be preserved, exact six-module
hashes, the sole allowed existing-file metadata change, round-trip tar integrity,
and two packages with the same SHA256. Runtime behavior/stability remains the
accepted HoneyRO result; the new package's GUI download/install test belongs to
the user. Wine 7.16 remains the independent Sakura fallback. This prerelease is
not a promise of compatibility with all RO servers or kernels.

The first local packaging attempt rejected an untrimmed Git CLI newline while
creating the source recipe archive. It was never published; its outputs are
preserved for inspection. The corrected recipe validates the full commit identity
before staging and tests that normalization explicitly. Final artifacts use the
separate `dist/publication-0.1.0-dev.2-r2` directory.

No external release should be created if a known source/notice mismatch,
unreviewed shipped component or runtime-byte discrepancy remains.
