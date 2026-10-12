# nndsk-ro-proton 0.1.0-dev.3

Experimental Linux x86_64 prerelease. Same pinned Proton-CachyOS 11 / Wine base,
the original three compatibility patches and the independent Wine 7.16 fallback.

## Changes

- Adds ephemeral ECDSA-P256 public-key import to Software KSP, covering .NET's
  named-curve descriptor, ephemeral metadata and export-policy PERSIST request.
  Verification remains real BCrypt/GnuTLS ECDSA; altered signatures/digests fail.
  Public keys cannot sign or export private material.
- Queries Wine's actual C volume GUID before normal `run`/`waitforexitandrun`
  targets and supplies its missing prefix-local filesystem alias. Only the owned
  `drive_c` mapping is accepted; conflicting names are retained and rejected.
  GUIDs are not guessed, permissions are not changed and validation is not bypassed.
- Preserves crypt32/Unix ntdll binaries and all unrelated runtime files. Only
  PE32/PE64 ncrypt DLLs are replaced; the scoped volume helper and Proton invocation
  step are supplied with corresponding source.

## Evidence and scope

The real HoneyRO installer failed in dev.2 at NCryptImportKey, then the initial
candidate exposed a separate missing PERSIST flag. The refined patch passed 144
checked API records per architecture, including invalid-signature controls and
32 repeated import/verify/free cycles. Certificate/RSA/persisted-key lifecycle,
user/machine separation, corruption and race regressions passed. COW/IAT remained
green. The real installer subsequently completed, confirmed by the user; its
resulting HoneyRO.exe and HoneyRO Patcher.exe are PE32.

The volume issue was error 2 (file not found), misreported by the installer as
AccessDenied. DOS queries succeeded; GUID queries failed until their real C mapping
was supplied. The release automates that narrowly scoped correspondence rather
than shipping the private experiment's hard-coded alias.

The assembled candidate passed the public-import and automatic-volume probes in
both architectures, then the existing crypto lifecycle/corruption/race suite with
an unchanged runner inventory and idle prefix at the end. The offline preparation
suite has no failures; one optional private historical capture is not supplied.

No new game stability session was requested or performed. The older game acceptance
remains historical, not proof for new clients, hashes or this release. No game,
anti-cheat, packets, server validation, system policy or native Windows DLL changed.
This is not a universal Wine/CNG provider, TPM, full upstream bit-reproducibility
or complete SPDX-SBOM claim. Inherited source/notice limitations remain documented
in the dev.2 distribution review; the unchanged materials accompany this package.

Existing selections and prefixes stay unchanged. RO-Launcher's catalog must pin
this exact version's binary size/hash and manifest/module identities. Publication
alone does not update an older launcher's compiled catalog. Selecting dev.3 is
explicit and obtains its own prefix; dev.2 must remain a recognized legacy runtime.

## Reproduction

The historical preservation lock is intentionally unchanged. Build the fourth
patch with `scripts/ecc_import_experiment.py`, compile the owned fixtures/helper
with `tests/build_probes.py`, and stage in a **fresh** output with:

```sh
python3 scripts/dev3_stage.py \
  --ncrypt-build work/experiments/ecc-import-05 \
  --probes work/probes/dev3-03 \
  --output work/experiments/dev3-stage-new
```

Use `scripts/dev3_package.py` to package a committed, verified source recipe,
matching Wine snapshot, exact inherited source/notices, preservation inventory,
manifest and SHA256SUMS. No old output, tag or release may be overwritten.
Publication is a separate maintainer action; this document alone is not authority
to commit, push, tag or publish.

## Publication record

Published with maintainer authorization on `2026-10-12T01:21:10Z` as public
prerelease [v0.1.0-dev.3](https://github.com/Nandem1/nndsk-ro-proton/releases/tag/v0.1.0-dev.3),
release ID `410035509`, `draft=false`, `prerelease=true`.
The immutable tag/source/packaging commit is `5855cfe862b1bc58f8bec75c51669153934116ca`.
Later evidence documentation does not move that tag.

- Binary: `399666743` bytes, SHA-256 `441d2d237649a7a84f7074e94173ded91ee3a593f29156531b6427e3dd631a14`.
- Sources: `1474411617` bytes, SHA-256 `c8bfb96fb8777e25836297672b0dead8131ff2d6478a5190140c952da3953a24`.
- Two independently packed binaries matched; the complete binary and nested/outer
  source inventories were read back and verified. All six GitHub asset sizes and
  digests matched the local package before publication.
- RO-Launcher's native development build accepted/reimported both dev.2 and dev.3,
  and installed dev.3 without modifying settings, server overrides or installation
  records. Its catalog changes remain local; no launcher release was made.
- An unauthenticated download from the exact public versioned HTTPS URL matched
  the pinned size/hash and passed native launcher CLI reimport. No GUI on-demand
  download/game session or installed launcher AppImage upgrade is claimed.

Exact remote asset identities and acceptance limits are recorded in
[`provenance/publication-dev3.json`](../provenance/publication-dev3.json).
