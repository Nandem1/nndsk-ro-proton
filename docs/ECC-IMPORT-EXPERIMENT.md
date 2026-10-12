# Ephemeral P-256 public import experiment

This is a private fourth-patch candidate, **not** a new published runtime or
authorization to replace existing runners/prefixes. The accepted three patches,
`patches/series`, `upstream.lock.json`, preservation source and existing build
outputs remain unchanged. Wine 7.16 remains the per-server fallback.

## Causal evidence

The HoneyRO installer reported `The client signature could not be verified` at
0%. Its bundled .NET code imports an ECDSA public key with `NCryptImportKey`,
`ECCPUBLICBLOB`, a generic ECC public header, and a version-0 descriptor containing
`NCRYPTBUFFER_ECC_CURVE_NAME` (60), `nistP256`. The pinned Wine implementation
rejects every non-null descriptor with `NTE_NOT_SUPPORTED` (`0x80090029`), before
performing cryptographic verification. The exact API call also fails in our own
PE64 fixture on installed dev.2. This is not an installer crash or proof of an
invalid server publication.

The public signed publication verified independently with Node/OpenSSL and the
embedded public SPKI. No private signing material or client modifications were
needed. Installer executable/hash and full traces are private diagnostic evidence,
not repository assets. This experiment does not change certificate trust,
signature verification, anti-cheat, payloads or network validation.

Primary references:

- [Microsoft NCryptImportKey contract](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptimportkey).
- [Pinned Wine implementation](https://github.com/CachyOS/wine-cachyos/blob/b5f2dc7b5906ef864f83df8fef94c9f539eaad2d/dlls/ncrypt/main.c).
- [.NET 10 named-curve descriptor](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/Common/src/System/Security/Cryptography/ECCng.ImportExport.NamedCurve.cs).
- [.NET CngKey import and ephemeral metadata](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/CngKey.Import.cs).
- [.NET public import/export-policy step](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/ECCng.ImportExport.cs).
- [.NET export policy uses Persist](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/Common/src/System/Security/Cryptography/CngHelpers.cs).

These .NET 10.0.0 sources explain the captured 10.0.12 call shape; they are not
an assertion that every patch-release source byte is identical.

## Deliberately narrow scope

- Microsoft Software KSP, ephemeral **public** ECDSA-P256 only.
- Exact 72-byte public blob, 32-byte coordinates; generic magic requires the
  explicit supported curve. Fixed P-256 magic can be imported without a descriptor.
- Descriptor version, count, type, pointer, bounded UTF-16 length, terminator,
  curve and flags are validated. Unknown parameters/curves are not ignored.
- Only a local blob copy is normalized for the pinned BCrypt backend. Verification
  still uses the real BCrypt/GnuTLS ECDSA implementation.
- Supports the one-byte `CLR IsEphemeral` custom property and post-import export
  policy metadata needed by .NET, including its `NCRYPT_PERSIST_FLAG` request on
  an unnamed public import. That property is applied only to the ephemeral object;
  no named key or storage record is created. Other properties/flags are not silently
  persisted or ignored. Existing generated/named-key mutation rules stay
  unchanged. Imported public keys cannot sign or export private material, including
  after enabling plaintext export policy.
- No full CNG provider, other curves, private imports, key-name import, VBS or TPM
  claims. No native-Windows differential result or allocation-failure injection yet.

## Reproduce without replacing anything

The original sealed preservation build must exist. Each output must be fresh;
failures are retained and are not cleaned up to obtain a green result.

```sh
python3 -m unittest discover -s tests -v
python3 tests/build_probes.py --output work/probes/ecc-import-own
python3 scripts/ecc_import_experiment.py --output work/experiments/ecc-import-own --jobs 8
python3 scripts/regression.py \
  --runner work/experiments/ecc-import-own/nndsk-ro-proton-ecc-import \
  --umu /absolute/path/to/managed/umu-run \
  --probes work/probes/ecc-import-own \
  --output work/ecc-import-own-regression --section ecc-import
python3 scripts/regression.py \
  --runner work/experiments/ecc-import-own/nndsk-ro-proton-ecc-import \
  --umu /absolute/path/to/managed/umu-run \
  --probes work/probes/ecc-import-own \
  --ncrypt-tests work/experiments/ecc-import-own/build-pe/dlls/ncrypt/tests \
  --output work/ecc-import-own-crypto --section crypto
```

The current candidate is `0.1.0-dev.3-ecc-import.2`, `publicationReady=false`, with an honest
uncommitted-input receipt. A full stage inventory comparison permits changes to
only PE32/PE64 `ncrypt.dll` before writing the new candidate's manifest. Other
runtime bytes, modes and symlinks must match the sealed baseline. Original source
commit identifies the inherited base; `experimentalSource` identifies the new
uncommitted patch and build inputs, not a fabricated committed source.

The existing API harness uses managed UMU and fresh owned prefixes, refuses reuse,
records stable process identities and checks prefix idleness. It does not disable
the launcher's session supervisor; it is a standalone test harness. Real desktop
installer testing must use the launcher-owned supervisor with a new experimental
prefix, never migrate/adopt the dev.2 installer prefix.

## Acceptance and review

The owned probe covers the .NET call shape, properties, public export, valid
signature, altered signature/digest rejection, malformed inputs, denied private
operations, fixed-format compatibility and 32 import/verify/free cycles in each
architecture. Its output gate requires every status and exact repetition counts;
an UMU exit status of zero or a `PASS` string alone cannot certify success.

Run the existing crypto persistence/corruption/race and COW/IAT regression anchors
on the candidate, then inspect all source, manifest, runner-copy and process seams
adversarially. A successful API result is not proof that the real installer works
or that HoneyRO/SakuraRO game behavior is unchanged. Native Windows differential
checks, game smoke/stability, packaging/license review and publication are separate
gates. Installer completion was subsequently confirmed by the user; the release
preparation and untested scope are recorded in [dev.3](RELEASE-0.1.0-dev.3.md).

The first real installer test of the initial import candidate still failed. Its
trace proved import and `CLR IsEphemeral` succeeded, then .NET passed
`NCRYPT_PERSIST_FLAG` (`0x80000000`) to set Export Policy and the candidate rejected
it. The initial native test incorrectly used flags=0 for that step. The regression
now reproduces the captured flag exactly, tests rejection of unrelated/mixed flags
and unsupported policies, and verifies that failed writes leave the policy intact.
The earlier API PASS is not recorded as installer acceptance.

## Observed results and the next filesystem boundary

The refined candidate passed the exact PERSIST call, 144 checked API records and
32 import/verify/free cycles **per architecture**. The existing certificate/RSA/
named-P256 persistence, user/machine separation, corruption and three cross-process
publication races passed; PE32/PE64 COW/IAT and PE32 boundary probes passed. The
offline suite at this diagnostic stage ran 80 tests, with one optional historical
capture skipped. Release preparation adds further packaging/volume guards.
Native Windows differential and game smoke/stability were not run.

The real installer then passed signature verification but reported `Windows denied
access` on `\\?\Volume{...}\HoneyRO\`. This was not a permissions/elevation result:
the installer's `SpacePlanner` calls `GetDiskFreeSpaceExW` on its canonical GUID
path, and its `NativeFileSystem.WinError` maps every Win32 failure to AccessDenied.
An owned PE64 reproduction observed:

| Lookup | Before directory handle | While held | After closing |
| --- | --- | --- | --- |
| `C:\ro-runtime-volume-fixture\` | success | success | success |
| Canonical `\\?\Volume{...}\ro-runtime-volume-fixture\` | — | error 2 | error 2 |

Error 2 is `ERROR_FILE_NOT_FOUND`, not an ACL denial or sharing violation. Wine
returned the volume GUID for C but could not round-trip that namespace back to
the filesystem. A **private diagnostic alias**, named exactly after Wine's reported
GUID and pointing at the same `drive_c` as `c:`, made all five queries pass in
both PE32 and PE64. Adding the same alias only to the owned experimental installer
prefix allowed the installer to download and complete, confirmed by the user. No
permissions, client validations, signatures or existing launcher prefixes changed.

The diagnostic alias was private experimental configuration, not a fifth Wine
functional patch or a launcher component. The dev.3 candidate now queries Wine's
actual C GUID through an owned read-only native helper and provisions only that
prefix-local alias in normal Proton target runs. It verifies the existing C mapping,
preserves/rejects collisions and never guesses a GUID. Both architectures passed
all five space-query checks without manual alias creation; the runner remained
unchanged and the test prefix was idle at completion. First game launch and new
game stability tests were not requested or performed.

The concurrent desktop capture initially generated Python bytecode caches in the
private candidate. The crypto harness correctly rejected its end inventory even
though every API test passed. The delta was exclusively new `__pycache__` files,
not modified source/modules. A fresh repeat after inspecting that delta passed
with the runner unchanged and prefix idle. No evidence or caches were deleted to
obtain that result. Future desktop captures should disable bytecode writes or use
an independently owned runtime copy; the preservation baseline was untouched.
