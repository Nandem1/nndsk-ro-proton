# Owned Windows API regression probes

These tests operate only on our inert fixtures or own Software-KSP keys. They do
not load any game, shield, Gepard or other proprietary guest software. All code
in this directory is distributed under LGPL-2.1-or-later; see the project root
license and [NOTICE](NOTICE.md). No native Windows DLLs are bundled or imported.

## Source custody

`provenance.json` identifies ten byte-exact sources imported from accepted local
experiments. The original sources have not been refactored or updated; relative
include layout is preserved. `build_probes.py` rejects an imported-source hash
change before compiling. Patches to runtime APIs remain separate in `patches/`.

The PE64 variants are **separate new derivatives**, not a target flip of PE32:

- `cow-probe/probe64.c`: pointer/SIZE_T64, MBI48 with PartitionId, SYSTEM_INFO48,
  64-bit address output, PE32+ header/machine checks. The original one 32-bit
  volatile data write and isolation checks are unchanged in meaning.
- `cow-probe/iat-loader/probe64.c`: uses the PE64 helpers, 64-bit IAT/ILT entries,
  PE32+ data-directory offset112, bounded name RVAs and pointer comparisons64.
  It still maps and loads only the inert own DLL; no entry point/TLS runs.
- Fixtures reuse our exact inert fixture C sources compiled for the proper
  architecture. PE32 source custody is byte-exact. Import-library selection
  changes binary hashes: only the diagnostic build using the historical import
  libraries reproduced the originally Windows-attested binaries. Fresh-project
  import libraries are identified separately, not falsely attested on Windows.

PE64 probes are compiled here, not yet claimed Windows-conformant from a new
native execution. CPU/I/O/guard/writewatch boundary coverage is the preserved
PE32 probe; PE64 equivalents additionally require Wine's `kernel32:virtual`
suite and, for unexplored behaviors, native comparison.

## Build without installed system Wine

After the runtime recipe produces `work/build-pe` import libraries:

```sh
python tests/build_probes.py --output work/probes/build-01
python -m unittest discover -s tests -p 'test_*.py'
```

Output must be a fresh child of ignored `work/probes`; existing output paths are
refused. The compiler/linker are existing clang/lld-link, with freestanding/noCRT
Windows targets, warnings as errors and PE timestamp0. Import libraries resolve
as `dlls/<name>/<arch>-windows/lib<name>.a` from the fresh pinned Wine build.
Missing libraries fail honestly. Build USER32 import libraries for IAT fixtures
as well as kernel32, ncrypt, bcrypt, crypt32, advapi32 and shell32.

For an explicit diagnostic build using already-installed **ABI import
libraries only**, not runtime DLLs:

```sh
python tests/build_probes.py --output work/probes/abi-01 --import-libs-root /usr/lib/wine
```

`build-manifest.json` records source SHA256, compiler/linker identity, exact
commands, selected import-library SHA256, diagnostics, binary architectures,
artifact hashes/sizes and whether all targets compiled. It never executes Wine.
`--arch i386` / `--arch x86_64` are available; default builds both.

### Artifacts

| Architecture | Artifact | Acceptance use |
| --- | --- | --- |
| PE32 | `cow-probe.exe` + `cow-fixture.dll` | SEC_IMAGE CPU write, target8→4/control8→8, file/views unchanged |
| PE32 | `iat-probe.exe` + `iat-fixture.dll` | Loader import resolution gives private IAT4; unloaded control8 |
| PE32 | `boundary-probe.exe` | CPU/ReadFile/NtWriteVirtualMemory/NtReadVirtualMemory, restore, guard, remap/writewatch |
| PE64 | `cow-probe64.exe` + `cow-fixture.dll` | New separately ABI-correct SEC_IMAGE probe |
| PE64 | `iat-probe64.exe` + `iat-fixture.dll` | New separately ABI-correct inert IAT fixture |
| Both | `cng-persist-probe.exe` | v2 named P256 lifecycle including explicit Key Type/scope |
| Both | `cng-persist-original.exe` | Preserved earlier lifecycle source for historical comparison |
| Both | `cng-persist-negative.exe` | Only own ciphertext/REG fault fixtures, no private bytes logged |
| Both | `cng-persist-race.exe` | Real two-worker barrier, one successful Finalize publisher |
| Both | `cng-ephemeral-historical.exe` | **Historical only, not a current acceptance gate** |

The historical ephemeral probe intentionally asserts named persistence is
unsupported. The final runtime now supports it, so running that historical
probe as a release gate would report expected obsolete failures. Its useful
P256/signature checks are also in the accepted NCrypt suite; we do not conceal
or alter the original probe's expectations.

## Execution contract for the separate harness

Use only a fresh project-owned prefix. The main regression harness owns runtime
execution, stable PID identities, environment sanitation, deadlines and process
cleanup. This directory's builder and parsers never launch a game or mutate an
existing prefix.

- Install binaries under `C:\ro-runtime-tests\i386` and `x86_64`; own COW/IAT
  fixture DLL must be beside the corresponding executable. Do not overwrite
  another architecture's DLLs.
- Each phase needs a fresh CWD because result files use CREATE_NEW. No old log
  should be accepted as a new run.
- Preserved CNG lifecycle sources use public-only references at
  `C:\ro-audit-cng\persist-user.public.bin` and `persist-machine.public.bin`.
  The harness must create that own directory in its disposable prefix; this is
  a declared fixture location, not an outside-repository source dependency.
- Use a generic name such as `Wine.RuntimeTests.PersistedP256` for both user and
  machine to test independent scopes. Never use or adopt the game's identity.
- Lifecycle: absent → init → process+wineserver exit → crossarch reopen →
  duplicate → delete → new-process absent. Check all 72 public bytes and hash;
  scopes with the same name must produce different public keys.
- Race: launch a PE64 parent with the **PE32 worker executable's DOS path** as
  its one argument. Worker1/2 result files record actual Finalize statuses;
  parent checks their exits, reopened full public material and deletes fixture.
- Negative/race fixture names and named events are fixed generic own names, so
  parallel suites require separate prefixes. Corruption probe restores the
  original own protected record; it never exports/decrypts/logs private data.

UMU's exit0 is not proof that its child tests passed. For Wine unit suites use
Windows cmd redirection in a fresh CWD and parse the suite summary. For probes
require their complete result/probe_exit and actual API/content assertions.

## Parser interface and gates

`result_validation.py` exposes:

```python
validate_probe(kind, text)  # dict or ValueError, never relies on Python assert
validate_wine_suite(text)
capture_virtual_suite(text)  # preserves every parent/child summary and all reds
validate_race_workers(parent_text, [worker1_text, worker2_text])
```

Kinds: `cow-probe`, `iat-probe`, `boundary-probe`, `cng-persist`, `cng-negative`,
`cng-race`. COW/IAT architecture is determined by the explicit protocol header;
CNG phase/scope by its lifecycle records. No incomplete/duplicate/truncated
results, nonzero probe_exit, successful denied export or unexpected todo success
are treated as PASS. CNG race parent validation labels whether separate direct
worker status records were checked; use `validate_race_workers` for full status
evidence.

The preserved boundary executable prints expected/observed COW masks without
itself rejecting all divergences. **The external parser compares all nine masks
and all 73 query rows**. Merely checking boundary `probe_exit=0` is insufficient.

`result_assertions.py` also provides a CLI for offline validation. Example:

```sh
python tests/result_assertions.py cow work/results/cow-probe-result.txt
python tests/result_assertions.py ncrypt work/results/cng-probe-result.txt --phase reopen --scope user
python tests/result_assertions.py race work/results/cng-race-result.txt --worker work/results/race-worker1.txt --worker work/results/race-worker2.txt
```

Unrelated historical NCrypt todos remain visible (176 in accepted captured
suite). Do not delete them to manufacture a green report. Unexpected success
inside a todo is not hidden; updated runtime assertions must be justified from
the behavior/Windows evidence separately.

## Local migration checks, not runtime executions

Diagnostic build-03 (`--import-libs-root /usr/lib/wine`): 19 PE artifacts compile,
zero compiler warnings/errors. The original PE32 COW/IAT four files reproduce
byte-exactly with those historical ABI libraries on this toolchain:

```text
cow-probe.exe    674317a17228483db02b6e06837d8c7b31f36f6e007c6074d5949517ca7cecd1
cow-fixture.dll  1e06cbd58ee04fb66cd00de6c8dec5af11c3a9f14422e089d4fd21556a6e06bc
iat-probe.exe    c6dece8f0e8d66bc15de15087fbf3dfdaf6f1987002d47f6737d6719d7adb153
iat-fixture.dll  66f48178db30e7f9d02a462df0afcb8db1e586540865de30e0d1625411d7a778
```

These are historical native-Windows-comparison binaries. This is compiler and
source custody evidence, not another native-Windows or Wine test execution.
PE64 outputs have new hashes and require their own native result if making a
new Windows equivalence claim.

The final local build `work/probes/project-imports-01` uses only import libraries
from the fresh project's pinned `work/build-pe` source build: all19 artifacts
compile, no Wine executed by this work. ABI library metadata changes probe and
IAT fixture binary hashes; original C sources remain exact. Its PE32 IAT still
has FileSize0xa00, IatRva0x2080, raw thunk0x2088, `user32.dll!MessageBoxW`, entry
point0/TLS0; the original COW fixture remains byte-identical. PE64 IAT has its own
64-bit thunk layout. This rebuild does **not** reuse the previous binaries'
Windows hash attestation. The regression harness must record these new artifact
hashes honestly; new native comparisons are separate if required.

Focused parser validation: 18 tests PASS; py_compile and git diff --check PASS.
No Wine or game execution is claimed by this import/build/parser work.
