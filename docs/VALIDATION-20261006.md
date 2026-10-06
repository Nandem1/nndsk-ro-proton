# Preservation milestone — 2026-10-06

Status: **experimental, not stable, not publication-ready, not a universal runner**.
The launcher and original validated runner remain unchanged.
HoneyRO compatibility/stability is now **accepted PASS**; the user stopped
additional game tests. See [the acceptance record](ACCEPTANCE-20261006.md)
for the distinction between measured PASS and waived follow-up tests.

## Identity and custody

- Runtime artifact: `0.1.0-dev.1`, patchset revision 1.
- Artifact source commit: `93bda981a6e8b7bdadb46fa3497f84df8dfc6fe2`.
- Pinned Proton: `3edf6fbb8af940de5c65b9dd0fbf366b51a218a8`.
- Pinned Wine: `b5f2dc7b5906ef864f83df8fef94c9f539eaad2d`.
- Three recovered behavior patches; ten final source files match the validated
  candidate byte-for-byte. Six freshly rebuilt modules are the only functional
  differences from the pinned official binary base.
- Build method: verified binary base with source-built module overlay, not a
  full Proton SDK rebuild. Later recipe/test/observer commits do not change the
  Wine functional patchset or silently relabel this already identified artifact.

Binary archive: `dist/nndsk-ro-proton-0.1.0-dev.1-linux-x86_64.tar.zst`,
398862860 bytes, SHA256
`75b0c916ccf6e7fcd64ed2afe576c2c0bc6a75ef63a8d74ad6dd9bee629d4d9f`.

Modified-Wine/recipe source archive: 37618585 bytes, SHA256
`425e0741db429ef43d719384f4cdda279ac27d81ae1d843f21b1cac6d0441481`.
This is not complete corresponding source for all inherited third parties.

Two independently packed copies of each snapshot have identical checksums;
streamed member/type/mode/content verification also passes. The extracted binary
artifact has 9432 inventory entries and zero differences from staging. This
proves deterministic packaging of fixed bytes, not bit-identical compilation
across different hosts/toolchains.

## Fresh-build regressions

Complete retained run: `work/regression-02/summary.json`.

| Gate | Result |
| --- | --- |
| PE32 COW / IAT / CPU-I/O-wineserver boundaries | PASS |
| PE64 COW / IAT | PASS |
| crypt32:cert, PE32 and PE64 | 669 checks each, zero failures/skips |
| ncrypt, PE32 and PE64 | 497 checks each, zero failures/skips; 176 expected TODOs each retained |
| Named P256: missing/create/finalize/cross-process crossarch reopen | PASS |
| New wineserver, identical 72-byte public key, sign/verify | PASS |
| Export Policy=0 private denial, public export, duplicate/delete | PASS |
| User/machine separation, corruption, three publication races | PASS |
| kernel32:virtual PE32 | 32173 checks incl. children; zero normal failures; one unexpected TODO success |
| kernel32:virtual PE64 | 31608 checks incl. children; zero normal failures; one unexpected TODO success |

There are 25 accepted API gates and two **CAPTURED_NOT_FORMALLY_GREEN** virtual
suite captures. Both virtual reds are `NtAreMappedFilesTheSame` at source line
1444. Expected TODOs remain visible (100 PE32 / 93 PE64). Do not report the whole
Wine suite green or upstream-ready. Resolved private/image COW expectations were
made ordinary assertions in a separate test-only patch, never runtime changes.

Runner inventory remained unchanged; each test prefix was idle at completion.
Own offline tests: 61 tests, OK, one optional historical-capture test skipped.
The initial run's child-summary reader error and all raw captures are retained;
the complete rerun uses the corrected reader and durable per-test records.

## Actual application acceptance

HoneyRO is running from the **extracted new artifact**, not the experimental
old runner. It uses a private clone of the accepted prepared prefix, identical
DOS arguments/CWD/graphics and the same unmodified session supervisor.
Executable, hRO.dll, Gepard and BGM/666.mp3 hashes match the accepted updated
client before launch. No manual guest or protection-file modification occurred.

The user confirmed login at 2026-10-06T23:23:29Z. The new-build stability window
finished at 23:43:31Z after 1202.119 seconds: **PASS for this 20-minute session**.
The same PID/start_time survived 120 samples, 40 threads, with zero new bounded-
log error/dialog records in the window. At 23:45:03Z the user reported normal
operation ("Esta todo correcto, todo fino"); this is user feedback, not automatic
audio/input/map correctness measurement.

RSS was 1219.0 -> 1238.3 MiB; the last-five-minute median was 1238.3 MiB. This
does not establish or exclude a leak. Runner, original prefix and protected
guest/core hashes remained unchanged at the post-window check. Evidence:
`work/smoke-01/cycle-01/stability-summary.json` and `.md`, samples, user markers
and the recorded window result. Game remains open with no automatic deadline
stop. Natural exit, cleanup and repeated cycles were not exercised and further
tests were waived by the user. The packaged
manifest's validation fields are its earlier packaging-time snapshot, not a
claim that these later observations were already available when it was built.

Cycle-01 has an explicit diagnostic limitation: its live CNG filter required a
colon after the function name, while Wine emits a space. Those entry lines were
discarded; no actual OpenKey return is claimed from that capture. The filter is
corrected and tested for subsequent cycles without restarting or modifying the
running game. Owned CNG probe results above remain independently valid.

## Remaining release gates

Unmeasured risks remain longer-term stability and multiple game cycles;
native PE64/broader conformance;
kernel capability/error-path/performance coverage and known COW cleanup risks;
immutable toolchain/full source-build feasibility; complete inherited-component
source/license closure. SakuraRO Wine 7.16 old-WoW64 comparison is deferred,
not assumed PASS. No further game tests are scheduled under the current request.

Distribution preparation continues without runtime changes:
[DISTRIBUTION.md](DISTRIBUTION.md). Supplemental exact top-level Proton source
is now archived; this is not closure of all inherited third-party sources.

No remote repository, release/tag publication, launcher updater integration,
client/security patch, TPM substitution or additional Wine fix was performed.
