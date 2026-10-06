# COW regression expectations

The functional patch `patches/0003-ntdll-private-cow-query.patch` is preserved
byte-for-byte. Its kernel-dependent runtime behavior is not changed here.
The separate `patches/tests/series` applies only to
`dlls/kernel32/tests/virtual.c`, after validated functional-source verification.
It must never be described as a fourth runtime fix.

## Which expectations are no longer TODO

The suite's three COW assertions previously generated 705 unexpected TODO
successes in the accepted PE32 candidate. However, **80 failures remained at
those same source lines**. Removing all three annotations would create real
suite failures and conceal the distinction between supported and pending
mapping paths.

The test-only classifier uses exclusively the initial mapping contract:

```c
BOOL untracked_cow = !(sec_flags & SEC_IMAGE) &&
                     (view[j].prot == PAGE_READWRITE ||
                      view[j].prot == PAGE_EXECUTE_READWRITE);
```

Initially writable shared, non-image views remain untracked when subsequently
changed to WRITECOPY. Those combinations retain TODO. Private views and
SEC_IMAGE views use normal assertions. A requested writable view of SEC_IMAGE
does not imply that the PE section is shared; image mapping must remain a
separate case.

The updated expectations cover protection after a write, RegionSize splitting,
and restoring protection on an already copied page. For the latter, the TODO
also retains the original expected/requested protection transformation condition
`map_prot_written(page_prot[k]) != actual_prot`. No observed API result, error,
or test-pass status selects whether an assertion is TODO.

## Preserved historical evidence, not a new Wine execution

`tests/cow-annotation-history.json` contains grouped events from the exact old
candidate capture and its SHA256. These are Wine's own API tests, not client
memory or protection code. Applying the new classification to those events
predicts:

| Historical source line | Normal PASS after annotation update | Pending TODO |
| --- | ---: | ---: |
| 4282: protection after write | 160 | 24 |
| 4285: RegionSize | 55 | 24 |
| 4320: restored protection | 490 | 32 |
| Total | 705 | 80 |

The unrelated expected-TODO failures (20) remain unchanged. The unexpected
TODO success at old line 1444 is **not removed** and remains visible. Therefore
this annotation change alone does not imply a formally green complete suite.
Do not subtract or suppress that unrelated failure in release reporting.

Portable offline checks, without Wine or a game:

```bash
python3 -m unittest discover -s tests -p test_cow_annotations.py -v
```

The private original capture can also be verified without copying it into the
project:

```bash
python3 tests/test_cow_annotations.py --historical-log /absolute/path/to/original/wine.log -v
```

The imported capture's schema uses pre-patch line numbers; after applying the
test-only patch, suite lines shift. Runtime verdicts must use Wine's actual
summary and assertion messages, not hardcoded historical line numbers.

## Runtime acceptance requirements

The suite must be rebuilt and rerun against the reproduced runtime; historical
event classification is not substitute execution evidence. Run PE32 first and
PE64 independently. Preserve any newly failing assertion.

The COW expectations require functional UFFD WP_ASYNC/WP_UNPOPULATED,
PAGEMAP_SCAN, accessible `/proc/self/pagemap`, and 4096-byte host pages. An
independent capability preflight must pass in the actual execution context.
Feature unavailable is UNSUPPORTED/PENDING, not an accepted 8→8 result and not
a reason to select TODO based on an observed wrong value. The functional patch
has no software fallback; the host policy must not be weakened to force a PASS.

Own SEC_IMAGE and IAT probes retain their original PE32 binaries/sources and
Windows controls. The boundary probe covers CPU, ReadFile,
NtWriteVirtualMemory/wineserver, NtReadVirtualMemory output, protection restore,
guard, remap and independent writewatch. Their ABI32-specific types cannot be
compiled as PE64 without adaptation. PE64 coverage, failed/partial I/O,
registration-failure cleanup, concurrency and feature-off testing are separate
pending gates, not implied by this test-only annotation change.
