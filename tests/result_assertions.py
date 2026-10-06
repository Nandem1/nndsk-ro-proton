# SPDX-License-Identifier: LGPL-2.1-or-later
"""Small offline gates for owned API probes. No guest execution or mutation."""

import argparse
import json
from pathlib import Path
import re


class ProbeFailure(ValueError):
    pass


def require(value, message):
    if not value:
        raise ProbeFailure(message)


def fields(line):
    pairs = re.findall(r"(\w+)=(0x[0-9a-fA-F]+)", line)
    require(len({key for key, _ in pairs}) == len(pairs), "Duplicate scalar field")
    return {key: int(value, 16) for key, value in pairs}


def unique_line(text, prefix):
    lines = [line for line in text.splitlines() if line.startswith(prefix)]
    require(len(lines) == 1, f"Expected one {prefix!r} record, found {len(lines)}")
    return lines[0]


def complete(text, header=None):
    if header:
        require(text.startswith(header), "Wrong probe protocol/header")
    require("FAIL" not in text and "STOP:" not in text, "Failure/stop record present")
    exits = re.findall(r"probe_exit=(0x[0-9a-fA-F]+)", text)
    require(exits == ["0x00000000"], "Missing, duplicate or nonzero probe exit")


def query_rows(text, type_, offset, *, return_bytes=28):
    rows = {}
    expected_fields = {"Address", "ReturnBytes", "LastError", "AllocationProtect",
                       "Protect", "State", "Type", "RegionSize", "BaseAddress", "AllocationBase"}
    for line in text.splitlines():
        if not line.startswith("QUERY "):
            continue
        match = re.search(r"phase=(\w+) view=(\w+)", line)
        require(match, "Missing query phase/view")
        key = match.groups()
        require(key not in rows, "Duplicate query")
        row = fields(line)
        require(set(row) == expected_fields, "Incomplete/unexpected query fields")
        require(row["ReturnBytes"] == return_bytes and row["State"] == 0x1000 and row["Type"] == type_,
                "Wrong query return size/state/type")
        require(row["Address"] - row["AllocationBase"] == offset, "Wrong query RVA")
        require(row["BaseAddress"] <= row["Address"] < row["BaseAddress"] + row["RegionSize"],
                "Address outside observed region")
        require(row["RegionSize"] == 4096 and row["AllocationProtect"] == 0x80,
                "Unexpected image region/protection")
        rows[key] = row
    return rows


def cow(text, *, baseline=False, arch="PE32"):
    require(arch in ("PE32", "PE64"), "Wrong COW architecture")
    protocol, bytes_ = (1, 28) if arch == "PE32" else (2, 48)
    complete(text, f"COW_PROBE protocol={protocol} arch={arch} ")
    require("no_VirtualProtect=1 no_LoadLibrary=1" in text, "Wrong probe restrictions")
    rows = query_rows(text, 0x1000000, 0x1000, return_bytes=bytes_)
    require(set(rows) == {("before", "target"), ("before", "control"),
                         ("after", "target"), ("after", "control")}, "Missing/unexpected COW query")
    require(rows["before", "control"] == rows["after", "control"], "Control view changed")
    require(rows["before", "target"]["AllocationBase"] != rows["before", "control"]["AllocationBase"],
            "Not two separate views")
    for view in ("target", "control"):
        for field in ("Address", "AllocationBase", "AllocationProtect"):
            require(rows["before", view][field] == rows["after", view][field], "Mapping identity changed")
    expected_after = 8 if baseline else 4
    require(rows["before", "target"]["Protect"] == rows["before", "control"]["Protect"] == 8,
            "Virgin views must report WRITECOPY")
    require(rows["after", "target"]["Protect"] == expected_after, "Wrong written-page protection")
    require(rows["after", "control"]["Protect"] == 8, "Wrong control protection")
    write = fields(unique_line(text, "WRITE "))
    require(write == {"Before": 0xdf9b5731, "Intended": 0xde995435, "After": 0xde995435,
                      "ControlAfter": 0xdf9b5731, "DiskAfter": 0xdf9b5731}, "COW content isolation failed")
    observation = unique_line(text, "OBSERVATION ")
    require(fields(observation) == {"ProtectBefore": 8, "ProtectAfter": expected_after}
            and "isolation=PASS pending_COW_before=YES" in observation, "Wrong observation record")
    return {"probe": "cow", "arch": arch, "baseline": baseline, "before": 8, "after": expected_after,
            "control": [8, 8], "isolation": "PASS"}


def iat(text, *, baseline=False, arch="PE32"):
    require(arch in ("PE32", "PE64"), "Wrong IAT architecture")
    protocol, bytes_ = (1, 28) if arch == "PE32" else (2, 48)
    complete(text, f"IAT_PROBE protocol={protocol} arch={arch} fixture=iat-fixture.dll ")
    require("own_fixture_only=1 no_manual_write=1 no_VirtualProtect=1" in text, "Wrong IAT restrictions")
    fixture = fields(unique_line(text, "FIXTURE "))
    if arch == "PE32":
        require(fixture == {"IatRva": 0x2080, "Characteristics": 0xc0000040, "FileSize": 0xa00,
                            "EntryPoint": 0, "TLS": 0}, "Unexpected original PE32 IAT fixture layout")
    else:
        require(set(fixture) == {"IatRva", "Characteristics", "FileSize", "EntryPoint", "TLS"}
                and fixture["Characteristics"] == 0xc0000040 and fixture["EntryPoint"] == fixture["TLS"] == 0
                and 0 < fixture["IatRva"] < 0x100000 and 512 <= fixture["FileSize"] <= 0x100000,
                "Unexpected own PE64 IAT fixture layout")
    rows = query_rows(text, 0x1000000, fixture["IatRva"], return_bytes=bytes_)
    require(set(rows) == {("before_load", "unloaded"), ("after_load", "loaded"),
                         ("after_load", "unloaded")}, "Missing/unexpected IAT query")
    require(rows["before_load", "unloaded"] == rows["after_load", "unloaded"], "Unloaded view changed")
    require(rows["after_load", "loaded"]["AllocationBase"] != rows["before_load", "unloaded"]["AllocationBase"],
            "Not two separate IAT views")
    expected_loaded = 8 if baseline else 4
    require(rows["before_load", "unloaded"]["Protect"] == 8, "Unloaded IAT must remain WRITECOPY")
    require(rows["after_load", "loaded"]["Protect"] == expected_loaded, "Wrong loaded IAT protection")
    line = unique_line(text, "IMPORT ")
    imports = fields(line)
    require(set(imports) == {"Expected", "LoadedIat", "UnloadedBefore", "UnloadedAfter"},
            "Incomplete IAT import record")
    require(imports["Expected"] != 0 and imports["Expected"] == imports["LoadedIat"], "Import unresolved")
    require(imports["UnloadedBefore"] == imports["UnloadedAfter"]
            and 0 < imports["UnloadedBefore"] < 0x100000, "Unloaded import bytes changed/not a fixture RVA")
    if arch == "PE32":
        require(imports["UnloadedBefore"] == 0x2088, "Unexpected original PE32 import RVA")
    require("resolution=PASS isolation=PASS" in line, "IAT isolation failed")
    observation = unique_line(text, "OBSERVATION ")
    require(fields(observation) == {"UnloadedProtect": 8, "LoadedIatProtect": expected_loaded}
            and "ImportResolved=YES OwnEntryPointCalled=NO ManualStores=0" in observation,
            "Wrong IAT observation")
    return {"probe": "iat", "arch": arch, "baseline": baseline, "loaded": expected_loaded,
            "control": [8, 8], "resolution": "PASS", "isolation": "PASS"}


BOUNDARY_MASKS = {"virgin": 0, "cpu": 1, "file_io": 2, "wineserver_write": 4,
                  "memory_read_output": 2, "unwritten_restore": 0,
                  "written_restore": 1, "guard_then_store": 1, "remap": 0}


def boundary(text, *, baseline=False):
    complete(text, "BOUNDARY_PROBE protocol=1 arch=PE32 own_fixtures_only=1")
    cases = {}
    for line in text.splitlines():
        if not line.startswith("CASE "):
            continue
        match = re.search(r"name=(\w+)", line)
        require(match, "Missing boundary case name")
        name = match[1]
        require(name not in cases and "isolation=PASS" in line, "Duplicate/failed boundary case")
        cases[name] = fields(line)
    require(set(cases) == set(BOUNDARY_MASKS), "Missing/unexpected boundary cases")
    for name, mask in BOUNDARY_MASKS.items():
        require(cases[name] == {"ExpectedCopiedMask": mask, "ObservedCopiedMask": 0 if baseline else mask},
                f"Copied-page mask divergence: {name}")
    queries = [line for line in text.splitlines() if line.startswith("QUERY ")]
    require(len(queries) == 73, "Missing/unexpected boundary queries")
    seen = set()
    for line in queries:
        match = re.search(r"phase=(\w+) view=(\w+)", line)
        require(match, "Missing boundary query phase/view")
        phase, view = match.groups()
        row = fields(line)
        require(set(row) == {"Address", "ReturnBytes", "LastError", "AllocationProtect", "Protect",
                             "State", "Type", "RegionSize", "BaseAddress", "AllocationBase"},
                "Incomplete/unexpected boundary query fields")
        offset = row["Address"] - row["AllocationBase"]
        key = phase, view, offset
        require(key not in seen and offset in (0, 4096, 8192, 12288), "Duplicate/invalid boundary query")
        seen.add(key)
        require(row["ReturnBytes"] == 28 and row["State"] == 0x1000 and row["Type"] == 0x40000
                and row["AllocationProtect"] == 8 and row["BaseAddress"] == row["Address"]
                and row["RegionSize"] >= 4096, "Wrong boundary memory query")
        if phase == "copied_readonly":
            require(view == "target" and offset == 0 and row["Protect"] == 2, "Readonly state incorrect")
        else:
            require(phase in BOUNDARY_MASKS and view in ("target", "control"), "Unexpected phase/view")
            copied = BOUNDARY_MASKS[phase] if not baseline and view == "target" else 0
            require(row["Protect"] == (4 if copied & (1 << (offset // 4096)) else 8),
                    "Per-page protection divergence")
            if view == "control":
                require(row["RegionSize"] == 16384 - offset, "Control region changed")
    api = [line for line in text.splitlines() if line.startswith("API ")]
    require(len(api) == 3 and fields(api[0]) == {"Return": 1, "Bytes": 4}
            and all(fields(line) == {"Status": 0, "Bytes": 4} for line in api[1:]), "IO API divergence")
    require(fields(unique_line(text, "GUARD ")) == {"Exceptions": 1, "ProtectAtHandler": 8},
            "Guard ordering divergence")
    writewatch = [fields(line) for line in text.splitlines() if line.startswith("WRITEWATCH ")]
    require(writewatch == [{"Status": 0, "Count": 2, "Granularity": 4096}, {"Status": 0, "Count": 0}],
            "Writewatch divergence")
    return {"probe": "boundary", "baseline": baseline, "cases": cases, "queries": 73,
            "io": "PASS", "guard": "PASS", "writewatch": "PASS"}


def status(text, api):
    row = unique_line(text, api + " status=")
    match = re.fullmatch(re.escape(api) + r" status=(0x[0-9a-fA-F]+)", row)
    require(match, "Malformed API status")
    return int(match[1], 16)


def ncrypt_lifecycle(text, phase, scope="user"):
    require(phase in ("absent", "init", "reopen", "duplicate", "delete", "check"), "Wrong lifecycle phase")
    require(scope in ("user", "machine"), "Wrong lifecycle scope")
    complete(text, "Software KSP probe; scope/name from argv;")
    require(status(text, "NCryptOpenStorageProvider(SoftwareKSP,flags=0)") == 0, "Software provider failed")
    flags = "0x60" if scope == "machine" else "0x40"
    opened = status(text, f"NCryptOpenKey(keyspec=0,flags={flags})")
    require(opened == (0x80090016 if phase in ("absent", "init") else 0), "OpenKey returned wrong status")
    if phase == "absent":
        require("missing_key_contract=PASS" in text, "Missing-key assertion absent")
        require("NCryptCreatePersistedKey(" not in text, "Absence probe created a key")
        return {"probe": "ncrypt", "phase": phase, "scope": scope, "open": opened}
    if phase == "check":
        require("open_existing_key_contract=PASS" in text, "Open-existing assertion absent")
        return {"probe": "ncrypt", "phase": phase, "scope": scope, "open": opened}
    if phase == "init":
        create_flags = "0x20" if scope == "machine" else "0"
        require(status(text, f"NCryptCreatePersistedKey(ECDSA_P256,named,flags={create_flags})") == 0,
                "Named P256 create failed")
        require(status(text, "NCryptSetProperty(Export Policy=0,size=4,flags=0)") == 0
                and status(text, "NCryptFinalizeKey(flags=0x40)") == 0, "Policy/finalize failed")
        require("reference_created=1" in text and "created_key_in_clone=1" in text, "Reference creation missing")
    else:
        require("public_key_matches_previous_process=1" in text, "Full public-key comparison missing")
        require("NCryptFinalizeKey(" not in text and "created_key_in_clone=1" not in text,
                "Existing identity was recreated")
    require(status(text, "NCryptExportKey(ECCPUBLICBLOB,silent)") == 0
            and "public_blob_size=0x00000048" in text, "Public export failed/incorrect size")
    digest_line = unique_line(text, "public_blob_sha256=")
    require(re.fullmatch(r"public_blob_sha256=[0-9a-f]{64}", digest_line), "Invalid public digest")
    require(status(text, "GetProperty(Export Policy)") == 0
            and "persisted_export_policy_zero=PASS" in text, "Policy was not preserved")
    require(status(text, "GetProperty(Key Type)") == 0 and "key_type_matches_scope=PASS" in text,
            "Use the v2 scope-checking probe")
    for api in ("ExportKey(private,policy=0)", "ExportKey(private-alias,policy=0)"):
        require(status(text, api) == 0x80090010, "Private export was not denied by policy")
    require(status(text, "SignHash(reopened-material)") == status(text, "VerifySignature(reopened-material)") == 0
            and status(text, "VerifySignature(altered-digest)") == 0x80090006
            and "persisted_sign_verify=PASS" in text, "Sign/verify or negative control failed")
    if phase == "duplicate":
        require(status(text, "NCryptCreatePersistedKey(existing,same_name,no_overwrite)") == 0x8009000f
                and "duplicate_name_contract=PASS" in text, "Duplicate semantics failed")
    if phase == "delete":
        require(status(text, "NCryptDeleteKey(flags=0)") == 0
                and status(text, f"NCryptOpenKey(after_delete,keyspec=0,flags={flags})") == 0x80090016
                and "delete_contract=PASS" in text, "Delete semantics failed")
    return {"probe": "ncrypt", "phase": phase, "scope": scope, "open": opened,
            "publicSha256": digest_line.split("=", 1)[1], "policy": 0, "signVerify": "PASS"}


def negative(text):
    complete(text)
    require(text.count("OpenKey(corrupt,not-missing) status=0x80090005") == 3,
            "Not all corruption cases rejected")
    require(text.count("CreateKey(corrupt,not-regenerated) status=0x8009000f") == 3,
            "Corrupt key was regenerated")
    for gate in ("corruption_never_became_missing_or_regenerated=PASS", "restored_public_and_policy=PASS",
                 "no_TPM_substitution=PASS"):
        require(gate in text, f"Missing {gate}")
    for api, wanted in (("OpenKey(bad-flags)", 0x80090009), ("CreateKey(bad-flags)", 0x80090009),
                        ("Named-RSA(must-not-fake-persistence)", 0x80090029),
                        ("OpenKey(legacy-keyspec,unsupported)", 0x80090029),
                        ("Platform-cannot-open-software-key", 0x80090029),
                        ("Platform-cannot-create-software-key", 0x80090029),
                        ("DeleteKey(own-fixture)", 0), ("OpenKey(after-fixture-delete)", 0x80090016)):
        require(status(text, api) == wanted, f"Unexpected {api} result")
    return {"probe": "negative", "corruptionCases": 3, "regeneration": False, "policy": "PASS"}


def race(parent, workers):
    complete(parent)
    require(len(workers) == 2, "Two worker results required")
    finals = sorted(status(text, "FinalizeKey(after-barrier)") for text in workers)
    require(finals == [0, 0x8009000f], "Expected exactly one successful publisher")
    child_codes = []
    for text in workers:
        match = re.findall(r"probe_exit=(0x[0-9a-fA-F]+)", text)
        require(len(match) == 1, "Missing/duplicate worker exit")
        child_codes.append(int(match[0], 16))
    require(sorted(child_codes) == [0, 15], "Worker exit semantics incorrect")
    require(fields(unique_line(parent, "child1_exit=")) == {"child1_exit": child_codes[0]}
            and fields(unique_line(parent, "child2_exit=")) == {"child2_exit": child_codes[1]},
            "Parent/worker exit disagreement")
    for gate in ("both_processes_configured_before_publish=PASS", "single_publisher_and_winner_public_key=PASS"):
        require(gate in parent, f"Missing {gate}")
    require(status(parent, "DeleteKey(own-race-fixture)") == 0
            and status(parent, "OpenKey(after-race-delete)") == 0x80090016, "Race fixture cleanup failed")
    return {"probe": "race", "finalizeStatuses": finals, "workerExitCodes": child_codes,
            "publicWinnerMatches": True}


def wine_suite(text, name):
    pattern = (r"(?:^|\n)[0-9a-fA-F]+:" + re.escape(name) +
               r": (\d+) tests executed \((\d+) marked as todo, (\d+) as flaky, (\d+) failures?\), (\d+) skipped\.")
    summaries = re.findall(pattern, text)
    require(len(summaries) == 1, "Missing/duplicate Wine suite summary")
    tests, todo, flaky, failures, skipped = map(int, summaries[0])
    require(tests > 0 and failures == 0 and flaky == 0 and skipped == 0, "Suite not fully passing")
    require("Test failed:" not in text and "Test succeeded inside todo block:" not in text,
            "Normal failure or unexpectedly resolved todo present")
    return {"suite": name, "tests": tests, "expectedTodos": todo, "failures": failures,
            "skipped": skipped, "flaky": flaky}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["cow", "iat", "boundary", "ncrypt", "negative", "race", "suite"])
    parser.add_argument("result", type=Path)
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--phase", choices=["absent", "init", "reopen", "duplicate", "delete", "check"])
    parser.add_argument("--scope", choices=["user", "machine"], default="user")
    parser.add_argument("--worker", type=Path, action="append", default=[])
    parser.add_argument("--suite-name", choices=["cert", "ncrypt", "virtual"])
    args = parser.parse_args()
    text = args.result.read_text(encoding="utf-8-sig")
    if args.kind in ("cow", "iat"):
        arch = "PE64" if text.startswith(("COW_PROBE protocol=2 arch=PE64 ",
                                          "IAT_PROBE protocol=2 arch=PE64 ")) else "PE32"
        result = globals()[args.kind](text, baseline=args.baseline, arch=arch)
    elif args.kind == "boundary":
        result = boundary(text, baseline=args.baseline)
    elif args.kind == "ncrypt":
        if not args.phase:
            parser.error("ncrypt requires --phase")
        result = ncrypt_lifecycle(text, args.phase, args.scope)
    elif args.kind == "negative":
        result = negative(text)
    elif args.kind == "race":
        result = race(text, [path.read_text(encoding="utf-8-sig") for path in args.worker])
    else:
        if not args.suite_name:
            parser.error("suite requires --suite-name")
        result = wine_suite(text, args.suite_name)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
