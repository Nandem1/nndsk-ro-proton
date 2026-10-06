# SPDX-License-Identifier: LGPL-2.1-or-later
"""Public offline validation interface used by the runtime regression harness."""

import re

import result_assertions as gate


def validate_probe(kind, text):
    """Validate an owned probe result; ValueError means not an acceptance PASS."""
    if kind == "cow-probe":
        return gate.cow(text, arch="PE64" if text.startswith("COW_PROBE protocol=2 arch=PE64 ") else "PE32")
    if kind == "iat-probe":
        return gate.iat(text, arch="PE64" if text.startswith("IAT_PROBE protocol=2 arch=PE64 ") else "PE32")
    if kind == "boundary-probe":
        return gate.boundary(text)
    if kind == "cng-negative":
        return gate.negative(text)
    if kind == "cng-persist":
        if "missing_key_contract=PASS" in text:
            phase = "absent"
        elif "created_key_in_clone=1" in text:
            phase = "init"
        elif "duplicate_name_contract=PASS" in text:
            phase = "duplicate"
        elif "delete_contract=PASS" in text:
            phase = "delete"
        elif "open_existing_key_contract=PASS" in text:
            phase = "check"
        else:
            phase = "reopen"
        scope = "machine" if "NCryptOpenKey(keyspec=0,flags=0x60)" in text else "user"
        return gate.ncrypt_lifecycle(text, phase, scope)
    if kind == "cng-race":
        gate.complete(text)
        exits = [gate.fields(gate.unique_line(text, f"child{i}_exit="))[f"child{i}_exit"] for i in (1, 2)]
        gate.require(sorted(exits) == [0, 15], "Expected one winning and one colliding worker")
        for record in ("both_processes_configured_before_publish=PASS", "single_publisher_and_winner_public_key=PASS"):
            gate.require(record in text, f"Missing {record}")
        gate.require(gate.status(text, "OpenKey(winner)") == 0
                     and gate.status(text, "ExportPublic(reopened-winner)") == 0
                     and gate.status(text, "DeleteKey(own-race-fixture)") == 0
                     and gate.status(text, "OpenKey(after-race-delete)") == 0x80090016,
                     "Race winner lifecycle failed")
        return {"probe": "race", "workerExitCodes": exits, "publicWinnerMatches": True,
                "workerStatusRecordsChecked": False}
    raise ValueError(f"Unknown probe kind: {kind}")


def validate_race_workers(parent, workers):
    """Additional direct FinalizeKey status evidence from the two owned workers."""
    return gate.race(parent, workers) | {"workerStatusRecordsChecked": True}


def validate_wine_suite(text):
    names = re.findall(r"(?:^|\n)[0-9a-fA-F]+:(\w+): \d+ tests executed", text)
    gate.require(len(names) == 1, "Missing/duplicate Wine suite summary")
    return gate.wine_suite(text, names[0])


class VirtualSuiteCaptureError(ValueError):
    """Malformed/incomplete evidence with the successfully decoded partial rows."""

    def __init__(self, message, capture):
        super().__init__(message)
        self.capture = capture


def capture_virtual_suite(text):
    """Preserve parent/child summaries and reds, never certify a green suite.

    Wine's virtual tests launch their own test children; each emits its Windows
    PID summary. Unprefixed assertion records cannot honestly be assigned to a
    PID, so those records remain global rather than guessed onto the parent.
    """
    pattern = re.compile(r"([0-9a-fA-F]+):virtual: (\d+) tests executed "
                         r"\((\d+) marked as todo, (\d+) as flaky, (\d+) failures?\), (\d+) skipped\.")
    summaries, malformed, errors, seen = [], [], [], set()
    normal, unexpected, expected_todo = [], [], []
    for index, line in enumerate(text.splitlines(), 1):
        if ":virtual:" in line and "tests executed" in line:
            match = pattern.fullmatch(line)
            if not match:
                malformed.append({"outputLine": index, "raw": line})
                continue
            pid, tests, todo, flaky, failures, skipped = match.groups()
            row = {"winePidHex": pid, "winePid": int(pid, 16), "tests": int(tests),
                   "expectedTodos": int(todo), "flaky": int(flaky), "reportedFailures": int(failures),
                   "skipped": int(skipped), "outputLine": index, "raw": line}
            summaries.append(row)
            if not row["winePid"] or not row["tests"]:
                errors.append("Invalid zero PID/test-count summary")
            if row["winePid"] in seen:
                errors.append("Duplicate/ambiguous Windows PID summary")
            seen.add(row["winePid"])
        for marker, target in (("Test failed:", normal),
                               ("Test succeeded inside todo block:", unexpected),
                               ("Test marked todo:", expected_todo)):
            if marker not in line:
                continue
            location = re.search(r"([^\s:]+):(\d+): " + re.escape(marker), line)
            target.append({"outputLine": index, "file": location[1] if location else None,
                           "sourceLine": int(location[2]) if location else None,
                           "winePid": None, "raw": line})
    if malformed:
        errors.append("Malformed/truncated virtual summary")
    if not summaries:
        errors.append("Missing virtual suite summaries")
    elif text.rstrip().splitlines()[-1] != summaries[-1]["raw"]:
        errors.append("No terminal virtual summary; output may be truncated")
    result = {"suite": "virtual", "mode": "explicit non-green suite capture",
              "formalGreen": False, "summaries": summaries, "summaryCount": len(summaries),
              "tests": sum(row["tests"] for row in summaries),
              "expectedTodos": sum(row["expectedTodos"] for row in summaries),
              "reportedFailures": sum(row["reportedFailures"] for row in summaries),
              "flaky": sum(row["flaky"] for row in summaries),
              "skipped": sum(row["skipped"] for row in summaries),
              "normalFailures": len(normal), "normalFailureRecords": normal,
              "unexpectedTodoSuccesses": len(unexpected), "unexpectedTodoRecords": unexpected,
              "expectedTodoRecords": expected_todo,
              "unattributedAssertionRecords": True,
              "malformedSummaryRecords": malformed, "captureComplete": not errors,
              "captureErrors": errors}
    result["failureAccountingMatches"] = result["reportedFailures"] == len(normal) + len(unexpected)
    result["regressionDetected"] = bool(normal or result["flaky"] or result["skipped"]
                                         or not result["failureAccountingMatches"])
    if errors:
        raise VirtualSuiteCaptureError("; ".join(errors), result)
    return result
