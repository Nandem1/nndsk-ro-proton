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
