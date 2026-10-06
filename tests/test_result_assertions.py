# SPDX-License-Identifier: LGPL-2.1-or-later
"""Adversarial parser tests using only synthetic owned-API result records."""

import unittest

import result_assertions as gate
import result_validation as public_gate


def query(phase, view, protect, base, offset=0x1000, type_=0x1000000, allocation=0x80, size=0x1000):
    address = base + offset
    values = {"Address": address, "ReturnBytes": 28, "LastError": 0, "AllocationProtect": allocation,
              "Protect": protect, "State": 0x1000, "Type": type_, "RegionSize": size,
              "BaseAddress": address & ~0xfff, "AllocationBase": base}
    return f"QUERY phase={phase} view={view} " + " ".join(f"{key}=0x{value:08x}" for key, value in values.items())


def cow_result():
    return "\n".join([
        "COW_PROBE protocol=1 arch=PE32 fixture=cow-fixture.dll mapping=SEC_IMAGE writes=1 no_VirtualProtect=1 no_LoadLibrary=1",
        query("before", "target", 8, 0x100000), query("before", "control", 8, 0x200000),
        query("after", "target", 4, 0x100000), query("after", "control", 8, 0x200000),
        "WRITE Before=0xdf9b5731 Intended=0xde995435 After=0xde995435 ControlAfter=0xdf9b5731 DiskAfter=0xdf9b5731",
        "OBSERVATION ProtectBefore=0x00000008 ProtectAfter=0x00000004 isolation=PASS pending_COW_before=YES",
        "COMPLETE probe_exit=0x00000000",
    ])


def iat_result():
    return "\n".join([
        "IAT_PROBE protocol=1 arch=PE32 fixture=iat-fixture.dll own_fixture_only=1 no_manual_write=1 no_VirtualProtect=1",
        "FIXTURE IatRva=0x00002080 Characteristics=0xc0000040 FileSize=0x00000a00 EntryPoint=0x00000000 TLS=0x00000000 Import=USER32.MessageBoxW",
        query("before_load", "unloaded", 8, 0x200000, offset=0x2080),
        query("after_load", "loaded", 4, 0x100000, offset=0x2080),
        query("after_load", "unloaded", 8, 0x200000, offset=0x2080),
        "IMPORT Expected=0x12340000 LoadedIat=0x12340000 UnloadedBefore=0x00002088 UnloadedAfter=0x00002088 resolution=PASS isolation=PASS",
        "OBSERVATION UnloadedProtect=0x00000008 LoadedIatProtect=0x00000004 ImportResolved=YES OwnEntryPointCalled=NO ManualStores=0",
        "COMPLETE probe_exit=0x00000000",
    ])


def boundary_result():
    lines = ["BOUNDARY_PROBE protocol=1 arch=PE32 own_fixtures_only=1"]
    for name, mask in gate.BOUNDARY_MASKS.items():
        for page in range(4):
            for view, base in (("target", 0x100000), ("control", 0x200000)):
                protect = 4 if view == "target" and mask & (1 << page) else 8
                size = 16384 - page * 4096 if view == "control" else 4096
                lines.append(query(name, view, protect, base, offset=page * 4096, type_=0x40000,
                                   allocation=8, size=size))
        lines.append(f"CASE name={name} ExpectedCopiedMask=0x{mask:08x} ObservedCopiedMask=0x{mask:08x} isolation=PASS")
    lines += [query("copied_readonly", "target", 2, 0x100000, offset=0, type_=0x40000, allocation=8),
              "API name=ReadFile Return=0x00000001 Bytes=0x00000004",
              "API name=NtWriteVirtualMemory_self Status=0x00000000 Bytes=0x00000004",
              "API name=NtReadVirtualMemory_self Status=0x00000000 Bytes=0x00000004",
              "GUARD Exceptions=0x00000001 ProtectAtHandler=0x00000008",
              "WRITEWATCH phase=written Status=0x00000000 Count=0x00000002 Granularity=0x00001000",
              "WRITEWATCH phase=reset Status=0x00000000 Count=0x00000000",
              "COMPLETE probe_exit=0x00000000"]
    return "\n".join(lines)


def ncrypt_result(phase="reopen"):
    lines = ["Software KSP probe; scope/name from argv; reference is full 72-byte PUBLIC blob.",
             "NCryptOpenStorageProvider(SoftwareKSP,flags=0) status=0x00000000",
             "NCryptOpenKey(keyspec=0,flags=0x40) status=0x00000000",
             "NCryptExportKey(ECCPUBLICBLOB,silent) status=0x00000000", "public_blob_size=0x00000048",
             "public_blob_sha256=" + "a" * 64, "public_key_matches_previous_process=1",
             "GetProperty(Export Policy) status=0x00000000", "GetProperty(Key Type) status=0x00000000",
             "key_type_matches_scope=PASS", "ExportKey(private,policy=0) status=0x80090010",
             "ExportKey(private-alias,policy=0) status=0x80090010", "persisted_export_policy_zero=PASS",
             "SignHash(reopened-material) status=0x00000000", "VerifySignature(reopened-material) status=0x00000000",
             "VerifySignature(altered-digest) status=0x80090006", "persisted_sign_verify=PASS"]
    if phase == "duplicate":
        lines += ["NCryptCreatePersistedKey(existing,same_name,no_overwrite) status=0x8009000f",
                  "duplicate_name_contract=PASS"]
    lines += ["probe_exit=0x00000000"]
    return "\n".join(lines)


class ResultAssertionsTest(unittest.TestCase):
    def test_cow_accepts_exact_transition_and_isolation(self):
        self.assertEqual(gate.cow(cow_result())["control"], [8, 8])

    def test_cow_rejects_baseline_when_candidate_required(self):
        text = cow_result().replace("Protect=0x00000004", "Protect=0x00000008").replace(
            "ProtectAfter=0x00000004", "ProtectAfter=0x00000008")
        with self.assertRaises(gate.ProbeFailure):
            gate.cow(text)
        self.assertEqual(gate.cow(text, baseline=True)["after"], 8)

    def test_cow_rejects_changed_disk(self):
        with self.assertRaises(gate.ProbeFailure):
            gate.cow(cow_result().replace("DiskAfter=0xdf9b5731", "DiskAfter=0xde995435"))

    def test_cow_rejects_duplicate_query(self):
        with self.assertRaises(gate.ProbeFailure):
            gate.cow(cow_result() + "\n" + query("before", "target", 8, 0x100000))

    def test_iat_requires_resolved_import_and_control(self):
        self.assertEqual(gate.iat(iat_result())["loaded"], 4)
        with self.assertRaises(gate.ProbeFailure):
            gate.iat(iat_result().replace("LoadedIat=0x12340000", "LoadedIat=0x00002088"))

    def test_boundary_masks_are_gate_not_probe_exit(self):
        self.assertEqual(gate.boundary(boundary_result())["queries"], 73)
        with self.assertRaises(gate.ProbeFailure):
            gate.boundary(boundary_result().replace("ObservedCopiedMask=0x00000004", "ObservedCopiedMask=0x00000000"))

    def test_boundary_rejects_guard_ordering_regression(self):
        with self.assertRaises(gate.ProbeFailure):
            gate.boundary(boundary_result().replace("ProtectAtHandler=0x00000008", "ProtectAtHandler=0x00000004"))

    def test_ncrypt_reopen_requires_identity_and_policy(self):
        self.assertEqual(gate.ncrypt_lifecycle(ncrypt_result(), "reopen")["policy"], 0)
        with self.assertRaises(gate.ProbeFailure):
            gate.ncrypt_lifecycle(ncrypt_result().replace("public_key_matches_previous_process=1", ""), "reopen")

    def test_ncrypt_rejects_successful_private_export(self):
        with self.assertRaises(gate.ProbeFailure):
            gate.ncrypt_lifecycle(ncrypt_result().replace("ExportKey(private,policy=0) status=0x80090010",
                                                        "ExportKey(private,policy=0) status=0x00000000"), "reopen")

    def test_ncrypt_duplicate_checks_actual_status(self):
        self.assertEqual(gate.ncrypt_lifecycle(ncrypt_result("duplicate"), "duplicate")["phase"], "duplicate")
        with self.assertRaises(gate.ProbeFailure):
            gate.ncrypt_lifecycle(ncrypt_result("duplicate").replace("status=0x8009000f", "status=0x00000000"), "duplicate")

    def test_nonzero_or_duplicate_probe_exit_not_umu_success(self):
        for text in (cow_result().replace("probe_exit=0x00000000", "probe_exit=0x00000010"),
                     cow_result() + "\nprobe_exit=0x00000000"):
            with self.assertRaises(gate.ProbeFailure):
                gate.cow(text)

    def test_todos_remain_visible_unexpected_success_not_green(self):
        text = "00e8:ncrypt: 497 tests executed (176 marked as todo, 0 as flaky, 0 failures), 0 skipped."
        self.assertEqual(gate.wine_suite(text, "ncrypt")["expectedTodos"], 176)
        with self.assertRaises(gate.ProbeFailure):
            gate.wine_suite("ncrypt.c:20: Test succeeded inside todo block:\n" + text, "ncrypt")

    def test_empty_or_truncated_results_cannot_pass(self):
        for function in (gate.cow, gate.iat, gate.boundary, lambda value: gate.ncrypt_lifecycle(value, "reopen")):
            with self.assertRaises(gate.ProbeFailure):
                function("")

    def test_duplicate_scalar_is_not_last_value_wins(self):
        with self.assertRaises(gate.ProbeFailure):
            gate.fields("Protect=0x8 Protect=0x4")

    def test_pe64_cow_requires_true_mbi_size(self):
        text = cow_result().replace("protocol=1 arch=PE32", "protocol=2 arch=PE64").replace(
            "ReturnBytes=0x0000001c", "ReturnBytes=0x00000030")
        self.assertEqual(public_gate.validate_probe("cow-probe", text)["arch"], "PE64")
        with self.assertRaises(gate.ProbeFailure):
            public_gate.validate_probe("cow-probe", text.replace("ReturnBytes=0x00000030", "ReturnBytes=0x0000001c"))

    def test_pe64_iat_uses_declared_fixture_rva_not_pe32_thunk(self):
        text = iat_result().replace("protocol=1 arch=PE32", "protocol=2 arch=PE64").replace(
            "ReturnBytes=0x0000001c", "ReturnBytes=0x00000030").replace("0x00002080", "0x000020a0").replace(
            "0x00202080", "0x002020a0").replace("0x00102080", "0x001020a0").replace("0x00002088", "0x000020b0")
        self.assertEqual(public_gate.validate_probe("iat-probe", text)["arch"], "PE64")
        with self.assertRaises(gate.ProbeFailure):
            public_gate.validate_probe("iat-probe", text.replace("TLS=0x00000000", "TLS=0x00002000"))

    def test_public_wrapper_rejects_unknown_kind(self):
        with self.assertRaises(ValueError):
            public_gate.validate_probe("ephemeral-historical", "probe_exit=0x00000000")

    def test_boundary_malformed_query_is_valueerror(self):
        with self.assertRaises(ValueError):
            public_gate.validate_probe("boundary-probe", boundary_result().replace("Address=0x00100000 ", ""))


if __name__ == "__main__":
    unittest.main()
