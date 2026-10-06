"""Test-only COW expectation classification; never runs Wine or a game.

Historical classification predicts annotations, not execution results of the
new runtime. The Wine suite still has to be built and executed independently.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
HISTORY = json.loads((ROOT / "tests/cow-annotation-history.json").read_text())
PATCH = ROOT / "patches/tests/0001-kernel32-cow-private-view-expectations.patch"
SEC_IMAGE = 0x01000000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
COW_LINES = (4282, 4285, 4320)
HISTORICAL_LOG = None


def untracked_cow(section_flags, initial_view_protect):
    """No API result enters this decision: only initial mapping semantics."""
    return not (section_flags & SEC_IMAGE) and initial_view_protect in (
        PAGE_READWRITE, PAGE_EXECUTE_READWRITE
    )


def parse_historical_capture(data):
    """Parse the pinned old suite's TODO events, not arbitrary Wine failures."""
    flags = None
    groups, others = Counter(), Counter()
    for line in data.decode(errors="replace").splitlines():
        marker = re.search(r"testing (file|anonymous) mapping flags ([0-9a-f]{8})", line)
        if marker:
            flags = int(marker[2], 16)
        event = re.search(
            r"virtual.c:(\d+): Test (succeeded inside todo block|marked todo):", line
        )
        if not event:
            continue
        at = int(event[1])
        status = "success" if event[2].startswith("succeeded") else "pending"
        if at not in COW_LINES:
            others[(at, status)] += 1
            continue
        view = re.search(r"view (0x[0-9a-f]+)", line)
        if flags is None or view is None:
            raise ValueError("COW TODO event lacks initial mapping provenance")
        groups[(at, flags, int(view[1], 16), status)] += 1
    return groups, others


class CowAnnotationTests(unittest.TestCase):
    def test_private_views_are_normal_assertions(self):
        for protect in (0x1, 0x2, 0x8, 0x10, 0x20, 0x80):
            with self.subTest(protect=protect):
                self.assertFalse(untracked_cow(0x08000000, protect))

    def test_shared_writable_views_remain_todo(self):
        for protect in (PAGE_READWRITE, PAGE_EXECUTE_READWRITE):
            with self.subTest(protect=protect):
                self.assertTrue(untracked_cow(0x08000000, protect))

    def test_images_are_normal_even_with_writable_requested_view(self):
        for protect in (0x1, 0x2, 0x4, 0x8, 0x20, 0x40, 0x80):
            with self.subTest(protect=protect):
                self.assertFalse(untracked_cow(SEC_IMAGE, protect))

    def test_classification_does_not_depend_on_observed_status(self):
        for status in ("success", "pending", "failed", "unknown"):
            with self.subTest(status=status):
                # Deliberately do not pass status into the classifier.
                self.assertFalse(untracked_cow(SEC_IMAGE, PAGE_READWRITE))
                self.assertTrue(untracked_cow(0x08000000, PAGE_READWRITE))

    def test_historical_classification_retains_80_known_pending(self):
        totals = Counter()
        by_line = Counter()
        for at, flags, view, old_status, count in HISTORY["groups"]:
            is_todo = untracked_cow(int(flags, 16), int(view, 16))
            self.assertEqual(is_todo, old_status == "pending", (at, flags, view))
            totals["pending" if is_todo else "normal_pass"] += count
            if is_todo:
                by_line[at] += count
        self.assertEqual(totals, {"normal_pass": 705, "pending": 80})
        self.assertEqual(by_line, {4282: 24, 4285: 24, 4320: 32})

    def test_unrelated_todo_events_are_not_reclassified(self):
        rows = HISTORY["otherTodos"]
        self.assertIn([1444, "success", 1], rows)
        self.assertEqual(sum(n for _, state, n in rows if state == "pending"), 20)
        self.assertEqual(sum(n for _, state, n in rows if state == "success"), 1)
        self.assertTrue(all(at not in COW_LINES for at, _, _ in rows))

    def test_patch_is_test_only_and_result_independent(self):
        patch = PATCH.read_text()
        headers = re.findall(r"^\+\+\+ (.*)$", patch, re.MULTILINE)
        self.assertEqual(headers, ["b/dlls/kernel32/tests/virtual.c"])
        added = "\n".join(line[1:] for line in patch.splitlines()
                          if line.startswith("+") and not line.startswith("+++"))
        self.assertIn("BOOL untracked_cow = !(sec_flags & SEC_IMAGE)", added)
        self.assertIn("view[j].prot == PAGE_READWRITE", added)
        self.assertIn("view[j].prot == PAGE_EXECUTE_READWRITE", added)
        self.assertEqual(added.count("todo_wine_if( untracked_cow )"), 2)
        self.assertIn("todo_wine_if( untracked_cow && map_prot_written( page_prot[k] ) != actual_prot )", added)
        self.assertNotIn("info.Protect", added)
        self.assertNotIn("info.RegionSize", added)
        self.assertNotIn("GetLastError", added)

    def test_preserved_functional_patch_remains_byte_exact(self):
        data = (ROOT / "patches/0003-ntdll-private-cow-query.patch").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         "cef3c285f09e8778a353536622f9ab00f8c3158ed091b26473be997bdd95a010")

    def test_original_capture_matches_archived_groups(self):
        if HISTORICAL_LOG is None:
            self.skipTest("Optional private capture not supplied; use --historical-log")
        data = HISTORICAL_LOG.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), HISTORY["captureSha256"])
        groups, others = parse_historical_capture(data)
        expected = Counter({(at, int(flags, 16), int(view, 16), status): n
                            for at, flags, view, status, n in HISTORY["groups"]})
        expected_other = Counter({(at, status): n
                                  for at, status, n in HISTORY["otherTodos"]})
        self.assertEqual(groups, expected)
        self.assertEqual(others, expected_other)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("--historical-log", type=Path)
    args, remaining = parser.parse_known_args()
    HISTORICAL_LOG = args.historical_log
    unittest.main(argv=[__file__, *remaining])
