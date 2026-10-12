# SPDX-License-Identifier: LGPL-2.1-or-later
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('ecc_experiment', ROOT / 'scripts/ecc_import_experiment.py')
experiment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(experiment)


class ExperimentTests(unittest.TestCase):
    def test_historical_lock_and_patch_hashes_remain_exact(self):
        p = experiment.profile()
        self.assertEqual(len(experiment.runtime.LOCK['patches']), 3)
        self.assertFalse(p['publicationReady'])
        self.assertIn('ecc-import', p['version'])

    def test_overlay_changes_exactly_two_ncrypt_modules(self):
        before = {'a': 1, 'b': 2, 'c': 3}
        allowed = ['a', 'b']
        self.assertEqual(set(experiment.check_overlay(before, {'a': 4, 'b': 5, 'c': 3}, allowed)), set(allowed))
        for after in ({'a': 4, 'b': 2, 'c': 3}, {'a': 4, 'b': 5, 'c': 4}, {'a': 4, 'b': 5}):
            with self.subTest(after=after), self.assertRaises(RuntimeError):
                experiment.check_overlay(before, after, allowed)

    def test_output_refuses_existing_broad_and_escaping_targets(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(experiment, 'ROOT', Path(directory)):
            root = Path(directory) / 'work/experiments'
            root.mkdir(parents=True)
            for path in (root, root.parent, Path(directory) / 'elsewhere'):
                with self.subTest(path=path), self.assertRaises(RuntimeError):
                    experiment.fresh_output(path)
            child = experiment.fresh_output(root / 'owned')
            with self.assertRaises(RuntimeError):
                experiment.fresh_output(child)
            (root / 'escape').symlink_to(Path(directory), target_is_directory=True)
            with self.assertRaises(RuntimeError):
                experiment.fresh_output(root / 'escape/another')

    def test_no_client_condition_or_crypto_bypass_in_patch(self):
        p = experiment.profile()
        data = (ROOT / p['patch']['path']).read_text()
        for token in ('HoneyRO', 'Gepard', 'GameGuard', 'WinVerifyTrust', 'NCryptVerifySignature'):
            self.assertNotIn(token, data)
        self.assertIn('BCryptImportKeyPair', data)
        self.assertIn('if (is_private && object->key.public_import) return NTE_PERM;', data)


if __name__ == '__main__':
    unittest.main()
