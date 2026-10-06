# SPDX-License-Identifier: LGPL-2.1-or-later
"""Offline smoke-contract guards: no Wine, game execution or real prefixes."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('smoke_test_subject', ROOT / 'scripts/game_smoke.py')
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class SmokeTests(unittest.TestCase):
    def test_drive_mapping_resolves_real_target_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix='runtime-smoke-test-') as folder:
            root = Path(folder)
            game = root / 'game with spaces'
            game.mkdir()
            exe = game / 'own.exe'
            exe.write_bytes(b'inert owned test fixture, not executable')
            prefix = root / 'prefix'
            (prefix / 'dosdevices').mkdir(parents=True)
            (prefix / 'dosdevices/x:').symlink_to(root, target_is_directory=True)
            self.assertEqual(smoke.dos_target(prefix, r'X:\game with spaces\own.exe', game), exe)
            for invalid in (str(exe), r'X:own.exe', r'X:\game with spaces\..\own.exe',
                            r'\\host\share\own.exe', 'X:/game with spaces/own.exe'):
                with self.assertRaises(ValueError):
                    smoke.dos_target(prefix, invalid, game)
            with self.assertRaises(ValueError):
                smoke.dos_target(prefix, r'X:\game with spaces\own.exe', root / 'different-game')
            (prefix / 'dosdevices/x:').unlink()
            (prefix / 'dosdevices/x:').symlink_to(root / 'elsewhere', target_is_directory=True)
            with self.assertRaises(ValueError):
                smoke.dos_target(prefix, r'X:\game with spaces\own.exe', game)

    def test_launch_spec_preserves_arguments_cwd_and_graphics(self):
        values = {'WINEPREFIX': '/old-prefix', 'PROTONPATH': '/old-runner',
                  'DXVK_LOG_PATH': '/old-evidence', 'WINEDEBUG': '-all,err+all',
                  'WINEDLLOVERRIDES': 'ddraw=n,b', 'GAMEID': '0'}
        original = {'spec': {'program': '/umu', 'args': [r'X:\Game\own.exe'], 'cwd': '/Game',
                            'env': [{'key': k, 'value': v} for k, v in values.items()]}}
        spec, changes = smoke.launch_spec(original, Path('/new-prefix'), Path('/new-runner'), Path('/new-evidence'))
        for key in ('program', 'args', 'cwd'):
            self.assertEqual(spec[key], original['spec'][key])
        final = smoke.changes_dict(spec['env'])
        self.assertEqual(final['WINEDLLOVERRIDES'], values['WINEDLLOVERRIDES'])
        self.assertEqual(final['WINEDEBUG'], values['WINEDEBUG'])
        self.assertEqual(set(changes), smoke.PATH_CHANGES)
        self.assertEqual(smoke.changes_dict(original['spec']['env']), values)
        traced, changes = smoke.launch_spec(original, Path('/new-prefix'), Path('/new-runner'), Path('/new-evidence'), True)
        self.assertEqual(smoke.changes_dict(traced['env'])['WINEDEBUG'], values['WINEDEBUG'] + ',+ncrypt')
        self.assertEqual(set(changes), smoke.PATH_CHANGES | {'WINEDEBUG'})

    def test_conflicting_or_sensitive_environment_is_not_serialized(self):
        for rows in ([{'key': 'WINEPREFIX', 'value': '/a'}, {'key': 'WINEPREFIX', 'value': '/b'}],
                     [{'key': 'AUTH_TOKEN', 'value': 'do not save'}],
                     [{'key': 'bad=key', 'value': 'bad'}]):
            with self.assertRaises(ValueError):
                smoke.changes_dict(rows)
        env = smoke.inherited_environment({'APPIMAGE': '/bad', 'LD_PRELOAD': '/bad',
                                           'WINEPREFIX': '/bad', 'PROTONPATH': '/bad',
                                           'DISPLAY': ':0', 'PATH': '/usr/bin'})
        self.assertEqual(env, {'DISPLAY': ':0', 'PATH': '/usr/bin'})

    def test_cng_traces_are_entries_not_success_claims(self):
        entry = '1.0:trace:ncrypt:NCryptOpenKey (0x1234, 0xabcd, L"Own.Key", 0, 0x40)'
        self.assertIsNone(smoke.diagnostic(entry, False))
        self.assertEqual(smoke.diagnostic(entry, True)['kind'], 'cng-entry')
        self.assertEqual(smoke.diagnostic(entry.replace('NCryptOpenKey ', 'NCryptOpenKey:'), True)['kind'], 'cng-entry')
        self.assertIsNone(smoke.diagnostic('trace:ncrypt:dump_private_blob:deadbeef', True))
        self.assertIn('redacted', smoke.diagnostic('err:winhttp:request:Authorization Bearer secret', False)['line'])

    def test_opaque_storage_records_are_hashed_not_decrypted(self):
        with tempfile.TemporaryDirectory(prefix='runtime-store-test-') as folder:
            prefix = Path(folder)
            registry = '[Software\\\\Wine\\\\Crypto\\\\CNG\\\\SoftwareKSP\\\\Keys]\n"Own.Key"=hex:01,02,03\n'
            (prefix / 'user.reg').write_text(registry)
            records = smoke.store_hashes(prefix)
            self.assertEqual(len(records), 1)
            record = next(iter(records.values()))
            self.assertEqual(record['size'], 3)
            self.assertEqual(set(record), {'size', 'sha256'})


if __name__ == '__main__':
    unittest.main()
