# SPDX-License-Identifier: LGPL-2.1-or-later
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('volume_aliases', ROOT / 'runtime/nndsk_volume_aliases.py')
volume = importlib.util.module_from_spec(spec)
spec.loader.exec_module(volume)
GUID = '00000000-0000-0000-0000-000000000043'
FRAME = ('NNDSK_C_VOLUME_V1 \\\\?\\Volume{' + GUID + '}\\\n').encode()


class VolumeAliasTests(unittest.TestCase):
    def test_query_is_not_a_guessed_guid(self):
        self.assertEqual(volume.decode_volume(FRAME), 'volume{' + GUID + '}')
        other = 'f8b1e3e7-2898-4226-a6aa-7abc2b127431'
        self.assertEqual(volume.decode_volume(FRAME.replace(GUID.encode(), other.encode())), 'volume{' + other + '}')
        for data in (FRAME+FRAME, FRAME[:-2], b'x'*257, FRAME.replace(b'Volume', b'Other'),
                     FRAME.replace(GUID.encode(), b'../../elsewhere'), FRAME+b'noise\n'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                volume.decode_volume(data)

    def test_idempotent_local_alias_and_collision_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            (prefix/'drive_c').mkdir()
            (prefix/'dosdevices').mkdir()
            (prefix/'dosdevices/c:').symlink_to('../drive_c', target_is_directory=True)
            name = volume.decode_volume(FRAME)
            alias = volume.install_alias(prefix, name)
            self.assertEqual(alias.resolve(), prefix/'drive_c')
            self.assertEqual(volume.install_alias(prefix, name), alias)
            # Explicitly remove only this owned unit-test link to inject a collision.
            alias.unlink()
            alias.write_text('preserve foreign entry')
            with self.assertRaises(RuntimeError):
                volume.install_alias(prefix, name)
            self.assertEqual(alias.read_text(), 'preserve foreign entry')

    def test_foreign_c_mapping_and_dosdevices_are_never_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)/'prefix'
            prefix.mkdir()
            (prefix/'drive_c').mkdir()
            (prefix/'dosdevices').mkdir()
            (prefix/'dosdevices/c:').symlink_to(directory, target_is_directory=True)
            with self.assertRaises(RuntimeError):
                volume.install_alias(prefix, volume.decode_volume(FRAME))
            self.assertFalse((prefix/'dosdevices'/volume.decode_volume(FRAME)).exists())
            (prefix/'dosdevices/c:').unlink()
            (prefix/'dosdevices').rmdir()
            (prefix/'dosdevices').symlink_to(directory, target_is_directory=True)
            with self.assertRaises(RuntimeError):
                volume.install_alias(prefix, volume.decode_volume(FRAME))

    def test_names_cannot_escape_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            (prefix/'drive_c').mkdir()
            (prefix/'dosdevices').mkdir()
            (prefix/'dosdevices/c:').symlink_to('../drive_c', target_is_directory=True)
            for name in ('../escape', '/tmp/escape', 'volume{../../escape}', 'volume{'+'f'*36+'}'):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    volume.install_alias(prefix, name)


if __name__ == '__main__':
    unittest.main()
