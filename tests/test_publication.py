# SPDX-License-Identifier: LGPL-2.1-or-later
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import publication_materials as materials
import publication_package as package
import collect_component_sources as sources


class PublicationTests(unittest.TestCase):
    def test_packaging_may_add_notices_but_cannot_change_code_or_remove_data(self):
        original = {'files/bin/wine': {'sha256': 'accepted'},
                    'nndsk-runtime.json': {'sha256': 'old'}, 'files/model': {'sha256': 'model'}}
        revised = {**original, 'nndsk-runtime.json': {'sha256': 'new'},
                   'nndsk-LICENSES/third-party/example/LICENSE': {'sha256': 'notice'}}
        package.validate_preservation(original, revised)
        for invalid in ({**revised, 'files/bin/wine': {'sha256': 'other'}},
                        {**revised, 'extra.dll': {'sha256': 'extra'}},
                        {k:v for k,v in revised.items() if k != 'files/model'}):
            with self.assertRaises(ValueError):
                package.validate_preservation(original, invalid)

    def test_original_notice_bytes_and_third_party_notices_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'fixture.tar.gz'
            data = b'original notice\r\n\xff\n'
            with tarfile.open(archive, 'w:gz') as tar:
                member = tarfile.TarInfo('fixture/ThirdPartyNotices.txt')
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
            self.assertEqual(list(materials.notice_files(archive)), [('fixture/ThirdPartyNotices.txt', data)])

    def test_zip_symlinks_are_not_notices_and_nothing_is_extracted(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'fixture.zip'
            with zipfile.ZipFile(archive, 'w') as zipped:
                link = zipfile.ZipInfo('LICENSE.link')
                link.create_system = 3
                link.external_attr = 0o120777 << 16
                zipped.writestr(link, '/etc/passwd')
                zipped.writestr('LICENSE', 'own notice')
            self.assertEqual(list(sources.notices(archive)), ['LICENSE'])
            self.assertEqual(list(materials.notice_files(archive)), [('LICENSE', b'own notice')])
            self.assertFalse((Path(directory) / 'LICENSE').exists())

    def test_paths_cannot_escape_or_use_backslashes(self):
        for name in ('/etc/passwd', '../LICENSE', 'x/../../LICENSE', 'x\\..\\LICENSE'):
            with self.assertRaises(ValueError):
                materials.safe_name(name)

    def test_rust_git_selector_is_not_used_as_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'source.tar.gz'
            data = ('[[package]]\nname="fixture"\nversion="1.0.0"\n'
                    'source="git+https://github.com/owner/repo?branch=main#' + 'a' * 40 + '"\n').encode()
            with tarfile.open(archive, 'w:gz') as tar:
                member = tarfile.TarInfo('fixture/Cargo.lock')
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
            records = sources.rust_dependencies([archive])
            self.assertEqual(records[0]['commit'], 'a' * 40)
            self.assertEqual(records[0]['repository'], 'https://github.com/owner/repo')


if __name__ == '__main__':
    unittest.main()
