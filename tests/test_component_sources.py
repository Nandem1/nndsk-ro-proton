import importlib.util
from pathlib import Path
import tempfile
import tarfile
import io
import unittest

SPEC = importlib.util.spec_from_file_location('component_sources', Path(__file__).resolve().parents[1] / 'scripts/collect_component_sources.py')
sources = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sources)


class ComponentSourcesTests(unittest.TestCase):
    def test_urls_pin_full_commit_and_reject_credentials_or_moving_refs(self):
        commit = 'a' * 40
        self.assertEqual(sources.archive_url('https://github.com/owner/repo.git', commit),
                         'https://codeload.github.com/owner/repo/tar.gz/' + commit)
        for repository, revision in [('https://github.com/owner/repo', 'main'),
                ('http://github.com/owner/repo', commit), ('https://token@github.com/owner/repo', commit),
                ('https://github.com/owner/../repo', commit), ('https://example.com/owner/repo', commit)]:
            with self.assertRaises(ValueError):
                sources.archive_url(repository, revision)

    def test_notice_collection_reads_files_not_symlinks_and_does_not_extract(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'source.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                member = tarfile.TarInfo('fixture/LICENSE')
                member.size = 12
                tar.addfile(member, io.BytesIO(b'own fixture\n'))
                link = tarfile.TarInfo('fixture/NOTICE.link')
                link.type = tarfile.SYMTYPE
                link.linkname = '/etc/passwd'
                tar.addfile(link)
            records = sources.notices(archive)
            self.assertEqual(list(records), ['fixture/LICENSE'])
            self.assertEqual(records['fixture/LICENSE']['size'], 12)
            self.assertFalse((Path(directory) / 'fixture').exists())

    def test_notice_collection_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'source.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                tar.addfile(tarfile.TarInfo('../LICENSE'))
            with self.assertRaises(ValueError):
                sources.notices(archive)


if __name__ == '__main__':
    unittest.main()
