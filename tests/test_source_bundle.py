# SPDX-License-Identifier: LGPL-2.1-or-later
"""Offline guards only: no Wine, prefixes, runtime changes or publication."""
import importlib.util
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('source_bundle', ROOT / 'scripts/source_bundle.py')
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class SourceBundleTests(unittest.TestCase):
    def test_git_and_compression_environment_cannot_redirect_sources(self):
        with patch.dict(os.environ, {'GIT_DIR': '/wrong', 'GIT_WORK_TREE': '/wrong',
                                    'GIT_INDEX_FILE': '/wrong', 'TAR_OPTIONS': '--exclude=wine',
                                    'ZSTD_CLEVEL': '1', 'LD_PRELOAD': '/wrong'}):
            with patch.object(bundle.subprocess, 'check_output', return_value=b'fixed') as call:
                self.assertEqual(bundle.git(ROOT, ['rev-parse', 'HEAD']), b'fixed')
        for key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'TAR_OPTIONS', 'ZSTD_CLEVEL', 'LD_PRELOAD'):
            self.assertNotIn(key, call.call_args.kwargs['env'])

    def test_commit_identity_requires_full_hash_not_an_arbitrary_revision(self):
        for invalid in ('HEAD', '-all', '93bda98', 'a' * 40 + ':file', '../source', None):
            with self.assertRaises(ValueError):
                bundle.commit_id(invalid)
        self.assertEqual(bundle.commit_id('a' * 40), 'a' * 40)

    def test_source_archive_rejects_normalized_link_traversal(self):
        link = tarfile.TarInfo('wine/./link')
        link.type = tarfile.SYMTYPE
        link.linkname = '/outside'
        with self.assertRaises(RuntimeError):
            bundle.validate_members([link, tarfile.TarInfo('wine/link/file')], 'wine')

    def test_source_archive_rejects_normalized_duplicates_and_special_types(self):
        with self.assertRaises(RuntimeError):
            bundle.validate_members([tarfile.TarInfo('wine/file'), tarfile.TarInfo('wine/./file')], 'wine')
        for name in ('../file', '/wine/file', 'other/file'):
            with self.assertRaises(RuntimeError):
                bundle.validate_members([tarfile.TarInfo(name)], 'wine')
        member = tarfile.TarInfo('wine/device')
        member.type = tarfile.CHRTYPE
        with self.assertRaises(RuntimeError):
            bundle.validate_members([member], 'wine')

    def test_manifest_requires_exact_binary_recipe_identity(self):
        lock = json.loads((ROOT / 'upstream.lock.json').read_text())
        manifest = {key: lock[key] for key in ('runtimeId', 'version', 'patchsetRevision', 'sourceDateEpoch')}
        manifest.update(sourceCommit='a' * 40, upstream={'wine': lock['wine'], 'proton': lock['proton']},
                        buildMethod=lock['method'], artifact={'filename': 'runtime.tar.zst'})
        bundle.validate_identity(manifest, lock)
        for key, bad in (('patchsetRevision', 999), ('version', '../wrong')):
            changed = manifest | {key: bad}
            with self.assertRaises(RuntimeError):
                bundle.validate_identity(changed, lock)
        with self.assertRaises(RuntimeError):
            bundle.validate_identity(manifest | {'artifact': {'filename': '../outside'}}, lock)

    def test_source_scope_never_claims_full_runtime_clearance(self):
        self.assertIn('NOT complete', bundle.SCOPE)
        self.assertIn('not legal clearance', bundle.SCOPE)

    def test_git_blob_identity_matches_committed_blob_without_filters(self):
        with tempfile.TemporaryDirectory(prefix='nndsk-source-unit-') as directory:
            path = Path(directory) / 'sample'
            path.write_bytes(b'source\n')
            object_id, mode = bundle.blob_identity(path)
            expected = bundle.git(ROOT, ['hash-object', '--no-filters', str(path)]).decode().strip()
            self.assertEqual(object_id, expected)
            self.assertEqual(mode, '100644')
            path.chmod(0o755)
            self.assertEqual(bundle.blob_identity(path)[1], '100755')


if __name__ == '__main__':
    unittest.main()
