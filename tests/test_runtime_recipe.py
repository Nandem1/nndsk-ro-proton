# SPDX-License-Identifier: LGPL-2.1-or-later
"""Adversarial checks of metadata, source locks and inherited build environment."""
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('recipe', ROOT / 'scripts/runtime.py')
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)

class RecipeTests(unittest.TestCase):
    def test_every_locked_input_matches(self):
        recipe.check_inputs()

    def test_patch_groups_separate_and_base_fixed(self):
        self.assertEqual(len(recipe.LOCK['patches']), 3)
        self.assertEqual(recipe.LOCK['wine']['commit'], 'b5f2dc7b5906ef864f83df8fef94c9f539eaad2d')
        self.assertEqual(recipe.LOCK['proton']['commit'], '3edf6fbb8af940de5c65b9dd0fbf366b51a218a8')

    def test_build_environment_does_not_inherit_conflicts(self):
        with patch.dict(os.environ, {'APPIMAGE': '/bad', 'APPDIR': '/bad', 'LD_LIBRARY_PATH': '/bad',
                                     'CFLAGS': '-Ofast', 'LDFLAGS': '-bad', 'MAKEFLAGS': '-j999',
                                     'WINEPREFIX': '/someone-elses-prefix', 'PROTON_USE_WINED3D': '1',
                                     'STEAM_COMPAT_DATA_PATH': '/bad', 'GIT_DIR': '/bad',
                                     'TAR_OPTIONS': '--exclude=licenses', 'CPATH': '/bad',
                                     'ZSTD_CLEVEL': '1'}):
            env = recipe.environment()
        for key in ('APPIMAGE', 'APPDIR', 'LD_LIBRARY_PATH', 'CFLAGS', 'LDFLAGS', 'MAKEFLAGS',
                    'WINEPREFIX', 'PROTON_USE_WINED3D', 'STEAM_COMPAT_DATA_PATH', 'GIT_DIR',
                    'TAR_OPTIONS', 'CPATH', 'ZSTD_CLEVEL'):
            self.assertNotIn(key, env)
        self.assertEqual(env['SOURCE_DATE_EPOCH'], str(recipe.LOCK['sourceDateEpoch']))

    def test_experimental_is_not_publication_authorization(self):
        self.assertIs(recipe.LOCK['publicationReady'], False)
        self.assertEqual(recipe.LOCK['method'], 'pinned-binary-base-with-source-built-module-overlay')

    def test_git_identity_queries_sanitize_repository_redirects(self):
        with patch.dict(os.environ, {'GIT_DIR': '/wrong/.git', 'GIT_WORK_TREE': '/wrong',
                                     'GIT_INDEX_FILE': '/wrong/index'}):
            with patch.object(recipe.subprocess, 'check_output', return_value='expected\n') as call:
                self.assertEqual(recipe.git_output(['rev-parse', 'HEAD'], ROOT), 'expected\n')
        argv = call.call_args.args[0]
        options = call.call_args.kwargs
        self.assertEqual(argv, ['git', 'rev-parse', 'HEAD'])
        self.assertEqual(options['cwd'], ROOT)
        for key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'):
            self.assertNotIn(key, options['env'])

    def test_no_product_condition_in_functional_patches(self):
        for item in recipe.LOCK['patches']:
            data = (ROOT / item['path']).read_text()
            for name in ('xShield', 'HoneyRO', 'hRO.dll', 'DeviceIdentity.v1'):
                self.assertNotIn(name, data)

    def test_ten_source_files_recovered_not_reimplemented(self):
        source = json.loads((ROOT / 'provenance/validated-source.json').read_text())
        self.assertEqual(len(source), 10)
        self.assertIn('dlls/ncrypt/storage.c', source)
        self.assertEqual(source['dlls/ntdll/unix/virtual.c']['candidateSha256'],
                         '1231737b684a0f1fb6f258288e8ed24cf12bb5873167b126bd38b7f646f79349')

    def test_archive_rejects_link_traversal(self):
        import tarfile
        root = recipe.LOCK['binaryBase']['root']
        link = tarfile.TarInfo(root + '/link')
        link.type = tarfile.SYMTYPE
        link.linkname = '/outside'
        child = tarfile.TarInfo(root + '/link/file')
        with self.assertRaises(RuntimeError):
            recipe.validate_archive_members([link, child])

    def test_archive_preserves_leaf_prefix_template_link(self):
        import tarfile
        root = recipe.LOCK['binaryBase']['root']
        link = tarfile.TarInfo(root + '/default_pfx/dosdevices/z:')
        link.type = tarfile.SYMTYPE
        link.linkname = '/'
        recipe.validate_archive_members([link])

    def test_archive_rejects_normalized_link_traversal(self):
        import tarfile
        root = recipe.LOCK['binaryBase']['root']
        link = tarfile.TarInfo(root + '/./link')
        link.type = tarfile.SYMTYPE
        link.linkname = '/outside'
        child = tarfile.TarInfo(root + '/link/file')
        with self.assertRaises(RuntimeError):
            recipe.validate_archive_members([link, child])

    def test_archive_rejects_normalized_duplicate(self):
        import tarfile
        root = recipe.LOCK['binaryBase']['root']
        with self.assertRaises(RuntimeError):
            recipe.validate_archive_members([tarfile.TarInfo(root + '/dir/file'),
                                            tarfile.TarInfo(root + '/dir/./file')])

if __name__ == '__main__':
    unittest.main()
