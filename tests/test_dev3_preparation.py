# SPDX-License-Identifier: LGPL-2.1-or-later
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import dev3_stage
import dev3_package


class Dev3PreparationTests(unittest.TestCase):
    def test_release_does_not_relabel_the_historical_recipe(self):
        self.assertEqual(dev3_stage.VERSION,'0.1.0-dev.3')
        self.assertEqual(dev3_stage.runtime.LOCK['version'],'0.1.0-dev.1')
        self.assertEqual(len(dev3_stage.runtime.LOCK['patches']),3)
        self.assertEqual(set(dev3_stage.ASSETS),{'proton','nndsk_volume_aliases.py',
                                               'files/share/nndsk/c-volume-query.exe'})

    def test_proton_step_only_changes_normal_target_run(self):
        patch=(ROOT/'patches/runtime/0001-proton-c-volume-alias.patch').read_text()
        added=[line[1:] for line in patch.splitlines() if line.startswith('+') and not line.startswith('+++')]
        self.assertEqual(len(added),7)
        self.assertIn('    def run(self):',patch)
        self.assertNotIn('runinprefix',patch)
        self.assertNotIn('kill',patch)
        self.assertNotIn('sysctl',patch)
        self.assertNotIn('relay',patch)

    def test_volume_mapping_does_not_ship_the_experiment_guid(self):
        for filename in ('runtime/c-volume-query.c','runtime/nndsk_volume_aliases.py',
                         'patches/runtime/0001-proton-c-volume-alias.patch'):
            text=(ROOT/filename).read_text()
            self.assertNotIn('00000000-0000-0000-0000-000000000043',text)
        self.assertIn('GetVolumeNameForVolumeMountPointW', (ROOT/'runtime/c-volume-query.c').read_text())

    def test_package_sources_are_not_private_worktree_copies(self):
        text=(ROOT/'scripts/dev3_package.py').read_text()
        self.assertIn('sources.export_commit',text)
        self.assertIn('sources.apply_patches',text)
        self.assertIn('prepared[\'patchsetRevision\'] != 2',text)
        self.assertNotIn('drive_c/HoneyRO',text)
        self.assertNotIn('gh release',text)

    def test_build_receipt_cannot_change_after_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root/'work/build'
            build.mkdir(parents=True)
            source = build/'source-receipt.json'
            data = b'{"sourceAfter": {}}\n'
            source.write_bytes(data)
            receipt = {'ncryptBuild': str(build),
                       'compiledSourceReceiptSha256': hashlib.sha256(data).hexdigest()}
            with patch.object(dev3_package, 'ROOT', root):
                self.assertEqual(dev3_package.checked_build_receipt(receipt), json.loads(data))
                source.write_bytes(b'{"sourceAfter": {"wrong": "changed"}}\n')
                with self.assertRaisesRegex(RuntimeError, 'changed since staging'):
                    dev3_package.checked_build_receipt(receipt)

    def test_build_receipt_cannot_adopt_a_foreign_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = {'ncryptBuild': str(root/'foreign'), 'compiledSourceReceiptSha256': 'f'*64}
            with patch.object(dev3_package, 'ROOT', root), self.assertRaisesRegex(RuntimeError, 'owned work/'):
                dev3_package.checked_build_receipt(receipt)

    def test_uncommitted_release_refuses_before_export_or_packaging(self):
        with patch.object(dev3_package.runtime, 'git_output', return_value=' M runtime/helper.py'), \
             patch.object(dev3_package, 'current_sources') as export, \
             self.assertRaisesRegex(RuntimeError, 'Freeze/commit'):
            dev3_package.main(type('Args', (), {'source_commit': 'a'*40})())
        export.assert_not_called()

    def test_source_asset_is_read_back_and_inherited_input_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scratch, output = root/'current-source', root/'output'
            scratch.mkdir()
            output.mkdir()
            (scratch/'recipe.py').write_text('# owned source fixture\n')
            inherited = root/'inherited.tar.zst'
            inherited.write_bytes(b'checksum-identified inherited fixture\n')
            before = inherited.read_bytes()
            digest = hashlib.sha256(before).hexdigest()
            index = {'recipeCommit': 'a'*40}
            with patch.object(dev3_package, 'INHERITED', inherited), \
                 patch.object(dev3_package, 'INHERITED_SHA', digest):
                result = dev3_package.pack_sources(scratch, output, index)
            self.assertEqual(result['sha256'], dev3_package.runtime.sha(output/result['filename']))
            self.assertEqual(index['inheritedSourceArchive']['sha256'], digest)
            self.assertEqual(inherited.read_bytes(), before)


if __name__=='__main__':
    unittest.main()
