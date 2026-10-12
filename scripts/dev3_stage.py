# SPDX-License-Identifier: LGPL-2.1-or-later
"""Stage dev.3 in a new directory, preserving the published dev.2 baseline."""
import argparse
import copy
import json
from pathlib import Path
import shutil

import runtime
import ecc_import_experiment as ecc

ROOT = runtime.ROOT
VERSION = '0.1.0-dev.3'
BASE = ROOT / 'work/publication-stage-20261008-r2/nndsk-ro-proton'
BASE_ARCHIVE = ROOT / 'dist/publication-0.1.0-dev.2-r2/nndsk-ro-proton-0.1.0-dev.2-linux-x86_64.tar.zst'
BASE_SHA = '208e6d4735c9a25c4f14b6465712a1069ce53aaf4d5a12eb5a3967abe962ead4'
ASSETS = ('proton', 'nndsk_volume_aliases.py', 'files/share/nndsk/c-volume-query.exe')


def stage(args):
    p = ecc.profile()
    build = args.ncrypt_build.resolve()
    receipt = json.loads((build / 'source-receipt.json').read_text())
    for key in ('upstream.lock.json', p['patch']['path']):
        if runtime.sha(ROOT / key) != receipt['inputs'][key]:
            raise RuntimeError('Compiled ncrypt input changed: ' + key)
    for name, expected in receipt['sourceAfter'].items():
        if runtime.sha(build / 'wine' / name) != expected:
            raise RuntimeError('Compiled source changed: ' + name)
    differences = json.loads((build / 'module-differences.json').read_text())
    if set(differences) != set(p['overlayModules']):
        raise RuntimeError('Unexpected ncrypt overlay')
    probes = args.probes.resolve()
    probe_manifest = json.loads((probes / 'build-manifest.json').read_text())
    if probe_manifest.get('complete') is not True or probe_manifest['sourceFiles']['runtime/c-volume-query.c'] != runtime.sha(ROOT / 'runtime/c-volume-query.c'):
        raise RuntimeError('Native query source/build mismatch')
    helper = probes / 'x86_64/c-volume-query.exe'
    helper_record = probe_manifest['artifacts']['x86_64/c-volume-query.exe']
    if runtime.sha(helper) != helper_record['sha256'] or helper_record['arch'] != 'x86_64':
        raise RuntimeError('Native query identity mismatch')
    if runtime.sha(BASE_ARCHIVE) != BASE_SHA:
        raise RuntimeError('Published baseline archive changed')
    before = runtime.inventory(BASE)
    runtime.verify_packaged_archive(BASE_ARCHIVE, BASE, before)
    output = ecc.fresh_output(args.output)
    runtime.WORK = output
    dest = output / 'nndsk-ro-proton'
    runtime.run(['cp', '-a', '--reflink=auto', BASE, dest], ROOT, 'copy-published-base')
    identity = json.loads((dest / 'nndsk-runtime.json').read_text())
    if identity['version'] != '0.1.0-dev.2' or identity['patchsetRevision'] != 1:
        raise RuntimeError('Unexpected baseline identity')
    for arch in runtime.ARCHS:
        name = f'files/lib/wine/{arch}-windows/ncrypt.dll'
        origin = build / f'build-pe/dlls/ncrypt/{arch}-windows/ncrypt.dll'
        expected = differences[name]['candidate']
        if runtime.sha(origin) != expected['sha256'] or origin.stat().st_size != expected['size']:
            raise RuntimeError('Compiled ncrypt module changed: ' + name)
        target = dest / name
        mode = target.stat().st_mode & 0o7777
        target.chmod(mode | 0o200)
        shutil.copyfile(origin, target)
        target.chmod(mode)
    apply = ['git', '--git-dir=' + str(ROOT / '.git'), '--work-tree=' + str(dest), 'apply']
    runtime.run([*apply, '--check', ROOT / 'patches/runtime/0001-proton-c-volume-alias.patch'], dest, 'check-proton-hook')
    runtime.run([*apply, ROOT / 'patches/runtime/0001-proton-c-volume-alias.patch'], dest, 'apply-proton-hook')
    shutil.copyfile(ROOT / 'runtime/nndsk_volume_aliases.py', dest / 'nndsk_volume_aliases.py')
    (dest / 'files/share/nndsk').mkdir()
    shutil.copyfile(helper, dest / ASSETS[2])
    (dest / ASSETS[2]).chmod(0o555)
    current = runtime.inventory(dest)
    changed = {name for name in before.keys() | current.keys() if before.get(name) != current.get(name)}
    expected_changes = {*p['overlayModules'], *ASSETS, 'files/share/nndsk'}
    if changed != expected_changes:
        raise RuntimeError('Unreviewed runtime delta: ' + repr(changed))
    if runtime.inventory(BASE) != before:
        raise RuntimeError('Published baseline changed during staging')
    source_inputs = {name: runtime.sha(ROOT / name) for name in (
        'upstream.lock.json', p['patch']['path'], 'patches/runtime/0001-proton-c-volume-alias.patch',
        'runtime/c-volume-query.c', 'runtime/nndsk_volume_aliases.py', 'scripts/dev3_stage.py')}
    new_identity = copy.deepcopy(identity)
    new_identity.update(version=VERSION, patchsetRevision=2, publicationReady=False,
                        sourceInheritance=identity['sourceCommit'],
                        preparationSource={'repositoryHead': runtime.git_output(['rev-parse', 'HEAD'], ROOT).strip(),
                                           'uncommittedInputs': True, 'inputs': source_inputs},
                        compatibilityAssets={name: current[name] for name in ASSETS})
    for key in ('acceptedArchiveSha256', 'packagingCommit', 'packagingRevision'):
        new_identity.pop(key, None)
    for name in p['overlayModules']:
        new_identity['modifiedModules'][name] = current[name]
    manifest = dest / 'nndsk-runtime.json'
    with manifest.open('w') as stream:
        json.dump(new_identity, stream, indent=2, sort_keys=True)
        stream.write('\n')
    runtime.save(output / 'stage-inventory.json', runtime.inventory(dest))
    runtime.save(output / 'stage-receipt.json', {'version': VERSION, 'baselineArchiveSha256': BASE_SHA,
        'baselineInventory': before, 'ncryptBuild': str(build), 'compiledSourceReceiptSha256': runtime.sha(build/'source-receipt.json'),
        'sourceInputs': source_inputs, 'runtimeDeltaBeforeManifest': sorted(changed)})
    print(dest, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ncrypt-build', type=Path, required=True)
    parser.add_argument('--probes', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    stage(parser.parse_args())
