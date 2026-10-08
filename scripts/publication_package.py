# SPDX-License-Identifier: LGPL-2.1-or-later
"""Metadata-only publication revision of the accepted immutable runtime.

Never compile, execute Wine, touch an installation/prefix, or publish remotely.
Refuses an unreviewed source set or any change to accepted runtime code/data.
"""
import argparse
import io
import hashlib
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
import shutil
import subprocess
import tarfile

import runtime
from publication_materials import checked_receipts

ROOT = runtime.ROOT
VERSION = '0.1.0-dev.2'
MATERIALS = ROOT / 'work/publication-materials-20261008-v3'
STAGE = ROOT / 'work/publication-stage-20261008-r2/nndsk-ro-proton'
DIST = ROOT / 'dist/publication-0.1.0-dev.2-r2'
OLD_SHA = '75b0c916ccf6e7fcd64ed2afe576c2c0bc6a75ef63a8d74ad6dd9bee629d4d9f'


def publication_commit(raw):
    commit = raw.strip()
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('Publication recipe requires a full Git commit')
    return commit


def validate_preservation(before, after):
    changed = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
    allowed = {'nndsk-runtime.json', 'SOURCES.nndsk.txt', 'nndsk-LICENSES/third-party',
               'nndsk-LICENSES/publication-review.md', 'nndsk-LICENSES/source-index.json'}
    if any(name not in allowed and not name.startswith('nndsk-LICENSES/third-party/') for name in changed):
        raise ValueError('Publication revision changed runtime code/data: ' + repr(changed))
    if any(name not in after for name in before):
        raise ValueError('Publication revision removed an accepted file')


def source_bundle(index, commit):
    name = f'nndsk-ro-proton-{VERSION}-sources.tar.zst'
    path = DIST / name
    source_files = [(ROOT / 'dist/source/nndsk-ro-proton-0.1.0-dev.1-source.tar.zst',
                     'modified-wine-and-original-recipe.tar.zst'),
                    (ROOT / 'dist/source/proton-cachyos-3edf6fbb8af9-source.tar.zst',
                     'proton-cachyos-root-source.tar.zst')]
    for record in index['sources']:
        if record['component'].endswith('-distribution'):
            continue  # Custody comparison binaries are not source material.
        source_files.append((ROOT / 'work/publication-sources-20261008' / record['filename'],
                             'components/' + record['filename']))
    recipe = DIST / 'publication-recipe.tar'
    with recipe.open('xb') as stream:
        subprocess.run(['git', 'archive', '--format=tar', commit], cwd=ROOT,
                       env=runtime.environment(), stdout=stream, check=True)
    source_files.append((recipe, 'publication-recipe.tar'))
    checksums = ''.join(runtime.sha(p) + '  ' + n + '\n' for p, n in source_files)
    env = runtime.environment()
    with path.open('xb') as output:
        compressor = subprocess.Popen(['zstd', '-q', '-T1', '-3', '-c'], stdin=subprocess.PIPE,
                                      stdout=output, env=env)
        try:
            with tarfile.open(fileobj=compressor.stdin, mode='w|', format=tarfile.GNU_FORMAT) as tar:
                for src, name in source_files:
                    member = tarfile.TarInfo('nndsk-ro-proton-sources/' + name)
                    member.size = src.stat().st_size
                    member.mode, member.mtime = 0o644, runtime.LOCK['sourceDateEpoch']
                    with src.open('rb') as stream:
                        tar.addfile(member, stream)
                for name, data in [('source-index.json', (MATERIALS / 'source-index.json').read_bytes()),
                                   ('SHA256SUMS', checksums.encode()),
                                   ('README.md', (ROOT / 'docs/PUBLICATION-20261008.md').read_bytes())]:
                    member = tarfile.TarInfo('nndsk-ro-proton-sources/' + name)
                    member.size, member.mode, member.mtime = len(data), 0o644, runtime.LOCK['sourceDateEpoch']
                    tar.addfile(member, io.BytesIO(data))
            compressor.stdin.close()
            if compressor.wait():
                raise RuntimeError('Source compression failed')
        finally:
            if compressor.poll() is None:
                compressor.terminate()
                compressor.wait()
    if path.stat().st_size >= 2 * 1024**3:
        raise ValueError('Source asset exceeds release size limit')
    return {'filename': path.name, 'size': path.stat().st_size, 'sha256': runtime.sha(path)}


def main():
    os.umask(0o022)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repeat-package', action='store_true')
    args = parser.parse_args()
    runtime.check_inputs()
    if runtime.git_output(['status', '--porcelain'], ROOT):
        raise ValueError('Publication recipe must be committed and clean')
    commit = publication_commit(runtime.git_output(['rev-parse', 'HEAD'], ROOT))
    review = json.loads((ROOT / 'provenance/publication-review.json').read_text())
    if review.get('status') != 'ACCEPTED_FOR_PRERELEASE_DISTRIBUTION':
        raise ValueError('Maintainer publication review is not accepted')
    index = json.loads((MATERIALS / 'source-index.json').read_text())
    if runtime.sha(MATERIALS / 'source-index.json') != review['materialsSourceIndexSha256']:
        raise ValueError('Unreviewed source index')
    material_files = {str(p.relative_to(MATERIALS)): runtime.sha(p)
                      for p in sorted(MATERIALS.rglob('*')) if p.is_file()}
    seal = hashlib.sha256(json.dumps(material_files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if seal != review['materialsInventorySha256']:
        raise ValueError('Unreviewed/modified license materials')
    records = checked_receipts()
    if [{k:v for k,v in r.items() if k != 'noticeFiles'} for r in index['sources']] != records:
        raise ValueError('Source index does not match verified custody')
    accepted = ROOT / 'work/stage/nndsk-ro-proton'
    expected = json.loads((ROOT / 'work/stage-inventory.json').read_text())
    if runtime.inventory(accepted) != expected:
        raise ValueError('Accepted staging changed')
    original = ROOT / 'dist/nndsk-ro-proton-0.1.0-dev.1-linux-x86_64.tar.zst'
    if runtime.sha(original) != OLD_SHA:
        raise ValueError('Original accepted archive changed')
    shutil.copytree(accepted, STAGE, symlinks=True)
    shutil.copytree(MATERIALS / 'notices', STAGE / 'nndsk-LICENSES/third-party')
    shutil.copyfile(MATERIALS / 'source-index.json', STAGE / 'nndsk-LICENSES/source-index.json')
    shutil.copyfile(ROOT / 'docs/PUBLICATION-20261008.md', STAGE / 'nndsk-LICENSES/publication-review.md')
    identity = json.loads((STAGE / 'nndsk-runtime.json').read_text())
    identity.update(version=VERSION, packagingRevision=1, packagingCommit=commit,
                    publicationReady=True, acceptedArchiveSha256=OLD_SHA)
    (STAGE / 'nndsk-runtime.json').write_text(json.dumps(identity, indent=2, sort_keys=True) + '\n')
    (STAGE / 'SOURCES.nndsk.txt').write_text(
        'nndsk-ro-proton ' + VERSION + '\n'
        'Source, original notices, Wine modifications and build recipes:\n'
        'https://github.com/Nandem1/nndsk-ro-proton/releases/tag/v' + VERSION + '\n'
        'See the accompanying nndsk-ro-proton-' + VERSION + '-sources.tar.zst.\n'
        'Module source commit: ' + identity['sourceCommit'] + '\n'
        'Publication recipe commit: ' + commit + '\n'
        'All runtime binaries/data match the accepted dev.1 build. Only packaging notices/metadata differ.\n'
        'Upstream binary compilation is not claimed bit-reproducible; see publication-review.md.\n')
    after = runtime.inventory(STAGE)
    validate_preservation(expected, after)
    DIST.mkdir()
    archive = DIST / f'nndsk-ro-proton-{VERSION}-linux-x86_64.tar.zst'
    if args.repeat_package:
        repeat = DIST / (archive.name + '.repeat')
        with ThreadPoolExecutor(max_workers=2) as pool:
            tasks = [pool.submit(runtime.pack_archive, STAGE, path) for path in (archive, repeat)]
            for task in tasks:
                task.result()
        if runtime.sha(archive) != runtime.sha(repeat):
            raise ValueError('Non-deterministic binary packaging')
    else:
        runtime.pack_archive(STAGE, archive)
    runtime.verify_packaged_archive(archive, STAGE, after)
    sources = source_bundle(index, commit)
    identity.update(platform='linux-x86_64', artifact={'filename': archive.name,
        'sha256': runtime.sha(archive), 'size': archive.stat().st_size, 'format': 'tar.zst', 'root': STAGE.name},
        sources=sources, sourceAndNoticeDistributionReview=review['status'],
        packagingDeterminismVerified=args.repeat_package, compilationBitReproducibilityVerified=False,
        validation={'runtimeCodeAndDataEqualAcceptedBuild': True, 'honeyroAcceptedStability': 'PASS',
                    'newPackageLauncherGuiTest': 'USER_PENDING', 'sakuraUsesWine716Fallback': True})
    runtime.save(DIST / 'manifest.json', identity)
    shutil.copyfile(MATERIALS / 'source-index.json', DIST / 'source-index.json')
    runtime.save(DIST / 'preservation.json', {'acceptedArchiveSha256': OLD_SHA,
        'acceptedInventoryRecords': len(expected), 'changedExistingFiles': ['nndsk-runtime.json'],
        'additionalPaths': [n for n in after if n not in expected],
        'modifiedModules': identity['modifiedModules']})
    with (DIST / 'SHA256SUMS').open('x') as stream:
        for path in (archive, DIST / sources['filename'], DIST / 'manifest.json',
                     DIST / 'source-index.json', DIST / 'preservation.json'):
            stream.write(runtime.sha(path) + '  ' + path.name + '\n')
    print(json.dumps({'artifact': identity['artifact'], 'sources': sources,
                      'packagingCommit': commit}, indent=2), flush=True)


if __name__ == '__main__':
    main()
