# SPDX-License-Identifier: LGPL-2.1-or-later
"""Private fourth-patch candidate. Never installs, publishes or changes the sealed recipe."""
import argparse
import copy
import json
from pathlib import Path
import shutil

import runtime

ROOT = runtime.ROOT
PROFILE_PATH = ROOT / 'experiments/ecc-import.json'


def profile():
    p = json.loads(PROFILE_PATH.read_text())
    runtime.check_inputs()
    if p['publicationReady'] is not False or p['schemaVersion'] != 1:
        raise RuntimeError('Not a private experimental profile')
    if runtime.sha(ROOT / 'upstream.lock.json') != p['upstreamLockSha256']:
        raise RuntimeError('Historical recipe changed')
    if runtime.sha(ROOT / p['patch']['path']) != p['patch']['sha256']:
        raise RuntimeError('Experimental patch changed without updating its lock')
    expected = {f'files/lib/wine/{arch}-windows/ncrypt.dll' for arch in runtime.ARCHS}
    if set(p['overlayModules']) != expected or len(p['overlayModules']) != 2:
        raise RuntimeError('Experiment may overlay only the two ncrypt modules')
    allowed_source = {'dlls/ncrypt/main.c', 'dlls/ncrypt/ncrypt_internal.h', 'include/ncrypt.h', 'include/bcrypt.h'}
    if set(p['sourcePaths']) != allowed_source or len(p['sourcePaths']) != 4:
        raise RuntimeError('Unexpected experimental source scope')
    return p


def fresh_output(path):
    path = path.resolve()
    parent = (ROOT / 'work/experiments').resolve()
    if not path.is_relative_to(parent) or path == parent or path.exists():
        raise RuntimeError('Use a new child of work/experiments; no existing outputs may be reused')
    path.mkdir(mode=0o700, parents=True)
    return path


def check_overlay(before, after, allowed):
    changed = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
    if changed != set(allowed):
        raise RuntimeError('Unexpected candidate changes: ' + repr(changed))
    return {name: {'base': before[name], 'candidate': after[name]} for name in sorted(changed)}


def build(args):
    p = profile()
    # All of these are read-only validation of the existing preservation build.
    runtime.verify_build_seal()
    baseline = ROOT / 'work/stage/nndsk-ro-proton'
    before = runtime.inventory(baseline)
    if before != json.loads((ROOT / 'work/stage-inventory.json').read_text()):
        raise RuntimeError('Preservation stage changed; refusing to use it as baseline')
    identity = json.loads((baseline / 'nndsk-runtime.json').read_text())
    if identity['upstream'] != {'wine': runtime.LOCK['wine'], 'proton': runtime.LOCK['proton']}:
        raise RuntimeError('Wrong preservation upstream')
    for name, record in identity['modifiedModules'].items():
        if before.get(name) != record:
            raise RuntimeError('Preservation module does not match its manifest')
    output = fresh_output(args.output)
    # Reuse the sealed recipe's environment and exclusive command logging, not
    # its source verifier (which must continue to require the original 3 patches).
    runtime.WORK = output
    source = output / 'wine'
    runtime.run(['git', 'clone', '--no-hardlinks', '--no-checkout', args.wine_cache, source], ROOT, 'clone')
    runtime.run(['git', 'checkout', '--detach', runtime.LOCK['wine']['commit']], source, 'checkout')
    for index, patch in enumerate(runtime.LOCK['patches'], 1):
        runtime.run(['git', 'apply', '--check', ROOT / patch['path']], source, f'check-{index}')
        runtime.run(['git', 'apply', ROOT / patch['path']], source, f'apply-{index}')
    original = json.loads((ROOT / 'provenance/validated-source.json').read_text())
    for name, info in original.items():
        if runtime.sha(source / name) != info['candidateSha256']:
            raise RuntimeError('The original 3 patches no longer reproduce their accepted source')
    historical = {name: runtime.sha(source / name) for name in original.keys() | set(p['sourcePaths'])}
    runtime.run(['git', 'apply', '--check', ROOT / p['patch']['path']], source, 'check-fourth')
    changed = runtime.git_output(['apply', '--numstat', str(ROOT / p['patch']['path'])], source)
    if {line.split('\t')[2] for line in changed.splitlines()} != set(p['sourcePaths']):
        raise RuntimeError('Experimental patch touches unexpected files')
    runtime.run(['git', 'apply', ROOT / p['patch']['path']], source, 'apply-fourth')
    patched = {name: runtime.sha(source / name) for name in historical}
    if {name for name in historical if historical[name] != patched[name]} != set(p['sourcePaths']):
        raise RuntimeError('Experimental functional source delta is wrong')
    for command, label in ((['autoconf'], 'autoconf'), (['autoheader'], 'autoheader'),
                           (['tools/make_requests'], 'requests'), (['tools/make_specfiles'], 'specfiles')):
        runtime.run(command, source, label)
    runtime.run(['./make_vulkan', '-x', ROOT / 'vendor/vulkan/vk.xml', '-X', ROOT / 'vendor/vulkan/video.xml'],
                source / 'dlls/winevulkan', 'vulkan')
    build_dir = output / 'build-pe'
    build_dir.mkdir()
    runtime.run([source / 'configure', '--enable-win64', '--enable-archs=i386,x86_64',
                 '--with-mingw=clang', *runtime.DISABLED], build_dir, 'configure')
    targets = [f'dlls/ncrypt/{arch}-windows/ncrypt.dll' for arch in runtime.ARCHS]
    targets += [f'dlls/ncrypt/tests/{arch}-windows/ncrypt_test.exe' for arch in runtime.ARCHS]
    runtime.run(['make', '-j' + str(args.jobs), *targets], build_dir, 'build')
    for name, expected in patched.items():
        if runtime.sha(source / name) != expected:
            raise RuntimeError('Functional source changed while compiling')
    candidate = output / 'nndsk-ro-proton-ecc-import'
    # Preserve symlinks/modes, use independent copy-on-write files, never hardlinks.
    runtime.run(['cp', '-a', '--reflink=auto', baseline, candidate], ROOT, 'copy-baseline')
    for arch in runtime.ARCHS:
        name = f'files/lib/wine/{arch}-windows/ncrypt.dll'
        dest = candidate / name
        if not dest.is_file() or dest.is_symlink():
            raise RuntimeError('Overlay destination is not a regular module')
        mode = dest.stat().st_mode & 0o7777
        dest.chmod(mode | 0o200)
        shutil.copyfile(build_dir / f'dlls/ncrypt/{arch}-windows/ncrypt.dll', dest)
        dest.chmod(mode)
    after = runtime.inventory(candidate)
    differences = check_overlay(before, after, p['overlayModules'])
    if runtime.inventory(baseline) != before:
        raise RuntimeError('Preservation baseline changed during build')
    runtime.save(output / 'module-differences.json', differences)
    inputs = ['upstream.lock.json', 'experiments/ecc-import.json', p['patch']['path'],
              'scripts/ecc_import_experiment.py', 'tests/cng-ecc-import-probe.c',
              'tests/ecc_import_assertions.py', 'tests/build_probes.py', 'tests/result_validation.py']
    receipt = {'repositoryHead': runtime.git_output(['rev-parse', 'HEAD'], ROOT).strip(),
               'uncommittedInputs': True, 'inputs': {name: runtime.sha(ROOT / name) for name in inputs},
               'baselineManifestSha256': runtime.sha(baseline / 'nndsk-runtime.json'),
               'sourceBefore': historical, 'sourceAfter': patched, 'profile': p}
    runtime.save(output / 'source-receipt.json', receipt)
    identified = copy.deepcopy(identity)
    # sourceCommit stays the inherited historical base, not a false assertion
    # that the new patch was committed. The new inputs are identified separately.
    identified.update(version=p['version'], publicationReady=False, quality='experimental',
                      patchsetRevision=2, experimentalSource=receipt)
    for key in ('acceptedArchiveSha256', 'packagingCommit', 'packagingRevision'):
        identified.pop(key, None)
    for name in p['overlayModules']:
        identified['modifiedModules'][name] = after[name]
    manifest = candidate / 'nndsk-runtime.json'
    manifest.chmod(manifest.stat().st_mode | 0o200)
    with manifest.open('w') as stream:  # only this newly-owned copy may be rewritten
        json.dump(identified, stream, indent=2, sort_keys=True)
        stream.write('\n')
    runtime.save(output / 'candidate-inventory.json', runtime.inventory(candidate))
    print(json.dumps({'candidate': str(candidate), 'publicationReady': False}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--wine-cache', type=Path, default=ROOT / 'work/wine')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 32:
        parser.error('--jobs must be 1..32')
    args.wine_cache = args.wine_cache.resolve()
    build(args)


if __name__ == '__main__':
    main()
