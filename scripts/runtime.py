"""Pinned source-module preservation build. No prefixes or game files touched."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'work'
LOCK = json.loads((ROOT / 'upstream.lock.json').read_text())
ARCHS = ('i386', 'x86_64')
DISABLED = ['--without-x', '--without-wayland', '--without-gstreamer',
            '--without-ffmpeg', '--without-pipewire', '--without-vulkan',
            '--without-opengl', '--without-vkd3d']

def sha(path, algorithm='sha256'):
    h = hashlib.new(algorithm)
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1048576), b''):
            h.update(block)
    return h.hexdigest()

def save(path, data):
    with path.open('x') as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write('\n')

def environment():
    env = os.environ.copy()
    for key in list(env):
        if key.startswith(('APPIMAGE', 'APPDIR', 'LD_', 'WINE', 'PROTON_', 'STEAM_COMPAT_', 'GIT_', 'ZSTD_')) or key in (
                'CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'MAKEFLAGS',
                'CONFIG_SITE', 'PKG_CONFIG_PATH', 'PKG_CONFIG_LIBDIR', 'PKG_CONFIG_SYSROOT_DIR',
                'TAR_OPTIONS', 'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH',
                'COMPILER_PATH', 'GCC_EXEC_PREFIX', 'GZIP', 'XZ_OPT', 'XZ_DEFAULTS', 'BZIP2',
                'ARFLAGS', 'AR', 'AS', 'LD', 'NM', 'RANLIB', 'OBJCFLAGS'):
            env.pop(key)
    env.update(SOURCE_DATE_EPOCH=str(LOCK['sourceDateEpoch']), LC_ALL='C', TZ='UTC')
    return env

def git_output(args, cwd):
    """Never let an inherited GIT_DIR/GIT_WORK_TREE redirect identity checks."""
    return subprocess.check_output(['git', *args], cwd=cwd, env=environment(), text=True)

def run(args, cwd, label, env=None):
    logdir = WORK / 'logs'
    logdir.mkdir(parents=True, exist_ok=True)
    save(logdir / (label + '.command.json'), {'argv': [str(a) for a in args], 'cwd': str(cwd)})
    print(label, flush=True)
    with (logdir / (label + '.log')).open('xb') as log:
        p = subprocess.run([str(a) for a in args], cwd=cwd, env=env or environment(),
                           stdout=log, stderr=subprocess.STDOUT)
    save(logdir / (label + '.result.json'), {'exitStatus': p.returncode})
    if p.returncode:
        print('\n'.join((logdir / (label + '.log')).read_text(errors='replace').splitlines()[-20:]))
        raise RuntimeError(label + ' failed, evidence preserved')

def check_inputs():
    series = (ROOT / 'patches/series').read_text().splitlines()
    assert series == [Path(x['path']).name for x in LOCK['patches']]
    for record in LOCK['patches'] + LOCK['generatorInputs'] + LOCK.get('testOnlyPatches', []):
        if sha(ROOT / record['path']) != record['sha256']:
            raise RuntimeError('Locked input mismatch: ' + record['path'])

def inventory(root, exclude=()):
    out = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in exclude]
        for name in sorted(dirs + files):
            p = Path(directory) / name
            rel = p.relative_to(root).as_posix()
            if p.is_symlink():
                out[rel] = {'link': os.readlink(p)}
            elif p.is_file():
                out[rel] = {'sha256': sha(p), 'size': p.stat().st_size,
                            'mode': p.stat().st_mode & 0o7777}
            elif p.is_dir():
                out[rel] = {'directory': True, 'mode': p.stat().st_mode & 0o7777}
            else:
                raise RuntimeError('Unexpected filesystem object: ' + str(p))
    return out

def verify_source():
    source = WORK / 'wine'
    head = git_output(['rev-parse', 'HEAD'], source).strip()
    if head != LOCK['wine']['commit']:
        raise RuntimeError('Source HEAD changed')
    expected = json.loads((ROOT / 'provenance/validated-source.json').read_text())
    for name, record in expected.items():
        if sha(source / name) != record['candidateSha256']:
            raise RuntimeError('Functional source changed: ' + name)
    changed = set(git_output(['diff', 'HEAD', '--name-only'], source).splitlines())
    extras = changed - expected.keys()
    for name in extras:
        if name not in LOCK['testSourceSha256'] or sha(source / name) != LOCK['testSourceSha256'][name]:
            raise RuntimeError('Unreviewed source change: ' + name)

def built_modules():
    paths = []
    for arch in ARCHS:
        paths.extend(WORK / f'build-pe/dlls/{module}/{arch}-windows/{module}.dll' for module in ('crypt32', 'ncrypt'))
        paths.append(WORK / ('build-unix-' + arch) / 'dlls/ntdll/ntdll.so')
    return {p.relative_to(WORK).as_posix(): {'sha256': sha(p), 'size': p.stat().st_size} for p in paths}

def seal_build(args):
    verify_source()
    for label in ('build-pe', 'build-unix-i386', 'build-unix-x86_64'):
        if json.loads((WORK / 'logs' / (label + '.result.json')).read_text())['exitStatus']:
            raise RuntimeError('Build did not succeed: ' + label)
    save(WORK / 'build-seal.json', {'modules': built_modules(),
         'source': inventory(WORK / 'wine', exclude=('.git', 'autom4te.cache'))})

def verify_build_seal():
    verify_source()
    seal = json.loads((WORK / 'build-seal.json').read_text())
    if built_modules() != seal['modules']:
        raise RuntimeError('Built module changed after compilation')
    current = inventory(WORK / 'wine', exclude=('.git', 'autom4te.cache'))
    for name, expected in LOCK['testSourceSha256'].items():
        if name in current and current[name].get('sha256') == expected:
            current[name] = seal['source'][name]
    if current != seal['source']:
        raise RuntimeError('Source changed after build sealing')

def validate_archive_members(members):
    names = {}
    root = LOCK['binaryBase']['root']
    for member in members:
        p = Path(member.name)
        if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0] != root:
            raise RuntimeError('Unexpected archive path: ' + member.name)
        canonical = p.as_posix().rstrip('/')
        if canonical in names:
            raise RuntimeError('Duplicate archive member')
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise RuntimeError('Unexpected archive object type')
        names[canonical] = member
    for member in names.values():
        for ancestor in Path(member.name).parents:
            previous = names.get(ancestor.as_posix())
            if previous and (previous.issym() or previous.islnk()):
                raise RuntimeError('Archive member traverses link: ' + member.name)
        if member.islnk():
            target = Path(member.linkname)
            original = names.get(target.as_posix())
            if target.is_absolute() or '..' in target.parts or not original or not original.isfile():
                raise RuntimeError('Unsafe archive hardlink')
    # Absolute leaf template symlinks (e.g. Wine dosdevices/z:) are preserved,
    # but no member may traverse any link when extracting a verified archive.

def verify_base():
    current = inventory(WORK / 'base' / LOCK['binaryBase']['root'])
    reference = json.loads((WORK / 'base-inventory.json').read_text())
    # Older first-run snapshot recorded files/links only; require those exact
    # bytes, no extra files, and also compare directory metadata in new snapshots.
    if not any('directory' in info for info in reference.values()):
        current = {n: info for n, info in current.items() if 'directory' not in info}
    if current != reference:
        raise RuntimeError('Extracted official base changed after checksum verification')

def prepare(args):
    check_inputs()
    WORK.mkdir(exist_ok=True)
    source = WORK / 'wine'
    if source.exists():
        raise RuntimeError('Refusing to reuse source worktree; preserve prior outputs')
    origin = args.wine_cache or LOCK['wine']['repository']
    run(['git', 'clone', '--no-hardlinks', '--no-checkout', origin, source], ROOT, 'clone-wine')
    run(['git', 'checkout', '--detach', LOCK['wine']['commit']], source, 'checkout-wine')
    for n, patch in enumerate(LOCK['patches'], 1):
        run(['git', 'apply', '--check', ROOT / patch['path']], source, f'check-patch-{n}')
        run(['git', 'apply', ROOT / patch['path']], source, f'apply-patch-{n}')
    expected = json.loads((ROOT / 'provenance/validated-source.json').read_text())
    for name, info in expected.items():
        if sha(source / name) != info['candidateSha256']:
            raise RuntimeError('Source does not reproduce validated bytes: ' + name)
    save(WORK / 'source-verified.json', {'wineCommit': LOCK['wine']['commit'],
         'functionalSources': expected, 'verified': True})
    download = WORK / 'downloads'
    download.mkdir(exist_ok=True)
    archive = Path(args.base_archive).resolve() if args.base_archive else download / LOCK['binaryBase']['filename']
    if not archive.exists():
        run(['curl', '--fail', '--location', '--retry', '3', '--output', archive,
             LOCK['binaryBase']['url']], ROOT, 'download-base')
    if (sha(archive, 'sha512') != LOCK['binaryBase']['sha512'] or
            sha(archive) != LOCK['binaryBase']['sha256']):
        raise RuntimeError('Base archive checksum mismatch; no extraction')
    save(WORK / 'base-archive.json', {'sha256': sha(archive), 'sha512': sha(archive, 'sha512'),
         'size': archive.stat().st_size, 'url': LOCK['binaryBase']['url']})
    base_dir = WORK / 'base'
    base_dir.mkdir(exist_ok=False)
    with tarfile.open(archive, 'r:xz') as tar:
        validate_archive_members(list(tar))
    # GNU tar preserves the official template symlinks. Source archive is pinned
    # and fully verified above; path/type validation precedes extraction.
    run(['tar', '--extract', '--xz', '--file', archive, '--directory', base_dir,
         '--no-same-owner', '--no-same-permissions'], ROOT, 'extract-base')
    save(WORK / 'base-inventory.json', inventory(base_dir / LOCK['binaryBase']['root']))
    print('Source and official binary base verified', flush=True)

def build(args):
    check_inputs()
    verify_source()
    verify_base()
    source = WORK / 'wine'
    for command, name in ((['autoconf'], 'autoconf'), (['autoheader'], 'autoheader'),
                          (['tools/make_requests'], 'generate-requests'),
                          (['tools/make_specfiles'], 'generate-specs')):
        run(command, source, name)
    run(['./make_vulkan', '-x', ROOT / 'vendor/vulkan/vk.xml', '-X', ROOT / 'vendor/vulkan/video.xml'],
        source / 'dlls/winevulkan', 'generate-vulkan')
    toolchain = {}
    for tool in ('gcc', 'clang', 'lld-link', 'llvm-strip', 'autoconf', 'make', 'tar', 'zstd'):
        path = Path(shutil.which(tool)).resolve()
        toolchain[tool] = {'path': str(path), 'sha256': sha(path),
                          'version': subprocess.check_output([tool, '--version'], env=environment(),
                                     stderr=subprocess.STDOUT, text=True).splitlines()[0]}
    save(WORK / 'toolchain.json', toolchain)
    pe = WORK / 'build-pe'
    pe.mkdir(exist_ok=False)
    run([source / 'configure', '--enable-win64', '--enable-archs=i386,x86_64',
         '--with-mingw=clang', *DISABLED], pe, 'configure-pe')
    targets = []
    for arch in ARCHS:
        targets.extend([f'dlls/{module}/{arch}-windows/{module}.dll' for module in ('crypt32', 'ncrypt')])
        targets.extend([f'dlls/{module}/tests/{arch}-windows/{module}_test.exe' for module in ('crypt32', 'ncrypt')])
    run(['make', '-j' + str(args.jobs), *targets], pe, 'build-pe')
    for arch in ('x86_64', 'i386'):
        directory = WORK / ('build-unix-' + arch)
        directory.mkdir(exist_ok=False)
        options = ['--enable-win64'] if arch == 'x86_64' else ['--with-wine64=' + str(WORK / 'build-unix-x86_64')]
        run([source / 'configure', '--without-unwind', '--with-mingw=clang', *DISABLED,
             'CFLAGS=-g -O2 -std=gnu17', *options], directory, 'configure-unix-' + arch)
        run(['make', '-j' + str(args.jobs), 'dlls/ntdll/ntdll.so'], directory, 'build-unix-' + arch)
    print('Fresh module build complete; no runtime registered', flush=True)
    seal_build(args)

def build_tests(args):
    check_inputs()
    verify_build_seal()
    source = WORK / 'wine'
    for n, patch in enumerate(LOCK.get('testOnlyPatches', []), 1):
        run(['git', 'apply', '--check', ROOT / patch['path']], source, f'check-test-patch-{n}')
        run(['git', 'apply', ROOT / patch['path']], source, f'apply-test-patch-{n}')
    targets = [f'dlls/kernel32/tests/{arch}-windows/kernel32_test.exe' for arch in ARCHS]
    run(['make', '-j' + str(args.jobs), *targets], WORK / 'build-pe', 'build-kernel32-tests')
    verify_build_seal()

def stage(args):
    check_inputs()
    verify_build_seal()
    verify_base()
    dest = WORK / 'stage/nndsk-ro-proton'
    dest.parent.mkdir(exist_ok=True)
    if dest.exists():
        raise RuntimeError('Refusing to overwrite staged runtime')
    base = WORK / 'base' / LOCK['binaryBase']['root']
    run(['cp', '--reflink=auto', '-a', base, dest], ROOT, 'stage-base')
    allowed = set()
    for arch in ARCHS:
        for module in ('crypt32', 'ncrypt'):
            rel = f'files/lib/wine/{arch}-windows/{module}.dll'
            target = dest / rel
            assert target.is_file() and not target.is_symlink()
            mode = target.stat().st_mode & 0o7777
            os.chmod(target, mode | 0o200)
            shutil.copy2(WORK / f'build-pe/dlls/{module}/{arch}-windows/{module}.dll', target)
            subprocess.run(['llvm-strip', '--strip-debug', str(target)], check=True, env=environment())
            os.chmod(target, mode)
            allowed.add(rel)
        rel = f'files/lib/wine/{arch}-unix/ntdll.so'
        target = dest / rel
        assert target.is_file() and not target.is_symlink()
        mode = target.stat().st_mode & 0o7777
        os.chmod(target, mode | 0o200)
        shutil.copy2(WORK / ('build-unix-' + arch) / 'dlls/ntdll/ntdll.so', target)
        os.chmod(target, mode)
        allowed.add(rel)
    reference = inventory(base)
    current = inventory(dest)
    differences = {name: {'base': reference.get(name), 'candidate': current.get(name)}
                   for name in reference.keys() | current.keys() if reference.get(name) != current.get(name)}
    if set(differences) != allowed:
        raise RuntimeError('Unexpected staged module changes: ' + repr(set(differences)))
    save(WORK / 'module-differences.json', differences)
    commit = git_output(['rev-parse', 'HEAD'], ROOT).strip()
    if git_output(['status', '--porcelain'], ROOT):
        raise RuntimeError('Commit source inputs before identifying a runtime')
    identity = {'schemaVersion': 1, 'runtimeId': LOCK['runtimeId'], 'version': LOCK['version'],
                'sourceCommit': commit, 'patchsetRevision': LOCK['patchsetRevision'],
                'upstream': {'proton': LOCK['proton'], 'wine': LOCK['wine']},
                'buildMethod': LOCK['method'], 'architectures': ['PE32', 'PE64', 'i386-unix', 'x86_64-unix'],
                'entrypoints': {'proton': 'proton', 'wine': 'files/bin/wine', 'wineserver': 'files/bin/wineserver'},
                'quality': 'experimental', 'publicationReady': False,
                'requiresVerifiedDosLaunchPath': True,
                'cowRequires': ['4096-byte-host-pages', 'UFFD_WP_ASYNC', 'UFFD_WP_UNPOPULATED', 'PAGEMAP_SCAN'],
                'modifiedModules': {name: current[name] for name in sorted(allowed)},
                'sourceDateEpoch': LOCK['sourceDateEpoch']}
    save(dest / 'nndsk-runtime.json', identity)
    shutil.copytree(ROOT / 'licenses', dest / 'nndsk-LICENSES')
    save(WORK / 'stage-inventory.json', inventory(dest))
    print(dest, flush=True)

def pack_archive(stage_path, out):
    env = environment()
    tar = subprocess.Popen(['tar', '--sort=name', '--format=gnu', '--mtime=@' + str(LOCK['sourceDateEpoch']),
                            '--owner=0', '--group=0', '--numeric-owner', '-cf', '-', '-C',
                            str(stage_path.parent), stage_path.name], stdout=subprocess.PIPE, env=env)
    try:
        with out.open('xb') as f:
            compressed = subprocess.run(['zstd', '-q', '-T1', '-19', '-c'], stdin=tar.stdout, stdout=f, env=env)
        tar.stdout.close()
        tar_code = tar.wait()
        if tar_code or compressed.returncode:
            raise RuntimeError('Packaging pipeline failed')
    finally:
        if tar.poll() is None:
            tar.terminate()
            tar.wait()

def verify_packaged_archive(archive, stage_path, expected):
    records = {}
    process = subprocess.Popen(['zstd', '-q', '-d', '-c', str(archive)], stdout=subprocess.PIPE, env=environment())
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|') as tar:
            for member in tar:
                if member.uid or member.gid or member.mtime != LOCK['sourceDateEpoch']:
                    raise RuntimeError('Unexpected artifact owner/mtime')
                path = Path(member.name)
                if path.is_absolute() or '..' in path.parts or path.parts[0] != stage_path.name:
                    raise RuntimeError('Unexpected packaged path')
                name = path.relative_to(stage_path.name).as_posix()
                if name == '.':
                    continue
                if name in records:
                    raise RuntimeError('Duplicate packaged member')
                if member.issym():
                    records[name] = {'link': member.linkname}
                elif member.isdir():
                    records[name] = {'directory': True, 'mode': member.mode}
                elif member.isfile():
                    h = hashlib.sha256()
                    with tar.extractfile(member) as f:
                        for block in iter(lambda: f.read(1048576), b''):
                            h.update(block)
                    records[name] = {'sha256': h.hexdigest(), 'size': member.size, 'mode': member.mode}
                else:
                    raise RuntimeError('Unexpected packaged type')
        process.stdout.close()
        if process.wait():
            raise RuntimeError('Archive decompression failed')
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait()
    if records != expected:
        raise RuntimeError('Packaged members/bytes differ from verified staging')

def package(args):
    stage_path = WORK / 'stage/nndsk-ro-proton'
    expected = json.loads((WORK / 'stage-inventory.json').read_text())
    if inventory(stage_path) != expected:
        raise RuntimeError('Staged bytes changed since build verification')
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=False)
    name = f"nndsk-ro-proton-{LOCK['version']}-linux-x86_64.tar.zst"
    archive = dist / name
    pack_archive(stage_path, archive)
    second = WORK / ('packaging-repeat-' + name)
    pack_archive(stage_path, second)
    if sha(archive) != sha(second):
        raise RuntimeError('Packaging not deterministic')
    verify_packaged_archive(archive, stage_path, expected)
    identity = json.loads((stage_path / 'nndsk-runtime.json').read_text())
    identity.update(platform='linux-x86_64', artifact={'filename': name, 'sha256': sha(archive),
                    'size': archive.stat().st_size, 'format': 'tar.zst', 'root': stage_path.name},
                    buildDateUtc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    packagingDeterminismVerified=True, compilationBitReproducibilityVerified=False,
                    licenseSourceAuditComplete=False, validation={'newBuildGameStability': 'PENDING',
                    'newBuildLifecycle': 'PENDING', 'wine716Comparison': 'PENDING'})
    save(dist / 'manifest.json', identity)
    with (dist / 'SHA256SUMS').open('x') as f:
        for path in (archive, dist / 'manifest.json'):
            f.write(sha(path) + '  ' + path.name + '\n')
    print(json.dumps(identity['artifact'], indent=2), flush=True)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('phase', choices=['prepare', 'build', 'build-tests', 'seal-build', 'stage', 'package'])
    p.add_argument('--wine-cache')
    p.add_argument('--base-archive')
    p.add_argument('--jobs', type=int, default=4)
    a = p.parse_args()
    if not 1 <= a.jobs <= 32:
        p.error('jobs must be 1..32')
    globals()[a.phase.replace('-', '_')](a)

if __name__ == '__main__':
    main()
