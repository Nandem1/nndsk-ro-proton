# SPDX-License-Identifier: LGPL-2.1-or-later
"""Local exact modified-Wine/recipe source snapshot; not full Proton source clearance."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ('Modified Wine and the committed preservation recipe only. Inherited '
         'Proton/third-party binary sources are NOT complete. Local-only snapshot; '
         'not legal clearance, publication authorization or full-runtime corresponding source.')


def environment(epoch=None):
    env = os.environ.copy()
    for key in list(env):
        if key.startswith(('GIT_', 'LD_', 'APPIMAGE', 'APPDIR', 'ZSTD_', 'WINE',
                           'PROTON_', 'STEAM_COMPAT_')) or key in (
                'TAR_OPTIONS', 'GZIP', 'XZ_OPT', 'XZ_DEFAULTS', 'BZIP2'):
            env.pop(key)
    env.update(LC_ALL='C', TZ='UTC', PYTHONDONTWRITEBYTECODE='1')
    if epoch is not None:
        env['SOURCE_DATE_EPOCH'] = str(epoch)
    return env


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def git(repo, args):
    return subprocess.check_output(['git', *args], cwd=repo, env=environment())


def commit_id(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{40}', value):
        raise ValueError('Expected full lowercase Git commit identity')
    return value


def validate_identity(manifest, lock):
    commit_id(manifest['sourceCommit'])
    for field in ('runtimeId', 'version', 'patchsetRevision', 'sourceDateEpoch'):
        if manifest[field] != lock[field]:
            raise RuntimeError('Artifact/recipe identity mismatch: ' + field)
    if manifest['upstream'] != {'proton': lock['proton'], 'wine': lock['wine']}:
        raise RuntimeError('Artifact/recipe upstream identity mismatch')
    if manifest['buildMethod'] != lock['method']:
        raise RuntimeError('Artifact build method differs from recipe')
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]*', manifest['version']):
        raise RuntimeError('Unsafe artifact version')
    filename = manifest['artifact']['filename']
    if Path(filename).name != filename or filename in ('', '.', '..'):
        raise RuntimeError('Unsafe binary artifact filename')


def tree_entries(repo, commit):
    entries = {}
    for record in git(repo, ['ls-tree', '-r', '-z', commit]).split(b'\0'):
        if not record:
            continue
        header, path = record.split(b'\t', 1)
        mode, kind, object_id = header.decode('ascii').split()
        if kind != 'blob' or mode not in ('100644', '100755', '120000'):
            raise RuntimeError('Source snapshot has unsupported gitlink/type')
        name = os.fsdecode(path)
        if PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts:
            raise RuntimeError('Unsafe Git source path')
        entries[name] = {'mode': mode, 'object': object_id}
    return entries


def validate_members(members, prefix):
    names = {}
    for member in members:
        path = PurePosixPath(member.name)
        name = path.as_posix()
        if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != prefix:
            raise RuntimeError('Unsafe source archive path')
        if name in names:
            raise RuntimeError('Duplicate normalized source member')
        if not (member.isdir() or member.isfile() or member.issym()):
            raise RuntimeError('Unexpected source archive type')
        names[name] = member
    for name, member in names.items():
        for ancestor in PurePosixPath(name).parents:
            prior = names.get(ancestor.as_posix())
            if prior is not None and not prior.isdir():
                raise RuntimeError('Source archive traverses non-directory')


def blob_identity(path):
    if path.is_symlink():
        data = os.fsencode(os.readlink(path))
        return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(), '120000'
    length = path.stat().st_size
    h = hashlib.sha1(b'blob ' + str(length).encode() + b'\0')
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest(), '100755' if path.stat().st_mode & 0o111 else '100644'


def file_entries(root):
    entries = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            if path.is_symlink() or path.is_file():
                object_id, mode = blob_identity(path)
                entries[path.relative_to(root).as_posix()] = {'mode': mode, 'object': object_id}
            elif not path.is_dir():
                raise RuntimeError('Unexpected source filesystem type')
    return entries


def export_commit(repo, commit, directory, name, scratch):
    commit = commit_id(commit)
    if git(repo, ['cat-file', '-t', commit]).strip() != b'commit':
        raise RuntimeError('Source identity is not a commit object')
    expected = tree_entries(repo, commit)
    archive = scratch / (name + '-git-archive.tar')
    with archive.open('xb') as stream:
        subprocess.run(['git', 'archive', '--format=tar', '--prefix=' + name + '/', commit],
                       cwd=repo, env=environment(), stdout=stream, check=True)
    with tarfile.open(archive, 'r:') as tar:
        validate_members(list(tar), name)
        tar.extractall(directory, filter='data')
    exported = directory / name
    if file_entries(exported) != expected:
        raise RuntimeError('git archive differs from complete committed tree (attributes/source gap)')
    return expected


def apply_patches(wine, recipe, lock, wine_git):
    if (recipe / 'patches/series').read_text().splitlines() != [Path(p['path']).name for p in lock['patches']]:
        raise RuntimeError('Behavior patch series differs from locked order')
    if len(lock['patches']) != 3:
        raise RuntimeError('Expected exactly three behavior patches')
    for record in lock['patches']:
        patch = recipe / record['path']
        if sha(patch) != record['sha256']:
            raise RuntimeError('Locked behavior patch changed')
        # Explicit Git directory/worktree avoid ancestor repository discovery;
        # without --index/--cached, apply modifies only the exported source.
        command = ['git', '--git-dir=' + str(wine_git), '--work-tree=' + str(wine), 'apply']
        for options in (['--check'], []):
            subprocess.run([*command, *options, str(patch)], cwd=wine,
                           env=environment(), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def verify_modified_source(wine, base_entries, expected):
    if len(expected) != 10:
        raise RuntimeError('Expected the ten validated source files')
    final = file_entries(wine)
    changes = {name for name in base_entries.keys() | final.keys()
               if base_entries.get(name) != final.get(name)}
    if changes != expected.keys():
        raise RuntimeError('Modified Wine tree has unrelated/missing changes: ' + repr(changes))
    for name, record in expected.items():
        if record['upstreamGitBlob'] != (base_entries.get(name) or {}).get('object'):
            raise RuntimeError('Wrong upstream source blob: ' + name)
        if sha(wine / name) != record['candidateSha256']:
            raise RuntimeError('Validated final source mismatch: ' + name)
    return final


def inventory(root):
    records = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            key = path.relative_to(root).as_posix()
            if path.is_symlink():
                records[key] = {'link': os.readlink(path)}
            elif path.is_file():
                records[key] = {'sha256': sha(path), 'size': path.stat().st_size,
                                'mode': path.stat().st_mode & 0o7777}
            elif path.is_dir():
                records[key] = {'directory': True, 'mode': path.stat().st_mode & 0o7777}
            else:
                raise RuntimeError('Unexpected source bundle filesystem type')
    return records


def pack(source, target, epoch):
    env = environment(epoch)
    process = subprocess.Popen(['tar', '--sort=name', '--format=gnu', '--mtime=@' + str(epoch),
        '--owner=0', '--group=0', '--numeric-owner', '-cf', '-', '-C', str(source.parent), source.name],
        env=env, stdout=subprocess.PIPE)
    try:
        with target.open('xb') as stream:
            result = subprocess.run(['zstd', '-q', '-T1', '-19', '-c'], env=env,
                                    stdin=process.stdout, stdout=stream)
        process.stdout.close()
        if process.wait() or result.returncode:
            raise RuntimeError('Source bundle packaging failed')
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait()


def verify_archive(archive, root, expected, epoch):
    records = {}
    process = subprocess.Popen(['zstd', '-q', '-d', '-c', str(archive)], env=environment(epoch),
                               stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|') as tar:
            for member in tar:
                path = PurePosixPath(member.name)
                if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != root:
                    raise RuntimeError('Unsafe packaged source path')
                if member.uid or member.gid or member.mtime != epoch:
                    raise RuntimeError('Noncanonical packaged source metadata')
                name = path.relative_to(root).as_posix()
                if name == '.':
                    if not member.isdir():
                        raise RuntimeError('Source root is not a directory')
                    continue
                if name in records:
                    raise RuntimeError('Duplicate packaged source member')
                if member.isdir():
                    records[name] = {'directory': True, 'mode': member.mode}
                elif member.issym():
                    records[name] = {'link': member.linkname}
                elif member.isfile():
                    h = hashlib.sha256()
                    with tar.extractfile(member) as stream:
                        for block in iter(lambda: stream.read(1048576), b''):
                            h.update(block)
                    records[name] = {'sha256': h.hexdigest(), 'size': member.size, 'mode': member.mode}
                else:
                    raise RuntimeError('Unexpected packaged source type')
        process.stdout.close()
        if process.wait():
            raise RuntimeError('Source bundle decompression failed')
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait()
    if records != expected:
        raise RuntimeError('Source archive differs from verified snapshot')


def build_bundle(manifest_path, wine_cache, scratch, output):
    if manifest_path.resolve() != ROOT / 'dist/manifest.json':
        raise RuntimeError('Use the identified local dist/manifest.json, not an arbitrary manifest')
    manifest = json.loads(manifest_path.read_text())
    source_commit = commit_id(manifest['sourceCommit'])
    lock = json.loads(git(ROOT, ['show', source_commit + ':upstream.lock.json']))
    validate_identity(manifest, lock)
    binary = manifest_path.parent / manifest['artifact']['filename']
    if binary.stat().st_size != manifest['artifact']['size'] or sha(binary) != manifest['artifact']['sha256']:
        raise RuntimeError('Binary artifact does not match its manifest')
    head = git(wine_cache, ['rev-parse', 'HEAD']).decode().strip()
    if head != lock['wine']['commit']:
        raise RuntimeError('Wine cache HEAD is not the artifact upstream base')
    wine_git = Path(git(wine_cache, ['rev-parse', '--absolute-git-dir']).decode().strip())
    scratch = scratch.resolve()
    if not scratch.is_relative_to(ROOT / 'work') or scratch == ROOT / 'work':
        raise RuntimeError('Scratch must be a new child of project work/')
    if output.resolve() != ROOT / 'dist/source':
        raise RuntimeError('Source outputs must live in project dist/source/')
    if scratch.exists() or output.exists():
        raise RuntimeError('Refusing to overwrite source custody/output')
    scratch.mkdir(mode=0o700, parents=True)
    name = 'nndsk-ro-proton-' + manifest['version'] + '-source'
    stage = scratch / name
    stage.mkdir(mode=0o755)
    recipe_base = export_commit(ROOT, source_commit, stage, 'recipe', scratch)
    wine_base = export_commit(wine_cache, lock['wine']['commit'], stage, 'wine', scratch)
    recipe = stage / 'recipe'
    wine = stage / 'wine'
    apply_patches(wine, recipe, lock, wine_git)
    expected = json.loads((recipe / 'provenance/validated-source.json').read_text())
    final_wine = verify_modified_source(wine, wine_base, expected)
    if file_entries(recipe) != recipe_base:
        raise RuntimeError('Committed recipe changed during source reconstruction')
    details = {'schemaVersion': 1, 'runtimeId': manifest['runtimeId'], 'version': manifest['version'],
        'sourceCommit': source_commit, 'upstreamWine': lock['wine'], 'patchsetRevision': lock['patchsetRevision'],
        'sourceDateEpoch': lock['sourceDateEpoch'], 'binaryArtifact': manifest['artifact'],
        'binaryManifestSha256': sha(manifest_path), 'scope': SCOPE,
        'localOnly': True, 'publicationReady': False, 'fullRuntimeSourceComplete': False,
        'licenseSourceAuditComplete': False, 'wineTreeFromGitArchive': True,
        'recipeTreeFromGitArchive': True, 'functionalSourceFilesVerified': expected,
        'behaviorPatchesApplied': lock['patches'], 'testOnlyPatchesApplied': False,
        'generatedBuildTreeCopied': False, 'wineFiles': len(final_wine), 'recipeFiles': len(recipe_base)}
    (stage / 'SOURCE-SCOPE.md').write_text('# Local source scope\n\n' + SCOPE + '\n', encoding='utf-8')
    save(stage / 'source-manifest.json', details)
    save(scratch / 'source-inventory.json', inventory(stage))
    output.mkdir(mode=0o700)
    archive = output / (name + '.tar.zst')
    pack(stage, archive, lock['sourceDateEpoch'])
    repeat = scratch / (name + '-repeat.tar.zst')
    pack(stage, repeat, lock['sourceDateEpoch'])
    if sha(archive) != sha(repeat):
        raise RuntimeError('Source packaging is not deterministic')
    verify_archive(archive, name, inventory(stage), lock['sourceDateEpoch'])
    details.update(sourceArtifact={'filename': archive.name, 'sha256': sha(archive),
                  'size': archive.stat().st_size, 'format': 'tar.zst', 'root': name},
                  packagingDeterminismVerified=True, packagedContentVerified=True)
    save(output / 'source-manifest.json', details)
    with (output / 'SHA256SUMS').open('x') as stream:
        for item in (archive, output / 'source-manifest.json'):
            stream.write(sha(item) + '  ' + item.name + '\n')
    print(json.dumps(details['sourceArtifact'], indent=2), flush=True)


def main():
    os.umask(0o022)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wine-cache', type=Path, default=ROOT / 'work/wine')
    parser.add_argument('--scratch', type=Path, default=ROOT / 'work/source-bundle-01')
    args = parser.parse_args()
    build_bundle(ROOT / 'dist/manifest.json', args.wine_cache.resolve(), args.scratch, ROOT / 'dist/source')


if __name__ == '__main__':
    main()
