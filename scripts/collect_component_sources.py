#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Collect pinned source archives and notices; never mark an audit complete."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import stat
import tarfile
import zipfile
import tomllib
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'work' / 'publication-sources-20261008'
NOTICE_NAME = r'^(LICENSE|LICENCE|COPYING|COPYRIGHT|NOTICE|PATENTS|THIRD.?PARTY.*NOTICE)'


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def archive_url(repository, commit):
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('A complete commit identity is required')
    url = urlsplit(repository)
    if url.scheme != 'https' or url.username or url.password or url.query or url.fragment:
        raise ValueError('An uncredentialed HTTPS repository URL is required')
    project = url.path.strip('/').removesuffix('.git')
    if not project or '..' in PurePosixPath(project).parts:
        raise ValueError('Unsafe repository path')
    if url.netloc == 'github.com':
        return f'https://codeload.github.com/{project}/tar.gz/{commit}'
    if url.netloc in ('gitlab.winehq.org', 'gitlab.freedesktop.org', 'gitlab.com'):
        name = project.rsplit('/', 1)[-1]
        return f'https://{url.netloc}/{project}/-/archive/{commit}/{name}-{commit}.tar.gz'
    raise ValueError('Unsupported source host')


def notices(archive):
    """Read notices only; do not extract symlinks, execute or modify source."""
    records = {}
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zipped:
            for member in zipped.infolist():
                path = PurePosixPath(member.filename)
                if path.is_absolute() or '..' in path.parts:
                    raise ValueError('Unsafe source archive path')
                if member.is_dir() or stat.S_ISLNK(member.external_attr >> 16) or member.file_size > 2 * 1048576:
                    continue
                if re.search(NOTICE_NAME, path.name, re.I):
                    data = zipped.read(member)
                    records[member.filename] = {'sha256': hashlib.sha256(data).hexdigest(),
                        'size': len(data), 'text': data.decode('utf-8', errors='replace')}
        return records
    with tarfile.open(archive, 'r:*') as tar:
        for member in tar:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('Unsafe source archive path')
            if not member.isfile() or member.size > 2 * 1048576:
                continue
            if not re.search(NOTICE_NAME, path.name, re.I):
                continue
            stream = tar.extractfile(member)
            data = stream.read()
            records[member.name] = {
                'sha256': hashlib.sha256(data).hexdigest(),
                'size': len(data),
                'text': data.decode('utf-8', errors='replace'),
            }
    return records


def collect(component):
    name = component['path'].replace('/', '--')
    if not re.fullmatch('[A-Za-z0-9.+_-]+', name):
        raise ValueError('Unsafe component identity')
    commit = component.get('commit')
    url = archive_url(component['repository'], commit) if commit else component['url']
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.username or parsed.password:
        raise ValueError('An uncredentialed HTTPS source URL is required')
    archive = OUTPUT / (f'{name}-{commit}.tar.gz' if commit else component['filename'])
    if archive.parent != OUTPUT:
        raise ValueError('Unsafe source output path')
    receipt = OUTPUT / f'{name}.json'
    if receipt.exists():
        record = json.loads(receipt.read_text())
        archive = OUTPUT / record['filename']
        if archive.parent != OUTPUT:
            raise ValueError('Unsafe receipt filename')
        if record['url'] != url or digest(archive) != record['sha256'] or (
                component.get('sha256') and record['sha256'] != component['sha256']):
            raise ValueError('Existing source custody mismatch: ' + name)
        print(name + ': reused verified archive', flush=True)
        return
    if archive.exists():
        # Failed zero-length transfers are evidence, not a reusable download.
        # Preserve them and retry under a new exclusive filename.
        if archive.is_symlink() or archive.stat().st_size:
            raise ValueError('Unverified output already exists: ' + name)
        archive = archive.with_name(archive.name + '.retry-1')
        if archive.exists():
            raise ValueError('Unverified retry already exists: ' + name)
    try:
        with archive.open('xb') as output:
            subprocess.run(['curl', '--disable', '--fail', '--silent', '--show-error', '--location',
                '--proto', '=https', '--proto-redir', '=https', '--connect-timeout', '15',
                '--max-time', '480', url], stdout=output, check=True)
        checksum = digest(archive)
        if component.get('sha256') and checksum != component['sha256']:
            raise ValueError('Pinned source checksum mismatch')
        record = {'component': component['path'], 'repository': component.get('repository'),
            'commit': commit, 'url': url, 'filename': archive.name,
            'sha256': checksum, 'size': archive.stat().st_size,
            'notices': notices(archive), 'licenseReviewComplete': False}
        with receipt.open('x') as stream:
            json.dump(record, stream, indent=2, sort_keys=True)
            stream.write('\n')
        print(name + ': preserved source + ' + str(len(record['notices'])) + ' notices', flush=True)
    except Exception:
        # Preserve failed owned downloads for inspection; never overwrite/reuse them.
        print(name + ': FAILED, owned output preserved', flush=True)
        raise


def rust_dependencies(archives):
    packages = {}
    for archive in archives:
        with tarfile.open(archive, 'r:*') as tar:
            for member in tar:
                if not member.isfile() or not member.name.endswith('/Cargo.lock'):
                    continue
                lock = tomllib.loads(tar.extractfile(member).read().decode('utf-8'))
                for package in lock.get('package', []):
                    source = package.get('source', '')
                    if not source:
                        continue
                    if source.startswith('git+'):
                        parsed = urlsplit(source[4:])
                        commit = parsed.fragment
                        repository = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
                        # Validate the immutable commit, not the branch/tag selector.
                        archive_url(repository, commit)
                        selector = parse_qs(parsed.query)
                        if set(selector) - {'branch', 'tag', 'rev'}:
                            raise ValueError('Unrecognized Rust git selector')
                        project = parsed.path.strip('/').removesuffix('.git').replace('/', '--')
                        identity = ('git', repository, commit)
                        packages[identity] = {'path': 'rust-git/' + project,
                            'repository': repository, 'commit': commit}
                        continue
                    if source != 'registry+https://github.com/rust-lang/crates.io-index':
                        raise ValueError('Non-registry Rust dependency requires individual review: ' + source)
                    name, version, checksum = package['name'], package['version'], package['checksum']
                    if not re.fullmatch('[A-Za-z0-9_-]+', name) or not re.fullmatch('[A-Za-z0-9.+_-]+', version):
                        raise ValueError('Unsafe Rust package identity')
                    if not re.fullmatch('[0-9a-f]{64}', checksum):
                        raise ValueError('Rust dependency must have a full checksum')
                    identity = (name, version)
                    if identity in packages and packages[identity]['sha256'] != checksum:
                        raise ValueError('Conflicting Rust dependency checksum')
                    packages[identity] = {'path': 'rust-crate/' + name + '-' + version,
                        'url': f'https://static.crates.io/crates/{name}/{name}-{version}.crate',
                        'filename': f'{name}-{version}.crate', 'sha256': checksum}
    return list(packages.values())


def nuget_dependencies():
    """Preserve Xalia's actual package references and immutable dependency archives."""
    pending = [('Superpower', '3.1.0'), ('System.Management', '10.0.7'),
        ('System.Security.Principal.Windows', '5.0.0'),
        ('System.Threading.Tasks.Extensions', '4.6.3'), ('Tmds.DBus.Protocol', '0.92.0')]
    seen = set()
    while pending:
        name, version = pending.pop(0)
        identity = (name.lower(), version)
        if identity in seen:
            continue
        if not re.fullmatch('[A-Za-z0-9._-]+', name) or not re.fullmatch('[0-9A-Za-z.+_-]+', version):
            raise ValueError('Unsafe NuGet identity')
        seen.add(identity)
        filename = f'{name.lower()}.{version.lower()}.nupkg'
        component = {'path': 'nuget/' + name + '-' + version,
            'url': f'https://api.nuget.org/v3-flatcontainer/{name.lower()}/{version.lower()}/{filename}',
            'filename': filename}
        collect(component)
        receipt = json.loads((OUTPUT / (component['path'].replace('/', '--') + '.json')).read_text())
        with zipfile.ZipFile(OUTPUT / receipt['filename']) as zipped:
            spec_names = [n for n in zipped.namelist() if n.endswith('.nuspec')]
            if len(spec_names) != 1:
                raise ValueError('Ambiguous NuGet metadata')
            spec = ET.fromstring(zipped.read(spec_names[0]))
            for dep in spec.iter():
                if dep.tag.rsplit('}', 1)[-1] != 'dependency':
                    continue
                constraint = dep.attrib['version']
                minimum = constraint.strip('[]()').split(',')[0].strip()
                if not minimum:
                    raise ValueError('Unbounded NuGet dependency requires review')
                pending.append((dep.attrib['id'], minimum))
    print(json.dumps({'nugetPackages': len(seen)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--components', nargs='*')
    parser.add_argument('--extras-only', action='store_true')
    parser.add_argument('--rust-locks', action='store_true')
    parser.add_argument('--nuget-xalia', action='store_true')
    parser.add_argument('--publication-lock', action='store_true')
    parser.add_argument('--jobs', type=int, default=4, choices=range(1, 9))
    args = parser.parse_args()
    OUTPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if OUTPUT.is_symlink():
        raise ValueError('Output must not be a symlink')
    if args.nuget_xalia:
        nuget_dependencies()
        return
    components = json.loads((ROOT / 'provenance/proton-components.json').read_text())['components']
    if args.extras_only:
        components = json.loads((ROOT / 'provenance/publication-extra-sources.json').read_text())['sources']
    if args.rust_locks:
        components = rust_dependencies([
            OUTPUT / 'zenity-rs-c395e32892b823f79b049f1397cd86a2ea87827b.tar.gz',
            OUTPUT / 'gst-plugins-rs-1d52139e35dd66ce6038aad05ca5cd6059df900d.tar.gz'])
    if args.publication_lock:
        components = [{**item, 'path': item['component'], 'url': item['url']}
            for item in json.loads((ROOT / 'provenance/publication-source-lock.json').read_text())['sources']]
    components = [item for item in components if item['path'] != 'wine']
    if args.components is not None:
        names = set(args.components)
        if names - {item['path'] for item in components}:
            raise ValueError('Unknown component')
        components = [item for item in components if item['path'] in names]
    failures = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [(item['path'], pool.submit(collect, item)) for item in components]
        for name, future in futures:
            try:
                future.result()
            except Exception as error:
                failures.append({'component': name, 'error': str(error)})
    print(json.dumps({'attempted': len(components), 'failed': failures}, indent=2), flush=True)
    if failures:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
