# SPDX-License-Identifier: LGPL-2.1-or-later
"""Generate checksum-pinned source/notices material without changing runtime code.

Collection is not legal clearance. This command cannot authorize publication;
the maintainer review remains a separate, committed document.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile

from collect_component_sources import OUTPUT, ROOT, digest, NOTICE_NAME, notices as source_notices


def safe_name(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name:
        raise ValueError('Unsafe archive member')
    return path.as_posix()


def regular_files(archive):
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zipped:
            for member in zipped.infolist():
                name = safe_name(member.filename)
                mode = (member.external_attr >> 16) & 0o170000
                if member.is_dir() or mode == 0o120000 or member.file_size > 2 * 1048576:
                    continue
                yield name, zipped.read(member)
    else:
        with tarfile.open(archive, 'r:*') as tar:
            for member in tar:
                name = safe_name(member.name)
                if member.isfile() and member.size <= 2 * 1048576:
                    yield name, tar.extractfile(member).read()


def notice_files(archive):
    """Keep original notice bytes, package license metadata and copyright headers."""
    has_notice = bool(source_notices(archive))
    for name, data in regular_files(archive):
        leaf = PurePosixPath(name).name
        if re.search(NOTICE_NAME, leaf, re.I) or leaf in ('Cargo.toml', 'Cargo.toml.orig') or leaf.endswith('.nuspec'):
            yield name, data
        elif not has_notice and leaf.endswith(('.c', '.h', '.rs', '.py', '.cpp', '.cs', '.md', '.txt')):
            lines = data.splitlines()
            header = b'\n'.join(lines[:80])
            if re.search(br'copyright|SPDX-License-Identifier', header, re.I):
                yield name + '.copyright-header.txt', header + b'\n'


def checked_receipts():
    records = []
    for path in sorted(OUTPUT.glob('*.json')):
        record = json.loads(path.read_text())
        archive = OUTPUT / record['filename']
        if archive.parent != OUTPUT or archive.is_symlink() or not archive.is_file():
            raise ValueError('Unsafe/missing source custody')
        if digest(archive) != record['sha256'] or archive.stat().st_size != record['size']:
            raise ValueError('Source custody mismatch: ' + record['component'])
        records.append({k: v for k, v in record.items() if k not in ('notices', 'licenseReviewComplete')})
    expected = json.loads((ROOT / 'provenance/proton-components.json').read_text())['components']
    by_name = {r['component']: r for r in records}
    for item in expected:
        if item['path'] != 'wine' and by_name.get(item['path'], {}).get('commit') != item['commit']:
            raise ValueError('Missing pinned component: ' + item['path'])
    for item in json.loads((ROOT / 'provenance/publication-extra-sources.json').read_text())['sources']:
        record = by_name.get(item['path'])
        if not record or item.get('commit') != record.get('commit'):
            raise ValueError('Missing supplemental source: ' + item['path'])
        if item.get('sha256') and item['sha256'] != record['sha256']:
            raise ValueError('Supplemental checksum mismatch')
    lock = ROOT / 'provenance/publication-source-lock.json'
    if lock.is_file() and json.loads(lock.read_text())['sources'] != records:
        raise ValueError('Source custody differs from committed publication lock')
    return records


def xalia_matches(records):
    root = ROOT / 'work/stage/nndsk-ro-proton/files/share/xalia'
    targets = {p.name: digest(p) for p in root.glob('*.dll') if p.name != 'SDL3.dll'}
    matches = {}
    for record in records:
        if not record['component'].startswith('nuget/'):
            continue
        with zipfile.ZipFile(OUTPUT / record['filename']) as zipped:
            for member in zipped.infolist():
                name = safe_name(member.filename)
                leaf = PurePosixPath(name).name
                if leaf in targets and hashlib.sha256(zipped.read(member)).hexdigest() == targets[leaf]:
                    matches[leaf] = {'component': record['component'], 'member': name, 'sha256': targets[leaf]}
    if set(matches) != set(targets):
        raise ValueError('Unreconciled Xalia assembly: ' + repr(set(targets) - set(matches)))
    return matches


def pack_materials(destination, records):
    if destination.exists():
        raise ValueError('Materials output must be new')
    destination.mkdir(mode=0o700, parents=True)
    notices = destination / 'notices'
    notices.mkdir()
    index = []
    for record in records:
        component = record['component'].replace('/', '--')
        notice_count = 0
        for name, data in notice_files(OUTPUT / record['filename']):
            target = notices / component / safe_name(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(data)
            notice_count += 1
        index.append({**record, 'noticeFiles': notice_count})
    for component, archive in [('proton-root', ROOT / 'dist/source/proton-cachyos-3edf6fbb8af9-source.tar.zst'),
            ('modified-wine', ROOT / 'dist/source/nndsk-ro-proton-0.1.0-dev.1-source.tar.zst')]:
        for name, data in notice_files(archive):
            target = notices / component / safe_name(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(data)
    # The font is embedded in zenity. Its OFL text does not inherit Liberation's copyright.
    font = notices / 'zenity-font'
    font.mkdir()
    (font / 'COPYRIGHT.txt').write_text(
        'Cantarell Regular, version 0.05; embedded in zenity-rs 0.2.8.\n'
        'Copyright (c) 2009-2011, Understanding Limited (dave@understandinglimited.com).\n'
        'Copyright (c) 2010-2011, Jakub Steiner (jimmac@gmail.com).\n'
        'Licensed under the SIL Open Font License, Version 1.1.\n')
    ofl = (ROOT / 'work/stage/nndsk-ro-proton/LICENSE.OFL').read_bytes()
    start = ofl.find(b'SIL OPEN FONT LICENSE')
    if start < 0:
        raise ValueError('OFL license missing')
    (font / 'LICENSE.OFL').write_bytes(ofl[start:])
    inventory = {'schemaVersion': 1, 'sourceArchiveCount': len(index),
        'scope': 'Pinned source and notice custody; not a complete SPDX SBOM or legal opinion.',
        'historicalUncertainty': ['Piper phonemizer pic archive original commit/hash unknown; MIT current candidate identified, not promoted to historical proof.'],
        'sources': index, 'xaliaAssemblyMatches': xalia_matches(records)}
    with (destination / 'source-index.json').open('x') as stream:
        json.dump(inventory, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'archives': len(index), 'notices': sum(r['noticeFiles'] for r in index),
                      'xaliaMatchedAssemblies': len(inventory['xaliaAssemblyMatches'])}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    pack_materials(args.output.resolve(), checked_receipts())


if __name__ == '__main__':
    main()
