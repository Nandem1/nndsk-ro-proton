# SPDX-License-Identifier: LGPL-2.1-or-later
"""Package a committed dev.3 recipe and its exact corresponding sources; no remote writes."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

import runtime
import source_bundle as sources
import dev3_stage

ROOT = runtime.ROOT
VERSION = dev3_stage.VERSION
INHERITED = ROOT / 'dist/publication-0.1.0-dev.2-r2/nndsk-ro-proton-0.1.0-dev.2-sources.tar.zst'
INHERITED_SHA = '846a3de09d64e37dbf02b17ee1da5199e8e8600eebbbe1cc63aef99387a87d68'


def checked_build_receipt(receipt):
    build = Path(receipt['ncryptBuild']).resolve()
    if not build.is_relative_to(ROOT/'work') or build == ROOT/'work':
        raise RuntimeError('Compiled source receipt must belong to an owned work/ build')
    source = build/'source-receipt.json'
    if runtime.sha(source) != receipt['compiledSourceReceiptSha256']:
        raise RuntimeError('Compiled source receipt changed since staging')
    return json.loads(source.read_text())


def current_sources(commit, receipt, scratch):
    compiled = checked_build_receipt(receipt)
    recipe = sources.export_commit(ROOT, commit, scratch, 'recipe', scratch)
    base = sources.export_commit(ROOT / 'work/wine', runtime.LOCK['wine']['commit'], scratch, 'wine', scratch)
    recipe_root, wine = scratch/'recipe', scratch/'wine'
    sources.apply_patches(wine, recipe_root, runtime.LOCK, ROOT/'work/wine/.git')
    profile = json.loads((recipe_root/'experiments/ecc-import.json').read_text())
    command = ['git', '--git-dir='+str(ROOT/'work/wine/.git'), '--work-tree='+str(wine), 'apply']
    subprocess.run([*command, '--check', str(recipe_root/profile['patch']['path'])], cwd=wine,
                   env=runtime.environment(), check=True)
    subprocess.run([*command, str(recipe_root/profile['patch']['path'])], cwd=wine,
                   env=runtime.environment(), check=True)
    expected = json.loads((recipe_root/'provenance/validated-source.json').read_text())
    final = sources.file_entries(wine)
    changed = {name for name in base.keys()|final.keys() if base.get(name)!=final.get(name)}
    if changed != expected.keys()|set(profile['sourcePaths']):
        raise RuntimeError('Current Wine snapshot has an unreviewed delta')
    for name in changed:
        target = compiled['sourceAfter'].get(name, expected.get(name, {}).get('candidateSha256'))
        if runtime.sha(wine/name) != target:
            raise RuntimeError('Current Wine snapshot differs from compiled source: '+name)
    if sources.file_entries(recipe_root) != recipe:
        raise RuntimeError('Committed recipe changed during source export')
    return {'recipeCommit': commit, 'wineCommit': runtime.LOCK['wine']['commit'],
            'wineFunctionalSha256': {name: runtime.sha(wine/name) for name in sorted(changed)}}


def pack_sources(scratch, output, index):
    # Retain all checksum-identified inherited sources/notices, and supply the full
    # new modified Wine tree and recipe. No generated prefix or game enters here.
    name = f'nndsk-ro-proton-{VERSION}-sources.tar.zst'
    path = output/name
    own = output/'current-wine-and-recipe.tar.zst'
    sources.pack(scratch, own, runtime.LOCK['sourceDateEpoch'])
    sources.verify_archive(own, scratch.name, sources.inventory(scratch), runtime.LOCK['sourceDateEpoch'])
    index['currentSourceArchive'] = {'filename': own.name, 'sha256': runtime.sha(own), 'size': own.stat().st_size}
    index['inheritedSourceArchive'] = {'filename': INHERITED.name, 'sha256': INHERITED_SHA, 'size': INHERITED.stat().st_size}
    data = json.dumps(index, sort_keys=True, indent=2).encode()+b'\n'
    with path.open('xb') as stream:
        process = subprocess.Popen(['zstd','-q','-T1','-3','-c'], stdin=subprocess.PIPE,
                                   stdout=stream, env=runtime.environment())
        try:
            with tarfile.open(fileobj=process.stdin, mode='w|', format=tarfile.GNU_FORMAT) as tar:
                for src, leaf in ((INHERITED, 'inherited-dev2-sources.tar.zst'), (own, own.name)):
                    member=tarfile.TarInfo('nndsk-ro-proton-sources/'+leaf)
                    member.size,member.mode,member.mtime=src.stat().st_size,0o644,runtime.LOCK['sourceDateEpoch']
                    with src.open('rb') as content: tar.addfile(member,content)
                member=tarfile.TarInfo('nndsk-ro-proton-sources/source-index.json')
                member.size,member.mode,member.mtime=len(data),0o644,runtime.LOCK['sourceDateEpoch']
                tar.addfile(member,io.BytesIO(data))
            process.stdin.close()
            if process.wait(): raise RuntimeError('Source packaging failed')
        finally:
            if process.poll() is None: process.terminate(); process.wait()
    if path.stat().st_size>=2*1024**3: raise RuntimeError('Source asset exceeds release limit')
    # Read the assembled outer asset back as well, not just its nested archives.
    expected = {
        'inherited-dev2-sources.tar.zst': {'sha256': INHERITED_SHA, 'size': INHERITED.stat().st_size, 'mode': 0o644},
        own.name: {'sha256': runtime.sha(own), 'size': own.stat().st_size, 'mode': 0o644},
        'source-index.json': {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'mode': 0o644},
    }
    sources.verify_archive(path, 'nndsk-ro-proton-sources', expected, runtime.LOCK['sourceDateEpoch'])
    return {'filename':path.name,'sha256':runtime.sha(path),'size':path.stat().st_size}


def main(args):
    commit = sources.commit_id(args.source_commit)
    if runtime.git_output(['status','--porcelain'],ROOT):
        raise RuntimeError('Freeze/commit reviewed inputs before identifying a release')
    if runtime.git_output(['rev-parse','HEAD'],ROOT).strip()!=commit:
        raise RuntimeError('Release source commit is not the reviewed HEAD')
    stage = args.stage.resolve()
    if not stage.is_relative_to(ROOT/'work') or stage.name != 'nndsk-ro-proton':
        raise RuntimeError('Release stage must be an owned nndsk-ro-proton child under work/')
    receipt = json.loads((stage.parent/'stage-receipt.json').read_text())
    expected = json.loads((stage.parent/'stage-inventory.json').read_text())
    prepared = json.loads((stage/'nndsk-runtime.json').read_text())
    if receipt['version'] != VERSION or prepared['version'] != VERSION or prepared['patchsetRevision'] != 2:
        raise RuntimeError('Wrong prepared release identity')
    if receipt['baselineArchiveSha256'] != dev3_stage.BASE_SHA:
        raise RuntimeError('Wrong prepared baseline')
    if runtime.inventory(stage)!=expected: raise RuntimeError('Prepared stage changed')
    for name, digest in receipt['sourceInputs'].items():
        if runtime.sha(ROOT/name)!=digest: raise RuntimeError('Prepared release source changed: '+name)
    if runtime.sha(INHERITED)!=INHERITED_SHA: raise RuntimeError('Inherited source material changed')
    output = args.output.resolve()
    if not output.is_relative_to(ROOT/'dist') or output==ROOT/'dist' or output.exists():
        raise RuntimeError('Use a new child of dist/')
    output.mkdir(mode=0o755)
    scratch = args.scratch.resolve()
    if not scratch.is_relative_to(ROOT/'work') or scratch==ROOT/'work' or scratch.exists():
        raise RuntimeError('Use a new child of work/ for source export')
    scratch.mkdir(mode=0o755)
    index = current_sources(commit, receipt, scratch)
    runtime.save(output/'source-index.json',index)
    archive = output/f'nndsk-ro-proton-{VERSION}-linux-x86_64.tar.zst'
    # Final packaging copies the tested stage; the source identity/notice updates
    # occur only on this new copy, never on a tested runner or existing install.
    final = output/'stage/nndsk-ro-proton'
    final.parent.mkdir()
    shutil.copytree(stage,final,symlinks=True)
    identity=json.loads((final/'nndsk-runtime.json').read_text())
    identity.update(sourceCommit=commit, packagingCommit=commit, publicationReady=True,
                    preparationSource={'committed':True,'inputs':receipt['sourceInputs']})
    (final/'nndsk-runtime.json').write_text(json.dumps(identity,sort_keys=True,indent=2)+'\n')
    (final/'SOURCES.nndsk.txt').write_text(f'nndsk-ro-proton {VERSION}\nCorresponding sources and notices:\n'
        f'https://github.com/Nandem1/nndsk-ro-proton/releases/tag/v{VERSION}\n'
        f'New Wine/runtime recipe commit: {commit}\nInherited dev.2 sources retained by checksum.\n')
    shutil.copyfile(ROOT/f'docs/RELEASE-{VERSION}.md',final/f'nndsk-LICENSES/release-{VERSION}.md')
    inventory=runtime.inventory(final)
    changed={name for name in expected.keys()|inventory.keys() if expected.get(name)!=inventory.get(name)}
    if changed!={'nndsk-runtime.json','SOURCES.nndsk.txt',f'nndsk-LICENSES/release-{VERSION}.md'}:
        raise RuntimeError('Packaging changed tested runtime bytes: '+repr(changed))
    runtime.pack_archive(final,archive)
    if args.repeat_package:
        repeat=output/(archive.name+'.repeat')
        runtime.pack_archive(final,repeat)
        if runtime.sha(archive)!=runtime.sha(repeat): raise RuntimeError('Packaging is not deterministic')
    runtime.verify_packaged_archive(archive,final,inventory)
    source_asset=pack_sources(scratch,output,index)
    # Rewrite only this new, generated source index after adding inner checksums.
    (output/'source-index.json').write_text(json.dumps(index,sort_keys=True,indent=2)+'\n')
    identity.update(platform='linux-x86_64',artifact={'filename':archive.name,'size':archive.stat().st_size,
        'sha256':runtime.sha(archive),'format':'tar.zst','root':'nndsk-ro-proton'},sources=source_asset,
        packagingDeterminismVerified=args.repeat_package,compilationBitReproducibilityVerified=False,
        validation={'honeyroInstaller':'PASS','invalidSignatureControls':'PASS',
                    'newGameStability':'NOT_REQUESTED','existingSelectionsMigrated':False})
    runtime.save(output/'manifest.json',identity)
    runtime.save(output/'preservation.json',{'baseArtifactSha256':dev3_stage.BASE_SHA,
        'changedRuntimePaths':receipt['runtimeDeltaBeforeManifest'],
        'moduleIdentities':identity['modifiedModules'],'compatibilityAssets':identity['compatibilityAssets']})
    with (output/'SHA256SUMS').open('x') as stream:
        for name in (archive.name,source_asset['filename'],'manifest.json','source-index.json','preservation.json'):
            stream.write(runtime.sha(output/name)+'  '+name+'\n')
    print(json.dumps({'artifact':identity['artifact'],'sources':source_asset,'sourceCommit':commit},indent=2),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--scratch',type=Path,required=True)
    parser.add_argument('--source-commit',required=True)
    parser.add_argument('--repeat-package',action='store_true')
    main(parser.parse_args())
