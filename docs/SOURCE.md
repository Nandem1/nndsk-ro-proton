# Local modified-Wine source snapshot

After the binary artifact and `dist/manifest.json` exist:

```sh
python3 scripts/source_bundle.py
python3 -m unittest discover -s tests -p test_source_bundle.py -v
(cd dist/source && sha256sum --check SHA256SUMS)
```

This creates only `dist/source/` and a new `work/source-bundle-01/` custody
directory. Existing outputs are never reused or overwritten. It does not modify
the runner, Wine cache, guest prefix, original binary manifest or its checksums.
No Wine/game execution, downloads or publication are involved.

The snapshot uses the **binary manifest's source commit**, not the current project
HEAD. Its recipe and full base Wine tree are exported from committed Git objects;
working-tree edits, generated files and test-only COW annotation changes are not
copied. Exactly the three locked functional patches are then applied. All ten
validated final source hashes and the absence of other Wine changes are checked.
The recipe snapshot still includes its separate test-only patch as a recipe
input, but that patch is **not applied** to the bundled Wine source.

The versioned `.tar.zst`, `source-manifest.json` and `SHA256SUMS` identify the
binary artifact and source commits. Two independently packed copies must hash
identically, and all packaged members/content are verified against the snapshot.
This is deterministic packaging of exact sources, not proof of bit-reproducible
compilation.

**Scope: modified Wine plus the committed preservation recipe only.** This does
not supply all corresponding sources/notices for inherited Proton binaries,
codecs, Mono/Gecko, speech/model components or other third parties. It is a local
custody artifact, not legal clearance or authorization to redistribute the full
runtime. `publicationReady:false`, `fullRuntimeSourceComplete:false` and
`licenseSourceAuditComplete:false` remain explicit. See [LICENSING.md](LICENSING.md).
