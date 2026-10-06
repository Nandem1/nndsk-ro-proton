# Preservation build

Requires Git, Python 3, GNU make/tar/diff, zstd, autoconf/autoheader, Perl, bison,
flex, clang/lld/llvm-strip and GCC with working i386 development libraries.
The accepted toolchain was clang/lld22.1.8 and GCC16.2.1. No package installation
or privileged Docker operation is part of these scripts.

```sh
python3 scripts/runtime.py prepare
python3 scripts/runtime.py build
python3 scripts/runtime.py build-tests
python3 scripts/runtime.py stage
python3 tests/build_probes.py
python3 scripts/runtime.py package
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

`prepare` accepts `--wine-cache /existing/wine/git/repository` for an offline
object cache; it clones committed upstream objects, not that worktree's edits.
`--base-archive /verified/file.tar.xz` avoids downloading the base again.
Both options are checked against the same lock; no cache path becomes a source
dependency of the project. Outputs are exclusive and never overwritten.

The pipeline reconstructs modified modules from a fresh checkout, not copied
experimental DLLs. PE crypt32/ncrypt use the prior multiarchitecture clang
configuration. Unix ntdll uses the prior old-WoW64 pair, GCC with
`--without-unwind`, `CFLAGS=-g -O2 -std=gnu17`. Only those six modules enter the
runtime; no graphics/loader/wineserver modules from the reduced configure are
deployed. Generated Vulkan inputs are frozen and checked, not fetched from HEAD.

`work/stage/nndsk-ro-proton/` is a private unpacked runtime, not a registered
launcher runner. `dist/` contains deterministic archive, external manifest and
SHA256SUMS. A corresponding-source snapshot for the modified Wine tree can be
created locally, but does not close source obligations for all inherited modules.

For packaging, file order, owners and mtimes use the lock's SOURCE_DATE_EPOCH;
gzip/zstd command identity is recorded. Build date is external metadata. Two
packages of the same staged bytes must hash identically. This does not establish
bitwise reproducibility of compilation on a different host. Host toolchain and
ELF dependencies are recorded; an immutable build image is still pending.

The staged manifest declares `publicationReady:false` and experimental quality.
Never promote it solely because build or probes passed. HoneyRO real lifecycle,
new-build stability, kernel/error-path coverage and source/license closure remain
separate acceptance gates. No automatic updater integration/publication command.
