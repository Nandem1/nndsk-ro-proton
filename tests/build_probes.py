#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Build owned Windows API fixtures only; never execute Wine or client software."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
WORK = ROOT / "work" / "probes"
COMMON = ["-ffreestanding", "-fno-builtin", "-fno-stack-protector",
          "-Wall", "-Wextra", "-Werror", "-Os"]
ARCHES = {"i386": ("i686-w64-windows-gnu", "x86", 0x14c, 0x10b),
          "x86_64": ("x86_64-w64-windows-gnu", "x64", 0x8664, 0x20b)}
CNG = [
    ("cng-persist-probe-v2.c", "cng-persist-probe.exe", ["kernel32", "shell32", "ncrypt", "crypt32"]),
    ("cng-persist-probe.c", "cng-persist-original.exe", ["kernel32", "shell32", "ncrypt", "crypt32"]),
    ("cng-persist-negative-probe.c", "cng-persist-negative.exe", ["kernel32", "ncrypt", "advapi32"]),
    ("cng-persist-race-probe.c", "cng-persist-race.exe", ["kernel32", "shell32", "ncrypt"]),
    ("cng-ncrypt-ephemeral-probe.c", "cng-ephemeral-historical.exe", ["kernel32", "ncrypt", "bcrypt"]),
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_sources():
    custody = json.loads((TESTS / "provenance.json").read_text())
    for source in custody["sources"]:
        path = ROOT / source["path"]
        if sha(path) != source["sha256"]:
            raise RuntimeError(f"Imported source changed: {source['path']}")
    return custody


def pe_identity(path, arch):
    """Basic binary identity, no platform execution or external PE dependency."""
    data = path.read_bytes()
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise RuntimeError(f"Not PE: {path.name}")
    at = struct.unpack_from("<I", data, 0x3c)[0]
    if at + 0x80 > len(data) or data[at:at + 4] != b"PE\0\0":
        raise RuntimeError(f"Invalid PE header: {path.name}")
    machine = struct.unpack_from("<H", data, at + 4)[0]
    magic = struct.unpack_from("<H", data, at + 24)[0]
    if (machine, magic) != ARCHES[arch][2:]:
        raise RuntimeError(f"Wrong PE architecture: {path.name}")
    return {"machine": hex(machine), "optionalMagic": hex(magic),
            "peTimestamp": struct.unpack_from("<I", data, at + 8)[0],
            "entrypointRva": struct.unpack_from("<I", data, at + 40)[0]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=WORK / "build-01")
    parser.add_argument("--import-libs-root", type=Path, default=ROOT / "work" / "build-pe")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--linker", default="lld-link")
    parser.add_argument("--arch", choices=["both", *ARCHES], default="both")
    args = parser.parse_args()
    custody = verify_sources()
    output = args.output.resolve()
    # Generated binaries belong only under this repository's ignored work tree.
    if not output.is_relative_to(WORK.resolve()) or output == WORK.resolve():
        parser.error("--output must be a new child of this project's work/probes")
    if output.exists():
        parser.error("Output exists; choose a fresh build directory, no overwrites")
    clang, linker = shutil.which(args.clang), shutil.which(args.linker)
    if not clang or not linker:
        parser.error("clang and lld-link must already be available")
    libroot = args.import_libs_root.resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"schemaVersion": 1, "kind": "owned-api-probes", "executed": False,
                "createdUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "sourceCustody": custody, "tools": {}, "importLibraries": {},
                "sourceFiles": {str(path.relative_to(ROOT)): sha(path) for path in TESTS.rglob("*.c")},
                "commands": [], "artifacts": {}, "errors": []}
    # Prevent accidental LD/AppImage contamination of the compiler invocation.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("APPIMAGE", "APPDIR", "LD_"))}
    for name, path in (("clang", clang), ("lld-link", linker)):
        version = subprocess.check_output([path, "--version"], env=env, text=True).splitlines()[0]
        manifest["tools"][name] = {"path": str(Path(path).resolve()), "sha256": sha(Path(path)), "version": version}

    def record():
        (output / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    def run(command):
        result = subprocess.run(command, cwd=output, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        manifest["commands"].append({"argv": command, "cwd": str(output),
                                     "exitCode": result.returncode, "diagnostics": result.stdout})
        record()
        if result.returncode:
            raise RuntimeError(f"Build failed: {Path(command[0]).name}; inspect build-manifest.json")

    def libraries(arch, names):
        result = []
        for name in names:
            path = libroot / f"{arch}-windows" / f"lib{name}.a"
            if not path.is_file():
                path = libroot / "dlls" / name / f"{arch}-windows" / f"lib{name}.a"
            if not path.is_file():
                raise RuntimeError(f"Required import library not available: {path}")
            manifest["importLibraries"][str(path)] = sha(path)
            result.append(str(path))
        return result

    def compile_(source, target, arch, *, msvc=False, sections=True):
        triple = ("i686" if arch == "i386" else "x86_64") + "-pc-windows-msvc" if msvc else ARCHES[arch][0]
        sections_flags = ["-ffunction-sections", "-fdata-sections"] if sections else []
        run([clang, f"--target={triple}", *COMMON, *sections_flags,
             "-c", str(TESTS / source), "-o", str(target)])

    def link(objects, target, arch, libs=(), flags=()):
        base = [linker, f"/machine:{ARCHES[arch][1]}", "/nodefaultlib", "/timestamp:0", "/opt:ref"]
        if arch == "i386":
            base.append("/safeseh:no")
        run([*base, *flags, f"/out:{target}", *map(str, objects), *libraries(arch, libs)])
        manifest["artifacts"][str(target.relative_to(output))] = {
            "sha256": sha(target), "size": target.stat().st_size,
            "arch": arch, **pe_identity(target, arch)}
        record()

    try:
        for arch in ARCHES if args.arch == "both" else [args.arch]:
            dest = output / arch
            dest.mkdir()
            if arch == "i386":
                obj = dest / "cow-probe.obj"
                compile_("cow-probe/probe.c", obj, arch, sections=False)
                link([obj], dest / "cow-probe.exe", arch, ["kernel32"],
                     ["/entry:entry", "/subsystem:console"])
                obj = dest / "cow-fixture.obj"
                compile_("cow-probe/fixture.c", obj, arch, sections=False)
                link([obj], dest / "cow-fixture.dll", arch, flags=["/dll", "/noentry",
                     "/base:0x20000000", "/dynamicbase:no", "/section:.cowpg,RW", "/opt:noref"])
                obj = dest / "iat-fixture.obj"
                compile_("cow-probe/iat-loader/fixture.c", obj, arch, msvc=True)
                link([obj], dest / "iat-fixture.dll", arch, ["user32"], ["/dll", "/noentry",
                     "/base:0x21000000", "/merge:.rdata=.xsv4", "/section:.xsv4,RW"])
                obj = dest / "iat-probe.obj"
                compile_("cow-probe/iat-loader/probe.c", obj, arch)
                link([obj], dest / "iat-probe.exe", arch, ["kernel32"],
                     ["/entry:entry", "/subsystem:console"])
                obj = dest / "boundary-probe.obj"
                compile_("cow-candidate/boundary-probe.c", obj, arch)
                link([obj], dest / "boundary-probe.exe", arch, ["kernel32"],
                     ["/entry:entry", "/subsystem:console"])
            else:
                obj = dest / "cow-probe64.obj"
                compile_("cow-probe/probe64.c", obj, arch, sections=False)
                link([obj], dest / "cow-probe64.exe", arch, ["kernel32"],
                     ["/entry:entry", "/subsystem:console"])
                obj = dest / "cow-fixture.obj"
                compile_("cow-probe/fixture.c", obj, arch, sections=False)
                link([obj], dest / "cow-fixture.dll", arch, flags=["/dll", "/noentry",
                     "/base:0x20000000", "/dynamicbase:no", "/section:.cowpg,RW", "/opt:noref"])
                obj = dest / "iat-fixture.obj"
                compile_("cow-probe/iat-loader/fixture.c", obj, arch, msvc=True)
                link([obj], dest / "iat-fixture.dll", arch, ["user32"], ["/dll", "/noentry",
                     "/base:0x21000000", "/merge:.rdata=.xsv4", "/section:.xsv4,RW"])
                obj = dest / "iat-probe64.obj"
                compile_("cow-probe/iat-loader/probe64.c", obj, arch)
                link([obj], dest / "iat-probe64.exe", arch, ["kernel32"],
                     ["/entry:entry", "/subsystem:console"])
            for source, basename, libs in CNG:
                obj = dest / (Path(basename).stem + ".obj")
                compile_(source, obj, arch)
                link([obj], dest / basename, arch, libs, ["/entry:entry", "/subsystem:console"])
        manifest["complete"] = True
        record()
    except Exception as error:
        manifest["complete"] = False
        manifest["errors"].append(str(error))
        record()
        raise
    print(json.dumps({"output": str(output), "artifacts": len(manifest["artifacts"]),
                      "compiledOnly": True}, indent=2))


if __name__ == "__main__":
    main()
