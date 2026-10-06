"""User-driven runtime smoke, isolated prefix; no deadlines, guest edits or hooks.

An external invocation is test input, never a build input. Preparation does not
execute Wine. Launch is deliberately a separate explicit action.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import selectors
import shutil
import subprocess
import time
import uuid

import regression
import runtime

ROOT = Path(__file__).resolve().parents[1]
MAX_LOG_BYTES = 1024 * 1024
PATH_CHANGES = {"WINEPREFIX", "PROTONPATH", "DXVK_LOG_PATH"}
SECRET = re.compile(r"password|passwd|authorization|bearer|cookie|token|secret|api[_-]?key", re.I)
CNG_FUNCTIONS = {
    "NCryptOpenStorageProvider", "NCryptOpenKey", "NCryptCreatePersistedKey",
    "NCryptFinalizeKey", "NCryptSetProperty", "NCryptGetProperty", "NCryptExportKey",
    "NCryptSignHash", "NCryptFreeObject", "NCryptDeleteKey",
}
STORE_PATH = r"Software\Wine\Crypto\CNG\SoftwareKSP\Keys".casefold()


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write(path, value):
    runtime.save(path, value)


def atomic_status(directory, value):
    temporary = directory / ".status-tmp.json"
    with temporary.open("w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    temporary.replace(directory / "status.json")


def checked_output(path):
    path = path.resolve()
    work = (ROOT / "work").resolve()
    if not path.is_relative_to(work) or path == work:
        raise ValueError("Smoke evidence must be a child of this project's work/")
    return path


def changes_dict(rows):
    result = {}
    for row in rows:
        key, value = row["key"], row["value"]
        if key in result or not key or "=" in key or "\0" in key:
            raise ValueError("Invalid or duplicated environment key")
        if not isinstance(value, str) or "\0" in value or SECRET.search(key):
            raise ValueError("Unset, sensitive or invalid baseline environment")
        result[key] = value
    return result


def dos_target(prefix, dos, cwd):
    """Read Wine's actual drive mapping; never invent one or invoke winepath."""
    path = PureWindowsPath(dos)
    if not re.fullmatch(r"[A-Za-z]:", path.drive) or path.root != "\\":
        raise ValueError("Target must be an absolute Windows/DOS drive path")
    if ".." in path.parts or "/" in dos or "\0" in dos:
        raise ValueError("Refusing Unix paths or traversal")
    mapping = prefix / "dosdevices" / (path.drive.lower())
    if not mapping.is_symlink():
        raise ValueError("DOS drive is not an existing Wine symlink")
    target = mapping.resolve().joinpath(*path.parts[1:]).resolve()
    cwd = cwd.resolve()
    if not target.is_relative_to(cwd) or not target.is_file() or target.suffix.lower() != ".exe":
        raise ValueError("DOS executable does not resolve inside the recorded CWD")
    return target


def read_baseline(path):
    data = json.loads(path.read_text())
    spec = data["spec"]
    env = changes_dict(spec["env"])
    prefix, runner, cwd = Path(data["prefix"]).resolve(), Path(data["runner"]).resolve(), Path(spec["cwd"]).resolve()
    if not prefix.is_dir() or not cwd.is_dir():
        raise ValueError("Baseline prefix/CWD missing")
    if Path(env["WINEPREFIX"]).resolve() != prefix or Path(env["PROTONPATH"]).resolve() != runner:
        raise ValueError("Baseline runner/prefix and explicit environment disagree")
    if Path(env["STEAM_COMPAT_INSTALL_PATH"]).resolve() != cwd:
        raise ValueError("Install path and CWD differ")
    if not spec["args"] or any(SECRET.search(value) for value in spec["args"]):
        raise ValueError("Missing DOS target or potentially credential-bearing arguments")
    target = dos_target(prefix, spec["args"][0], cwd)
    if runtime.sha(target) != data["guestExeSha256"]:
        raise ValueError("Executable differs from the validated baseline")
    if not Path(spec["program"]).is_file():
        raise ValueError("Recorded UMU program missing")
    return data, env, prefix, cwd, target


def runtime_identity(runner):
    identity_path = runner / "nndsk-runtime.json"
    data = json.loads(identity_path.read_text())
    expected = {f"files/lib/wine/{arch}-windows/{module}.dll"
                for arch in ("i386", "x86_64") for module in ("crypt32", "ncrypt")}
    expected |= {f"files/lib/wine/{arch}-unix/ntdll.so" for arch in ("i386", "x86_64")}
    if data.get("runtimeId") != "nndsk-ro-proton" or set(data.get("modifiedModules", {})) != expected:
        raise ValueError("Runner is not the identified six-module preservation runtime")
    current = runtime.inventory(runner)
    for name, record in data["modifiedModules"].items():
        if current.get(name) != record:
            raise ValueError("Runtime manifest/module mismatch: " + name)
    return data, current


def clone_idle_prefix(source, destination, before):
    if regression.identities(source):
        raise RuntimeError("Original prefix active; STOP before clone")
    subprocess.run(["cp", "--reflink=auto", "-a", str(source), str(destination)],
                   env=runtime.environment(), check=True)
    if runtime.inventory(destination) != before:
        raise RuntimeError("Prefix clone is not byte-identical")
    for name in ("user.reg", "system.reg", "userdef.reg"):
        if (source / name).is_file() and (source / name).stat().st_ino == (destination / name).stat().st_ino:
            raise RuntimeError("Prefix clone shares registry inode")
    if regression.identities(source) or runtime.inventory(source) != before:
        raise RuntimeError("Original prefix changed/started during clone; STOP")
    os.chmod(destination, 0o700)


def guest_snapshot(cwd):
    protected, config = {}, {}
    for directory, _, files in os.walk(cwd, followlinks=False):
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(cwd)
            is_core = len(relative.parts) == 2 and relative.parts[0].casefold() == "bgm" and name.casefold() == "666.mp3"
            if path.suffix.lower() in (".exe", ".dll") or is_core:
                if path.is_symlink() or not path.is_file():
                    raise ValueError("Protected input is not a regular local file: " + str(relative))
                protected[str(relative)] = {"sha256": runtime.sha(path), "size": path.stat().st_size}
            elif path.suffix.lower() in (".ini", ".conf", ".cfg", ".json", ".lua", ".xml") and path.stat().st_size <= 1024 * 1024:
                config[str(relative)] = {"sha256": runtime.sha(path), "size": path.stat().st_size}
    if sum(name.casefold() == "bgm/666.mp3" for name in protected) != 1:
        raise ValueError("Affected core file is missing or ambiguous")
    return {"protected": protected, "smallConfig": config}


def store_hashes(prefix):
    """Hash opaque REG_BINARY ciphertext only; never decrypt or log key bytes."""
    records = {}
    for file, scope in (("user.reg", "user"), ("system.reg", "machine")):
        path = prefix / file
        if not path.is_file():
            continue
        rows = iter(path.read_text(errors="replace").splitlines())
        in_store = False
        for row in rows:
            if row.startswith("["):
                in_store = row[1:row.index("]")].replace("\\\\", "\\").casefold() == STORE_PATH
                continue
            if not in_store:
                continue
            value = re.fullmatch(r'"((?:\\.|[^"\\])*)"=hex:(.*)', row)
            if not value:
                continue
            encoded = value[2]
            while encoded.rstrip().endswith("\\"):
                encoded = encoded.rstrip()[:-1] + next(rows, "")
            raw = bytes.fromhex(encoded.replace(",", " "))
            name_hash = hashlib.sha256(value[1].casefold().encode("utf-16le")).hexdigest()
            records[scope + ":" + name_hash] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    return records


def prepare(args):
    os.umask(0o077)
    output = checked_output(args.output)
    baseline, _, original, cwd, _ = read_baseline(args.baseline.resolve())
    runner, sessiond = args.runner.resolve(), args.sessiond.resolve()
    identity, runner_before = runtime_identity(runner)
    if runtime.sha(sessiond) != baseline["supervisorSha256"]:
        raise ValueError("Supervisor differs from baseline; explicit review required")
    if output.exists():
        raise ValueError("Output exists; never adopt or overwrite an unknown prefix")
    if regression.identities(original):
        raise RuntimeError("Original prefix still active")
    original_before = runtime.inventory(original)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    write(output / "original-prefix-before.json", original_before)
    write(output / "runner-before.json", runner_before)
    write(output / "baseline-invocation.json", baseline)
    clone_idle_prefix(original, output / "prefix", original_before)
    write(output / "prefix/.nndsk-runtime-test-prefix.json", {
        "schemaVersion": 1, "scope": "private-cloned-runtime-test",
        "runnerPath": str(runner), "runtimeId": identity["runtimeId"],
        "runtimeSourceCommit": identity["sourceCommit"],
        "templatePrefix": str(original), "managedLauncherPrefix": False,
    })
    write(output / "prepared.json", {
        "createdUtc": stamp(), "runner": str(runner), "sessiond": str(sessiond),
        "baselineInvocationSha256": runtime.sha(args.baseline), "runtimeIdentity": identity,
        "originalPrefix": str(original), "testPrefix": str(output / "prefix"),
        "prefixManifestPolicy": "Original manifest preserved as provenance, not adopted/registered",
        "guest": guest_snapshot(cwd), "opaqueCngRecordHashes": store_hashes(output / "prefix"),
        "invocationInputIsBuildInput": False,
    })
    print("SMOKE_PREPARED_NO_WINE_EXECUTED", output, flush=True)


def launch_spec(baseline, prefix, runner, run, trace_cng=False):
    original = changes_dict(baseline["spec"]["env"])
    delta = {"WINEPREFIX": str(prefix), "PROTONPATH": str(runner), "DXVK_LOG_PATH": str(run)}
    if trace_cng:
        delta["WINEDEBUG"] = original["WINEDEBUG"] + ",+ncrypt"
    final = original | delta
    allowed = PATH_CHANGES | ({"WINEDEBUG"} if trace_cng else set())
    if {k for k in original if final[k] != original[k]} - allowed or set(original) != set(final):
        raise ValueError("Unexpected explicit environment change")
    spec = dict(baseline["spec"])
    spec["env"] = [{"key": row["key"], "value": final[row["key"]]} for row in baseline["spec"]["env"]]
    return spec, {k: {"before": original[k], "after": final[k]} for k in delta if original[k] != final[k]}


def inherited_environment(environ):
    # Match the accepted keeper's AppImage/runner sanitation; never serialize
    # the complete inherited environment or command-line credentials.
    return {k: v for k, v in environ.items()
            if not k.startswith(("APPIMAGE", "APPDIR", "LD_", "PROTON_", "STEAM_COMPAT_", "WINE", "XSHIELD_"))
            and k not in ("PROTONPATH", "GAMEID", "STORE")}


def resource_sample(identity):
    pid, expected = identity["pid"], str(identity["startTimeTicks"])
    proc = Path("/proc") / str(pid)
    try:
        before = (proc / "stat").read_text().rsplit(")", 1)[1].split()
        if before[19] != expected:
            return None
        fields = dict(row.split(":", 1) for row in (proc / "status").read_text().splitlines() if ":" in row)
        cwd = os.readlink(proc / "cwd")
        after = (proc / "stat").read_text().rsplit(")", 1)[1].split()
        if after[19] != expected:
            return None
        return {"pid": pid, "startTimeTicks": expected, "time": stamp(), "monotonicNs": time.monotonic_ns(),
                "state": after[0], "VmRSS": fields.get("VmRSS", "").strip(),
                "threads": fields.get("Threads", "").strip(), "cwd": cwd,
                "comm": identity["comm"], "linuxExecutable": identity["executable"]}
    except OSError:
        return None


def diagnostic(line, trace_cng):
    """Strict entry-only CNG allowlist; no relay or buffer-content records."""
    # Wine's __wine_dbg_header prints "class:channel:function " (space),
    # not a mandatory trailing colon after the function name.
    cng = re.search(r"(?:trace|fixme):ncrypt:(\w+)(?=[:\s])", line)
    if cng and trace_cng and cng[1] in CNG_FUNCTIONS:
        kind = "cng-entry"
    elif re.search(r"err:|trace:msgbox:|Unhandled exception|assertion failed|segfault", line, re.I):
        kind = "error-or-dialog"
    else:
        return None
    if SECRET.search(line):
        line = "[sensitive diagnostic redacted]"
    else:
        line = re.sub(r"https?://\S+", "[URL redacted]", line)
        line = re.sub(r"[A-Za-z0-9+/=_-]{80,}", "[opaque data redacted]", line)
    return {"kind": kind, "time": stamp(), "line": line[:4096]}


def backup_runtime_evidence(cwd, run, phase):
    records = {}
    for name in ("game_data.cache", "game_crash_log.txt"):
        path = cwd / name
        if path.is_file() and not path.is_symlink():
            record = {"size": path.stat().st_size, "sha256": runtime.sha(path)}
            if record["size"] <= 16 * 1024 * 1024:
                destination = run / (phase + "-" + name)
                shutil.copy2(path, destination)
                os.chmod(destination, 0o600)
                if runtime.sha(destination) != record["sha256"]:
                    raise RuntimeError("Evidence changed during backup")
                record["copy"] = destination.name
            records[name] = record
    write(run / (phase + "-runtime-evidence.json"), records)


def kept_event(event):
    # Session errors may quote input; persist only typed, non-sensitive fields.
    fields = ("type", "protocolVersion", "supervisorPid", "prefix", "subreaper", "requestId",
              "controllerPid", "controllerStartTime", "exitCode", "signal", "stage", "errno")
    return {"time": stamp(), "monotonicNs": time.monotonic_ns(), **{k: event[k] for k in fields if k in event}}


def launch(args):
    os.umask(0o077)
    output = checked_output(args.output)
    prepared = json.loads((output / "prepared.json").read_text())
    baseline = json.loads((output / "baseline-invocation.json").read_text())
    prefix, original = Path(prepared["testPrefix"]), Path(prepared["originalPrefix"])
    runner, sessiond, cwd = Path(prepared["runner"]), Path(prepared["sessiond"]), Path(baseline["spec"]["cwd"])
    custody = json.loads((prefix / ".nndsk-runtime-test-prefix.json").read_text())
    if (custody.get("runnerPath") != str(runner) or
            custody.get("runtimeSourceCommit") != prepared["runtimeIdentity"]["sourceCommit"] or
            custody.get("templatePrefix") != str(original) or custody.get("managedLauncherPrefix") is not False):
        raise RuntimeError("Test-prefix ownership manifest differs from preparation")
    with (output / ".keeper.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if regression.identities(prefix) or regression.identities(original):
            raise RuntimeError("Test/original prefix active; no overlap/relaunch")
        if runtime.inventory(original) != json.loads((output / "original-prefix-before.json").read_text()):
            raise RuntimeError("Original prefix changed since preparation; STOP")
        _, runner_before = runtime_identity(runner)
        if runner_before != json.loads((output / "runner-before.json").read_text()):
            raise RuntimeError("Runner changed since preparation")
        if runtime.sha(sessiond) != baseline["supervisorSha256"]:
            raise RuntimeError("Supervisor changed")
        dos_target(prefix, baseline["spec"]["args"][0], cwd)
        before = guest_snapshot(cwd)
        if before["protected"] != prepared["guest"]["protected"]:
            raise RuntimeError("Protected guest files changed since preparation")
        if args.cycle and not re.fullmatch(r"cycle-[0-9]{2,4}", args.cycle):
            raise ValueError("Cycle label must be cycle-NN")
        label = args.cycle or f"cycle-{1 + len(list(output.glob('cycle-*'))):02d}"
        run = output / label
        run.mkdir(mode=0o700, exist_ok=False)
        spec, changed = launch_spec(baseline, prefix, runner, run, args.trace_cng)
        cng_before = store_hashes(prefix)
        write(run / "before.json", {"time": stamp(), "guest": before, "opaqueCngRecordHashes": cng_before})
        write(run / "invocation.json", {"spec": spec, "explicitEnvironmentChanges": changed,
              "supervisorSha256": runtime.sha(sessiond), "umuSha256": runtime.sha(Path(spec["program"])),
              "inheritedEnvironmentKeys": sorted(inherited_environment(os.environ)),
              "fullHistoricalInheritedEnvironmentKnown": False, "automaticTimeoutTermination": False,
              "traceCngEntryOnly": args.trace_cng, "runtimeIdentity": prepared["runtimeIdentity"]})
        backup_runtime_evidence(cwd, run, "before")
        observe_session(sessiond, spec, prefix, cwd, run, args.trace_cng)
        # No signals or global wineserver commands: wait briefly for owned cleanup.
        deadline = time.monotonic() + 20
        while regression.identities(prefix) and time.monotonic() < deadline:
            time.sleep(.2)
        after = guest_snapshot(cwd)
        cng_after = store_hashes(prefix)
        remaining = regression.identities(prefix)
        original_ok = runtime.inventory(original) == json.loads((output / "original-prefix-before.json").read_text())
        runner_ok = runtime.inventory(runner) == runner_before
        write(run / "after.json", {"time": stamp(), "guest": after, "opaqueCngRecordHashes": cng_after,
              "originalPrefixUnchanged": original_ok, "runnerUnchanged": runner_ok,
              "protectedGuestFilesUnchanged": before["protected"] == after["protected"],
              "configChanged": before["smallConfig"] != after["smallConfig"], "remainingPrefixProcesses": remaining,
              "opaqueCngRecordsUnchanged": cng_before == cng_after,
              "cngReturnStatusObserved": False, "cngReuseInference": "SUPPORTED only if OpenKey entry exists and no Create/Finalize entry; not direct SUCCESS",
              "scope": "Manual-user game smoke; no automated audio/input/map/login verification"})
        backup_runtime_evidence(cwd, run, "after")
        if remaining or not original_ok or not runner_ok or before["protected"] != after["protected"]:
            raise RuntimeError("Smoke integrity/lifecycle gate failed; evidence retained, no next cycle")
        print("SMOKE_NATURAL_SESSION_CLOSED", run, flush=True)


def observe_session(sessiond, spec, prefix, cwd, run, trace_cng):
    env = inherited_environment(os.environ)
    request = str(uuid.uuid4())
    child = subprocess.Popen([str(sessiond), "--prefix", str(prefix), "--parent-pid", str(os.getpid())],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    write(run / "keeper.json", {
        "pid": os.getpid(), "startTimeTicks": Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19],
        "supervisorPid": child.pid,
        "supervisorStartTimeTicks": Path(f'/proc/{child.pid}/stat').read_text().rsplit(')', 1)[1].split()[19],
        "automaticTimeoutTermination": False,
    })
    selector = selectors.DefaultSelector()
    for stream, label in ((child.stdout, "protocol"), (child.stderr, "wine")):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, label)
    carry = {"protocol": b"", "wine": b""}
    sent = ending = False
    controller_event = None
    seen, last_sample, saved = {}, 0, 0
    status = {"phase": "STARTING", "automaticTimeoutTermination": False, "run": str(run)}
    print("SMOKE_WAITING_USER_LOGIN", run, flush=True)
    child.stdin.write(b'{"type":"hello","protocolVersion":1}\n')
    child.stdin.flush()
    with (run / "session.jsonl").open("x") as events, (run / "samples.jsonl").open("x") as samples, (run / "wine-filtered.jsonl").open("x") as log:
        try:
            while selector.get_map():
                if sent and time.monotonic() - last_sample >= 10:
                    for identity in regression.identities(prefix):
                        sample = resource_sample(identity)
                        if sample is None:
                            continue
                        key = (identity["pid"], identity["startTimeTicks"])
                        seen[key] = identity
                        samples.write(json.dumps(sample) + "\n")
                        if identity["comm"].casefold() == PureWindowsPath(spec["args"][0]).name.casefold() and Path(sample["cwd"]).resolve() == cwd.resolve():
                            if not (run / "game.json").exists():
                                write(run / "game.json", identity)
                            status["phase"] = "RUNNING_WAITING_USER_CONFIRMATION"
                            status["game"] = identity
                    samples.flush()
                    last_sample = time.monotonic()
                    if (run / "user-start.json").exists() and "game" in status:
                        marker = json.loads((run / "user-start.json").read_text())
                        if marker["game"] == status["game"] and resource_sample(marker["game"]):
                            elapsed = (time.monotonic_ns() - marker["monotonicNs"]) / 1e9
                            status["userWindowElapsedSeconds"] = elapsed
                            if elapsed >= 1200 and not (run / "20-minute-result.json").exists():
                                write(run / "20-minute-result.json", {"elapsedSeconds": elapsed, "time": stamp(),
                                      "sameGameIdentityAlive": True, "userConfirmedStart": True, "gameLeftOpen": True})
                                print("SMOKE_20_MINUTE_PROCESS_WINDOW_GAME_LEFT_OPEN", flush=True)
                    atomic_status(run, status)
                for key, _ in selector.select(timeout=.5):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    label = key.data
                    carry[label] += chunk
                    while b"\n" in carry[label]:
                        row, carry[label] = carry[label].split(b"\n", 1)
                        if label == "protocol":
                            event = json.loads(row)
                            events.write(json.dumps(kept_event(event)) + "\n")
                            events.flush()
                            if event.get("type") == "ready" and not sent:
                                if event.get("protocolVersion") != 1 or event.get("supervisorPid") != child.pid or Path(event["prefix"]).resolve() != prefix.resolve():
                                    raise RuntimeError("Invalid supervisor Ready identity")
                                child.stdin.write((json.dumps({"type": "launch", "requestId": request, "spec": spec}) + "\n").encode())
                                child.stdin.flush()
                                sent = True
                            if event.get("type") == "controllerExited" and event.get("requestId") == request:
                                controller_event = kept_event(event)
                                child.stdin.close()
                                ending = True
                            if event.get("type") == "error":
                                raise RuntimeError("Supervisor error: " + str(event.get("stage")))
                        elif saved < MAX_LOG_BYTES:
                            item = diagnostic(row.decode(errors="replace"), trace_cng)
                            if item:
                                record = json.dumps(item) + "\n"
                                if saved + len(record.encode()) <= MAX_LOG_BYTES:
                                    log.write(record)
                                    log.flush()
                                    saved += len(record.encode())
                                else:
                                    saved = MAX_LOG_BYTES
                                    status["diagnosticLogTruncated"] = True
                    if len(carry[label]) > MAX_LOG_BYTES:
                        if label == "protocol":
                            raise RuntimeError("Oversized supervisor protocol frame")
                        carry[label] = b""
                        status["discardedOversizedDiagnosticLine"] = True
            code = child.wait()
            status.update(phase="SESSION_CLOSED", supervisorExitCode=code, controllerExit=controller_event,
                          gameEverObserved=(run / "game.json").exists(), observedAt=stamp())
            atomic_status(run, status)
            write(run / "process-identities.json", list(seen.values()))
            if not ending or controller_event is None or code or controller_event.get("exitCode") != 0:
                raise RuntimeError("Not a clean natural controller/supervisor exit")
        finally:
            # EOF is owned-supervisor cleanup on unexpected keeper failure; never
            # an elapsed-test deadline. No direct game/wineserver signal here.
            if not child.stdin.closed:
                child.stdin.close()
            selector.close()
            for stream in (child.stdout, child.stderr):
                stream.close()
            if child.poll() is None:
                child.wait()


def mark(args):
    run = checked_output(args.run)
    game = json.loads((run / "game.json").read_text())
    if resource_sample(game) is None:
        raise RuntimeError("Game exited or PID reused; cannot mark a window")
    phase = "start" if args.action == "mark-start" else "end"
    write(run / ("user-" + phase + ".json"), {"time": stamp(), "monotonicNs": time.monotonic_ns(),
          "game": game, "confirmation": args.confirmation, "source": "Explicit user confirmation; no automatic UI observation"})
    print("SMOKE_USER_CONFIRMATION_RECORDED", phase, run, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prepare_ = sub.add_parser("prepare")
    prepare_.add_argument("--runner", type=Path, required=True)
    prepare_.add_argument("--baseline", type=Path, required=True)
    prepare_.add_argument("--sessiond", type=Path, required=True)
    prepare_.add_argument("--output", type=Path, required=True)
    launch_ = sub.add_parser("launch")
    launch_.add_argument("--output", type=Path, required=True)
    launch_.add_argument("--cycle")
    launch_.add_argument("--trace-cng", action="store_true")
    for action in ("mark-start", "mark-end"):
        mark_ = sub.add_parser(action)
        mark_.add_argument("--run", type=Path, required=True)
        mark_.add_argument("--confirmation", required=True)
    args = parser.parse_args()
    {"prepare": prepare, "launch": launch, "mark-start": mark, "mark-end": mark}[args.action](args)


if __name__ == "__main__":
    main()
