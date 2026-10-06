"""Own API tests only, fresh prefix. Does not launch or inspect any game."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import result_validation

spec = importlib.util.spec_from_file_location('runtime_build', ROOT / 'scripts/runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)

def identities(prefix):
    expected = prefix.resolve()
    records = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            before = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
            env = (proc / 'environ').read_bytes().split(b'\0')
            match = any(field.startswith(b'WINEPREFIX=') and
                        Path(os.fsdecode(field.split(b'=', 1)[1])).resolve() == expected for field in env)
            if not match:
                continue
            executable = os.readlink(proc / 'exe')
            comm = (proc / 'comm').read_text().strip()
            after = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
            if before[19] != after[19]:
                continue
            records.append({'pid': int(proc.name), 'startTimeTicks': before[19],
                            'comm': comm, 'executable': executable})
        except (OSError, ProcessLookupError, PermissionError):
            continue
    return records

def await_idle(prefix):
    end = time.monotonic() + 15
    while time.monotonic() < end:
        if not identities(prefix):
            return
        time.sleep(.1)
    raise RuntimeError('Test prefix still live; STOP, do not start next test')

class Harness:
    def __init__(self, args):
        self.runner = args.runner.resolve()
        self.umu = args.umu.resolve()
        self.output = args.output.resolve()
        if not self.output.is_relative_to(ROOT / 'work'):
            raise RuntimeError('Outputs must live under project work/')
        if self.output.exists():
            raise RuntimeError('Refusing to reuse test prefix/evidence')
        self.output.mkdir(mode=0o700, parents=True)
        self.prefix = self.output / 'prefix'
        self.prefix.mkdir(mode=0o700)
        self.bins = self.prefix / 'drive_c/ro-runtime-tests'
        self.bins.mkdir(parents=True)
        (self.prefix / 'drive_c/ro-audit-cng').mkdir()
        self.probes = args.probes.resolve()
        for arch in ('i386', 'x86_64'):
            shutil.copytree(self.probes / arch, self.bins / arch)
            for module in ('crypt32', 'ncrypt'):
                shutil.copy2(ROOT / f'work/build-pe/dlls/{module}/tests/{arch}-windows/{module}_test.exe',
                             self.bins / arch / (module + '_test.exe'))
        self.before = runtime.inventory(self.runner)
        identity_path = self.runner / 'nndsk-runtime.json'
        self.identity = json.loads(identity_path.read_text())
        if self.identity['runtimeId'] != 'nndsk-ro-proton':
            raise RuntimeError('Not an identified nndsk-ro-proton runtime')
        for name, expected in self.identity['modifiedModules'].items():
            if self.before.get(name) != expected:
                raise RuntimeError('Runtime manifest/module mismatch: ' + name)
        runtime.save(self.output / 'runtime-inventory.json', self.before)
        self.identity_sha = runtime.sha(identity_path)
        self.results = []
        self.counter = 0

    def run(self, label, arch, executable, args=(), kind=None, result_name=None, suite=False,
            capture_virtual=False):
        await_idle(self.prefix)
        self.counter += 1
        out = self.output / f'{self.counter:02d}-{label}'
        out.mkdir(mode=0o700)
        for fixture in ('cow-fixture.dll', 'iat-fixture.dll'):
            origin = self.bins / arch / fixture
            if origin.is_file():
                shutil.copy2(origin, out / fixture)
        env = runtime.environment()
        for name in ('GAMEID', 'PROTONPATH', 'UMU_LOG', 'STORE'):
            env.pop(name, None)
        env.update(WINEPREFIX=str(self.prefix), PROTONPATH=str(self.runner), GAMEID='0',
                   PROTON_VERB='waitforexitandrun', UMU_RUNTIME_UPDATE='0',
                   STEAM_COMPAT_INSTALL_PATH=str(out), WINEDEBUG='-all', WINETEST_PLATFORM='wine',
                   WAYLAND_DISPLAY='', PYTHONDONTWRITEBYTECODE='1')
        dos = 'C:\\ro-runtime-tests\\' + arch + '\\' + executable
        if suite:
            command = [str(self.umu), 'C:\\windows\\system32\\cmd.exe', '/d', '/c',
                       dos + ' ' + ' '.join(args) + ' > suite-result.txt 2>&1']
            result_name = 'suite-result.txt'
        else:
            command = [str(self.umu), dos, *args]
        runtime.save(out / 'invocation.json', {'argv': command, 'cwd': str(out),
                     'environment': {k: env[k] for k in ('WINEPREFIX', 'PROTONPATH', 'PROTON_VERB',
                      'UMU_RUNTIME_UPDATE', 'STEAM_COMPAT_INSTALL_PATH', 'WINEDEBUG')},
                     'executableSha256': runtime.sha(self.bins / arch / executable)})
        seen = {}
        stop = threading.Event()
        def monitor():
            while not stop.wait(.02):
                for item in identities(self.prefix):
                    seen[(item['pid'], item['startTimeTicks'])] = item
        watcher = threading.Thread(target=monitor)
        watcher.start()
        try:
            with (out / 'wine.log').open('xb') as log:
                p = subprocess.Popen(command, env=env, cwd=out, stdout=log, stderr=subprocess.STDOUT,
                                     start_new_session=True)
                identity = {'pid': p.pid, 'startTimeTicks': Path(f'/proc/{p.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]}
                runtime.save(out / 'controller.json', identity)
                try:
                    code = p.wait(timeout=180 if suite else 55)
                except subprocess.TimeoutExpired:
                    # Preserve live test processes for diagnosis; never signal a
                    # global wineserver or another prefix merely to get green.
                    runtime.save(out / 'timeout.json', identity)
                    raise RuntimeError('Own probe timed out; processes retained, STOP')
        finally:
            stop.set()
            watcher.join()
            runtime.save(out / 'process-identities.json', list(seen.values()))
        await_idle(self.prefix)
        result_path = out / result_name
        if not result_path.is_file():
            raise RuntimeError('Test did not produce expected result: ' + str(result_path))
        text = result_path.read_text(errors='replace')
        if capture_virtual:
            summaries = re.findall(r'([0-9a-f]+):virtual: (\d+) tests executed \((\d+) marked as todo, (\d+) as flaky, (\d+) failures?\), (\d+) skipped\.', text)
            if len(summaries) != 1:
                raise RuntimeError('Missing/ambiguous virtual suite summary')
            _, checks, todos, flaky, failures, skipped = summaries[0]
            unexpected = text.count('Test succeeded inside todo block:')
            normal = text.count('Test failed:')
            result = {'suite': 'virtual', 'tests': int(checks), 'expectedTodos': int(todos),
                      'reportedFailures': int(failures), 'unexpectedTodoSuccesses': unexpected,
                      'normalFailures': normal, 'skipped': int(skipped),
                      'formalGreen': int(failures) == 0, 'mode': 'explicit non-green suite capture'}
            runtime.save(out / 'suite-evaluation.json', result)
            if normal or int(flaky) or int(skipped) or int(failures) != unexpected:
                raise RuntimeError('New/unclassified Wine regression; STOP')
        else:
            result = (result_validation.validate_wine_suite(text) if suite else
                      result_validation.validate_probe(kind, text))
        if kind == 'cng-race':
            result = result_validation.validate_race_workers(text,
                        [(out / ('race-worker' + str(n) + '.txt')).read_text() for n in (1, 2)])
        record = {'label': label, 'arch': arch, 'controllerExitStatus': code,
                  'apiGate': result, 'wineservers': [v for v in seen.values() if v['comm'] == 'wineserver']}
        if code:
            raise RuntimeError('Nonzero controller status, even if output appears valid')
        self.results.append(record)
        print(label, arch, 'CAPTURED_NOT_FORMALLY_GREEN' if capture_virtual and not result['formalGreen'] else 'PASS', flush=True)
        return record

    def finish(self):
        await_idle(self.prefix)
        if runtime.inventory(self.runner) != self.before:
            raise RuntimeError('Runner changed during test execution')
        runtime.save(self.output / 'summary.json', {'results': self.results,
                     'runnerUnchanged': True, 'runtimeIdentity': self.identity,
                     'runtimeIdentitySha256': self.identity_sha,
                     'prefixIdleAtEnd': True, 'gameRuns': 0})

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runner', type=Path, default=ROOT / 'work/stage/nndsk-ro-proton')
    p.add_argument('--umu', type=Path, required=True)
    p.add_argument('--probes', type=Path, default=ROOT / 'work/probes/build-01')
    p.add_argument('--output', type=Path, default=ROOT / 'work/regression-01')
    p.add_argument('--section', choices=['all', 'cow', 'crypto', 'virtual'], default='all')
    a = p.parse_args()
    h = Harness(a)
    if a.section in ('all', 'cow'):
        for name in ('cow-probe', 'iat-probe', 'boundary-probe'):
            h.run(name, 'i386', name + '.exe', kind=name, result_name=name + '-result.txt')
        for name in ('cow-probe', 'iat-probe'):
            h.run(name + '-PE64', 'x86_64', name + '64.exe', kind=name, result_name=name + '-result.txt')
    if a.section in ('all', 'crypto'):
        for arch in ('i386', 'x86_64'):
            h.run('crypt32-cert', arch, 'crypt32_test.exe', ['cert'], suite=True)
            h.run('ncrypt-suite', arch, 'ncrypt_test.exe', ['ncrypt'], suite=True)
        name = 'Nndsk.Runtime.PersistenceFixture'
        protocol = [('absent', 'i386', 'user'), ('init', 'i386', 'user'),
                    ('reopen', 'x86_64', 'user'), ('reopen', 'i386', 'user'),
                    ('duplicate', 'i386', 'user'), ('init', 'x86_64', 'machine'),
                    ('reopen', 'i386', 'machine')]
        for phase, arch, scope in protocol:
            h.run(phase + '-' + scope, arch, 'cng-persist-probe.exe', [phase, name, scope],
                  kind='cng-persist', result_name='cng-probe-result.txt')
        user = h.prefix / 'drive_c/ro-audit-cng/persist-user.public.bin'
        machine = h.prefix / 'drive_c/ro-audit-cng/persist-machine.public.bin'
        if len(user.read_bytes()) != 72 or len(machine.read_bytes()) != 72 or user.read_bytes() == machine.read_bytes():
            raise RuntimeError('User/machine key separation invalid')
        for scope in ('user', 'machine'):
            for phase in ('delete', 'absent'):
                h.run(phase + '-' + scope, 'i386', 'cng-persist-probe.exe', [phase, name, scope],
                      kind='cng-persist', result_name='cng-probe-result.txt')
        for arch in ('i386', 'x86_64'):
            h.run('corruption', arch, 'cng-persist-negative.exe', kind='cng-negative', result_name='cng-negative-result.txt')
        for repeat in range(3):
            h.run('race-' + str(repeat + 1), 'x86_64', 'cng-persist-race.exe',
                  ['C:\\ro-runtime-tests\\i386\\cng-persist-race.exe'],
                  kind='cng-race', result_name='cng-race-result.txt')
        servers = [r['wineservers'] for r in h.results if r['label'] in ('init-user', 'reopen-user')]
        if any(not ids for ids in servers):
            raise RuntimeError('Wineserver restart could not be observed')
        unique = {(v['pid'], v['startTimeTicks']) for ids in servers for v in ids}
        if len(unique) < len(servers):
            raise RuntimeError('Expected new wineserver between lifecycle phases')
    if a.section in ('all', 'virtual'):
        for arch in ('i386', 'x86_64'):
            shutil.copy2(ROOT / f'work/build-pe/dlls/kernel32/tests/{arch}-windows/kernel32_test.exe',
                         h.bins / arch / 'kernel32_test.exe')
            h.run('kernel32-virtual', arch, 'kernel32_test.exe', ['virtual'], suite=True, capture_virtual=True)
    h.finish()

if __name__ == '__main__':
    main()
