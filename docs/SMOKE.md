# User-driven private game validation

`scripts/game_smoke.py` has separate `prepare` and `launch` actions. Preparation
does not execute Wine. Supply the existing accepted invocation as explicit test
input; this is not a hidden dependency of the runtime build.

```sh
python3 scripts/game_smoke.py prepare --runner /absolute/extracted/nndsk-ro-proton \
  --baseline /absolute/accepted/invocation.json --sessiond /absolute/ro-sessiond \
  --output work/smoke-01
python3 scripts/game_smoke.py launch --output work/smoke-01 --cycle cycle-01 --trace-cng
```

The original prefix must be idle. A byte-identical clone is made without sharing
registry inodes. The old launcher manifest is retained as template provenance,
not adopted as a managed prefix; a separate private-test custody manifest records
the new runner. The original prefix and runner are rechecked after natural exit.
No managed prefix, launcher configuration or guest protection binary is edited.

The DOS executable must resolve through the clone's actual drive mapping into
the accepted CWD. Executable arguments, CWD and graphics settings stay identical;
only runner/prefix/evidence paths change. `--trace-cng` additionally enables the
Wine `ncrypt` debug channel and records this diagnostic delta. It saves a bounded
entry-only trace, not relay, private-key buffers or security predicates.

The accepted unmodified session supervisor owns the UMU lifecycle. Stable
`(pid, start_time)` identities and resource samples are recorded. No deadline
kills the game; the user enters credentials, changes maps and exits normally.
The same private clone can then be used for `cycle-02` and subsequent cycles.

After an explicit new user confirmation, record the observation window:

```sh
python3 scripts/game_smoke.py mark-start --run work/smoke-01/cycle-01 \
  --confirmation 'User confirmed being in game now'
python3 scripts/game_smoke.py mark-end --run work/smoke-01/cycle-01 \
  --confirmation 'User confirmed graphics/audio/input/map transition normal'
```

Twenty minutes of process survival is not automatic proof of correct gameplay.
Neither historical user confirmation nor a visible window can replace a new
confirmation for this build. CNG entry traces plus unchanged encrypted-record
hashes support identity reuse but do not directly measure the API return status.
Exact `OpenKey=SUCCESS`, public-key equality and SignHash are separate owned-probe
gates. Do not label all lifecycle/stability gates PASS merely because launch works.
