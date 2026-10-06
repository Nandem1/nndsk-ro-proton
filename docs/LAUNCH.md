# Launcher contract (not part of the Wine patchset)

Supply the executable to Proton/managed UMU as a **verified Windows/DOS path**,
not its Unix path. Preserve the game's CWD, arguments and graphics configuration.
Convert using the target runner and target prefix, do not invent drive mappings.

The pinned Proton script selects its `umu.exe` helper for a Unix-path target.
That helper retains the `PROCESS_ALL_ACCESS` process handle returned by
CreateProcess. Using the supported DOS launch path avoids this helper legitimately;
it neither changes handle enumeration nor weakens protection policy.

The runtime cannot enforce this by changing Wine. Future launcher integration
must separately test path quoting, spaces, Unicode, patcher handoff, lifetime
tracking, cancellation and concurrent clients. Keep the existing supervisor,
stable `(pid, start_time)` identity and AppImage environment sanitation contracts.
Runner/prefix ownership stays per server. No launcher integration in this milestone.
