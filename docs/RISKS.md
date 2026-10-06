# Preservation risks and release gates

The validated candidate is authoritative. Behavioral fixes are imported without
refactoring. Hardening changes must be separate, reviewed and revalidated.

## COW

Requires Linux asynchronous userfaultfd write-protection, WP_UNPOPULATED,
PAGEMAP_SCAN, accessible `/proc/self/pagemap` and host pages of 4096 bytes. If
these facilities are absent, the preserved implementation retains Wine's old
behavior; no software fallback has been validated. A minimum kernel version
alone is not a capability test.

Static review found possible nontransactional cleanup on registration/arming
failure after server mapping publication, and debugger-list cleanup after PE
mapping registration failure. Neither failure was injected in the successful
experiment. Reset/discard may need additional validation. PE64 functional
coverage, unsupported-feature behavior, fault injection and performance remain
release gates. Do not silently repair these while freezing the tested version.

## Software KSP

The implemented subset is named ECDSA-P256 Software KSP, not a complete CNG KSP.
Wine registry namespaces separate user/machine state inside one prefix. Wine
DPAPI and prefix permissions protect stored material; this is **not TPM**, not
Windows LSA isolation, and not protection against the same host user inspecting
their own prefix. Export Policy=0 is an API restriction, not that stronger claim.
Crash/power-loss durability and full Windows differential testing remain open.

## Runtime and compatibility

- Full Proton source rebuild needs pinned SDK and transitive downloads.
- The original official archive/source/license correspondence is still under
  audit; a private experimental package is not release authorization.
- The tested Unix ntdll has local GCC exception handling (`--without-unwind`).
  Preserve this instead of substituting a different unwind configuration.
- HoneyRO's old-candidate success is not a new-build smoke/stability result.
- SakuraRO's hash-specific Wine 7.16 old-WoW64 anchor must remain available until
  an explicit controlled comparison is completed. No single-runner claim yet.
- No account automation, packet capture, security-predicate inspection or
  client/protection edits are part of runtime acceptance.
