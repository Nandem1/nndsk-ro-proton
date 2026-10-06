# Redistribution status: BLOCKED / audit incomplete

This is not a legal clearance or an assertion that the entire inherited binary
bundle has complete corresponding source. Do not publish binary artifacts yet.

Wine is LGPL-2.1-or-later; preserve license text, attribution, modifications and
exact corresponding source/build instructions. Proton's own wrapper has its
separate license. The inherited archive also contains separately licensed
components: DXVK, VKD3D, codecs, fonts, Mono/Gecko, speech/ML components and others.
An old aggregate LICENSE or a generic upstream homepage is not a complete
corresponding-source inventory for every included binary.

`licenses/` preserves upstream notices rather than relicensing their code.
All Wine patches keep source-file copyright/license headers.

The exact modified-Wine/recipe snapshot and supplemental top-level Proton
archive are available locally. The 50 pinned component references and payload
groups are recorded in `provenance/proton-components.json`; this is not a
complete SBOM or license/source audit. See [DISTRIBUTION.md](DISTRIBUTION.md).

Before distribution:

1. Inventory every binary/component and map it to exact source and license.
2. Recover and make available corresponding sources, modifications, build scripts
   and applicable dependency source for the exact distributed version.
3. Audit bundled downloaded artifacts/transitive dependencies and their notices.
4. Choose and review a compliant source-distribution mechanism, not just a URL to
   a moving branch; preserve checksums and source availability.
5. Resolve the runtime validation/portability blockers separately.

No remote repositories, tags, releases or public artifacts have been created.
