# Attribution and source custody

Upstream Wine/Proton and individual component copyright/license notices remain
unchanged. This project does not claim authorship of their source. Recovered
behavior patches originate in the local compatibility experiments; this migration
reformats their upstream-relative diff boundaries but verifies final source bytes
against the accepted candidate. No upstream acceptance or sign-off is implied.

The repository's new orchestration and owned regression fixtures are licensed
under LGPL-2.1-or-later (LICENSE), without removing notices in imported sources.
`licenses/Proton.txt` applies to the imported Proton wrapper, not every bundled
component. `licenses/Upstream-bundle-NOTICE.txt` is preserved historical metadata,
not a declaration that the component-source audit is complete.

Vulkan generator XML inputs are from Vulkan-Docs v1.4.339; preserve their embedded
Khronos copyright/license notices. URLs and checksums are locked for these inputs.
Runtime binary base is from the pinned upstream release, verified by SHA512 and
SHA256 before extraction. New artifacts are not the upstream archive and must
use their own manifest/checksums and corresponding-source information.
