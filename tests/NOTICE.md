# Probe and helper license notice

The own fixture/probe sources imported into this directory were authored during
the local runtime compatibility investigation. They contain no proprietary
Ragnarok/xShield/Gepard code, payloads or extracted data. `provenance.json`
preserves original paths and source hashes; the original C files remain
byte-identical instead of inserting new headers into historical evidence.

These own C sources, their PE64 derivatives, and new Python build/validation
helpers are part of `nndsk-ro-proton` and distributed under GNU LGPL version2.1
or, at your option, any later version. See the root `LICENSE`/license notices.
New authored code declares `SPDX-License-Identifier: LGPL-2.1-or-later`.

Wine unit tests stay with the Wine patchset/source under their original Wine
license and upstream authorship. ABI import libraries used for building are
not bundled by this tests builder; their selected hashes and provenance are
recorded in the generated build manifest.
