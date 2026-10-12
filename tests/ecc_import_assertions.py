# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fail closed on incomplete, forged-positive or duplicated ECC probe evidence."""
from collections import Counter
import re

import result_assertions as gate

HEADER = 'CNG_ECC_IMPORT protocol=1 own_public_fixture_only=1 curve=nistP256 bytes=72'
FOOTER = 'roundtrip_and_signature_controls=PASS repeated_cycles=32'
EXPECTED = {
    **dict.fromkeys(('open-software-ksp', 'dotnet-named-generic-import', 'length',
        'dotnet-ephemeral-set', 'dotnet-ephemeral-get', 'dotnet-export-policy',
        'ephemeral-export-policy-no-persist', 'export-policy-unchanged-after-error',
        'verify-valid', 'export-size', 'export-public', 'fixed-p256-no-parameters',
        'fixed-verify', 'fixed-empty-parameters', 'repeat-import', 'repeat-verify',
        'property-size', 'property-value', 'free-imported-key'), 0),
    **dict.fromkeys(('generic-needs-curve', 'short-blob', 'extra-blob-byte',
        'wrong-coordinate-size', 'null-blob', 'odd-curve-bytes', 'null-curve',
        'unterminated-curve', 'descriptor-version', 'duplicate-curve',
        'null-buffer-list', 'null-handle-output', 'invalid-ephemeral-value'), 0x80090027),
    **dict.fromkeys(('unknown-parameter', 'unsupported-curve', 'unsupported-export-policy'), 0x80090029),
    **dict.fromkeys(('bad-flags', 'invalid-ephemeral-flags', 'export-policy-mixed-flags',
                    'persist-unrelated-property-denied'), 0x80090009),
    **dict.fromkeys(('verify-altered-signature', 'verify-altered-digest'), 0x80090006),
    'export-short': 0x80090028, 'null-provider': 0x80090026,
    'public-private-export-denied': 0x80090010,
}
COUNTS = Counter({name: 1 for name in EXPECTED})
COUNTS.update({'property-size': 2, 'property-value': 2, 'free-imported-key': 34,
               'repeat-import': 31, 'repeat-verify': 31})


def validate(text):
    gate.complete(text, HEADER)
    lines = text.splitlines()
    gate.require(lines[0] == HEADER and lines[-2:] == [FOOTER, 'probe_exit=0x00000000'],
                 'Wrong header or truncated terminal evidence')
    counts = Counter()
    sign_denied = []
    for line in lines[1:-2]:
        if line.startswith('public-sign-denied status='):
            sign_denied.append(gate.fields(line).get('status'))
            continue
        match = re.fullmatch(r'CASE name=([a-z0-9-]+) status=(0x[0-9a-f]{8}) expected=(0x[0-9a-f]{8})', line)
        gate.require(match is not None, 'Unknown/malformed ECC record')
        name, actual, claimed = match.groups()
        gate.require(name in EXPECTED and int(actual, 16) == EXPECTED[name]
                     and int(claimed, 16) == EXPECTED[name], 'Wrong ECC status: ' + name)
        counts[name] += 1
    gate.require(counts == COUNTS, 'Missing/duplicate ECC API case')
    gate.require(sign_denied == [0x80090010], 'Public key signing was not denied')
    return {'probe': 'cng-ecc-import', 'signatureControls': 'PASS', 'repeatedCycles': 32,
            'publicOnly': True, 'caseRecords': sum(counts.values())}
