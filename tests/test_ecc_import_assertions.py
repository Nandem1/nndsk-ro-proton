# SPDX-License-Identifier: LGPL-2.1-or-later
import unittest
import ecc_import_assertions as ecc


def fixture():
    lines = [ecc.HEADER]
    for name, count in ecc.COUNTS.items():
        value = ecc.EXPECTED[name]
        lines.extend([f'CASE name={name} status=0x{value:08x} expected=0x{value:08x}'] * count)
    return '\n'.join(lines + ['public-sign-denied status=0x80090010', ecc.FOOTER, 'probe_exit=0x00000000'])


class EccEvidenceTests(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(ecc.validate(fixture())['repeatedCycles'], 32)

    def test_reject_bad_signature_accepted_even_when_claim_matches(self):
        with self.assertRaises(ValueError):
            ecc.validate(fixture().replace('status=0x80090006 expected=0x80090006',
                                          'status=0x00000000 expected=0x00000000'))

    def test_missing_duplicate_unknown_and_truncated_evidence(self):
        good = fixture()
        lines = good.splitlines()
        for bad in ('\n'.join(lines[:1] + lines[2:]), good + '\n' + lines[1],
                    good.replace(lines[1], lines[1] + '\n' + lines[1]),
                    good.replace('open-software-ksp', 'unknown-case'),
                    '\n'.join(lines[:-1]), good + '\nFAIL', good.replace('repeated_cycles=32', 'repeated_cycles=31')):
            with self.subTest(bad=bad[-100:]), self.assertRaises(ValueError):
                ecc.validate(bad)

    def test_public_key_never_signs_or_exports_private_material(self):
        for name in ('public-sign-denied status=0x80090010',
                     'public-private-export-denied status=0x80090010 expected=0x80090010'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                ecc.validate(fixture().replace(name, name.replace('0x80090010', '0x00000000')))


if __name__ == '__main__':
    unittest.main()
