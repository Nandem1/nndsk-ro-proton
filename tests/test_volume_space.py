# SPDX-License-Identifier: LGPL-2.1-or-later
import unittest
import result_validation


def fixture():
    queries = ('before-direct', 'during-direct', 'during-guid', 'after-direct', 'after-guid')
    return '\n'.join(['VOLUME_SPACE protocol=1 own_directory_only=1',
        r'CANONICAL path=\\?\Volume{00000000-0000-0000-0000-000000000043}\ro-runtime-volume-fixture',
        *[f'QUERY name={name} success=0x00000001 error=0x00000000 capacityNonzero=0x00000001'
          for name in queries], 'probe_exit=0x00000000'])


class VolumeSpaceEvidenceTests(unittest.TestCase):
    def test_complete(self):
        self.assertTrue(result_validation.validate_probe('volume-space', fixture())['guidRoundTrip'])

    def test_missing_duplicates_failed_and_truncated_queries_never_pass(self):
        good = fixture()
        query = good.splitlines()[2]
        for bad in (good.replace(query, ''), good.replace(query, query + '\n' + query),
                    good.replace('success=0x00000001', 'success=0x00000000'),
                    good.replace('error=0x00000000', 'error=0x00000002'),
                    good.replace('Volume{', 'NotVolume{'), good.replace('probe_exit=0x00000000', ''),
                    good + '\nFAIL'):
            with self.subTest(bad=bad[-80:]), self.assertRaises(ValueError):
                result_validation.validate_probe('volume-space', bad)


if __name__ == '__main__':
    unittest.main()
