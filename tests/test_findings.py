from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from oss_harness.findings import filter_finding_files_by_verdict, finding_verdict


class FindingsTests(unittest.TestCase):
    def test_finding_verdict_maps_legacy_not_cve_to_discarding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'finding.txt'
            path.write_text('Strict verdict:\n- not_cve_candidate\n', encoding='utf-8')
            self.assertEqual(finding_verdict(path), 'discarding')

    def test_filter_finding_files_by_verdict_keeps_only_matching_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            latent = tmpdir / 'latent.txt'
            strong = tmpdir / 'strong.txt'
            latent.write_text('Strict verdict:\n- latent_bug\n', encoding='utf-8')
            strong.write_text('Strict verdict:\n- plausible_security_bug\n', encoding='utf-8')

            filtered = filter_finding_files_by_verdict([latent, strong], {'latent_bug'})
            self.assertEqual(filtered, [latent])

    def test_finding_verdict_accepts_inline_strict_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'finding.txt'
            path.write_text('Strict verdict: latent_bug\nSummary:\n- seed\n', encoding='utf-8')
            self.assertEqual(finding_verdict(path), 'latent_bug')


if __name__ == '__main__':
    unittest.main()
