from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from oss_harness.executor import ExecArtifacts
from oss_harness.findings import finding_slug
from oss_harness.reporting import run_report
from oss_harness.reviewing import run_review


def failed_artifacts(root: Path) -> ExecArtifacts:
    return ExecArtifacts(
        response_file=root / 'response.txt',
        stdout_file=root / 'stdout.txt',
        stderr_file=root / 'stderr.txt',
        returncode=1,
    )


class TaskFailureTests(unittest.TestCase):
    def test_review_nonzero_exit_cannot_reuse_stale_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            repo.mkdir()
            finding = root / 'finding.txt'
            finding.write_text('Strict verdict: cve_candidate\n', encoding='utf-8')
            stale_dir = root / 'review' / finding_slug(finding)
            stale_dir.mkdir(parents=True)
            stale_review = stale_dir / 'review.json'
            stale_review.write_text(json.dumps({'tier': 'S'}), encoding='utf-8')

            with patch('oss_harness.reviewing.run_codex_exec', return_value=failed_artifacts(root)):
                result = run_review(
                    root,
                    repo_root=repo,
                    finding_files=[finding],
                    timeout_spec='1s',
                    model='',
                    reasoning_effort='',
                    sandbox='read-only',
                    full_auto=False,
                    unsafe_bypass=False,
                )

            index = json.loads((root / 'review' / 'review_index.json').read_text(encoding='utf-8'))

        self.assertEqual(result['succeeded'], '0')
        self.assertEqual(result['failed'], '1')
        self.assertFalse(stale_review.exists())
        self.assertEqual(index['reviews'], [])

    def test_report_nonzero_exit_cannot_reuse_stale_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            repo.mkdir()
            finding = root / 'finding.txt'
            finding.write_text('Strict verdict: cve_candidate\n', encoding='utf-8')
            stale_dir = root / 'reports' / finding_slug(finding)
            stale_dir.mkdir(parents=True)
            stale_report = stale_dir / 'report.md'
            stale_report.write_text('old report', encoding='utf-8')

            with patch('oss_harness.reporting.run_codex_exec', return_value=failed_artifacts(root)):
                result = run_report(
                    root,
                    repo_root=repo,
                    finding_files=[finding],
                    template_text='advisory',
                    timeout_spec='1s',
                    model='',
                    reasoning_effort='',
                    sandbox='read-only',
                    full_auto=False,
                    unsafe_bypass=False,
                )

        self.assertEqual(result['succeeded'], '0')
        self.assertEqual(result['failed'], '1')
        self.assertFalse(stale_report.exists())


if __name__ == '__main__':
    unittest.main()
