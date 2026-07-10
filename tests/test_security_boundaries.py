from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from oss_harness.autopilot import _normalize_target_reference
from oss_harness.cli import build_parser
from oss_harness.followup import render_followup_snippet
from oss_harness.paths import iter_safe_repo_files, normalize_repo_target, safe_output_relative, safe_repo_file
from oss_harness.policy import load_policy, write_policy_template
from oss_harness.repro import _validate_repro_envelope


class PathBoundaryTests(unittest.TestCase):
    def test_cli_defaults_to_read_only_without_full_auto(self) -> None:
        args = build_parser().parse_args(['autopilot', '/tmp/session'])
        self.assertEqual(args.sandbox, 'read-only')
        self.assertFalse(args.full_auto)

    def test_repository_symlink_is_never_read_as_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo = base / 'repo'
            repo.mkdir()
            (repo / 'safe.py').write_text('safe = True\n', encoding='utf-8')
            outside = base / 'outside.py'
            outside.write_text('secret = True\n', encoding='utf-8')
            (repo / 'leak.py').symlink_to(outside)

            files = {path.name for path in iter_safe_repo_files(repo)}

            self.assertEqual(files, {'safe.py'})
            self.assertIsNone(safe_repo_file(repo, 'leak.py'))
            self.assertEqual(render_followup_snippet(repo, 'leak.py'), '')

    def test_target_rejects_absolute_traversal_windows_unc_and_multiline_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / 'safe.py').write_text('safe = True\n', encoding='utf-8')
            for unsafe in ('/etc/passwd', '../outside.py', r'C:\\secret.py', r'\\\\server\\share.py', 'safe.py\nother.py', 'safe.py\x00tail'):
                with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                    normalize_repo_target(repo, unsafe)
            with self.assertRaises(ValueError):
                _normalize_target_reference('safe.py\nother.py', repo)

    def test_repro_output_rejects_path_escape(self) -> None:
        for unsafe in ('../repro.sh', '/tmp/repro.sh', r'C:\\repro.sh', 'a\nrepro.sh'):
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                safe_output_relative(unsafe)


class SafeTemplateAndReproTests(unittest.TestCase):
    def test_unedited_policy_template_does_not_create_scope_filters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_policy_template(Path(tmp) / '.codex-harness.md')
            policy = load_policy(path)

        self.assertEqual(policy['include_paths'], [])
        self.assertEqual(policy['exclude_paths'], [])
        self.assertEqual(policy['languages'], [])

    def test_repro_envelope_requires_safe_files_and_matching_status(self) -> None:
        files = _validate_repro_envelope(
            {
                'status': 'partial',
                'files': [
                    {'path': 'repro.sh', 'content': '#!/usr/bin/env bash\nexit 0'},
                    {'path': 'result.md', 'content': 'Status: partial\nBlocked by dependency.'},
                    {'path': 'helpers/payload.py', 'content': 'print("payload")'},
                ],
            }
        )
        self.assertEqual(len(files), 3)
        with self.assertRaisesRegex(ValueError, 'status must match'):
            _validate_repro_envelope(
                {
                    'status': 'success',
                    'files': [
                        {'path': 'repro.sh', 'content': '#!/usr/bin/env bash'},
                        {'path': 'result.md', 'content': 'Status: partial\nNo.'},
                    ],
                }
            )


if __name__ == '__main__':
    unittest.main()
