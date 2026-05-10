from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from oss_harness.followup import render_followup_snippet


class FollowupTests(unittest.TestCase):
    def test_render_followup_snippet_anchors_to_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            source = repo_root / 'src'
            source.mkdir()
            path = source / 'demo.ts'
            path.write_text(
                '\n'.join([
                    'export function alpha() {',
                    '  return 1;',
                    '}',
                    '',
                    'export async function fetchRemoteContent(url: string) {',
                    '  const value = url;',
                    '  return value;',
                    '}',
                ]) + '\n',
                encoding='utf-8',
            )
            snippet = render_followup_snippet(repo_root, 'src/demo.ts::fetchRemoteContent')
            self.assertIn('fetchRemoteContent', snippet)
            self.assertIn('const value = url;', snippet)
            self.assertIn('## follow-up snippet src/demo.ts :: fetchRemoteContent', snippet)


if __name__ == '__main__':
    unittest.main()
