from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from oss_harness.bundle import ensure_prompt_bundle


class BundleTests(unittest.TestCase):
    def test_ensure_prompt_bundle_generates_missing_bundle_from_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            repo_root = tmpdir / 'repo'
            repo_root.mkdir()
            source = repo_root / 'src'
            source.mkdir()
            file_path = source / 'demo.py'
            file_path.write_text('def sink(x):\n    return x\n', encoding='utf-8')

            session_dir = tmpdir / 'session'
            session_dir.mkdir()
            manifest = {
                'repo_root': str(repo_root),
                'policy_path': '',
                'policy_summary': 'focus on real security impact',
                'framework_hints': [],
                'preferred_sinks': [],
                'candidates': [
                    {
                        'path': 'src/demo.py',
                        'language': 'python',
                        'subsystem': 'src/demo',
                        'exposure': 'rpc',
                        'score': 42,
                        'attack_surfaces': ['rpc'],
                        'sink_kinds': ['code'],
                        'framework_hints': [],
                        'entrypoint_markers': [],
                        'primary_symbols': [{'name': 'sink', 'kind': 'function', 'line_start': 1, 'line_end': 2, 'score': 1, 'tags': []}],
                        'semantic_summary': ['candidate summary'],
                        'reasons': ['because'],
                        'path_signals': [],
                        'signals': [],
                        'external_signals': [],
                    }
                ],
            }
            (session_dir / 'targets.json').write_text(json.dumps(manifest), encoding='utf-8')

            prompt_path, snippet_path = ensure_prompt_bundle(session_dir, manifest, 1)
            self.assertTrue(prompt_path.exists())
            self.assertTrue(snippet_path.exists())
            self.assertIn('Target file: `src/demo.py`', prompt_path.read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
