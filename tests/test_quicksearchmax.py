from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from oss_harness.quicksearchmax import build_variant_signals, ensure_empty_review, merge_chain_indexes, merge_review_indexes


class QuicksearchmaxTests(unittest.TestCase):
    def test_coldrisk_filters_public_signals_and_keeps_low_heat_risk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            input_path = tmpdir / 'signals.json'
            output_path = tmpdir / 'coldrisk.json'
            input_path.write_text(
                json.dumps(
                    {
                        'signals': [
                            {
                                'path': 'src/authz/router.py',
                                'source': 'manual',
                                'weight': 6,
                                'summary': 'permission boundary around route parser is fragile',
                                'metadata': {'evidence': 'auth_boundary'},
                            },
                            {
                                'path': 'src/http/upload.py',
                                'source': 'advisory',
                                'weight': 10,
                                'summary': 'recent CVE fix',
                                'metadata': {},
                            },
                        ]
                    }
                ),
                encoding='utf-8',
            )
            result = build_variant_signals(input_path, output_path, 'coldrisk')
            payload = json.loads(output_path.read_text(encoding='utf-8'))

        self.assertEqual(result['count'], 1)
        self.assertEqual(payload['signals'][0]['source'], 'manual')
        self.assertEqual(payload['signals'][0]['metadata']['quicksearchmax_variant'], 'coldrisk')

    def test_coldrisk_demotes_obvious_hot_git_and_keeps_underwatched_manual_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            input_path = tmpdir / 'signals.json'
            output_path = tmpdir / 'coldrisk.json'
            input_path.write_text(
                json.dumps(
                    {
                        'signals': [
                            {
                                'path': 'packages/fs-detectors/src/services/resolve.ts',
                                'source': 'git',
                                'weight': 10,
                                'summary': 'recent fix at core trust boundary',
                                'metadata': {'evidence': 'recent_fix', 'adjacent_to_fix': True, 'bug_classes': ['path traversal']},
                            },
                            {
                                'path': 'python/vercel-runtime/src/vercel_runtime/vc_init.py',
                                'source': 'manual',
                                'weight': 8,
                                'summary': 'internal header trust and oidc propagation boundary',
                                'metadata': {'evidence': 'auth_boundary', 'bug_classes': ['auth bypass'], 'sinks': ['header trust']},
                            },
                        ]
                    }
                ),
                encoding='utf-8',
            )
            build_variant_signals(input_path, output_path, 'coldrisk')
            payload = json.loads(output_path.read_text(encoding='utf-8'))

        self.assertEqual(len(payload['signals']), 1)
        self.assertEqual(payload['signals'][0]['path'], 'python/vercel-runtime/src/vercel_runtime/vc_init.py')
        self.assertEqual(payload['signals'][0]['source'], 'manual')

    def test_hotrisk_keeps_and_boosts_high_signal_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            input_path = tmpdir / 'signals.json'
            output_path = tmpdir / 'hotrisk.json'
            input_path.write_text(
                json.dumps(
                    {
                        'signals': [
                            {
                                'path': 'src/server/upload.go',
                                'source': 'advisory',
                                'weight': 9,
                                'summary': 'path traversal in upload pipeline',
                                'metadata': {},
                            },
                            {
                                'path': 'src/server/upload.go',
                                'source': 'manual',
                                'weight': 9,
                                'summary': 'analyst note',
                                'metadata': {},
                            },
                        ]
                    }
                ),
                encoding='utf-8',
            )
            build_variant_signals(input_path, output_path, 'hotrisk')
            payload = json.loads(output_path.read_text(encoding='utf-8'))

        self.assertEqual(len(payload['signals']), 1)
        self.assertEqual(payload['signals'][0]['source'], 'advisory')
        self.assertGreaterEqual(payload['signals'][0]['weight'], 10)

    def test_init_empty_review_writes_expected_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp) / 'session'
            result = ensure_empty_review(session_dir)
            review_dir = session_dir / 'review'
            payload = json.loads((review_dir / 'review_index.json').read_text(encoding='utf-8'))
            summary = (review_dir / 'REVIEW_SUMMARY.md').read_text(encoding='utf-8')

        self.assertEqual(result['count'], 0)
        self.assertEqual(payload, {'reviews': []})
        self.assertEqual(summary, '# Review Summary\n')

    def test_merge_reviews_keeps_all_items_and_tags_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            default_dir = tmpdir / 'default'
            hotrisk_dir = tmpdir / 'hotrisk'
            merged_dir = tmpdir / 'merged-review'
            self._write_review_index(
                default_dir,
                [
                    {
                        'finding_file': 'finding-a.txt',
                        'title': 'Path Traversal In Upload Handler',
                        'tier': 'A',
                        'confidence': 'high',
                        'disposition': 'strong',
                        'summary': 'Upload path joins attacker input directly.',
                        '_path': str(default_dir / 'review' / 'finding-a' / 'review.json'),
                    }
                ],
            )
            self._write_review_index(
                hotrisk_dir,
                [
                    {
                        'finding_file': 'finding-b.txt',
                        'title': 'Path Traversal In Upload Handler',
                        'tier': 'S',
                        'confidence': 'high',
                        'disposition': 'confirmed',
                        'summary': 'Upload path joins attacker input directly.',
                        '_path': str(hotrisk_dir / 'review' / 'finding-b' / 'review.json'),
                    }
                ],
            )

            result = merge_review_indexes({'default': default_dir, 'hotrisk': hotrisk_dir}, merged_dir)
            payload = json.loads((merged_dir / 'review_index.json').read_text(encoding='utf-8'))

        self.assertEqual(result['count'], 2)
        self.assertEqual(payload['review_count'], 2)
        self.assertEqual(payload['reviews'][0]['session'], 'hotrisk')
        self.assertEqual(payload['reviews'][0]['sessions'], ['hotrisk'])
        self.assertEqual(payload['reviews'][0]['schema_version'], '2.0')
        self.assertEqual(payload['reviews'][1]['session'], 'default')
        self.assertEqual(payload['reviews'][1]['sessions'], ['default'])

    def test_merge_reviews_preserves_generic_duplicates_as_separate_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            default_dir = tmpdir / 'default'
            nosignal_dir = tmpdir / 'nosignal'
            merged_dir = tmpdir / 'merged-review'
            generic = {
                'title': 'Potential Path Traversal',
                'tier': 'A',
                'confidence': 'medium',
                'disposition': 'strong',
                'summary': 'User-controlled path reaches a filesystem operation.',
                '_path': 'placeholder.json',
            }
            self._write_review_index(default_dir, [dict(generic, finding_file='finding-1.txt', _path='default.json')])
            self._write_review_index(nosignal_dir, [dict(generic, finding_file='finding-2.txt', _path='nosignal.json')])

            result = merge_review_indexes({'default': default_dir, 'nosignal': nosignal_dir}, merged_dir)
            payload = json.loads((merged_dir / 'review_index.json').read_text(encoding='utf-8'))

        self.assertEqual(result['count'], 2)
        self.assertEqual(payload['review_count'], 2)
        self.assertEqual({item['session'] for item in payload['reviews']}, {'default', 'nosignal'})
        self.assertEqual(payload['reviews'][0]['attacker_control']['summary'], '')
        self.assertEqual(payload['reviews'][0]['entrypoints'], [])

    def test_merge_reviews_appends_latent_findings_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            default_dir = tmpdir / 'default'
            merged_dir = tmpdir / 'merged-review'
            self._write_review_index(
                default_dir,
                [
                    {
                        'title': 'Reviewed item',
                        'tier': 'B',
                        'confidence': 'medium',
                        'disposition': 'plausible',
                        'summary': 'review summary',
                        'finding_file': 'finding-1.txt',
                        '_path': 'default.json',
                    }
                ],
            )
            findings_dir = default_dir / 'autopilot' / 'findings'
            findings_dir.mkdir(parents=True, exist_ok=True)
            (findings_dir / 'finding-latent.txt').write_text('Strict verdict: latent_bug\nSummary: latent seed\n', encoding='utf-8')

            merge_review_indexes({'default': default_dir}, merged_dir)
            payload = json.loads((merged_dir / 'review_index.json').read_text(encoding='utf-8'))
            summary = (merged_dir / 'REVIEW_SUMMARY.md').read_text(encoding='utf-8')

        self.assertEqual(len(payload['latent_findings']), 1)
        self.assertIn('## Chain: latent_bug', summary)
        self.assertIn('latent seed', summary)

    def test_merge_chains_aggregates_top_targets_and_tags_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            default_dir = tmpdir / 'default'
            coldrisk_dir = tmpdir / 'coldrisk'
            merged_dir = tmpdir / 'merged-chain'
            self._write_chain_index(
                default_dir,
                [
                    {
                        'clusters': [{'cluster_id': 'cluster-1'}],
                        'top_chain_targets': ['src/a.py::sink', 'src/shared.py::edge'],
                        'top_promotion_candidates': ['src/shared.py::edge'],
                        '_path': str(default_dir / 'chain' / 'batch-001' / 'chain_summary.json'),
                    }
                ],
            )
            self._write_chain_index(
                coldrisk_dir,
                [
                    {
                        'clusters': [{'cluster_id': 'cluster-1'}, {'cluster_id': 'cluster-2'}],
                        'top_chain_targets': ['src/shared.py::edge'],
                        'top_promotion_candidates': ['src/cold.py::entry'],
                        '_path': str(coldrisk_dir / 'chain' / 'batch-001' / 'chain_summary.json'),
                    }
                ],
            )

            result = merge_chain_indexes({'default': default_dir, 'coldrisk': coldrisk_dir}, merged_dir)
            payload = json.loads((merged_dir / 'chain_index.json').read_text(encoding='utf-8'))
            summary = (merged_dir / 'CHAIN_SUMMARY.md').read_text(encoding='utf-8')

        self.assertEqual(result['count'], 2)
        self.assertEqual(payload['batch_count'], 2)
        self.assertEqual(payload['cluster_count'], 3)
        self.assertEqual(payload['batches'][0]['session'], 'default' if payload['batches'][0]['cluster_count'] == 1 else 'coldrisk')
        self.assertEqual(payload['top_chain_targets'][0]['target'], 'src/shared.py::edge')
        self.assertEqual(payload['top_chain_targets'][0]['count'], 2)
        self.assertIn('# Merged Chain Summary', summary)
        self.assertIn('src/shared.py::edge (2 batches)', summary)

    def _write_review_index(self, session_dir: Path, reviews: list[dict[str, object]]) -> None:
        review_dir = session_dir / 'review'
        review_dir.mkdir(parents=True, exist_ok=True)
        (review_dir / 'review_index.json').write_text(json.dumps({'reviews': reviews}, indent=2), encoding='utf-8')

    def _write_chain_index(self, session_dir: Path, batches: list[dict[str, object]]) -> None:
        chain_dir = session_dir / 'chain'
        chain_dir.mkdir(parents=True, exist_ok=True)
        (chain_dir / 'chain_index.json').write_text(json.dumps({'batches': batches}, indent=2), encoding='utf-8')


if __name__ == '__main__':
    unittest.main()
