from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from oss_harness.quicksearchmax import _merged_score, build_variant_signals, ensure_empty_review, merge_chain_indexes, merge_review_indexes
from oss_harness.review_schema import normalize_and_validate_review_record


class QuicksearchmaxTests(unittest.TestCase):
    def test_tier_always_dominates_session_rank(self) -> None:
        weakest_s = {'tier': 'S', 'confidence': 'low', 'session_rank': 1000}
        strongest_d = {'tier': 'D', 'confidence': 'high', 'session_rank': 1}
        self.assertGreater(_merged_score(weakest_s), _merged_score(strongest_d))
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

    def test_merge_reviews_groups_duplicate_items_and_preserves_session_hits(self) -> None:
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

        self.assertEqual(result['count'], 1)
        self.assertEqual(result['raw_count'], 2)
        self.assertEqual(payload['review_count'], 1)
        self.assertEqual(payload['raw_review_count'], 2)
        self.assertEqual(payload['unique_review_count'], 1)
        self.assertEqual(payload['reviews'][0]['session'], 'hotrisk')
        self.assertEqual(payload['reviews'][0]['sessions'], ['default', 'hotrisk'])
        self.assertEqual(len(payload['reviews'][0]['session_hits']), 2)
        self.assertEqual(payload['reviews'][0]['schema_version'], '2.0')

    def test_merge_reviews_reports_raw_and_unique_duplicate_counts(self) -> None:
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

        self.assertEqual(result['count'], 1)
        self.assertEqual(result['raw_count'], 2)
        self.assertEqual(payload['review_count'], 1)
        self.assertEqual(payload['raw_review_count'], 2)
        self.assertEqual(payload['reviews'][0]['sessions'], ['default', 'nosignal'])
        self.assertEqual(payload['reviews'][0]['attacker_control']['summary'], 'attacker controls input')
        self.assertEqual(len(payload['reviews'][0]['entrypoints']), 1)

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

    def test_invalid_s_tier_review_is_excluded_from_merged_ranking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp) / 'default'
            merged_dir = Path(tmp) / 'merged'
            repo_root = self._write_manifest(session_dir)
            invalid = self._complete_review(
                {
                    'finding_file': 'finding-invalid.txt',
                    'title': 'Invalid high-tier claim',
                    'tier': 'S',
                    'confidence': 'high',
                    'key_evidence': ['unknown evidence'],
                },
                repo_root,
            )
            review_dir = session_dir / 'review'
            review_dir.mkdir(parents=True, exist_ok=True)
            (review_dir / 'review_index.json').write_text(json.dumps({'reviews': [invalid]}), encoding='utf-8')

            result = merge_review_indexes({'default': session_dir}, merged_dir)
            payload = json.loads((merged_dir / 'review_index.json').read_text(encoding='utf-8'))

        self.assertEqual(result['count'], 0)
        self.assertEqual(result['failed'], 1)
        self.assertEqual(payload['reviews'], [])
        self.assertIn('placeholder', payload['invalid_reviews'][0]['error'])

    def test_root_level_review_locations_survive_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp) / 'session'
            repo_root = self._write_manifest(session_dir)
            (repo_root / 'main.py').write_text('def sink(value):\n    return value\n', encoding='utf-8')
            review = self._complete_review(
                {'finding_file': 'finding-root.txt', 'title': 'Root handler issue', 'tier': 'S', 'confidence': 'high'},
                repo_root,
            )
            review['entrypoints'][0]['location']['file'] = 'main.py'
            review['sinks'][0]['location']['file'] = 'main.py'
            review['evidence_locations'][0]['file'] = 'main.py'

            normalized = normalize_and_validate_review_record(review, repo_root=repo_root)

        self.assertEqual(normalized['entrypoints'][0]['location']['file'], 'main.py')
        self.assertEqual(normalized['sinks'][0]['location']['file'], 'main.py')
        self.assertEqual(normalized['evidence_locations'][0]['file'], 'main.py')

    def test_dash_placeholders_cannot_promote_s_tier_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp) / 'session'
            repo_root = self._write_manifest(session_dir)
            review = self._complete_review(
                {'finding_file': 'finding-placeholder.txt', 'title': 'Placeholder claim', 'tier': 'S', 'confidence': 'high'},
                repo_root,
            )
            review['impact'] = '-'
            review['attacker_control']['summary'] = '-'
            review['reachability']['summary'] = '-'
            review['key_evidence'] = ['-']

            with self.assertRaisesRegex(ValueError, 'placeholder'):
                normalize_and_validate_review_record(review, repo_root=repo_root)

    def test_malformed_chain_types_are_excluded_without_coercion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp) / 'default'
            merged_dir = Path(tmp) / 'merged'
            self._write_manifest(session_dir)
            chain_dir = session_dir / 'chain'
            chain_dir.mkdir(parents=True, exist_ok=True)
            (chain_dir / 'chain_index.json').write_text(
                json.dumps({'batches': [{'clusters': [], 'top_chain_targets': [{'path': 'src/a.py'}], 'top_promotion_candidates': []}]}),
                encoding='utf-8',
            )

            result = merge_chain_indexes({'default': session_dir}, merged_dir)

        self.assertEqual(result['count'], 0)
        self.assertEqual(result['failed'], 1)

    def _write_review_index(self, session_dir: Path, reviews: list[dict[str, object]]) -> None:
        repo_root = self._write_manifest(session_dir)
        review_dir = session_dir / 'review'
        review_dir.mkdir(parents=True, exist_ok=True)
        normalized = [self._complete_review(review, repo_root) for review in reviews]
        (review_dir / 'review_index.json').write_text(json.dumps({'reviews': normalized}, indent=2), encoding='utf-8')

    def _write_chain_index(self, session_dir: Path, batches: list[dict[str, object]]) -> None:
        self._write_manifest(session_dir)
        chain_dir = session_dir / 'chain'
        chain_dir.mkdir(parents=True, exist_ok=True)
        normalized = []
        for batch in batches:
            item = dict(batch)
            item['clusters'] = [
                {
                    'cluster_id': cluster.get('cluster_id', 'cluster'),
                    'theme': cluster.get('theme', 'shared boundary'),
                    'finding_files': cluster.get('finding_files', []),
                    'shared_entrypoints': cluster.get('shared_entrypoints', []),
                    'shared_sinks': cluster.get('shared_sinks', []),
                    'shared_boundaries': cluster.get('shared_boundaries', []),
                    'priority': cluster.get('priority', 'medium'),
                    'why_it_matters': cluster.get('why_it_matters', 'follow-up value'),
                    'promote_first': cluster.get('promote_first', []),
                    'chain_next': cluster.get('chain_next', []),
                    'duplicates_or_near_duplicates': cluster.get('duplicates_or_near_duplicates', []),
                    'notes': cluster.get('notes', []),
                }
                for cluster in item.get('clusters', [])
            ]
            normalized.append(item)
        (chain_dir / 'chain_index.json').write_text(json.dumps({'batches': normalized}, indent=2), encoding='utf-8')

    def _write_manifest(self, session_dir: Path) -> Path:
        repo_root = session_dir / 'repo'
        source = repo_root / 'src'
        source.mkdir(parents=True, exist_ok=True)
        for name in ('example.py', 'a.py', 'shared.py', 'cold.py'):
            (source / name).write_text('def sink(value):\n    return value\n', encoding='utf-8')
        (session_dir / 'targets.json').write_text(json.dumps({'repo_root': str(repo_root), 'candidates': []}), encoding='utf-8')
        return repo_root

    def _complete_review(self, review: dict[str, object], repo_root: Path) -> dict[str, object]:
        tier = str(review.get('tier', 'B')).upper()
        dispositions = {'S': 'confirmed', 'A': 'strong', 'B': 'plausible', 'C': 'weak', 'D': 'reject'}
        confidence = str(review.get('confidence', 'medium')).lower()
        item: dict[str, object] = {
            'schema_version': '2.0',
            'finding_file': review.get('finding_file', 'finding.txt'),
            'title': review.get('title', 'Example finding'),
            'tier': tier,
            'confidence': confidence,
            'disposition': dispositions[tier],
            'summary': review.get('summary', 'Concrete summary'),
            'impact': review.get('impact', 'Concrete security impact'),
            'attacker_control': {'summary': 'attacker controls input', 'controlled_inputs': []},
            'reachability': {'summary': 'reachable flow', 'trigger': 'request', 'entry_condition': 'normal use', 'path_hint': []},
            'entrypoints': [{'name': 'entry', 'kind': 'request', 'surface': 'api', 'location': {'file': 'src/example.py', 'symbol': 'sink', 'lines': '1-2'}}],
            'sinks': [{'name': 'sink', 'kind': 'security sink', 'privilege': 'service', 'location': {'file': 'src/example.py', 'symbol': 'sink', 'lines': '1-2'}}],
            'evidence_locations': [{'file': 'src/example.py', 'symbol': 'sink', 'lines': '1-2', 'role': 'entrypoint'}],
            'candidate_components': {'source': ['api'], 'target': ['sink'], 'intermediate': []},
            'candidate_boundaries': [],
            'capabilities': [],
            'preconditions': [],
            'affected_assets': [],
            'candidate_policies': [],
            'candidate_invariants': [],
            'exploit_path': [],
            'confidence_breakdown': {'overall': confidence, 'attacker_control': confidence, 'reachability': confidence, 'impact': confidence, 'notes': ''},
            'key_evidence': ['src/example.py:1-2'],
            'blocking_gaps': [],
            'next_actions': ['verify reproduction'],
        }
        item.update(review)
        item['disposition'] = dispositions[tier]
        return item


if __name__ == '__main__':
    unittest.main()
