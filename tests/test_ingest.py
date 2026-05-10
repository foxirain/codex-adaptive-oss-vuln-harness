from __future__ import annotations

import unittest

from oss_harness.ingest import parse_response


class IngestTests(unittest.TestCase):
    def test_discarding_maps_from_legacy_not_cve(self) -> None:
        parsed = parse_response(
            'Strict verdict:\n'
            '- not_cve_candidate\n\n'
            'Single best next target:\n'
            '- none\n'
        )
        self.assertEqual(parsed['verdict'], 'discarding')
        self.assertEqual(parsed['next_target'], '')
        self.assertFalse(parsed['should_continue'])

    def test_discarding_does_not_falsely_match_cve_candidate(self) -> None:
        parsed = parse_response(
            'Strict verdict:\n'
            '- discarding\n\n'
            'Single best next target:\n'
            '- none\n'
        )
        self.assertEqual(parsed['verdict'], 'discarding')

    def test_needs_more_context_with_next_target_continues(self) -> None:
        parsed = parse_response(
            'Strict verdict:\n'
            '- needs_more_context\n\n'
            'Single best next target:\n'
            '- src/foo.rs::bar\n'
        )
        self.assertEqual(parsed['verdict'], 'needs_more_context')
        self.assertEqual(parsed['next_target'], 'src/foo.rs::bar')
        self.assertTrue(parsed['should_continue'])

    def test_latent_bug_with_next_target_continues(self) -> None:
        parsed = parse_response(
            'Strict verdict:\n'
            '- latent_bug\n\n'
            'Single best next target:\n'
            '- src/foo.rs::bar\n'
        )
        self.assertEqual(parsed['verdict'], 'latent_bug')
        self.assertTrue(parsed['should_continue'])


if __name__ == '__main__':
    unittest.main()
