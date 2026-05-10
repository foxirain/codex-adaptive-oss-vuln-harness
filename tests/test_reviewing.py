from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from oss_harness.reviewing import _normalize_review_json_file


class ReviewingTests(unittest.TestCase):
    def test_normalize_review_json_file_rewrites_missing_structured_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            path.write_text(
                json.dumps(
                    {
                        "finding_file": "finding.txt",
                        "title": "Example",
                        "tier": "B",
                        "confidence": "medium",
                        "disposition": "plausible",
                        "summary": "summary",
                        "attacker_control": "attacker controls x",
                        "reachability": "reachable in normal flow",
                        "impact": "impact",
                    }
                ),
                encoding="utf-8",
            )

            _normalize_review_json_file(path)
            item = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(item["schema_version"], "2.0")
        self.assertEqual(item["attacker_control"]["summary"], "attacker controls x")
        self.assertEqual(item["reachability"]["summary"], "reachable in normal flow")
        self.assertEqual(item["entrypoints"], [])
        self.assertEqual(item["sinks"], [])


if __name__ == "__main__":
    unittest.main()
