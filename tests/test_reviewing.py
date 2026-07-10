from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from oss_harness.reviewing import _normalize_review_json_file


class ReviewingTests(unittest.TestCase):
    def test_normalize_review_json_file_rejects_missing_structured_fields(self) -> None:
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

            with self.assertRaisesRegex(ValueError, 'missing required review field'):
                _normalize_review_json_file(path)


if __name__ == "__main__":
    unittest.main()
