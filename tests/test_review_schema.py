from __future__ import annotations

import unittest

from oss_harness.review_schema import REVIEW_SCHEMA_VERSION, normalize_review_record


class ReviewSchemaTests(unittest.TestCase):
    def test_normalize_review_record_preserves_flat_fields_and_upgrades_strings(self) -> None:
        payload = {
            "finding_file": "finding-a.txt",
            "title": "Example",
            "tier": "B",
            "confidence": "medium",
            "disposition": "plausible",
            "summary": "flat summary",
            "reachability": "reachable from normal UI flow",
            "attacker_control": "attacker controls remote URI fields",
            "impact": "main process fetches attacker URL",
            "key_evidence": ["a", "b"],
            "blocking_gaps": [],
            "next_actions": ["verify boundary"],
        }

        item = normalize_review_record(payload)

        self.assertEqual(item["schema_version"], REVIEW_SCHEMA_VERSION)
        self.assertEqual(item["summary"], "flat summary")
        self.assertEqual(item["attacker_control"]["summary"], "attacker controls remote URI fields")
        self.assertEqual(item["attacker_control"]["controlled_inputs"], [])
        self.assertEqual(item["reachability"]["summary"], "reachable from normal UI flow")
        self.assertEqual(item["reachability"]["path_hint"], [])
        self.assertEqual(item["entrypoints"], [])
        self.assertEqual(item["sinks"], [])
        self.assertEqual(item["candidate_components"], {"source": [], "target": [], "intermediate": []})
        self.assertEqual(item["confidence_breakdown"]["overall"], "medium")

    def test_normalize_review_record_keeps_structured_fields(self) -> None:
        payload = {
            "finding_file": "finding-b.txt",
            "title": "Structured",
            "tier": "A",
            "confidence": "high",
            "disposition": "strong",
            "summary": "summary",
            "impact": "impact",
            "attacker_control": {
                "summary": "controls preview URI",
                "controlled_inputs": [
                    {"name": "preview_uri", "kind": "metadata_field", "scope": "remote_untrusted", "notes": "from NFT"}
                ],
            },
            "reachability": {
                "summary": "reachable",
                "trigger": "normal_ui_flow",
                "entry_condition": "open preview",
                "path_hint": ["NFTPreview", "downloadFile"],
            },
            "entrypoints": [
                {
                    "name": "preview ingestion",
                    "kind": "metadata_ingestion",
                    "surface": "renderer",
                    "location": {"file": "src/a.ts", "symbol": "A", "lines": "1-3"},
                }
            ],
            "sinks": [
                {
                    "name": "downloadFile",
                    "kind": "network_sink",
                    "privilege": "outbound_network",
                    "location": {"file": "src/b.ts", "symbol": "B", "lines": "7-9"},
                }
            ],
            "evidence_locations": [{"file": "src/a.ts", "symbol": "A", "lines": "1-3", "role": "entrypoint"}],
            "candidate_components": {"source": ["component.renderer"], "target": ["component.main_process"]},
            "candidate_boundaries": [{"id": "boundary.x", "kind": "authority", "crossing_reason": "renderer to main"}],
            "preconditions": ["user opens preview"],
            "affected_assets": [{"name": "host network", "kind": "asset", "notes": ""}],
            "confidence_breakdown": {"overall": "high", "attacker_control": "high", "reachability": "medium", "impact": "high"},
        }

        item = normalize_review_record(payload)

        self.assertEqual(item["entrypoints"][0]["location"]["file"], "src/a.ts")
        self.assertEqual(item["sinks"][0]["privilege"], "outbound_network")
        self.assertEqual(item["candidate_components"]["source"], ["component.renderer"])
        self.assertEqual(item["candidate_boundaries"][0]["id"], "boundary.x")
        self.assertEqual(item["preconditions"][0]["name"], "user opens preview")
        self.assertEqual(item["affected_assets"][0]["name"], "host network")
        self.assertEqual(item["confidence_breakdown"]["overall"], "high")

    def test_normalize_review_record_derives_locations_and_components_from_flat_evidence(self) -> None:
        payload = {
            "finding_file": "finding-c.txt",
            "title": "Derived",
            "tier": "A",
            "confidence": "high",
            "disposition": "strong",
            "summary": "processSessionRequest() in `packages/gui/src/util/walletConnect.ts:221-247` accepts the request and forwards it onward.",
            "attacker_control": "dApp controls method and params",
            "reachability": "reachable from paired dApp request flow",
            "impact": "handleProcess() in `packages/gui/src/hooks/useWalletConnectCommand.tsx:223-258` can invoke wallet API calls.",
            "key_evidence": [
                "`processSessionRequest()` accepts attacker-controlled data (`packages/gui/src/util/walletConnect.ts:221-247`).",
                "`handleProcess()` dispatches wallet actions (`packages/gui/src/hooks/useWalletConnectCommand.tsx:223-258`).",
            ],
        }

        item = normalize_review_record(payload)

        self.assertGreaterEqual(len(item["evidence_locations"]), 2)
        self.assertGreaterEqual(len(item["entrypoints"]), 1)
        self.assertGreaterEqual(len(item["sinks"]), 1)
        self.assertTrue(item["candidate_components"]["source"])
        self.assertTrue(item["candidate_components"]["target"])


if __name__ == "__main__":
    unittest.main()
