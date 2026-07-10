# Adaptive Codex OSS Vulnerability Harness

Adaptive, multi-session Codex automation harness for vulnerability hunting across general open source software.

## What It Does

- ranks high-signal files before Codex starts reviewing
- injects project-specific scope and exclusions from one Markdown policy file
- supports Python, JS/TS, Go, Rust, C/C++, Java/Kotlin, PHP, and Ruby
- accepts external signals from advisories, git history, crash logs, sanitizer logs, and manual analyst input
- combines a fixed high-priority prefix with batched adaptive tail exploration
- runs independent signal variants and merges validated reviews with session provenance
- keeps Codex access to the target repository read-only by default

## Quick Start

```bash
git clone <this-repository>
cd <this-repository>
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .

adaptive-oss-harness init-policy /path/to/repo/.codex-harness.md
python3 -m oss_harness scan /path/to/repo --policy /path/to/repo/.codex-harness.md --out /tmp/oss-artifacts
python3 -m oss_harness inspect /tmp/oss-artifacts/session-<UTC-timestamp> --top 10
python3 -m oss_harness autopilot /tmp/oss-artifacts/session-<UTC-timestamp> --duration 2h --per-run-timeout 20m --include-snippet
```

The distribution and CLI are intentionally distinct from the earlier v2 engine. The Python import package remains `oss_harness` for source compatibility, so install v1/v2 and this adaptive variant in separate virtual environments.

## Safety Contract

- Codex runs with `--sandbox read-only` by default.
- Full-auto is never implicit; `--full-auto` must be requested explicitly and cannot be combined with the read-only sandbox.
- Repository symlinks, absolute paths, traversal paths, UNC paths, and model-proposed targets outside the repository are rejected.
- Bootstrap, review, chain, repro, and report stages accept final-response artifacts through `codex exec -o`; the harness validates them before writing session outputs.
- Nonzero exits, timeouts, malformed verdicts, and invalid schemas are operational failures. They are not recorded as vulnerability verdicts or bandit rewards.
- `--dangerously-bypass-approvals-and-sandbox` remains an explicit unsafe escape hatch and is not used by the default workflows.
- Read-only mode blocks mutation but does not guarantee confidentiality for every host-readable secret. Analyze untrusted repositories in a credential-free disposable or containerized environment, and treat every model-produced finding or reproduction as requiring human validation.

## External Signals

Use `--signals-json` for advisory or analyst hints and `--crash-dir` for crash or sanitizer artifacts.

```bash
python3 -m oss_harness scan /path/to/repo   --policy /path/to/repo/.codex-harness.md   --signals-json /path/to/signals.json   --crash-dir /path/to/crash-logs   --out /tmp/oss-artifacts
```

Templates:

- `configs/oss/generic-policy-template.md`
- `configs/oss/signals-template.json`

Detailed usage:

- `docs/OSS_HARNESS.md`

## Multi-Session Search

Use `scripts/quicksearchmax.sh` to run four isolated sessions and merge their review output:

```bash
scripts/quicksearchmax.sh /path/to/repo --out /tmp/oss-artifacts
```

Pass `--model MODEL` and `--reasoning-effort low|medium|high|xhigh` to apply the same Codex settings to bootstrap, autopilot, review, repro/report helpers, and every parallel session.

It creates:

- `default`: bootstrap signals
- `nosignal`: no external signals
- `coldrisk`: lower-heat, potentially risky paths
- `hotrisk`: high-confidence external-signal paths
- `merged-review`: deterministic merged ranking with session provenance

Merged output reports both raw review rows and a conservative heuristic grouping count. The grouped count is not a unique-CVE count and must not be presented as one.

`scan` generates prompt bundles for the top 45 ranked candidates by default, or fewer when fewer candidates are retained.

## Lineage And Limits

This repository preserves the earlier standalone engine's ranked-target, policy, artifact, and CLI workflow while adding multi-session exploration, fixed-prefix plus adaptive-tail allocation, chaining, watchdog/recovery artifacts, and deterministic merged review. It is an adaptive prioritization harness, not a semantic proof engine, and its first-pass verdict reward is a search-allocation proxy rather than ground-truth vulnerability validation.

The exact CVE case studies and discovery evidence are intentionally left for the dedicated results section that will be added after disclosure metadata is verified.
