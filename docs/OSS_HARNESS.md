# OSS Harness

`oss_harness` is a generalized Codex automation harness for vulnerability hunting across web applications, backend services, native libraries, parsers, desktop code, CLIs, and mixed-language repositories.

## Design Goals

- Keep Codex focused on the highest-signal files first.
- Make project-specific scope, exclusions, and bug-class preferences configurable through one Markdown policy file.
- Preserve a fully automated `codex exec` loop so the operator does not need to intervene.
- Bias toward reachable attack surface, adjacent variant hunting, and evidence strong enough for CVE-quality reporting.

## Policy File

Create a policy file once per target repository:

```bash
oss-harness init-policy /path/to/repo/.codex-harness.md
```

The scanner understands both core sections and biasing sections:

- `In Scope`
- `Out of Scope`
- `Focus Areas`
- `Forbidden Findings`
- `Entry Points`
- `Include Paths`
- `Exclude Paths`
- `Languages`
- `Framework Hints`
- `Hot Paths`
- `Preferred Sinks`
- `Preferred Bug Classes`
- `Ignore Patterns`
- `Notes`

The policy is injected into prompts and also directly affects ranking.

## Basic Workflow

```bash
python3 -m oss_harness scan /path/to/repo   --policy /path/to/repo/.codex-harness.md   --signals-json /path/to/signals.json   --crash-dir /path/to/crash-logs   --out /tmp/oss-artifacts

python3 -m oss_harness inspect /tmp/oss-artifacts/session-YYYYMMDDTHHMMSSZ --top 10
python3 -m oss_harness autopilot /tmp/oss-artifacts/session-YYYYMMDDTHHMMSSZ --duration 2h --per-run-timeout 20m --include-snippet
```

By default, `scan` creates prompt bundles for the top 45 ranked candidates, or fewer if the session retains fewer candidates.

## What It Scores

The scanner combines several signal classes:

- Language-aware sink and entrypoint heuristics for Python, JS/TS, Go, Rust, C/C++, Java/Kotlin, PHP, and Ruby.
- Repo and framework detection from manifests and framework markers.
- Lightweight internal import graph fan-in and fan-out signals.
- Git-history security scoring from recent churn and security-like commit subjects.
- Symbol-level semantic hints. Python uses AST-based function/class indexing; other languages use lightweight function and handler extraction.
- Local crash and sanitizer feeds via `--crash-dir`.
- Local advisory or external targeting feeds via `--signals-json`.

Priority is highest when the same file looks reachable from policy-defined entrypoints, contains request-like handling, and lands near a sensitive sink or crash trace.

## External Signals

`--signals-json` accepts a local JSON file shaped like:

```json
{
  "signals": [
    {
      "path": "src/server/upload.go",
      "source": "advisory",
      "weight": 9,
      "summary": "recent path traversal fix nearby",
      "url": "https://example.test/advisory",
      "metadata": {"family": "variant-hunt"}
    }
  ]
}
```

`--crash-dir` points at a directory of ASan, UBSan, panic, or other crash logs. The harness extracts file paths and line numbers from those logs and maps them back into the repo.

## Bundle Output

Each ranked target now carries more context into Codex:

- line-level signals
- primary symbols and approximate line ranges
- semantic summaries
- attached git, graph, framework, crash, and external signals
- generated snippets centered on top symbols before fallback signal slices

## Autopilot Behavior

`autopilot` repeatedly:

1. picks the next ranked prompt
2. runs `codex exec`
3. ingests the response
4. stores logs and findings
5. follows one branch briefly if Codex names a better adjacent target
6. cools off repeated dead-end targets
7. cools off entire low-yield subsystems after repeated stalling verdicts

This keeps unattended runs from wasting the whole budget on one bad branch.

Autopilot also writes lightweight local diagnostics under `autopilot/`:

- `AUTOPILOT_PROGRESS.txt`: high-level run log
- `AUTOPILOT_STATUS.txt`: latest status snapshot
- `AUTOPILOT_TRACE.tsv`: low-overhead event trace with render/ingest/exec durations and candidate skip or cooling reasons

## Notes

This is still a prioritization engine, not a semantic proof engine. The goal is to maximize Codex time on the most promising, attacker-reachable surfaces while preserving enough structure that confirmed findings are specific and reportable.

## Quicksearchmax

`scripts/quicksearchmax.sh` runs four independent sessions:

- `default`
- `nosignal`
- `coldrisk`
- `hotrisk`

Each session gets its own `session_dir`, `review_state.json`, `codex_response.txt`, `autopilot/`, and `review/`. The script then builds `merged-review/review_index.json` and `merged-review/REVIEW_SUMMARY.md` without another Codex pass, so merged review ranking is deterministic and does not depend on `--unsafe-bypass`.

Use `--model MODEL` and `--reasoning-effort low|medium|high|xhigh` to apply the same Codex settings to bootstrap, every parallel autopilot session, review, repro, and report generation.

## Review And Chaining

`review` now defaults to stronger findings only:

- `cve_candidate`
- `plausible_security_bug`

Use `--include-latent` if you explicitly want `latent_bug` findings reviewed one by one.

Use `chain` for `latent_bug` findings. It analyzes latent findings in batches and writes chaining-oriented artifacts under `chain/` instead of assigning S/A/B/C/D tiers one file at a time.
