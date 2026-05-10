#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  quicksearchmax.sh REPO_PATH [options]
  quicksearchmax.sh --resume-run-dir RUN_DIR [options]

Runs four fully independent sessions:
  1. bootstrap
  2. signal variants (coldrisk, hotrisk)
  3. default:   scan -> autopilot -> review
  4. nosignal:  scan -> autopilot -> review
  5. coldrisk:  scan -> autopilot -> review
  6. hotrisk:   scan -> autopilot -> review
  7. merged review
  8. complete

Options:
  --resume-run-dir DIR      Resume an existing quicksearchmax run directory
  --out DIR                 Artifact parent directory. Default: /tmp/oss-artifacts
  --duration SPEC           Autopilot total duration per session. Default: 2h
  --per-run-timeout SPEC    Autopilot per-run timeout. Default: 30m
  --review-timeout SPEC     Review timeout per finding. Default: 20m
  --parallel-sessions N     Run up to N sessions concurrently. Default: 1
  --progress-interval SEC   Print per-session progress every SEC seconds when parallel. Default: 30
  --model MODEL             Optional Codex model override
  --reasoning-effort EFFORT Optional Codex reasoning effort override: low, medium, high, or xhigh
  --sandbox MODE            Codex sandbox mode. Default: workspace-write
  --no-include-snippet      Do not pass --include-snippet to autopilot
  --unsafe-bypass           Pass --dangerously-bypass-approvals-and-sandbox
  -h, --help                Show help

Examples:
  quicksearchmax.sh /work/grpc
  quicksearchmax.sh /work/grpc --out /tmp/grpc-artifacts --duration 4h --review-timeout 30m
  quicksearchmax.sh /work/grpc --parallel-sessions 4
  quicksearchmax.sh --resume-run-dir /tmp/grpc-artifacts/quicksearchmax-20260423T075126Z --parallel-sessions 4
USAGE
}

REPO_PATH=""
RESUME_RUN_DIR=""
OUT_DIR="/tmp/oss-artifacts"
DURATION="2h"
PER_RUN_TIMEOUT="30m"
REVIEW_TIMEOUT="20m"
PARALLEL_SESSIONS="1"
PROGRESS_INTERVAL="30"
MODEL=""
REASONING_EFFORT=""
SANDBOX="workspace-write"
INCLUDE_SNIPPET=1
UNSAFE_BYPASS=0
RESUME_MODE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --resume-run-dir)
      RESUME_RUN_DIR="$2"
      shift 2
      ;;
    --out)
      OUT_DIR="$2"
      shift 2
      ;;
    --duration)
      DURATION="$2"
      shift 2
      ;;
    --per-run-timeout)
      PER_RUN_TIMEOUT="$2"
      shift 2
      ;;
    --review-timeout)
      REVIEW_TIMEOUT="$2"
      shift 2
      ;;
    --parallel-sessions)
      PARALLEL_SESSIONS="$2"
      shift 2
      ;;
    --progress-interval)
      PROGRESS_INTERVAL="$2"
      shift 2
      ;;
    --model)
      MODEL="$2"
      shift 2
      ;;
    --reasoning-effort)
      REASONING_EFFORT="$2"
      shift 2
      ;;
    --sandbox)
      SANDBOX="$2"
      shift 2
      ;;
    --no-include-snippet)
      INCLUDE_SNIPPET=0
      shift
      ;;
    --unsafe-bypass)
      UNSAFE_BYPASS=1
      shift
      ;;
    --*)
      printf 'unknown option: %s\n' "$1" >&2
      exit 1
      ;;
    *)
      if [[ -z "$REPO_PATH" ]]; then
        REPO_PATH="$1"
        shift
      else
        printf 'unexpected argument: %s\n' "$1" >&2
        exit 1
      fi
      ;;
  esac
done

if [[ -z "$REPO_PATH" && -z "$RESUME_RUN_DIR" ]]; then
  usage
  exit 1
fi

if ! [[ "$PARALLEL_SESSIONS" =~ ^[0-9]+$ ]] || [[ "$PARALLEL_SESSIONS" -lt 1 ]]; then
  printf 'invalid --parallel-sessions: %s\n' "$PARALLEL_SESSIONS" >&2
  exit 1
fi

if ! [[ "$PROGRESS_INTERVAL" =~ ^[0-9]+$ ]] || [[ "$PROGRESS_INTERVAL" -lt 1 ]]; then
  printf 'invalid --progress-interval: %s\n' "$PROGRESS_INTERVAL" >&2
  exit 1
fi

HARNESS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TODAY_UTC="$(date -u +%F)"
RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
session_names=(default nosignal coldrisk hotrisk)

if [[ -n "$RESUME_RUN_DIR" ]]; then
  RESUME_MODE=1
  RUN_DIR="$(cd "$RESUME_RUN_DIR" && pwd)"
else
  RUN_DIR="$OUT_DIR/quicksearchmax-$RUN_STAMP"
fi

mkdir -p "$RUN_DIR"
RESULTS_DIR="$RUN_DIR/.session-results"
mkdir -p "$RESULTS_DIR"

resolve_repo_path_from_run() {
  python3 - "$RUN_DIR" <<'PY'
import json
import sys
from pathlib import Path
run_dir = Path(sys.argv[1])
for name in ('default', 'nosignal', 'coldrisk', 'hotrisk'):
    manifest = run_dir / name / 'targets.json'
    if not manifest.exists():
        continue
    data = json.loads(manifest.read_text(encoding='utf-8'))
    repo_root = data.get('repo_root')
    if repo_root:
        print(repo_root)
        raise SystemExit(0)
raise SystemExit(1)
PY
}

resolve_policy_path_from_run() {
  python3 - "$RUN_DIR" <<'PY'
import json
import sys
from pathlib import Path
run_dir = Path(sys.argv[1])
for name in ('default', 'nosignal', 'coldrisk', 'hotrisk'):
    manifest = run_dir / name / 'targets.json'
    if not manifest.exists():
        continue
    data = json.loads(manifest.read_text(encoding='utf-8'))
    policy_path = data.get('policy_path')
    if policy_path:
        print(policy_path)
        raise SystemExit(0)
raise SystemExit(1)
PY
}

if [[ -n "$REPO_PATH" ]]; then
  REPO_PATH="$(cd "$REPO_PATH" && pwd)"
elif [[ "$RESUME_MODE" -eq 1 ]]; then
  REPO_PATH="$(resolve_repo_path_from_run)"
else
  printf 'missing repository path\n' >&2
  exit 1
fi

if [[ "$RESUME_MODE" -eq 1 ]]; then
  POLICY_PATH="$(resolve_policy_path_from_run 2>/dev/null || true)"
  if [[ -z "$POLICY_PATH" ]]; then
    POLICY_PATH="$REPO_PATH/.codex-harness.md"
  fi
else
  POLICY_PATH="$REPO_PATH/.codex-harness.md"
fi

DEFAULT_SIGNALS_PATH="$REPO_PATH/external_signals_${TODAY_UTC}.json"
COLDRISK_SIGNALS_PATH="$RUN_DIR/coldrisk_signals.json"
HOTRISK_SIGNALS_PATH="$RUN_DIR/hotrisk_signals.json"

COMMON_ARGS=()
if [[ -n "$MODEL" ]]; then
  COMMON_ARGS+=(--model "$MODEL")
fi
if [[ -n "$REASONING_EFFORT" ]]; then
  COMMON_ARGS+=(--reasoning-effort "$REASONING_EFFORT")
fi
COMMON_ARGS+=(--sandbox "$SANDBOX")
if [[ "$UNSAFE_BYPASS" -eq 1 ]]; then
  COMMON_ARGS+=(--dangerously-bypass-approvals-and-sandbox)
fi

print_progress() {
  local session_name="$1"
  local final_dir="$RUN_DIR/$session_name"
  local status_file="$final_dir/autopilot/AUTOPILOT_STATUS.txt"
  local state_file="$final_dir/review_state.json"
  local stage="pending"
  local runs="0"
  local rank="?"
  local next_rank=""
  local history_len="0"
  local findings="0"
  local stop_reason=""

  if [[ -f "$status_file" ]]; then
    stage="$(awk -F= '/^stage=/{print $2; exit}' "$status_file")"
    runs="$(awk -F= '/^runs=/{print $2; exit}' "$status_file")"
    rank="$(awk -F= '/^current_rank=/{print $2; exit}' "$status_file")"
    stop_reason="$(awk -F= '/^stop_reason=/{print $2; exit}' "$status_file")"
  fi

  if [[ -f "$state_file" ]]; then
    local state_vals
    state_vals="$(python3 - "$state_file" <<'PY2'
import json
import sys
from pathlib import Path
obj = json.loads(Path(sys.argv[1]).read_text())
pending_rank = obj.get('pending_rank')
print(pending_rank if pending_rank is not None else '')
print(obj.get('current_rank', ''))
print(len(obj.get('history', [])))
print(obj.get('manual_next_target', ''))
PY2
)"
    local pending_rank
    pending_rank="$(printf '%s\n' "$state_vals" | sed -n '1p')"
    local state_rank
    state_rank="$(printf '%s\n' "$state_vals" | sed -n '2p')"
    history_len="$(printf '%s\n' "$state_vals" | sed -n '3p')"
    local manual_next_target
    manual_next_target="$(printf '%s\n' "$state_vals" | sed -n '4p')"
    if [[ -n "$pending_rank" ]]; then
      rank="$pending_rank"
    elif [[ -n "$manual_next_target" ]]; then
      rank="manual"
    elif [[ -z "$rank" || "$rank" == "0" ]]; then
      rank="$state_rank"
    fi
    if [[ -n "$state_rank" && "$state_rank" != "$rank" ]]; then
      next_rank="$state_rank"
    fi
  fi

  if [[ -d "$final_dir/autopilot/findings" ]]; then
    findings="$(find "$final_dir/autopilot/findings" -maxdepth 1 -name 'finding-*.txt' | wc -l | tr -d ' ')"
  fi

  if [[ -n "$next_rank" && -n "$stop_reason" ]]; then
    printf '[progress] %-8s stage=%-12s runs=%-4s rank=%-6s next=%-4s history=%-4s findings=%s reason=%s\n' "$session_name" "$stage" "$runs" "$rank" "$next_rank" "$history_len" "$findings" "$stop_reason"
  elif [[ -n "$next_rank" ]]; then
    printf '[progress] %-8s stage=%-12s runs=%-4s rank=%-6s next=%-4s history=%-4s findings=%s\n' "$session_name" "$stage" "$runs" "$rank" "$next_rank" "$history_len" "$findings"
  elif [[ -n "$stop_reason" ]]; then
    printf '[progress] %-8s stage=%-12s runs=%-4s rank=%-6s history=%-4s findings=%s reason=%s\n' "$session_name" "$stage" "$runs" "$rank" "$history_len" "$findings" "$stop_reason"
  else
    printf '[progress] %-8s stage=%-12s runs=%-4s rank=%-6s history=%-4s findings=%s\n' "$session_name" "$stage" "$runs" "$rank" "$history_len" "$findings"
  fi
}

monitor_progress() {
  local -a names=("$@")
  while true; do
    local any_running=0
    printf '[progress] snapshot %s\n' "$(date -u +%H:%M:%S)"
    for session_name in "${names[@]}"; do
      print_progress "$session_name"
      local status_file="$RUN_DIR/$session_name/autopilot/AUTOPILOT_STATUS.txt"
      if [[ ! -f "$status_file" ]]; then
        any_running=1
        continue
      fi
      local stage
      stage="$(awk -F= '/^stage=/{print $2; exit}' "$status_file")"
      if [[ "$stage" != "finished" && "$stage" != "auth_expired" && "$stage" != "exec_failed" ]]; then
        any_running=1
      fi
    done
    if [[ "$any_running" -eq 0 ]]; then
      break
    fi
    sleep "$PROGRESS_INTERVAL"
  done
}

write_session_stop_hint() {
  local session_name="$1"
  local final_dir="$RUN_DIR/$session_name"
  local status_file="$final_dir/autopilot/AUTOPILOT_STATUS.txt"
  local hint_file="$final_dir/autopilot/SESSION_RESUME_HINT.txt"
  local state_file="$final_dir/review_state.json"
  local stage="unknown"
  local stop_reason=""
  local current_rank=""
  local current_target=""
  local pending_rank=""
  local pending_target=""
  local failure_detail=""
  local manual_next_target=""

  mkdir -p "$(dirname "$hint_file")"

  if [[ -f "$status_file" ]]; then
    stage="$(awk -F= '/^stage=/{print $2; exit}' "$status_file")"
    stop_reason="$(awk -F= '/^stop_reason=/{print $2; exit}' "$status_file")"
    current_rank="$(awk -F= '/^current_rank=/{print $2; exit}' "$status_file")"
    current_target="$(awk -F= '/^current_target=/{print $2; exit}' "$status_file")"
    failure_detail="$(awk -F= '/^failure_detail=/{sub(/^[^=]*=/,""); print; exit}' "$status_file")"
  fi
  if [[ -f "$state_file" ]]; then
    local state_vals
    state_vals="$(python3 - "$state_file" <<'PY3'
import json
import sys
from pathlib import Path
obj = json.loads(Path(sys.argv[1]).read_text())
pending_rank = obj.get('pending_rank')
print(pending_rank if pending_rank is not None else '')
print(obj.get('pending_target', ''))
print(obj.get('manual_next_target', ''))
PY3
)"
    pending_rank="$(printf '%s\n' "$state_vals" | sed -n '1p')"
    pending_target="$(printf '%s\n' "$state_vals" | sed -n '2p')"
    manual_next_target="$(printf '%s\n' "$state_vals" | sed -n '3p')"
  fi

  {
    printf 'session=%s\n' "$session_name"
    printf 'stage=%s\n' "$stage"
    [[ -n "$stop_reason" ]] && printf 'stop_reason=%s\n' "$stop_reason"
    [[ -n "$current_rank" ]] && printf 'current_rank=%s\n' "$current_rank"
    [[ -n "$current_target" ]] && printf 'current_target=%s\n' "$current_target"
    [[ -n "$pending_rank" ]] && printf 'pending_rank=%s\n' "$pending_rank"
    [[ -n "$pending_target" ]] && printf 'pending_target=%s\n' "$pending_target"
    [[ -n "$manual_next_target" ]] && printf 'manual_next_target=%s\n' "$manual_next_target"
    [[ -n "$failure_detail" ]] && printf 'failure_detail=%s\n' "$failure_detail"
    printf 'resume_command=bash scripts/quicksearchmax.sh --resume-run-dir %s --duration %s --per-run-timeout %s --review-timeout %s --parallel-sessions %s --progress-interval %s --sandbox %s%s%s%s\n' \
      "$RUN_DIR" "$DURATION" "$PER_RUN_TIMEOUT" "$REVIEW_TIMEOUT" "$PARALLEL_SESSIONS" "$PROGRESS_INTERVAL" "$SANDBOX" \
      "${MODEL:+ --model $MODEL}" \
      "${REASONING_EFFORT:+ --reasoning-effort $REASONING_EFFORT}" \
      "$( [[ "$INCLUDE_SNIPPET" -eq 0 ]] && printf ' --no-include-snippet' )" \
      "$( [[ "$UNSAFE_BYPASS" -eq 1 ]] && printf ' --unsafe-bypass' )"
  } > "$hint_file"

  printf '[session:%s] stopped stage=%s' "$session_name" "$stage"
  [[ -n "$pending_rank" ]] && printf ' pending_rank=%s' "$pending_rank"
  if [[ -n "$pending_target" ]]; then
    printf ' pending_target=%s' "$pending_target"
  elif [[ -n "$current_target" ]]; then
    printf ' current_target=%s' "$current_target"
  fi
  [[ -n "$failure_detail" ]] && printf ' detail=%s' "$failure_detail"
  printf '\n'
  printf '[session:%s] resume hint: %s\n' "$session_name" "$hint_file"
}

run_review_for_session() {
  local session_name="$1"
  local final_dir="$RUN_DIR/$session_name"
  if compgen -G "$final_dir/autopilot/findings/finding-*.txt" > /dev/null; then
    printf '[session:%s] review\n' "$session_name"
    python3 -m oss_harness review "$final_dir" \
      --timeout "$REVIEW_TIMEOUT" \
      "${COMMON_ARGS[@]}"
  else
    printf '[session:%s] review skipped: no findings\n' "$session_name"
    python3 -m oss_harness.quicksearchmax init-empty-review --session-dir "$final_dir"
  fi
}

run_session() {
  local session_name="$1"
  local signals_mode="$2"
  local signals_path="$3"
  local work_out="$RUN_DIR/.${session_name}-scan"
  local final_dir="$RUN_DIR/$session_name"
  local scan_output=""
  local scan_session=""
  local -a scan_args
  local -a autopilot_args
  local status_file="$final_dir/autopilot/AUTOPILOT_STATUS.txt"
  local review_index="$final_dir/review/review_index.json"
  local existing_stage=""

  if [[ -f "$status_file" ]]; then
    existing_stage="$(awk -F= '/^stage=/{print $2; exit}' "$status_file")"
  fi

  if [[ -d "$final_dir" && -f "$final_dir/targets.json" ]]; then
    printf '[session:%s] resume using existing session: %s\n' "$session_name" "$final_dir"
    if [[ "$existing_stage" == "finished" && -f "$review_index" ]]; then
      printf '[session:%s] already finished, skipping\n' "$session_name"
      return 0
    fi
  else
    printf '[session:%s] scan\n' "$session_name"
    scan_args=(
      "$REPO_PATH"
      --policy "$POLICY_PATH"
      --out "$work_out"
    )
    if [[ "$signals_mode" == "with-signals" ]]; then
      scan_args+=(--signals-json "$signals_path")
    fi
    scan_output="$({
      python3 -m oss_harness scan "${scan_args[@]}"
    })"
    printf '%s\n' "$scan_output"

    scan_session="$(printf '%s\n' "$scan_output" | awk -F= '/^session=/{print $2; exit}')"
    if [[ -z "$scan_session" ]]; then
      printf 'failed to parse session path from scan output for %s\n' "$session_name" >&2
      return 1
    fi

    mv "$scan_session" "$final_dir"
  fi

  autopilot_args=(
    "$final_dir"
    --duration "$DURATION"
    --per-run-timeout "$PER_RUN_TIMEOUT"
    "${COMMON_ARGS[@]}"
  )
  if [[ "$INCLUDE_SNIPPET" -eq 1 ]]; then
    autopilot_args+=(--include-snippet)
  fi

  printf '[session:%s] autopilot: %s\n' "$session_name" "$final_dir"
  local autopilot_rc=0
  set +e
  python3 -m oss_harness autopilot "${autopilot_args[@]}"
  autopilot_rc=$?
  set -e

  if [[ "$autopilot_rc" -eq 0 ]]; then
    run_review_for_session "$session_name"
    return 0
  fi

  write_session_stop_hint "$session_name"
  return "$autopilot_rc"
}

run_session_job() {
  local session_name="$1"
  local signals_mode="$2"
  local signals_path="$3"
  local result_file="$RESULTS_DIR/$session_name.env"
  local rc=0
  set +e
  run_session "$session_name" "$signals_mode" "$signals_path"
  rc=$?
  set -e
  {
    printf 'session=%s\n' "$session_name"
    printf 'rc=%s\n' "$rc"
  } > "$result_file"
  return 0
}

if [[ "$RESUME_MODE" -eq 0 ]]; then
  printf '[1/8] bootstrap: %s\n' "$REPO_PATH"
  cd "$HARNESS_ROOT"
  python3 -m oss_harness bootstrap "$REPO_PATH" "${COMMON_ARGS[@]}"

  printf '[2/8] build signal variants\n'
  python3 -m oss_harness.quicksearchmax build-signals \
    --variant coldrisk \
    --input "$DEFAULT_SIGNALS_PATH" \
    --output "$COLDRISK_SIGNALS_PATH"
  python3 -m oss_harness.quicksearchmax build-signals \
    --variant hotrisk \
    --input "$DEFAULT_SIGNALS_PATH" \
    --output "$HOTRISK_SIGNALS_PATH"
else
  printf '[resume] run_dir=%s\n' "$RUN_DIR"
  cd "$HARNESS_ROOT"
  if [[ ! -f "$COLDRISK_SIGNALS_PATH" && -f "$DEFAULT_SIGNALS_PATH" ]]; then
    python3 -m oss_harness.quicksearchmax build-signals \
      --variant coldrisk \
      --input "$DEFAULT_SIGNALS_PATH" \
      --output "$COLDRISK_SIGNALS_PATH"
  fi
  if [[ ! -f "$HOTRISK_SIGNALS_PATH" && -f "$DEFAULT_SIGNALS_PATH" ]]; then
    python3 -m oss_harness.quicksearchmax build-signals \
      --variant hotrisk \
      --input "$DEFAULT_SIGNALS_PATH" \
      --output "$HOTRISK_SIGNALS_PATH"
  fi
fi

session_specs=(
  "default|with-signals|$DEFAULT_SIGNALS_PATH|3/8"
  "nosignal|no-signals||4/8"
  "coldrisk|with-signals|$COLDRISK_SIGNALS_PATH|5/8"
  "hotrisk|with-signals|$HOTRISK_SIGNALS_PATH|6/8"
)

active_jobs=0
monitor_pid=""
session_pids=()

stop_progress_monitor() {
  if [[ -n "${monitor_pid:-}" ]]; then
    kill "$monitor_pid" 2>/dev/null || true
    wait "$monitor_pid" 2>/dev/null || true
    monitor_pid=""
  fi
}
trap stop_progress_monitor EXIT

if [[ "$PARALLEL_SESSIONS" -gt 1 ]]; then
  monitor_progress "${session_names[@]}" &
  monitor_pid="$!"
fi

for spec in "${session_specs[@]}"; do
  IFS='|' read -r session_name signals_mode signals_path progress_label <<< "$spec"
  printf '[%s] %s session\n' "$progress_label" "$session_name"
  if [[ "$PARALLEL_SESSIONS" -gt 1 ]]; then
    run_session_job "$session_name" "$signals_mode" "$signals_path" &
    session_pids+=("$!")
    active_jobs=$((active_jobs + 1))
    if [[ "$active_jobs" -ge "$PARALLEL_SESSIONS" ]]; then
      wait -n || true
      active_jobs=$((active_jobs - 1))
    fi
  else
    run_session_job "$session_name" "$signals_mode" "$signals_path"
  fi
done

if [[ "$PARALLEL_SESSIONS" -gt 1 ]]; then
  for session_pid in "${session_pids[@]}"; do
    wait "$session_pid" 2>/dev/null || true
  done
  stop_progress_monitor
fi

resume_required=0
hard_failure=0
for session_name in "${session_names[@]}"; do
  result_file="$RESULTS_DIR/$session_name.env"
  rc=1
  if [[ -f "$result_file" ]]; then
    rc="$(awk -F= '/^rc=/{print $2; exit}' "$result_file")"
  fi
  if [[ "$rc" -eq 75 ]]; then
    resume_required=1
  elif [[ "$rc" -ne 0 ]]; then
    hard_failure=1
  fi
done

if [[ "$hard_failure" -ne 0 ]]; then
  printf '[error] one or more sessions failed before completion\n' >&2
  for session_name in "${session_names[@]}"; do
    result_file="$RESULTS_DIR/$session_name.env"
    if [[ -f "$result_file" ]]; then
      rc="$(awk -F= '/^rc=/{print $2; exit}' "$result_file")"
      if [[ "$rc" -ne 0 && "$rc" -ne 75 ]]; then
        write_session_stop_hint "$session_name"
      fi
    fi
  done
  exit 1
fi

if [[ "$resume_required" -ne 0 ]]; then
  printf '[resume-required] one or more sessions stopped due to token/auth expiry\n'
  for session_name in "${session_names[@]}"; do
    result_file="$RESULTS_DIR/$session_name.env"
    if [[ -f "$result_file" ]]; then
      rc="$(awk -F= '/^rc=/{print $2; exit}' "$result_file")"
      if [[ "$rc" -eq 75 ]]; then
        write_session_stop_hint "$session_name"
      fi
    fi
  done
  printf '[resume-required] rerun with: bash scripts/quicksearchmax.sh --resume-run-dir %s --duration %s --per-run-timeout %s --review-timeout %s --parallel-sessions %s --progress-interval %s --sandbox %s%s%s%s\n' \
    "$RUN_DIR" "$DURATION" "$PER_RUN_TIMEOUT" "$REVIEW_TIMEOUT" "$PARALLEL_SESSIONS" "$PROGRESS_INTERVAL" "$SANDBOX" \
    "${MODEL:+ --model $MODEL}" \
    "${REASONING_EFFORT:+ --reasoning-effort $REASONING_EFFORT}" \
    "$( [[ "$INCLUDE_SNIPPET" -eq 0 ]] && printf ' --no-include-snippet' )" \
    "$( [[ "$UNSAFE_BYPASS" -eq 1 ]] && printf ' --unsafe-bypass' )"
  exit 75
fi

printf '[7/8] merged review\n'
python3 -m oss_harness.quicksearchmax merge-reviews \
  --out "$RUN_DIR/merged-review" \
  --session "default=$RUN_DIR/default" \
  --session "nosignal=$RUN_DIR/nosignal" \
  --session "coldrisk=$RUN_DIR/coldrisk" \
  --session "hotrisk=$RUN_DIR/hotrisk"

printf '[8/8] complete\n'
printf '\nDone.\n'
printf 'run_dir=%s\n' "$RUN_DIR"
printf 'policy=%s\n' "$POLICY_PATH"
printf 'default_signals=%s\n' "$DEFAULT_SIGNALS_PATH"
printf 'coldrisk_signals=%s\n' "$COLDRISK_SIGNALS_PATH"
printf 'hotrisk_signals=%s\n' "$HOTRISK_SIGNALS_PATH"
printf 'default_session=%s\n' "$RUN_DIR/default"
printf 'nosignal_session=%s\n' "$RUN_DIR/nosignal"
printf 'coldrisk_session=%s\n' "$RUN_DIR/coldrisk"
printf 'hotrisk_session=%s\n' "$RUN_DIR/hotrisk"
printf 'merged_review=%s\n' "$RUN_DIR/merged-review"
