#!/usr/bin/env bash
#
# perf_gate.sh — fail the build when the hot-path cycle profile regresses
# (the CI cycle_profile job used to print numbers but never fail on a
# slowdown).
#
# Runs fast_proxy::tests::cycle_profile_report (release, cycle_profile feature)
# and compares the measured mean of build_upstream_head / build_response_head
# against the authored baseline (2026-07-30: upstream 121.0 ns, response
# 80.1 ns), failing when either exceeds BASELINE * PERF_FACTOR.
#
# The bench box is noisy, so the factor defaults to 1.5x — a real regression
# shows up as >1.5x, run noise does not. Set SKIP_PERF_GATE=1 to skip entirely
# (local development on a loaded machine), or override PERF_FACTOR for a
# one-off strict pass.
#
# Quiet-run methodology — for trustworthy numbers, not just a pass/fail:
#   * measure on an idle box: `uptime` load < ~1.0, no browser/CI colocated;
#   * the report test itself does 200k iterations with a 20k warmup pass, so
#     frequency scaling / caches / branch predictor are settled BEFORE the
#     instrumented window;
#   * take the MEDIAN of >=3 runs, not a single one (single-run scatter on a
#     loaded box measured 154-191ns for the same binary);
#   * pin the bench thread: `taskset -c <core> nice -n -10 ...` only helps
#     against preemption, NOT against DRAM/L3 contention — a busy neighbour
#     core still inflates memory-touching header builders.
#
# Usage:   ./bench/perf_gate.sh        # runs the gate
#          SKIP_PERF_GATE=1 ./bench/perf_gate.sh
set -euo pipefail

[ "${SKIP_PERF_GATE:-0}" = "1" ] && { echo "perf_gate: SKIP_PERF_GATE=1, skipping"; exit 0; }

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

BASELINE_UPSTREAM="${BASELINE_UPSTREAM:-121.0}"   # ns, measured 2026-07-30
BASELINE_RESPONSE="${BASELINE_RESPONSE:-80.1}"    # ns
PERF_FACTOR="${PERF_FACTOR:-1.5}"
LIMIT_UPSTREAM=$(python3 -c "print($BASELINE_UPSTREAM * $PERF_FACTOR)")
LIMIT_RESPONSE=$(python3 -c "print($BASELINE_RESPONSE * $PERF_FACTOR)")

echo "==> running cycle_profile_report (limit upstream <${LIMIT_UPSTREAM}ns, response <${LIMIT_RESPONSE}ns)"
cd "$ROOT"
OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT
cargo test --release --features cycle_profile -- --ignored --nocapture cycle_profile_report >"$OUT" 2>&1

# The test prints the report table twice (live + final dump); take the last
# occurrence of each site's mean, which is the most stable.
upstream_mean="$(grep -E '^  build_upstream_head ' "$OUT" | tail -1 | sed -E 's/.*mean=([0-9]+).*/\1/')"
response_mean="$(grep -E '^  build_response_head ' "$OUT" | tail -1 | sed -E 's/.*mean=([0-9]+).*/\1/')"

echo "==> build_upstream_head mean = ${upstream_mean}ns (limit ${LIMIT_UPSTREAM}ns)"
echo "==> build_response_head mean = ${response_mean}ns (limit ${LIMIT_RESPONSE}ns)"

ok=1
if [ -n "$upstream_mean" ] && awk "BEGIN{exit !($upstream_mean > $LIMIT_UPSTREAM)}"; then
    echo "!! perf regression: build_upstream_head ${upstream_mean}ns > ${LIMIT_UPSTREAM}ns" >&2
    ok=0
fi
if [ -n "$response_mean" ] && awk "BEGIN{exit !($response_mean > $LIMIT_RESPONSE)}"; then
    echo "!! perf regression: build_response_head ${response_mean}ns > ${LIMIT_RESPONSE}ns" >&2
    ok=0
fi

if [ "$ok" != "1" ]; then
    echo "!! perf gate FAILED (SKIP_PERF_GATE=1 to bypass on a loaded box)" >&2
    exit 1
fi
echo "==> perf gate OK"
