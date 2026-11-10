#!/usr/bin/env bash
# Run the two live-model experiments. Needs: ANTHROPIC_API_KEY, `pip install -e '.[llm]'`.
#
#   1. Sandbox-ID benchmark (cheap, no code execution): MODELS="claude-opus-5-5 claude-sonnet-5-5"
#   2. Agent study (EXECUTES MODEL-CHOSEN SHELL COMMANDS): only with RUN_STUDY=1, only in a disposable sandbox.
#
# Use a scoped, low-spend API key. Commands the model runs do not receive the key via their environment
# (allowlisted env), but they run as your user in the same sandbox, so isolation of the sandbox is on you.
set -euo pipefail
: "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY first}"
MODELS=${MODELS:-claude-opus-5-5}
TRIALS=${TRIALS:-5}
OUT=${OUT:-results/$(date +%Y%m%d-%H%M)}
mkdir -p "$OUT"

echo "== benchmark: $MODELS"
args=(); for m in $MODELS; do args+=(--model "$m"); done
python -m evalaware bench data/measured data/reference "${args[@]}" --out "$OUT/bench.json" | tee "$OUT/bench.txt"

if [[ "${RUN_STUDY:-0}" == "1" ]]; then
  echo "== agent study: $TRIALS trials/cell, 3 cues x 2 home modes x 3 tasks (executes commands!)"
  for m in $MODELS; do
    python -m evalaware study --model "$m" --trials "$TRIALS" --allow-exec --out "$OUT/study-$m.jsonl"
    python -m evalaware report "$OUT/study-$m.jsonl" | tee "$OUT/study-$m.txt"
  done
else
  echo "(skipping agent study; set RUN_STUDY=1 inside a disposable sandbox to run it)"
fi
echo "results in $OUT"
