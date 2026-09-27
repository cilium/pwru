#!/usr/bin/env bash
#
# Regression test for actions/pwru-run/action.yaml "Deploy PWRU workload" step.
#
# Guards issue #713: a Kubernetes readiness failure (rollout status / wait
# timeout) must make the step exit NONZERO, while still printing diagnostics.
#
# The real `run:` block is extracted from the action at runtime, so the test
# tracks the action instead of a hand-copied one that can drift. A stub
# `kubectl` placed first on PATH simulates a workload that never becomes Ready.
#
# Scenarios:
#    1. failure + daemonset (no nodename)    -> exit 1, diagnostics printed
#    2. failure + pod         (nodename set)  -> exit 1, diagnostics printed
#    3. success + daemonset                   -> exit 0, no diagnostics
#    4. success + pod                         -> exit 0, no diagnostics
#
set -u
dir="$(cd "$(dirname "$0")" && pwd)"        # dir of this script == actions/pwru-run
ACTION="$dir/action.yaml"

# The GitHub Action's input placeholder, kept as a literal string so the current
# shell does not try to expand it.
# shellcheck disable=SC2016
TEMPLATE='${{ inputs.nodename }}'

# --- extract + dedent (8 spaces) the "Deploy PWRU workload" run block ---------
block=$(awk '
      /^ *- *name: Deploy PWRU workload$/ { grab=1; next }
  grab && /run:[[:space:]]+\|/            { inrun=1; next }
  inrun { line=$0; sub(/^ {8}/, "", line); print line }
' "$ACTION")

# --- render {{ inputs.nodename }} to a literal value ($1) via awk (portable) --
render() {
  awk -v v="$1" -v tpl="$TEMPLATE" '
    {
    while ((i = index($0, tpl)) > 0)
         $0 = substr($0, 1, i-1) v substr($0, i + length(tpl))
    print
    }
    ' <<<"$block"
}

# --- stub kubectl; FORCE_FAIL=1 makes rollout/wait (the readiness checks) fail -
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/kubectl" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  apply)    echo "[stub] apply $*"; exit 0 ;;
  rollout)  if [ "${FORCE_FAIL:-}" = "1" ]; then echo "[stub] rollout FAIL"; exit 1; fi; echo "[stub] rollout OK"; exit 0 ;;
  wait)     if [ "${FORCE_FAIL:-}" = "1" ]; then echo "[stub] wait FAIL"; exit 1; fi; echo "[stub] wait OK"; exit 0 ;;
  describe) echo "[stub] describe $2"; exit 0 ;;
esac
echo "[stub] UNHANDLED $*" >&2; exit 2
STUB
chmod +x "$tmp/kubectl"
PATH="$tmp:$PATH"

# --- run_case <node> <force_fail> <expect_exit> <expect_diag> -----------------
rc=0
run_case() {
  local node="$1" force="$2" expect_exit="$3" expect_diag="$4"
  local rendered out code
  rendered="$(render "$node")"
  out="$(FORCE_FAIL="$force" bash -c "$rendered")"; code=$?
  echo "--- node='$node' force=$force (expect exit $expect_exit, diag=$expect_diag) ---"
  printf '%s\n' "$out"
  if [ "$code" != "$expect_exit" ]; then
    echo "FAIL: expected exit $expect_exit, got $code"; rc=1
  fi
  if [ "$expect_diag" = yes ]; then
    grep -q 'describ' <<<"$out" || { echo "FAIL: expected diagnostics, none printed"; rc=1; }
  else
    grep -q 'describ' <<<"$out" && { echo "FAIL: unexpected diagnostics on success"; rc=1; }
  fi
}

run_case ""       1 1 yes   # 1: failure + daemonset
run_case node-1   1 1 yes   # 2: failure + pod
run_case ""       0 0 no    # 3: success + daemonset
run_case node-1   0 0 no    # 4: success + pod

exit $rc
