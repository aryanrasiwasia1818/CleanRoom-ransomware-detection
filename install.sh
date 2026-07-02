#!/usr/bin/env bash
#
# CleanRoom — one-shot local setup.
#
# Creates an isolated virtualenv, installs CleanRoom + dependencies, and (unless
# --no-demo is passed) generates and analyzes a demo ransomware timeline so you
# can see it work immediately.
#
# Usage:
#   ./install.sh              # full setup + run a demo
#   ./install.sh --no-demo    # just set up the environment
#
set -euo pipefail

cd "$(dirname "$0")"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
say() { echo -e "${CYAN}▶ $*${NC}"; }
ok()  { echo -e "${GREEN}✓ $*${NC}"; }

RUN_DEMO=1
[[ "${1:-}" == "--no-demo" ]] && RUN_DEMO=0

# --- 1. locate a suitable Python ------------------------------------------- #
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Python 3 is required but was not found. Install Python 3.10+ and retry."
  exit 1
fi
PYVER=$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
say "Using Python $PYVER ($PYTHON)"
"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)' || {
  echo -e "${YELLOW}Python 3.10+ recommended; found $PYVER. Continuing anyway.${NC}"
}

# --- 2. virtualenv --------------------------------------------------------- #
if [[ ! -d ".venv" ]]; then
  say "Creating virtual environment (.venv)"
  "$PYTHON" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
ok "Virtual environment active"

# --- 3. dependencies + package (editable) ---------------------------------- #
say "Upgrading pip"
python -m pip install --upgrade pip >/dev/null
say "Installing CleanRoom and dependencies (this can take a minute)…"
python -m pip install -e . >/dev/null
ok "Installed CleanRoom $(python -c 'import cleanroom; print(cleanroom.__version__)')"

# --- 4. smoke demo --------------------------------------------------------- #
if [[ "$RUN_DEMO" -eq 1 ]]; then
  echo
  say "Running a demo (LockBit-style attack)…"
  echo
  python -m cleanroom demo --family lockbit --data data/demo
fi

echo
ok "Setup complete."
cat <<'EOF'

Next steps (activate the venv first):

  source .venv/bin/activate

  cleanroom demo --family intermittent   # try the stealthy strain
  cleanroom serve --data data/demo       # open the web dashboard (http://127.0.0.1:8000)
  cleanroom benchmark                     # measure detection precision/recall
  cleanroom --help                        # all commands

EOF
