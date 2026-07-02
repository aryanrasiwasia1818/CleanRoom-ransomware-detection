# CleanRoom 🧬🔒

**A ransomware-resilience engine that does storage forensics on immutable backup snapshots.**

> Detects ransomware in backups at high precision and pinpoints your last clean snapshot across the timeline — recover in minutes, not days.

CleanRoom analyzes the **deltas between backup snapshots** — block-level entropy spikes (the encryption signature), file-change velocity, and mass deletion/modification patterns — to catch ransomware the way Rubrik's Anomaly Detection does. Then it does the distinctly-Rubrik part: it **pinpoints the exact last-clean recovery point** and **computes the blast radius** across the backup timeline.

It is *not* an endpoint agent and never touches production. It reasons purely over metadata and statistical fingerprints of immutable data — the same posture a real backup-security platform takes.

👉 **New here? Read [`ABOUT.md`](ABOUT.md)** for a plain-English explanation of what this does, how it works end to end, who it's for, and why each piece of the tech stack was chosen — with a workflow diagram.

---

## Quick start (one command)

```bash
git clone <your-repo-url> cleanroom      # or unzip the folder
cd cleanroom
./install.sh
```

`install.sh` creates an isolated virtualenv, installs everything, and then runs a live demo: it simulates a LockBit-style attack across a backup timeline and shows you the forensic report.

Prefer to set up without the demo? `./install.sh --no-demo`.

> **Requirements:** Python 3.10+ and `pip`. Nothing else. (macOS / Linux / WSL. On Windows use WSL or run the manual steps below in PowerShell.)

---

## Run it locally

After `install.sh`, activate the environment once per shell:

```bash
source .venv/bin/activate
```

Then use any of these:

```bash
# 1. See it work end-to-end (simulate an attack, then analyze it)
cleanroom demo --family lockbit          # fast, loud rename+encrypt strain
cleanroom demo --family intermittent     # stealthy, partial "slow-burn" encryption
cleanroom demo --family wiper            # destructive mass-deletion strain

# 2. Explore the same timeline in the web dashboard
cleanroom serve --data data/demo         # → http://127.0.0.1:8000

# 3. Prove the detection quality (precision / recall over many runs)
cleanroom benchmark

# 4. Do the two steps yourself
cleanroom simulate --family lockbit --out data/snapshots --seed 42
cleanroom analyze  --data data/snapshots
cleanroom analyze  --data data/snapshots --json   # machine-readable output

cleanroom --help                         # all commands and flags
```

You can also run everything without installing the console script:

```bash
python -m cleanroom demo
```

### One-shot demo **with** the dashboard

```bash
cleanroom demo --serve      # simulate + analyze, then open the dashboard
```

---

## What you'll see

The CLI prints a snapshot-by-snapshot timeline with an anomaly score, a verdict
(`CLEAN` / `SUSPICIOUS` / `COMPROMISED`) and the single strongest signal behind
each verdict, followed by a **Recovery Plan** — last clean snapshot, first
compromised snapshot, and the blast radius. Example (LockBit demo):

```
 0004 ◀ LAST CLEAN   71   1 / 6 / 0    ░░░░░░░░░░░░ 0.09   CLEAN         mass_ops · modified 9% of the corpus
 0005 ◀ INFECTION    78   7 / 50 / 0   ██████████░░ 0.82   COMPROMISED   entropy · 64% of changed files now high-entropy, +3.54 bits/byte

 ⚠  RANSOMWARE DETECTED
 Last clean recovery point : 0004
 First compromised snapshot: 0005
 Blast radius: 57 files affected · 0.3 MB · 1 snapshot(s) impacted
 → Restore from snapshot 0004. Do NOT restore from 0005 or later.
```

The web dashboard renders the same analysis as an interactive timeline chart,
KPI cards, and a forensic table.

---

## Manual setup (if you skip `install.sh`)

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .                   # installs CleanRoom + deps, adds `cleanroom` command
cleanroom demo
```

---

## Running the tests

```bash
source .venv/bin/activate
pip install -e ".[dev]"     # if you didn't already
pytest                      # 28 tests: unit + end-to-end + a precision guard
```

The suite simulates real attacks on a temporary directory and runs the full
capture → diff → detect → recover pipeline, plus a benchmark test that guards the
headline precision claim.

---

## Project layout

```
cleanroom/
├── install.sh                  one-command local setup + demo
├── README.md                   you are here
├── ABOUT.md                    plain-English explainer + workflow diagram
├── pyproject.toml              packaging, deps, `cleanroom` entrypoint
├── docs/workflow.svg           the end-to-end workflow diagram
├── tests/                      pytest suite (unit + e2e + benchmark)
└── cleanroom/
    ├── domain/                 pure data model (snapshots, deltas, verdicts, recovery)
    ├── services/               entropy, capture, diff, feature extraction
    ├── detection/              heuristic detectors (Strategy) + ML + scorer
    ├── recovery/               last-clean point + blast radius
    ├── simulator/              ransomware families + timeline generator
    ├── infrastructure/         append-only snapshot repository
    ├── interfaces/             CLI, FastAPI, web dashboard
    ├── app.py                  the CleanRoomApp facade (used by every interface)
    ├── ports.py                abstract interfaces (Dependency-Inversion seams)
    └── config.py               all tunables in one typed place
```

The architecture is layered (domain → services → detection/recovery → app → interfaces) and follows SOLID: detectors are interchangeable **Strategy** objects, storage sits behind a **Repository** port, ransomware families are pluggable strategies built with the **Template Method** pattern, and every interface talks to a single **Facade**. See `ABOUT.md` for the design rationale.

---

## Configuration

Everything tunable lives in `cleanroom/config.py`. A few high-value knobs can be
overridden via environment variables without touching code:

| Variable | Meaning | Default |
|---|---|---|
| `CLEANROOM_SUSPICIOUS_THRESHOLD` | fused score to flag *suspicious* | `0.30` |
| `CLEANROOM_COMPROMISED_THRESHOLD` | fused score to flag *compromised* | `0.50` |
| `CLEANROOM_HIGH_ENTROPY` | bits/byte treated as "encrypted" | `7.9` |
| `CLEANROOM_STORAGE_ROOT` | default snapshot store location | `data/snapshots` |

---

## License

MIT — see `pyproject.toml`. Built as a portfolio/demonstration project inspired by Rubrik's data-security approach; not affiliated with Rubrik, Inc.
