"""Command-line interface for CleanRoom.

Thin adapter: parse args → call the :class:`~cleanroom.app.CleanRoomApp` facade →
render. No business logic lives here.

Commands
--------
  simulate    generate a labelled ransomware timeline into a snapshot store
  analyze     run the forensic pipeline over a snapshot store and report
  benchmark   measure detection precision/recall over many simulations
  demo        simulate + analyze in one step (optionally launch the dashboard)
  serve       start the API + web dashboard against a snapshot store
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console

from cleanroom import __version__
from cleanroom.app import CleanRoomApp
from cleanroom.config import Config
from cleanroom.interfaces.render import render_analysis, render_benchmark
from cleanroom.simulator import FAMILIES

_DEFAULT_STORE = "data/snapshots"
_console = Console()


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _clear_store(root: str) -> None:
    """Remove existing snapshot manifests so a fresh timeline can be written."""
    p = Path(root)
    if p.exists():
        for manifest in p.glob("*.snapshot.json"):
            manifest.unlink()


def _app() -> CleanRoomApp:
    return CleanRoomApp(Config.from_env())


# --------------------------------------------------------------------------- #
# command handlers
# --------------------------------------------------------------------------- #
def cmd_simulate(args: argparse.Namespace) -> int:
    if args.force:
        _clear_store(args.out)
    result = _app().simulate(
        family_name=args.family,
        root=args.out,
        clean_snapshots=args.clean,
        scale=args.scale,
        seed=args.seed,
    )
    _console.print(
        f"[bold green]✓[/] Simulated [cyan]{result.family_name}[/] timeline: "
        f"{len(result.clean_ids)} clean + {len(result.infected_ids)} infected "
        f"snapshot(s) → [dim]{args.out}[/]"
    )
    _console.print(
        f"  Infection begins at snapshot [red]{result.first_infected_id}[/]. "
        f"Run [bold]cleanroom analyze --data {args.out}[/] to investigate."
    )
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    app = _app()
    repo = app.repository(args.data)
    if len(repo) == 0:
        _console.print(
            f"[bold red]No snapshots found in {args.data}.[/] "
            "Run 'cleanroom simulate' or 'cleanroom demo' first."
        )
        return 1
    report = app.analyze(repo)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        render_analysis(report, _console)
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    report = _app().benchmark(
        runs_per_family=args.runs,
        families=args.families,
        scale=args.scale,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        render_benchmark(report, _console)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    out = args.data
    _clear_store(out)
    _console.rule("[bold cyan]CleanRoom demo")
    cmd_simulate(
        argparse.Namespace(
            family=args.family, out=out, clean=4, scale=args.scale,
            seed=args.seed, force=True,
        )
    )
    _console.print()
    cmd_analyze(argparse.Namespace(data=out, json=False))
    if args.serve:
        _console.print()
        _console.print("[bold]Launching dashboard…[/]")
        return cmd_serve(argparse.Namespace(data=out, host=args.host, port=args.port))
    _console.print(
        f"\n[dim]Tip: run [bold]cleanroom serve --data {out}[/bold] "
        "to explore this timeline in the web dashboard.[/]"
    )
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        _console.print("[bold red]uvicorn is not installed.[/] Run install.sh first.")
        return 1
    from cleanroom.interfaces.api import create_app

    api = create_app(data_root=args.data, config=Config.from_env())
    _console.print(
        f"[bold green]CleanRoom dashboard[/] → "
        f"[cyan]http://{args.host}:{args.port}[/]  (data: {args.data})"
    )
    uvicorn.run(api, host=args.host, port=args.port, log_level="warning")
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cleanroom",
        description="Ransomware-resilience engine: storage forensics on immutable snapshots.",
    )
    parser.add_argument("--version", action="version", version=f"cleanroom {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    families = list(FAMILIES)

    p_sim = sub.add_parser("simulate", help="generate a labelled ransomware timeline")
    p_sim.add_argument("--family", choices=families, default="lockbit")
    p_sim.add_argument("--out", default=_DEFAULT_STORE)
    p_sim.add_argument("--clean", type=int, default=4, help="clean snapshots before attack")
    p_sim.add_argument("--scale", type=int, default=6, help="corpus size multiplier")
    p_sim.add_argument("--seed", type=int, default=None)
    p_sim.add_argument("--force", action="store_true", help="overwrite existing store")
    p_sim.set_defaults(func=cmd_simulate)

    p_an = sub.add_parser("analyze", help="analyze a snapshot store")
    p_an.add_argument("--data", default=_DEFAULT_STORE)
    p_an.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p_an.set_defaults(func=cmd_analyze)

    p_bm = sub.add_parser("benchmark", help="measure detection precision/recall")
    p_bm.add_argument("--runs", type=int, default=5, help="runs per family")
    p_bm.add_argument("--families", nargs="*", choices=families, default=None)
    p_bm.add_argument("--scale", type=int, default=5)
    p_bm.add_argument("--json", action="store_true")
    p_bm.set_defaults(func=cmd_benchmark)

    p_demo = sub.add_parser("demo", help="simulate + analyze in one step")
    p_demo.add_argument("--family", choices=families, default="lockbit")
    p_demo.add_argument("--data", default="data/demo")
    p_demo.add_argument("--scale", type=int, default=6)
    p_demo.add_argument("--seed", type=int, default=7)
    p_demo.add_argument("--serve", action="store_true", help="open the dashboard after")
    p_demo.add_argument("--host", default="127.0.0.1")
    p_demo.add_argument("--port", type=int, default=8000)
    p_demo.set_defaults(func=cmd_demo)

    p_srv = sub.add_parser("serve", help="launch the API + web dashboard")
    p_srv.add_argument("--data", default="data/demo")
    p_srv.add_argument("--host", default="127.0.0.1")
    p_srv.add_argument("--port", type=int, default=8000)
    p_srv.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        _console.print("\n[dim]interrupted[/]")
        return 130
    except Exception as exc:  # user-facing: no traceback spam
        _console.print(f"[bold red]Error:[/] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
