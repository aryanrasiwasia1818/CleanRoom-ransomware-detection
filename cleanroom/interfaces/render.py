"""Rich renderers — turn report objects into readable terminal output.

Kept separate from the CLI argument plumbing (SRP) so the same renderers can be
reused by tests or future interfaces.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cleanroom.app import AnalysisReport, BenchmarkReport

_VERDICT_STYLE = {
    "clean": "bold green",
    "suspicious": "bold yellow",
    "compromised": "bold red",
}


def _score_bar(score: float, width: int = 12) -> Text:
    filled = int(round(score * width))
    if score >= 0.5:
        color = "red"
    elif score >= 0.3:
        color = "yellow"
    else:
        color = "green"
    bar = Text("█" * filled + "░" * (width - filled), style=color)
    bar.append(f" {score:0.2f}", style="dim")
    return bar


def render_analysis(report: AnalysisReport, console: Console | None = None) -> None:
    console = console or Console()
    data = report.to_dict()

    table = Table(
        title="Snapshot Timeline — CleanRoom Forensic Analysis",
        title_style="bold cyan",
        expand=True,
    )
    table.add_column("Snapshot", justify="center")
    table.add_column("Files", justify="right")
    table.add_column("+ / ~ / -", justify="center")
    table.add_column("Anomaly", justify="left")
    table.add_column("Verdict", justify="center")
    table.add_column("Top signal", justify="left", ratio=2)

    for row in data["timeline"]:
        verdict = row["verdict"]
        changes = f"[green]{row['added']}[/] / [yellow]{row['modified'] + row['renamed']}[/] / [red]{row['deleted']}[/]"
        top = row["signals"][0] if row["signals"] else None
        top_txt = (
            f"{top['name']} · {top['evidence']}"
            if top and top["score"] > 0.01
            else "—"
        )
        marker = ""
        rp = data["recovery_plan"]
        if row["snapshot_id"] == rp["last_clean_snapshot_id"] and rp["incident_detected"]:
            marker = " [bold green]◀ LAST CLEAN[/]"
        if row["snapshot_id"] == rp["first_compromised_snapshot_id"]:
            marker = " [bold red]◀ INFECTION[/]"
        table.add_row(
            f"{row['snapshot_id']}{marker}",
            str(row["file_count"]),
            changes,
            _score_bar(row["anomaly_score"]),
            Text(verdict.upper(), style=_VERDICT_STYLE.get(verdict, "white")),
            top_txt,
        )
    console.print(table)

    rp = data["recovery_plan"]
    br = rp["blast_radius"]
    if rp["incident_detected"]:
        body = Text()
        body.append("⚠  RANSOMWARE DETECTED\n\n", style="bold red")
        body.append("Last clean recovery point : ", style="bold")
        body.append(f"{rp['last_clean_snapshot_id']}\n", style="bold green")
        body.append("First compromised snapshot: ", style="bold")
        body.append(f"{rp['first_compromised_snapshot_id']}\n", style="bold red")
        body.append("Detection confidence      : ", style="bold")
        body.append(f"{rp['confidence']:.0%}\n\n")
        body.append("Blast radius\n", style="bold underline")
        body.append(
            f"  {br['files_encrypted']} encrypted · "
            f"{br['files_deleted']} deleted · "
            f"{br['files_renamed']} renamed · "
            f"{br['files_added']} added (notes/payloads)\n"
        )
        body.append(
            f"  {br['total_files_affected']} files total · "
            f"{br['bytes_affected'] / 1_048_576:.1f} MB affected · "
            f"{br['snapshots_impacted']} snapshot(s) impacted\n\n"
        )
        body.append("Recommendation\n", style="bold underline")
        body.append("  " + rp["recommendation"])
        console.print(Panel(body, title="Recovery Plan", border_style="red"))
    else:
        console.print(
            Panel(
                Text(rp["summary"], style="bold green"),
                title="Recovery Plan",
                border_style="green",
            )
        )


def render_benchmark(report: BenchmarkReport, console: Console | None = None) -> None:
    console = console or Console()
    d = report.to_dict()

    summary = Text()
    summary.append("Detection quality over ", style="bold")
    summary.append(f"{d['runs']} simulated timelines\n\n", style="bold cyan")
    summary.append(f"  Precision : {d['precision']:.1%}\n", style="bold green")
    summary.append(f"  Recall    : {d['recall']:.1%}\n")
    summary.append(f"  F1 score  : {d['f1']:.1%}\n")
    summary.append(f"  Accuracy  : {d['accuracy']:.1%}\n\n")
    c = d["confusion"]
    summary.append(
        f"  TP={c['tp']}  FP={c['fp']}  TN={c['tn']}  FN={c['fn']}", style="dim"
    )
    console.print(Panel(summary, title="CleanRoom Benchmark", border_style="cyan"))

    table = Table(title="Per-family breakdown", expand=True)
    table.add_column("Family")
    table.add_column("Precision", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("F1", justify="right")
    for fam, m in d["per_family"].items():
        table.add_column
        table.add_row(
            fam, f"{m['precision']:.1%}", f"{m['recall']:.1%}", f"{m['f1']:.1%}"
        )
    console.print(table)
