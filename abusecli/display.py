import pandas as pd

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .constants import RISK_COLORS, RISK_CRITICAL_MIN, RISK_HIGH_MIN, RISK_MEDIUM_MIN

console = Console()


def print_success(message: str) -> None:
    print(f"\033[92m[+]\033[0m {message}")


def print_error(message: str) -> None:
    print(f"\033[91m[!]\033[0m {message}")


def print_info(message: str) -> None:
    print(f"\033[94m[i]\033[0m {message}")


def print_warning(message: str) -> None:
    print(f"\033[93m[~]\033[0m {message}")


def build_score_bar(score: int, width: int = 15) -> Text:
    filled = round(score / 100 * width)
    empty = width - filled

    if score >= RISK_CRITICAL_MIN:
        color = "red"
    elif score >= RISK_HIGH_MIN:
        color = "dark_orange"
    elif score >= RISK_MEDIUM_MIN:
        color = "yellow"
    else:
        color = "green"

    bar = Text()
    bar.append("#" * filled, style=color)
    bar.append("." * empty, style="dim")
    bar.append(f" {score}%", style=f"bold {color}")
    return bar


def display_results(df: pd.DataFrame) -> None:
    table = Table(
        title="IP Analysis Results",
        show_lines=True,
        header_style="bold cyan",
        border_style="dim",
    )

    has_reports = "totalReports" in df.columns
    has_last_reported = "lastReportedAt" in df.columns

    table.add_column("IP Address", style="bold white", no_wrap=True)
    table.add_column("Risk", justify="center")
    table.add_column("Score", justify="center", min_width=20)
    table.add_column("Country", justify="center")
    table.add_column("Whitelisted", justify="center")
    table.add_column("TOR", justify="center")
    table.add_column("Public", justify="center")
    if has_reports:
        table.add_column("Reports", justify="right")
    if has_last_reported:
        table.add_column("Last Reported", justify="center", no_wrap=True)

    for _, row in df.iterrows():
        risk = str(row.get("risk_level", "N/A"))
        risk_color = RISK_COLORS.get(risk, "white")
        score = int(row.get("abuseConfidenceScore", 0))

        cells = [
            str(row.get("ipAddress", "N/A")),
            Text(risk.upper(), style=f"bold {risk_color}"),
            build_score_bar(score),
            str(row.get("countryCode", "N/A")),
            "Yes" if row.get("isWhitelisted") else "No",
            Text("Yes", style="bold red") if row.get("isTor") else Text("No"),
            "Yes" if row.get("isPublic") else Text("No", style="dim"),
        ]

        if has_reports:
            report_count = int(row.get("totalReports", 0))
            report_text = Text(str(report_count))
            if report_count > 100:
                report_text.stylize("bold red")
            elif report_count > 10:
                report_text.stylize("dark_orange")
            cells.append(report_text)

        if has_last_reported:
            last = str(row.get("lastReportedAt") or "Never")
            if last != "Never" and last != "None":
                last = last[:10]
            cells.append(Text(last, style="dim" if last == "Never" else ""))

        table.add_row(*cells)

    console.print()
    console.print(table)

    total = len(df)
    risk_counts = df["risk_level"].value_counts() if "risk_level" in df.columns else pd.Series()

    summary_lines = [f"[bold]Total IPs:[/bold]  {total}"]

    for level in ["critical", "high", "medium", "low"]:
        count = risk_counts.get(level, 0)
        color = RISK_COLORS.get(level, "white")
        bar_width = round(count / total * 20) if total > 0 else 0
        bar = "#" * bar_width + "." * (20 - bar_width)
        summary_lines.append(
            f"[{color}]{level.capitalize():10s}[/{color}]  {count:>3d}  [{color}]{bar}[/{color}]"
        )

    if "countryCode" in df.columns:
        unique_countries = df["countryCode"].nunique()
        summary_lines.append(f"[bold]Countries:[/bold]  {unique_countries}")

    if "isTor" in df.columns:
        tor_count = df["isTor"].sum()
        if tor_count > 0:
            summary_lines.append(f"[bold red]TOR nodes:[/bold red] {tor_count}")

    if has_reports:
        total_reports = int(df["totalReports"].sum())
        never_reported = int((df["totalReports"] == 0).sum())
        summary_lines.append(f"[bold]Total reports:[/bold] {total_reports}")
        if never_reported:
            summary_lines.append(f"[dim]Never reported:  {never_reported}[/dim]")

    console.print()
    console.print(Panel("\n".join(summary_lines), title="Summary", border_style="cyan", expand=False))
    console.print()


def display_recent_activity(reports_by_ip: dict[str, list]) -> None:
    if not reports_by_ip:
        return

    lines = []
    for ip, reports in reports_by_ip.items():
        if not reports:
            continue
        lines.append(f"[bold cyan]{ip}[/bold cyan]  ({len(reports)} report(s))")
        for r in reports[:5]:
            reported_at = str(r.get("reportedAt", "N/A"))[:19]
            categories = r.get("categories", [])
            reporter_cc = r.get("reporterCountryCode", "?")
            comment = r.get("comment", "").strip()
            comment_preview = f" — {comment[:80]}" if comment else ""
            lines.append(
                f"  [dim]{reported_at}[/dim]  cc={reporter_cc}  cat={categories}{comment_preview}"
            )
        if len(reports) > 5:
            lines.append(f"  [dim]... and {len(reports) - 5} more[/dim]")
        lines.append("")

    if lines:
        console.print()
        console.print(
            Panel(
                "\n".join(lines).rstrip(),
                title="Recent Activity",
                border_style="dim",
                expand=False,
            )
        )


def display_report_confirmation(
    df: pd.DataFrame,
    categories: list[int],
    comment: str,
    dry_run: bool = False,
) -> bool:
    total = len(df)

    table = Table(
        title="IPs queued for report" + (" (dry run)" if dry_run else ""),
        show_lines=True,
        header_style="bold yellow",
        border_style="yellow" if not dry_run else "dim",
    )

    table.add_column("IP Address", style="bold white", no_wrap=True)
    table.add_column("Risk", justify="center")
    table.add_column("Score", justify="center", min_width=18)
    table.add_column("Country", justify="center")

    for _, row in df.iterrows():
        risk = str(row.get("risk_level", "N/A"))
        risk_color = RISK_COLORS.get(risk, "white")
        score = int(row.get("abuseConfidenceScore", 0))
        table.add_row(
            str(row.get("ipAddress", "N/A")),
            Text(risk.upper(), style=f"bold {risk_color}"),
            build_score_bar(score),
            str(row.get("countryCode", "N/A")),
        )

    console.print()
    console.print(table)

    cat_str = ", ".join(str(c) for c in categories)
    summary_lines = [
        f"[bold]IPs to report:[/bold]  {total}",
        f"[bold]Categories:[/bold]    {cat_str}",
    ]
    if comment:
        summary_lines.append(f"[bold]Comment:[/bold]       {comment}")
    if dry_run:
        summary_lines.append("[dim]Dry run — no API calls will be made[/dim]")

    console.print()
    console.print(
        Panel("\n".join(summary_lines), title="Report summary", border_style="yellow", expand=False)
    )
    console.print()

    if dry_run:
        print_info("Dry run complete. Remove --dry-run to submit these reports.")
        return False

    try:
        answer = input(f"Report {total} IP(s) to AbuseIPDB? [y/N] ").strip().lower()
    except KeyboardInterrupt:
        print_error("\nAborted.")
        return False

    if answer not in ("y", "yes"):
        print_info("Aborted by user.")
        return False

    return True


def display_verbose_report(ip: str, report_data: dict) -> None:
    lines = []

    meta = {
        "IP": report_data.get("ipAddress", ip),
        "Domain": report_data.get("domain", "N/A"),
        "Hostname": report_data.get("hostnames", ["N/A"])[0] if report_data.get("hostnames") else "N/A",
        "ISP": report_data.get("isp", "N/A"),
        "Usage Type": report_data.get("usageType", "N/A"),
        "Country": report_data.get("countryCode", "N/A"),
        "Total Reports": report_data.get("totalReports", 0),
        "Distinct Users": report_data.get("numDistinctUsers", 0),
        "Last Reported": report_data.get("lastReportedAt", "N/A"),
    }

    for key, value in meta.items():
        lines.append(f"[bold]{key}:[/bold] {value}")

    reports = report_data.get("reports", [])
    if reports:
        lines.append(f"\n[bold]Reports ({len(reports)}):[/bold]")
        for r in reports[:10]:
            reported_at = str(r.get("reportedAt", "N/A"))[:19]
            comment = r.get("comment", "").strip() or "No comment"
            categories = r.get("categories", [])
            reporter_cc = r.get("reporterCountryCode", "?")
            lines.append(
                f"  [dim]{reported_at}[/dim]  cc={reporter_cc}  cat={categories} — {comment[:120]}"
            )
        if len(reports) > 10:
            lines.append(f"  [dim]... and {len(reports) - 10} more[/dim]")

    console.print()
    console.print(
        Panel(
            "\n".join(lines),
            title=f"[bold cyan]{ip}[/bold cyan]",
            border_style="dim",
            expand=False,
        )
    )