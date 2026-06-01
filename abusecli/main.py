from enum import Enum
from types import SimpleNamespace
from typing import Optional

import typer
from typing import Annotated

from .auth import load_api_key
from .commands import cmd_check, cmd_report, cmd_load, cmd_categories
from .constants import DEFAULT_MAX_AGE_IN_DAYS
from .display import print_error


class RiskLevel(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class ExportFormat(str, Enum):
    csv = "csv"
    json = "json"
    excel = "excel"
    html = "html"
    parquet = "parquet"


class SourceFormat(str, Enum):
    csv = "csv"
    json = "json"
    excel = "excel"
    parquet = "parquet"
    auto = "auto"


app = typer.Typer(
    name="abusecli",
    help="Bulk check, report, and filter IP addresses via the AbuseIPDB API.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
)


def _resolve_api_key(token: Optional[str], verbose: bool) -> str:
    try:
        return load_api_key(SimpleNamespace(token=token, verbose=verbose))
    except KeyboardInterrupt:
        print_error("Aborted.")
        raise typer.Exit(1)
    except SystemExit:
        raise
    except Exception as e:
        print_error(f"Failed to load API key: {e}")
        raise typer.Exit(1)


@app.command()
def check(
    ips: Annotated[
        Optional[list[str]],
        typer.Option(
            "--ips", metavar="IP", help="IP address to check. Repeat for multiple."
        ),
    ] = None,
    from_file: Annotated[
        Optional[str],
        typer.Option(
            "--from-file",
            metavar="FILE",
            help="Plain-text file, one IP per line (# ignored). Use - for stdin.",
        ),
    ] = None,
    max_age: Annotated[
        int,
        typer.Option(
            "--max-age",
            metavar="DAYS",
            help=f"Only consider reports from the last N days (default: {DEFAULT_MAX_AGE_IN_DAYS}, max: 365).",
        ),
    ] = DEFAULT_MAX_AGE_IN_DAYS,
    risk_level: Annotated[
        Optional[RiskLevel],
        typer.Option(
            "--risk-level",
            "-r",
            metavar="LEVEL",
            help="Keep only IPs at this risk level.",
        ),
    ] = None,
    score: Annotated[
        Optional[int],
        typer.Option(
            "--score", metavar="N", help="Keep IPs with abuse score >= N (0-100)."
        ),
    ] = None,
    country_code: Annotated[
        Optional[str],
        typer.Option(
            "--country-code",
            metavar="CC",
            help="Keep IPs matching this ISO country code (e.g. US, DE).",
        ),
    ] = None,
    is_tor: Annotated[
        bool, typer.Option("--is-tor", help="Keep only TOR exit nodes.")
    ] = False,
    is_not_tor: Annotated[
        bool, typer.Option("--is-not-tor", help="Exclude TOR exit nodes.")
    ] = False,
    remove_private: Annotated[
        bool,
        typer.Option("--remove-private", help="Exclude private/RFC-1918 addresses."),
    ] = False,
    remove_whitelisted: Annotated[
        bool,
        typer.Option(
            "--remove-whitelisted", help="Exclude AbuseIPDB-whitelisted addresses."
        ),
    ] = False,
    export: Annotated[
        Optional[list[ExportFormat]],
        typer.Option(
            "--export",
            "-e",
            metavar="FORMAT",
            help="Export results. Repeat for multiple formats (csv/json/excel/html/parquet).",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show per-IP detail, filter trace, and API diagnostics.",
        ),
    ] = False,
    token: Annotated[
        Optional[str],
        typer.Option(
            "--token",
            metavar="KEY",
            help="API key — overrides .env and environment variable.",
        ),
    ] = None,
):
    """Query AbuseIPDB for one or more IP addresses."""
    if not ips and not from_file:
        print_error("check requires --ips and/or --from-file")
        raise typer.Exit(1)

    api_key = _resolve_api_key(token, verbose)

    args = SimpleNamespace(
        ips=ips,
        from_file=from_file,
        max_age=max_age,
        risk_level=risk_level.value if risk_level else None,
        score=score,
        country_code=country_code,
        is_tor=is_tor,
        is_not_tor=is_not_tor,
        remove_private=remove_private,
        remove_whitelisted=remove_whitelisted,
        export=[f.value for f in export] if export else None,
        verbose=verbose,
    )
    cmd_check(args, api_key)


@app.command()
def report(
    ips: Annotated[
        Optional[list[str]],
        typer.Option(
            "--ips", metavar="IP", help="IP address to report. Repeat for multiple."
        ),
    ] = None,
    from_file: Annotated[
        Optional[str],
        typer.Option(
            "--from-file",
            metavar="FILE",
            help="Plain-text file, one IP per line (# ignored). Use - for stdin.",
        ),
    ] = None,
    source: Annotated[
        Optional[str],
        typer.Option(
            "--source",
            "-s",
            metavar="FILE",
            help="Load IPs from a previous export (CSV/JSON/Excel/Parquet). Exclusive with --ips/--from-file.",
        ),
    ] = None,
    file_format: Annotated[
        SourceFormat,
        typer.Option(
            "--format",
            "-f",
            metavar="FORMAT",
            help="Source file format (default: auto-detect).",
        ),
    ] = SourceFormat.auto,
    min_score: Annotated[
        Optional[int],
        typer.Option(
            "--min-score",
            metavar="N",
            help="Only report IPs with score >= N. Only used with --source.",
        ),
    ] = None,
    categories: Annotated[
        Optional[list[int]],
        typer.Option(
            "--categories",
            metavar="ID",
            help="Category ID to report. Repeat for multiple. Run 'categories' for the full list.",
        ),
    ] = None,
    comment: Annotated[
        str,
        typer.Option(
            "--comment",
            metavar="TEXT",
            help="Free-text comment attached to every report in this batch.",
        ),
    ] = "",
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run", help="Preview the batch without submitting anything."
        ),
    ] = False,
    no_confirm: Annotated[
        bool,
        typer.Option(
            "--no-confirm", help="Skip the confirmation prompt and report immediately."
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show per-IP detail and API diagnostics."),
    ] = False,
    token: Annotated[
        Optional[str],
        typer.Option(
            "--token",
            metavar="KEY",
            help="API key — overrides .env and environment variable.",
        ),
    ] = None,
):
    """Submit abuse reports to AbuseIPDB."""
    if not ips and not from_file and not source:
        print_error("report requires --ips, --from-file, or --source")
        raise typer.Exit(1)

    if source and (ips or from_file):
        print_error("--source cannot be combined with --ips or --from-file")
        raise typer.Exit(1)

    if not categories:
        print_error("--categories is required (run 'categories' for the full list)")
        raise typer.Exit(1)

    api_key = _resolve_api_key(token, verbose)

    args = SimpleNamespace(
        ips=ips,
        from_file=from_file,
        source=source,
        format=file_format.value,
        min_score=min_score,
        categories=categories,
        comment=comment,
        dry_run=dry_run,
        no_confirm=no_confirm,
        verbose=verbose,
    )
    cmd_report(args, api_key)


@app.command()
def load(
    source: Annotated[
        Optional[str],
        typer.Option("--source", "-s", metavar="FILE", help="Source file to load."),
    ] = None,
    file_format: Annotated[
        SourceFormat,
        typer.Option(
            "--format",
            "-f",
            metavar="FORMAT",
            help="File format (default: auto-detect).",
        ),
    ] = SourceFormat.auto,
    risk_level: Annotated[
        Optional[RiskLevel],
        typer.Option(
            "--risk-level",
            "-r",
            metavar="LEVEL",
            help="Keep only IPs at this risk level.",
        ),
    ] = None,
    score: Annotated[
        Optional[int],
        typer.Option(
            "--score", metavar="N", help="Keep IPs with abuse score >= N (0-100)."
        ),
    ] = None,
    country_code: Annotated[
        Optional[str],
        typer.Option(
            "--country-code",
            metavar="CC",
            help="Keep IPs matching this ISO country code.",
        ),
    ] = None,
    is_tor: Annotated[
        bool, typer.Option("--is-tor", help="Keep only TOR exit nodes.")
    ] = False,
    is_not_tor: Annotated[
        bool, typer.Option("--is-not-tor", help="Exclude TOR exit nodes.")
    ] = False,
    remove_private: Annotated[
        bool,
        typer.Option("--remove-private", help="Exclude private/RFC-1918 addresses."),
    ] = False,
    remove_whitelisted: Annotated[
        bool,
        typer.Option(
            "--remove-whitelisted", help="Exclude AbuseIPDB-whitelisted addresses."
        ),
    ] = False,
    export: Annotated[
        Optional[list[ExportFormat]],
        typer.Option(
            "--export",
            "-e",
            metavar="FORMAT",
            help="Export results. Repeat for multiple formats.",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show filter trace and file diagnostics."),
    ] = False,
):
    """Reload a previous export, apply filters, and re-export."""
    if not source:
        print_error("load requires --source")
        raise typer.Exit(1)

    args = SimpleNamespace(
        source=source,
        format=file_format.value,
        risk_level=risk_level.value if risk_level else None,
        score=score,
        country_code=country_code,
        is_tor=is_tor,
        is_not_tor=is_not_tor,
        remove_private=remove_private,
        remove_whitelisted=remove_whitelisted,
        export=[f.value for f in export] if export else None,
        verbose=verbose,
    )
    cmd_load(args)


@app.command()
def categories():
    """List all AbuseIPDB report category IDs and names."""
    cmd_categories()


def main() -> None:
    app()
