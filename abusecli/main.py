from enum import Enum
from types import SimpleNamespace
from typing import Optional

import typer
from typing import Annotated

from .auth import load_api_key
from .cache import CACHE_PATH
from .commands import (
    cmd_blacklist,
    cmd_cache_clean,
    cmd_cache_clear,
    cmd_cache_show,
    cmd_cache_stats,
    cmd_categories,
    cmd_check,
    cmd_load,
    cmd_report,
)
from .config import get as config_get
from .constants import (
    DEFAULT_BLACKLIST_CONFIDENCE,
    DEFAULT_BLACKLIST_LIMIT,
    DEFAULT_CACHE_TTL_HOURS,
    DEFAULT_MAX_AGE_IN_DAYS,
)
from .display import print_banner, print_error


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

cache_app = typer.Typer(
    name="cache",
    help="Inspect and manage the local IP cache.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
)


@app.callback()
def _app_callback() -> None:
    print_banner()


def _resolve_cache_path(location: Optional[str]):
    from pathlib import Path as _Path
    return _Path(location) if location else CACHE_PATH


def _parse_countries(value: Optional[str]) -> list[str] | None:
    if not value:
        return None
    return [c.strip().upper() for c in value.replace(" ", ",").split(",") if c.strip()]


def _parse_ips(ips: Optional[list[str]]) -> list[str]:
    if not ips:
        return []
    result = []
    for entry in ips:
        for ip in entry.replace(",", " ").split():
            ip = ip.strip()
            if ip:
                result.append(ip)
    return result


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


# ── Lookup ────────────────────────────────────────────────────────────────────

@app.command(rich_help_panel="Lookup")
def blacklist(
    # ── Input ────────────────────────────────────────────────────────────────
    confidence: Annotated[
        int,
        typer.Option(
            "--confidence",
            "-c",
            metavar="N",
            help="Minimum abuse confidence score (25–100). Scores below 100 require a premium account.",
            rich_help_panel="Input",
        ),
    ] = DEFAULT_BLACKLIST_CONFIDENCE,
    except_countries: Annotated[
        Optional[str],
        typer.Option(
            "--except-countries",
            metavar="CC,...",
            help="Comma-separated country codes to exclude (server-side).",
            rich_help_panel="Input",
        ),
    ] = None,
    ip_version: Annotated[
        Optional[int],
        typer.Option(
            "--ip-version",
            metavar="4|6",
            help="Filter by IP version (4 or 6).",
            rich_help_panel="Input",
        ),
    ] = None,
    limit: Annotated[
        int,
        typer.Option(
            "--limit",
            "-l",
            metavar="N",
            help=f"Maximum number of IPs to return (default: {DEFAULT_BLACKLIST_LIMIT}).",
            rich_help_panel="Input",
        ),
    ] = DEFAULT_BLACKLIST_LIMIT,
    only_countries: Annotated[
        Optional[str],
        typer.Option(
            "--only-countries",
            metavar="CC,...",
            help="Comma-separated country codes to include (server-side).",
            rich_help_panel="Input",
        ),
    ] = None,
    # ── Filters ───────────────────────────────────────────────────────────────
    country_code: Annotated[
        Optional[str],
        typer.Option(
            "--country-code",
            metavar="CC",
            help="Keep only IPs matching this ISO country code (client-side).",
            rich_help_panel="Filters",
        ),
    ] = None,
    risk_level: Annotated[
        Optional[RiskLevel],
        typer.Option(
            "--risk-level",
            "-r",
            metavar="LEVEL",
            help="Keep only IPs at this risk level.",
            rich_help_panel="Filters",
        ),
    ] = None,
    score: Annotated[
        Optional[int],
        typer.Option(
            "--score",
            metavar="N",
            help="Keep IPs with abuse score >= N (0–100).",
            rich_help_panel="Filters",
        ),
    ] = None,
    # ── Output ────────────────────────────────────────────────────────────────
    export: Annotated[
        Optional[list[ExportFormat]],
        typer.Option(
            "--export",
            "-e",
            metavar="FORMAT",
            help="Export results. Repeat for multiple formats (csv/json/excel/html/parquet).",
            rich_help_panel="Output",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show filter trace, metadata, and API diagnostics.",
            rich_help_panel="Output",
        ),
    ] = False,
    # ── Auth ──────────────────────────────────────────────────────────────────
    token: Annotated[
        Optional[str],
        typer.Option(
            "--token",
            metavar="KEY",
            help="API key — overrides .env and environment variable.",
            rich_help_panel="Auth",
        ),
    ] = None,
):
    """Download the AbuseIPDB blacklist of most-reported IPs."""
    if ip_version is not None and ip_version not in (4, 6):
        print_error("--ip-version must be 4 or 6")
        raise typer.Exit(1)

    if not (25 <= confidence <= 100):
        print_error("--confidence must be between 25 and 100")
        raise typer.Exit(1)

    api_key = _resolve_api_key(token, verbose)

    args = SimpleNamespace(
        confidence=confidence,
        country_code=country_code,
        except_countries=_parse_countries(except_countries),
        export=[f.value for f in export] if export else None,
        ip_version=ip_version,
        limit=limit,
        only_countries=_parse_countries(only_countries),
        risk_level=risk_level.value if risk_level else None,
        score=score,
        verbose=verbose,
    )
    cmd_blacklist(args, api_key)


@app.command(rich_help_panel="Lookup")
def check(
    # ── Input ────────────────────────────────────────────────────────────────
    from_file: Annotated[
        Optional[str],
        typer.Option(
            "--from-file",
            metavar="FILE",
            help="Plain-text file, one IP per line (# ignored). Use - for stdin.",
            rich_help_panel="Input",
        ),
    ] = None,
    ips: Annotated[
        Optional[list[str]],
        typer.Option(
            "--ips",
            metavar="IP",
            help="IP address(es) to check. Repeat or comma-separate for multiple.",
            rich_help_panel="Input",
        ),
    ] = None,
    max_age: Annotated[
        Optional[int],
        typer.Option(
            "--max-age",
            metavar="DAYS",
            help=f"Only consider reports from the last N days (default: {DEFAULT_MAX_AGE_IN_DAYS} or from config, max: 365).",
            rich_help_panel="Input",
        ),
    ] = None,
    # ── Filters ───────────────────────────────────────────────────────────────
    country_code: Annotated[
        Optional[str],
        typer.Option(
            "--country-code",
            metavar="CC",
            help="Keep IPs matching this ISO country code (e.g. US, DE).",
            rich_help_panel="Filters",
        ),
    ] = None,
    is_not_tor: Annotated[
        bool,
        typer.Option(
            "--is-not-tor",
            help="Exclude TOR exit nodes.",
            rich_help_panel="Filters",
        ),
    ] = False,
    is_tor: Annotated[
        bool,
        typer.Option(
            "--is-tor",
            help="Keep only TOR exit nodes.",
            rich_help_panel="Filters",
        ),
    ] = False,
    remove_private: Annotated[
        bool,
        typer.Option(
            "--remove-private",
            help="Exclude private/RFC-1918 addresses.",
            rich_help_panel="Filters",
        ),
    ] = False,
    remove_whitelisted: Annotated[
        bool,
        typer.Option(
            "--remove-whitelisted",
            help="Exclude AbuseIPDB-whitelisted addresses.",
            rich_help_panel="Filters",
        ),
    ] = False,
    risk_level: Annotated[
        Optional[RiskLevel],
        typer.Option(
            "--risk-level",
            "-r",
            metavar="LEVEL",
            help="Keep only IPs at this risk level.",
            rich_help_panel="Filters",
        ),
    ] = None,
    score: Annotated[
        Optional[int],
        typer.Option(
            "--score",
            metavar="N",
            help="Keep IPs with abuse score >= N (0-100).",
            rich_help_panel="Filters",
        ),
    ] = None,
    # ── Cache ─────────────────────────────────────────────────────────────────
    cache_ttl: Annotated[
        Optional[int],
        typer.Option(
            "--cache-ttl",
            metavar="HOURS",
            help=f"Cache TTL in hours (default: {DEFAULT_CACHE_TTL_HOURS} or from config). Set 0 to disable.",
            rich_help_panel="Cache",
        ),
    ] = None,
    no_cache: Annotated[
        bool,
        typer.Option(
            "--no-cache",
            help="Bypass cache and always query the API.",
            rich_help_panel="Cache",
        ),
    ] = False,
    # ── Output ────────────────────────────────────────────────────────────────
    activity: Annotated[
        bool,
        typer.Option(
            "--activity",
            "-a",
            help="Show recent report activity per IP.",
            rich_help_panel="Output",
        ),
    ] = False,
    export: Annotated[
        Optional[list[ExportFormat]],
        typer.Option(
            "--export",
            "-e",
            metavar="FORMAT",
            help="Export results. Repeat for multiple formats (csv/json/excel/html/parquet).",
            rich_help_panel="Output",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show per-IP detail, filter trace, and API diagnostics.",
            rich_help_panel="Output",
        ),
    ] = False,
    # ── Auth ──────────────────────────────────────────────────────────────────
    token: Annotated[
        Optional[str],
        typer.Option(
            "--token",
            metavar="KEY",
            help="API key — overrides .env and environment variable.",
            rich_help_panel="Auth",
        ),
    ] = None,
):
    """Query AbuseIPDB for one or more IP addresses."""
    if not ips and not from_file:
        print_error("check requires --ips and/or --from-file")
        raise typer.Exit(1)

    api_key = _resolve_api_key(token, verbose)

    resolved_max_age = max_age if max_age is not None else config_get("max_age", DEFAULT_MAX_AGE_IN_DAYS)
    resolved_cache_ttl = cache_ttl if cache_ttl is not None else config_get("cache_ttl", DEFAULT_CACHE_TTL_HOURS)

    args = SimpleNamespace(
        activity=activity,
        cache_ttl=resolved_cache_ttl if resolved_cache_ttl > 0 else 0,
        country_code=country_code,
        export=[f.value for f in export] if export else None,
        from_file=from_file,
        ips=_parse_ips(ips),
        is_not_tor=is_not_tor,
        is_tor=is_tor,
        max_age=resolved_max_age,
        no_cache=no_cache or resolved_cache_ttl == 0,
        remove_private=remove_private,
        remove_whitelisted=remove_whitelisted,
        risk_level=risk_level.value if risk_level else None,
        score=score,
        verbose=verbose,
    )
    cmd_check(args, api_key)


# ── Reporting ─────────────────────────────────────────────────────────────────

@app.command(rich_help_panel="Reporting")
def categories():
    """List all AbuseIPDB report category IDs and names."""
    cmd_categories()


@app.command(rich_help_panel="Reporting")
def report(
    # ── Input ────────────────────────────────────────────────────────────────
    file_format: Annotated[
        SourceFormat,
        typer.Option(
            "--format",
            "-f",
            metavar="FORMAT",
            help="Source file format (default: auto-detect).",
            rich_help_panel="Input",
        ),
    ] = SourceFormat.auto,
    from_file: Annotated[
        Optional[str],
        typer.Option(
            "--from-file",
            metavar="FILE",
            help="Plain-text file, one IP per line (# ignored). Use - for stdin.",
            rich_help_panel="Input",
        ),
    ] = None,
    ips: Annotated[
        Optional[list[str]],
        typer.Option(
            "--ips",
            metavar="IP",
            help="IP address(es) to report. Repeat or comma-separate for multiple.",
            rich_help_panel="Input",
        ),
    ] = None,
    min_score: Annotated[
        Optional[int],
        typer.Option(
            "--min-score",
            metavar="N",
            help="Only report IPs with score >= N. Only used with --source.",
            rich_help_panel="Input",
        ),
    ] = None,
    source: Annotated[
        Optional[str],
        typer.Option(
            "--source",
            "-s",
            metavar="FILE",
            help="Load IPs from a previous export (CSV/JSON/Excel/Parquet). Exclusive with --ips/--from-file.",
            rich_help_panel="Input",
        ),
    ] = None,
    # ── Report ────────────────────────────────────────────────────────────────
    categories: Annotated[
        Optional[list[int]],
        typer.Option(
            "--categories",
            metavar="ID",
            help="Category ID to report. Repeat for multiple. Run 'categories' for the full list.",
            rich_help_panel="Report",
        ),
    ] = None,
    comment: Annotated[
        str,
        typer.Option(
            "--comment",
            metavar="TEXT",
            help="Free-text comment attached to every report in this batch.",
            rich_help_panel="Report",
        ),
    ] = "",
    # ── Behavior ──────────────────────────────────────────────────────────────
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Preview the batch without submitting anything.",
            rich_help_panel="Behavior",
        ),
    ] = False,
    no_confirm: Annotated[
        bool,
        typer.Option(
            "--no-confirm",
            help="Skip the confirmation prompt and report immediately.",
            rich_help_panel="Behavior",
        ),
    ] = False,
    # ── Output ────────────────────────────────────────────────────────────────
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show per-IP detail and API diagnostics.",
            rich_help_panel="Output",
        ),
    ] = False,
    # ── Auth ──────────────────────────────────────────────────────────────────
    token: Annotated[
        Optional[str],
        typer.Option(
            "--token",
            metavar="KEY",
            help="API key — overrides .env and environment variable.",
            rich_help_panel="Auth",
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
        categories=categories,
        comment=comment,
        dry_run=dry_run,
        format=file_format.value,
        from_file=from_file,
        ips=_parse_ips(ips),
        min_score=min_score,
        no_confirm=no_confirm,
        source=source,
        verbose=verbose,
    )
    cmd_report(args, api_key)


# ── Local ─────────────────────────────────────────────────────────────────────

_LocationOption = Annotated[
    Optional[str],
    typer.Option(
        "--location",
        "-l",
        metavar="FILE",
        help="Cache file path (default: next to abusecli.py).",
        rich_help_panel="Cache",
    ),
]

_CacheTtlOption = Annotated[
    int,
    typer.Option(
        "--cache-ttl",
        metavar="HOURS",
        help=f"TTL in hours for expiry calculation (default: {DEFAULT_CACHE_TTL_HOURS}).",
        rich_help_panel="Cache",
    ),
]


@cache_app.command("stats")
def cache_stats(
    cache_ttl: _CacheTtlOption = DEFAULT_CACHE_TTL_HOURS,
    location: _LocationOption = None,
):
    """Show cache statistics: size, valid/expired counts, oldest and newest entry."""
    cmd_cache_stats(ttl_hours=cache_ttl, path=_resolve_cache_path(location))


@cache_app.command("show")
def cache_show(
    cache_ttl: _CacheTtlOption = DEFAULT_CACHE_TTL_HOURS,
    expired_only: Annotated[
        bool,
        typer.Option(
            "--expired-only",
            help="Show only expired entries.",
            rich_help_panel="Filters",
        ),
    ] = False,
    location: _LocationOption = None,
    search: Annotated[
        Optional[str],
        typer.Option(
            "--search",
            "-s",
            metavar="IP",
            help="Filter entries whose IP contains this string.",
            rich_help_panel="Filters",
        ),
    ] = None,
):
    """Dump cached entries as a table. Use --search to filter by IP."""
    cmd_cache_show(
        search=search,
        expired_only=expired_only,
        ttl_hours=cache_ttl,
        path=_resolve_cache_path(location),
    )


@cache_app.command("clear")
def cache_clear(
    location: _LocationOption = None,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            "-y",
            help="Skip confirmation prompt.",
            rich_help_panel="Behavior",
        ),
    ] = False,
):
    """Delete all cached entries."""
    cmd_cache_clear(yes=yes, path=_resolve_cache_path(location))


@cache_app.command("clean")
def cache_clean(
    cache_ttl: _CacheTtlOption = DEFAULT_CACHE_TTL_HOURS,
    location: _LocationOption = None,
):
    """Remove expired entries from the cache."""
    cmd_cache_clean(ttl_hours=cache_ttl, path=_resolve_cache_path(location))


app.add_typer(cache_app, rich_help_panel="Local")


@app.command(rich_help_panel="Local")
def load(
    # ── Input ────────────────────────────────────────────────────────────────
    file_format: Annotated[
        SourceFormat,
        typer.Option(
            "--format",
            "-f",
            metavar="FORMAT",
            help="File format (default: auto-detect).",
            rich_help_panel="Input",
        ),
    ] = SourceFormat.auto,
    source: Annotated[
        Optional[str],
        typer.Option(
            "--source",
            "-s",
            metavar="FILE",
            help="Source file to load.",
            rich_help_panel="Input",
        ),
    ] = None,
    # ── Filters ───────────────────────────────────────────────────────────────
    country_code: Annotated[
        Optional[str],
        typer.Option(
            "--country-code",
            metavar="CC",
            help="Keep IPs matching this ISO country code.",
            rich_help_panel="Filters",
        ),
    ] = None,
    is_not_tor: Annotated[
        bool,
        typer.Option(
            "--is-not-tor",
            help="Exclude TOR exit nodes.",
            rich_help_panel="Filters",
        ),
    ] = False,
    is_tor: Annotated[
        bool,
        typer.Option(
            "--is-tor",
            help="Keep only TOR exit nodes.",
            rich_help_panel="Filters",
        ),
    ] = False,
    remove_private: Annotated[
        bool,
        typer.Option(
            "--remove-private",
            help="Exclude private/RFC-1918 addresses.",
            rich_help_panel="Filters",
        ),
    ] = False,
    remove_whitelisted: Annotated[
        bool,
        typer.Option(
            "--remove-whitelisted",
            help="Exclude AbuseIPDB-whitelisted addresses.",
            rich_help_panel="Filters",
        ),
    ] = False,
    risk_level: Annotated[
        Optional[RiskLevel],
        typer.Option(
            "--risk-level",
            "-r",
            metavar="LEVEL",
            help="Keep only IPs at this risk level.",
            rich_help_panel="Filters",
        ),
    ] = None,
    score: Annotated[
        Optional[int],
        typer.Option(
            "--score",
            metavar="N",
            help="Keep IPs with abuse score >= N (0-100).",
            rich_help_panel="Filters",
        ),
    ] = None,
    # ── Output ────────────────────────────────────────────────────────────────
    export: Annotated[
        Optional[list[ExportFormat]],
        typer.Option(
            "--export",
            "-e",
            metavar="FORMAT",
            help="Export results. Repeat for multiple formats.",
            rich_help_panel="Output",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show filter trace and file diagnostics.",
            rich_help_panel="Output",
        ),
    ] = False,
):
    """Reload a previous export, apply filters, and re-export."""
    if not source:
        print_error("load requires --source")
        raise typer.Exit(1)

    args = SimpleNamespace(
        country_code=country_code,
        export=[f.value for f in export] if export else None,
        format=file_format.value,
        is_not_tor=is_not_tor,
        is_tor=is_tor,
        remove_private=remove_private,
        remove_whitelisted=remove_whitelisted,
        risk_level=risk_level.value if risk_level else None,
        score=score,
        source=source,
        verbose=verbose,
    )
    cmd_load(args)


def main() -> None:
    app()
