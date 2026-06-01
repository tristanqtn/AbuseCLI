import ipaddress
import sys
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from .api import check_block, check_ip, format_reset_time, get_blacklist, get_rate_limits, report_ip
from .cache import (
    clean_cache,
    clear_cache,
    get_all_entries,
    get_cache_stats,
    get_cached,
    set_cached,
    CACHE_PATH,
)
from .data import apply_all_filters, reorder_columns
from .io import (
    load_dataframe,
    validate_dataframe,
    validate_report_source,
    fill_missing_columns,
    export_dataframe,
)
from .display import (
    console,
    display_cache_stats,
    display_cache_table,
    display_recent_activity,
    display_report_confirmation,
    display_results,
    display_verbose_report,
    print_error,
    print_info,
    print_success,
    print_warning,
)
from .constants import (
    DEFAULT_BLACKLIST_CONFIDENCE,
    DEFAULT_BLACKLIST_LIMIT,
    DEFAULT_CACHE_TTL_HOURS,
    DEFAULT_MAX_AGE_IN_DAYS,
    DISPLAY_COLUMN_ORDER,
    MAX_CIDR_EXPANSION,
    RATE_LIMIT_WARNING_THRESHOLD,
    VALID_REPORT_CATEGORIES,
    ABUSE_CATEGORIES,
)


def _make_export_filename(base: str) -> str:
    timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
    return f"{base}_{timestamp}"


def _run_export(df: pd.DataFrame, args, base: str) -> None:
    if not getattr(args, "export", None):
        return
    verbose = getattr(args, "verbose", False)
    if verbose:
        print_info(f"Exporting to: {', '.join(args.export)}")
    export_dataframe(
        df=df,
        formats=args.export,
        base_filename=_make_export_filename(base),
        verbose=verbose,
    )


def _load_ips_from_file(path: str) -> list[str]:
    try:
        if path == "-":
            lines = sys.stdin.read().splitlines()
        else:
            lines = Path(path).read_text().splitlines()
        ips = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ip = line.split("#")[0].strip()
            if ip:
                ips.append(ip)
        return ips
    except Exception as e:
        label = "stdin" if path == "-" else path
        print_error(f"Could not read IP file {label}: {e}")
        return []


def _parse_ip_entries(entries: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Validate and separate entries into (plain_ips, cidr_blocks, invalid)."""
    plain_ips: list[str] = []
    cidr_blocks: list[str] = []
    invalid: list[str] = []

    for entry in entries:
        if "/" in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                canonical = str(network)
                if canonical != entry:
                    print_info(f"CIDR {entry} interpreted as {canonical}")
                cidr_blocks.append(canonical)
            except ValueError:
                invalid.append(entry)
        else:
            try:
                ipaddress.ip_address(entry)
                plain_ips.append(entry)
            except ValueError:
                invalid.append(entry)

    return plain_ips, cidr_blocks, invalid


def _expand_cidrs(cidrs: list[str]) -> list[str]:
    """Expand CIDR blocks to individual IPs (for reporting). Skips blocks exceeding MAX_CIDR_EXPANSION."""
    result: list[str] = []
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.num_addresses > MAX_CIDR_EXPANSION:
                print_error(
                    f"{cidr} expands to {network.num_addresses:,} addresses"
                    f" — exceeds limit of {MAX_CIDR_EXPANSION:,}, skipped"
                )
                continue
            hosts = [str(ip) for ip in network.hosts()] or [str(network.network_address)]
            print_info(f"CIDR {cidr} -> {len(hosts)} IP(s)")
            result.extend(hosts)
        except ValueError:
            pass
    return result


def _normalize_block_row(raw: dict) -> dict:
    """Normalize a check-block reportedAddress entry to match check_ip field names."""
    return {
        "ipAddress": raw.get("ipAddress"),
        "abuseConfidenceScore": raw.get("abuseConfidenceScore", 0),
        "countryCode": raw.get("countryCode"),
        "totalReports": raw.get("numReports", 0),
        "lastReportedAt": raw.get("mostRecentReport"),
    }


def _show_rate_limit(endpoint: str, verbose: bool = False) -> None:
    rl = get_rate_limits().get(endpoint)
    if not rl or rl.get("remaining") is None:
        return
    remaining = rl["remaining"]
    limit = rl["limit"]
    reset = rl.get("reset")
    reset_str = f" — resets in {format_reset_time(reset)}" if reset else ""
    ratio = remaining / limit if limit > 0 else 1.0
    if ratio <= RATE_LIMIT_WARNING_THRESHOLD:
        print_warning(
            f"Rate limit ({endpoint}): {remaining}/{limit} remaining{reset_str}"
        )
    elif verbose:
        print_info(f"Rate limit ({endpoint}): {remaining}/{limit} remaining{reset_str}")


def _validate_categories(categories: list[int]) -> bool:
    invalid = [c for c in categories if c not in VALID_REPORT_CATEGORIES]
    if invalid:
        print_error(f"Invalid category ID(s): {', '.join(str(c) for c in invalid)}")
        print_info(
            "Valid IDs: " + ", ".join(str(c) for c in sorted(VALID_REPORT_CATEGORIES))
        )
        print_info("Full reference: https://www.abuseipdb.com/categories")
        return False
    return True


def cmd_check(args, api_key: str) -> pd.DataFrame | None:
    verbose = getattr(args, "verbose", False)
    max_age = getattr(args, "max_age", DEFAULT_MAX_AGE_IN_DAYS)
    cache_ttl = getattr(args, "cache_ttl", DEFAULT_CACHE_TTL_HOURS)
    no_cache = getattr(args, "no_cache", False)

    raw_ips = list(getattr(args, "ips", None) or [])
    entries = list(dict.fromkeys(raw_ips))

    from_file = getattr(args, "from_file", None)
    if from_file:
        file_ips = _load_ips_from_file(from_file)
        if not file_ips:
            print_error(f"No valid IPs found in {from_file}")
            if not entries:
                return None
        else:
            if verbose:
                print_info(f"Loaded {len(file_ips)} IP(s) from {from_file}")
            entries = list(dict.fromkeys(entries + file_ips))

    plain_ips, cidr_blocks, invalid = _parse_ip_entries(entries)
    if invalid:
        shown = ", ".join(invalid[:5])
        suffix = f" (+{len(invalid) - 5} more)" if len(invalid) > 5 else ""
        print_error(
            f"Skipping {len(invalid)} invalid entr{'y' if len(invalid) == 1 else 'ies'}: {shown}{suffix}"
        )
    plain_ips = list(dict.fromkeys(plain_ips))
    cidr_blocks = list(dict.fromkeys(cidr_blocks))

    if not plain_ips and not cidr_blocks:
        print_error("No valid IP addresses or CIDR blocks to check")
        return None

    if verbose:
        if no_cache:
            print_info("Cache disabled (--no-cache)")
        else:
            print_info(f"Cache: {CACHE_PATH}  TTL: {cache_ttl}h")
        if plain_ips:
            print_info(f"Checking {len(plain_ips)} IP(s)  maxAgeInDays={max_age}")
        if cidr_blocks:
            print_info(f"Checking {len(cidr_blocks)} CIDR block(s) via check-block API  maxAgeInDays={max_age}")

    results = []
    reports_by_ip: dict[str, list] = {}
    success_count = 0
    error_count = 0
    cached_count = 0
    rate_limit_warned = False

    total_tasks = len(plain_ips) + len(cidr_blocks)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn(
            "[green]{task.fields[ok]}✓[/green]"
            "  [dim cyan]{task.fields[cached]}↺[/dim cyan]"
            "  [red]{task.fields[err]}✗[/red]"
        ),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Checking IPs", total=total_tasks, ok=0, err=0, cached=0)

        # ── Plain IPs ─────────────────────────────────────────────────────────
        for ip in plain_ips:
            progress.update(task, description=ip)

            if not no_cache:
                cached_data = get_cached(ip, ttl_hours=cache_ttl)
                if cached_data is not None and not cached_data.get("_block"):
                    ip_reports = cached_data.get("reports", [])
                    if ip_reports:
                        reports_by_ip[ip] = ip_reports
                    row = {k: v for k, v in cached_data.items() if k != "reports"}
                    results.append(row)
                    cached_count += 1
                    success_count += 1
                    progress.update(task, advance=1, ok=success_count, err=error_count, cached=cached_count)
                    continue

            try:
                response = check_ip(
                    ip_address=ip,
                    api_key=api_key,
                    max_age_in_days=max_age,
                    verbose=verbose,
                )
                data = response.get("data") if response else None

                if data:
                    ip_reports = data.get("reports", [])
                    if ip_reports:
                        reports_by_ip[ip] = ip_reports
                    row = {k: v for k, v in data.items() if k != "reports"}
                    results.append(row)
                    success_count += 1
                    if not no_cache:
                        set_cached(ip, data)
                    if not rate_limit_warned:
                        rl = get_rate_limits().get("check", {})
                        remaining = rl.get("remaining")
                        limit = rl.get("limit", 1)
                        if remaining is not None and limit > 0 and remaining / limit <= RATE_LIMIT_WARNING_THRESHOLD:
                            rate_limit_warned = True
                            reset = rl.get("reset")
                            reset_str = f" — resets in {format_reset_time(reset)}" if reset else ""
                            print_warning(f"Rate limit low (check): {remaining}/{limit} remaining{reset_str}")
                else:
                    error_count += 1

            except Exception as e:
                error_count += 1
                if verbose:
                    print_error(f"Error checking {ip}: {e}")

            progress.update(task, advance=1, ok=success_count, err=error_count, cached=cached_count)

        # ── CIDR blocks ───────────────────────────────────────────────────────
        for cidr in cidr_blocks:
            progress.update(task, description=cidr)

            if not no_cache:
                cached_data = get_cached(cidr, ttl_hours=cache_ttl)
                if cached_data is not None and cached_data.get("_block"):
                    for row in cached_data.get("rows", []):
                        results.append(row)
                    cached_count += 1
                    success_count += 1
                    progress.update(task, advance=1, ok=success_count, err=error_count, cached=cached_count)
                    continue

            try:
                response = check_block(
                    network=cidr,
                    api_key=api_key,
                    max_age_in_days=max_age,
                    verbose=verbose,
                )
                data = response.get("data") if response else None

                if data:
                    reported = data.get("reportedAddress", [])
                    normalized_rows = [_normalize_block_row(r) for r in reported]

                    if verbose:
                        num_hosts = data.get("numPossibleHosts", "?")
                        desc = data.get("addressSpaceDesc", "")
                        desc_str = f"  [{desc}]" if desc else ""
                        print_info(f"Block {cidr}: {num_hosts} possible hosts, {len(normalized_rows)} with reports{desc_str}")

                    for row in normalized_rows:
                        results.append(row)
                    success_count += 1

                    if not no_cache:
                        set_cached(cidr, {"_block": True, "network": cidr, "rows": normalized_rows})

                    if not rate_limit_warned:
                        rl = get_rate_limits().get("check-block", {})
                        remaining = rl.get("remaining")
                        limit = rl.get("limit", 1)
                        if remaining is not None and limit > 0 and remaining / limit <= RATE_LIMIT_WARNING_THRESHOLD:
                            rate_limit_warned = True
                            reset = rl.get("reset")
                            reset_str = f" — resets in {format_reset_time(reset)}" if reset else ""
                            print_warning(f"Rate limit low (check-block): {remaining}/{limit} remaining{reset_str}")
                else:
                    error_count += 1

            except Exception as e:
                error_count += 1
                if verbose:
                    print_error(f"Error checking block {cidr}: {e}")

            progress.update(task, advance=1, ok=success_count, err=error_count, cached=cached_count)

    if verbose:
        api_calls = success_count - cached_count
        print_info(f"API calls: {api_calls} ok, {error_count} failed, {cached_count} from cache")
    _show_rate_limit("check", verbose)
    _show_rate_limit("check-block", verbose)

    if not results:
        print_error("No valid data retrieved")
        return None

    df = pd.DataFrame(results)
    df = apply_all_filters(df, args)

    if df.empty:
        print_error("No IPs match the specified filters")
        return None

    df = reorder_columns(df, DISPLAY_COLUMN_ORDER)

    if verbose and reports_by_ip:
        surviving_ips = set(df["ipAddress"].values)
        for ip, payload in reports_by_ip.items():
            if ip in surviving_ips:
                display_verbose_report(ip, {"ipAddress": ip, "reports": payload})

    display_results(df, verbose=verbose)

    show_activity = getattr(args, "activity", False)
    if show_activity:
        active = {
            ip: r
            for ip, r in reports_by_ip.items()
            if ip in set(df["ipAddress"].values)
        }
        if active:
            display_recent_activity(active)

    _run_export(df, args, "ip_check")
    return df


def cmd_report(args, api_key: str) -> None:
    verbose = getattr(args, "verbose", False)
    dry_run = getattr(args, "dry_run", False)
    no_confirm = getattr(args, "no_confirm", False)

    if not _validate_categories(args.categories):
        sys.exit(1)

    source = getattr(args, "source", None)

    if source:
        df = _build_report_df_from_source(args, verbose)
        if df is None:
            return
    else:
        ips = list(dict.fromkeys(getattr(args, "ips", None) or []))
        from_file = getattr(args, "from_file", None)
        if from_file:
            file_ips = _load_ips_from_file(from_file)
            label = "stdin" if from_file == "-" else from_file
            if not file_ips:
                print_error(f"No valid IPs found in {label}")
                if not ips:
                    return
            else:
                if verbose:
                    print_info(f"Loaded {len(file_ips)} IP(s) from {label}")
                ips = list(dict.fromkeys(ips + file_ips))

        plain_ips, cidr_blocks, invalid = _parse_ip_entries(ips)
        if invalid:
            shown = ", ".join(invalid[:5])
            suffix = f" (+{len(invalid) - 5} more)" if len(invalid) > 5 else ""
            print_error(
                f"Skipping {len(invalid)} invalid entr{'y' if len(invalid) == 1 else 'ies'}: {shown}{suffix}"
            )
        if cidr_blocks:
            expanded = _expand_cidrs(cidr_blocks)
            plain_ips = list(dict.fromkeys(plain_ips + expanded))
        ips = plain_ips

        if not ips:
            print_error("No valid IP addresses to report")
            return
        df = pd.DataFrame({"ipAddress": ips})

    if df.empty:
        print_error("No IPs to report")
        return

    if not dry_run and not no_confirm:
        confirmed = display_report_confirmation(
            df=df,
            categories=args.categories,
            comment=args.comment,
            dry_run=False,
        )
        if not confirmed:
            return
    elif dry_run:
        display_report_confirmation(
            df=df,
            categories=args.categories,
            comment=args.comment,
            dry_run=True,
        )
        return

    _execute_reports(
        ips=df["ipAddress"].tolist(),
        api_key=api_key,
        categories=args.categories,
        comment=args.comment,
        verbose=verbose,
    )
    _show_rate_limit("report", verbose)


def _build_report_df_from_source(args, verbose: bool) -> pd.DataFrame | None:
    df = load_dataframe(args.source, getattr(args, "format", "auto"), verbose=verbose)
    if df is None:
        return None

    if not validate_report_source(df, verbose=verbose):
        return None

    min_score = getattr(args, "min_score", None)
    if min_score is not None:
        if "abuseConfidenceScore" not in df.columns:
            print_error(
                "--min-score requires an 'abuseConfidenceScore' column in the source file"
            )
            return None
        before = len(df)
        df = df[df["abuseConfidenceScore"] >= min_score]
        if verbose:
            print_info(
                f"--min-score {min_score}: {before - len(df)} IP(s) removed, {len(df)} remaining"
            )

    if df.empty:
        print_error("No IPs remain after applying --min-score filter")
        return None

    if "abuseConfidenceScore" not in df.columns:
        df["abuseConfidenceScore"] = 0

    from .data import add_risk_level_column

    df = add_risk_level_column(df, verbose=verbose)

    return df


def _execute_reports(
    ips: list[str],
    api_key: str,
    categories: list[int],
    comment: str,
    verbose: bool,
) -> None:
    success_count = 0
    error_count = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("[green]{task.fields[ok]}✓[/green]  [red]{task.fields[err]}✗[/red]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Reporting IPs", total=len(ips), ok=0, err=0)
        for ip in ips:
            progress.update(task, description=ip)
            try:
                response = report_ip(
                    ip_address=ip,
                    api_key=api_key,
                    categories=categories,
                    comment=comment,
                    verbose=verbose,
                )
                if response:
                    success_count += 1
                else:
                    error_count += 1
            except Exception as e:
                error_count += 1
                if verbose:
                    print_error(f"Error reporting {ip}: {e}")

            progress.update(task, advance=1, ok=success_count, err=error_count)

    if success_count:
        print_success(f"Reported {success_count} IP(s) successfully")
    if error_count:
        print_error(f"{error_count} report(s) failed")


def cmd_blacklist(args, api_key: str) -> pd.DataFrame | None:
    verbose = getattr(args, "verbose", False)
    confidence = getattr(args, "confidence", DEFAULT_BLACKLIST_CONFIDENCE)
    except_countries = getattr(args, "except_countries", None)
    ip_version = getattr(args, "ip_version", None)
    limit = getattr(args, "limit", DEFAULT_BLACKLIST_LIMIT)
    only_countries = getattr(args, "only_countries", None)

    if verbose:
        print_info(f"Fetching blacklist  confidence>={confidence}  limit={limit}")
        if ip_version:
            print_info(f"IP version filter: IPv{ip_version}")
        if only_countries:
            print_info(f"Only countries: {', '.join(only_countries)}")
        if except_countries:
            print_info(f"Except countries: {', '.join(except_countries)}")

    with console.status("[bold]Fetching AbuseIPDB blacklist…[/bold]"):
        response = get_blacklist(
            api_key=api_key,
            confidence_minimum=confidence,
            limit=limit,
            ip_version=ip_version,
            only_countries=only_countries,
            except_countries=except_countries,
            verbose=verbose,
        )

    _show_rate_limit("blacklist", verbose)

    if not response:
        print_error("Failed to fetch blacklist")
        return None

    data = response.get("data", [])
    meta = response.get("meta", {})

    if not data:
        print_error("Blacklist is empty")
        return None

    if verbose:
        generated_at = meta.get("generatedAt", "N/A")
        print_info(f"Generated at: {generated_at}  ({len(data)} IPs received)")

    df = pd.DataFrame(data)

    filter_args = SimpleNamespace(
        country_code=getattr(args, "country_code", None),
        is_not_tor=False,
        is_tor=False,
        remove_private=False,
        remove_whitelisted=False,
        risk_level=getattr(args, "risk_level", None),
        score=getattr(args, "score", None),
        verbose=verbose,
    )
    df = apply_all_filters(df, filter_args)

    if df.empty:
        print_error("No IPs match the specified filters")
        return None

    df = reorder_columns(df, DISPLAY_COLUMN_ORDER)
    display_results(df, verbose=verbose)
    _run_export(df, args, "blacklist")
    return df


def cmd_cache_stats(ttl_hours: int, path: Path) -> None:
    stats = get_cache_stats(ttl_hours=ttl_hours, path=path)
    display_cache_stats(stats)


def cmd_cache_show(
    search: str | None,
    expired_only: bool,
    ttl_hours: int,
    path: Path,
) -> None:
    entries = get_all_entries(path=path)
    if not entries:
        print_info(f"Cache is empty ({path})")
        return
    display_cache_table(
        entries, ttl_hours=ttl_hours, search=search, expired_only=expired_only
    )


def cmd_cache_clear(yes: bool, path: Path) -> None:
    entries = get_all_entries(path=path)
    if not entries:
        print_info(f"Cache is already empty ({path})")
        return
    if not yes:
        try:
            answer = (
                input(f"Delete all {len(entries)} cached IP(s) from {path}? [y/N] ")
                .strip()
                .lower()
            )
        except KeyboardInterrupt:
            print_error("\nAborted.")
            return
        if answer not in ("y", "yes"):
            print_info("Aborted.")
            return
    count = clear_cache(path=path)
    print_success(f"Cleared {count} cached IP(s)")


def cmd_cache_clean(ttl_hours: int, path: Path) -> None:
    count = clean_cache(ttl_hours=ttl_hours, path=path)
    if count:
        print_success(
            f"Removed {count} expired entr{'y' if count == 1 else 'ies'} "
            f"(TTL: {ttl_hours}h)"
        )
    else:
        print_info("No expired entries to remove")


def cmd_categories() -> None:
    from rich.table import Table
    from rich.console import Console

    console = Console()

    table = Table(
        title="AbuseIPDB Report Categories",
        show_lines=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("ID", justify="right", style="bold white", width=6)
    table.add_column("Name", style="white")

    for cat_id, name in sorted(ABUSE_CATEGORIES.items()):
        table.add_row(str(cat_id), name)

    console.print()
    console.print(table)
    console.print()
    print_info("Use these IDs with: abusecli.py report --categories <ID> [ID ...]")
    print_info("Full reference: https://www.abuseipdb.com/categories")


def cmd_load(args) -> pd.DataFrame | None:
    verbose = getattr(args, "verbose", False)

    df = load_dataframe(args.source, getattr(args, "format", "auto"), verbose=verbose)
    if df is None:
        return None

    if not validate_dataframe(df, verbose=verbose):
        return None

    df = fill_missing_columns(df, verbose=verbose)
    df = apply_all_filters(df, args)

    if df.empty:
        print_error("No IPs match the specified filters")
        return None

    df = reorder_columns(df, DISPLAY_COLUMN_ORDER)

    source_stem = Path(args.source).stem
    _run_export(df, args, f"{source_stem}_filtered")

    display_results(df, verbose=verbose)
    return df
