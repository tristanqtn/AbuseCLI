import sys
from pathlib import Path

import pandas as pd
from tqdm import tqdm

from .api import check_ip, report_ip
from .data import apply_all_filters, reorder_columns
from .io import (
    load_dataframe,
    validate_dataframe,
    validate_report_source,
    fill_missing_columns,
    export_dataframe,
)
from .display import (
    print_success,
    print_error,
    print_info,
    display_results,
    display_recent_activity,
    display_report_confirmation,
    display_verbose_report,
)
from .constants import (
    DEFAULT_MAX_AGE_IN_DAYS,
    VALID_REPORT_CATEGORIES,
    ABUSE_CATEGORIES,
    DISPLAY_COLUMN_ORDER,
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
        lines = Path(path).read_text().splitlines()
        ips = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
        return ips
    except Exception as e:
        print_error(f"Could not read IP file {path}: {e}")
        return []


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

    ips = list(getattr(args, "ips", None) or [])

    from_file = getattr(args, "from_file", None)
    if from_file:
        file_ips = _load_ips_from_file(from_file)
        if not file_ips:
            print_error(f"No valid IPs found in {from_file}")
            if not ips:
                return None
        else:
            if verbose:
                print_info(f"Loaded {len(file_ips)} IP(s) from {from_file}")
            ips = list(dict.fromkeys(ips + file_ips))

    if not ips:
        print_error("No IP addresses to check")
        return None

    if verbose:
        print_info(f"Checking {len(ips)} IP(s) with maxAgeInDays={max_age}")

    results = []
    reports_by_ip: dict[str, list] = {}
    success_count = 0
    error_count = 0

    with tqdm(ips, desc="Checking IPs", unit="ip", colour="green") as pbar:
        for ip in pbar:
            pbar.set_description(f"Checking {ip}")
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

                    if verbose and data.get("reports") is not None:
                        reports_by_ip.setdefault(ip, ip_reports)

                    row = {k: v for k, v in data.items() if k != "reports"}
                    results.append(row)
                    success_count += 1
                else:
                    error_count += 1

            except Exception as e:
                error_count += 1
                if verbose:
                    print_error(f"Error checking {ip}: {e}")

            pbar.set_postfix(ok=success_count, err=error_count)

    if verbose:
        print_info(f"API calls: {success_count} ok, {error_count} failed")

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

    display_results(df)

    active = {ip: r for ip, r in reports_by_ip.items() if ip in set(df["ipAddress"].values)}
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
        ips = list(args.ips)
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


def _build_report_df_from_source(args, verbose: bool) -> pd.DataFrame | None:
    df = load_dataframe(args.source, getattr(args, "format", "auto"), verbose=verbose)
    if df is None:
        return None

    if not validate_report_source(df, verbose=verbose):
        return None

    min_score = getattr(args, "min_score", None)
    if min_score is not None:
        if "abuseConfidenceScore" not in df.columns:
            print_error("--min-score requires an 'abuseConfidenceScore' column in the source file")
            return None
        before = len(df)
        df = df[df["abuseConfidenceScore"] >= min_score]
        if verbose:
            print_info(f"--min-score {min_score}: {before - len(df)} IP(s) removed, {len(df)} remaining")

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

    with tqdm(ips, desc="Reporting IPs", unit="ip", colour="red") as pbar:
        for ip in pbar:
            pbar.set_description(f"Reporting {ip}")
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

            pbar.set_postfix(ok=success_count, err=error_count)

    if success_count:
        print_success(f"Reported {success_count} IP(s) successfully")
    if error_count:
        print_error(f"{error_count} report(s) failed")


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

    display_results(df)
    return df