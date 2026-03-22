import argparse
import textwrap

from .constants import EXPORT_FORMATS, DEFAULT_MAX_AGE_IN_DAYS
from . import __version__


CATEGORY_TABLE = """\
  3   Fraud Orders          14  Port Scan             21  FTP Brute-Force
  4   DDoS Attack           15  Hacking               22  Ping of Death
  5   FTP Fraud             16  SQL Injection         23  Phishing
  6   Ping Flood            17  Spoofing              24  Fraud VoIP
  7   Proxy / TOR           18  Brute-Force           25  Open Proxy
  9   Web Spam              19  Bad Web Bot           26  Web Spam
 10   Email Spam            20  Exploited Host        27  Email Spam
 11   Blog Spam                                       28  Exploited Host"""


class _Formatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=32, width=90)


def _add_filter_arguments(parser: argparse.ArgumentParser) -> None:
    g = parser.add_argument_group("filters")
    g.add_argument(
        "--risk-level", "-r",
        choices=["critical", "high", "medium", "low"],
        metavar="LEVEL",
        help="critical (>=75)  high (>=50)  medium (>=25)  low (<25)",
    )
    g.add_argument(
        "--score",
        type=int,
        metavar="N",
        help="keep IPs with abuse score >= N  (0-100)",
    )
    g.add_argument(
        "--country-code",
        metavar="CC",
        help="keep IPs matching this ISO country code  (e.g. US, DE, FR)",
    )
    g.add_argument(
        "--is-tor",
        action="store_true",
        help="keep only TOR exit nodes",
    )
    g.add_argument(
        "--is-not-tor",
        action="store_true",
        help="exclude TOR exit nodes",
    )
    g.add_argument(
        "--remove-private",
        action="store_true",
        help="exclude private / RFC-1918 addresses",
    )
    g.add_argument(
        "--remove-whitelisted",
        action="store_true",
        help="exclude AbuseIPDB-whitelisted addresses",
    )


def _add_export_argument(parser: argparse.ArgumentParser) -> None:
    g = parser.add_argument_group("output")
    g.add_argument(
        "--export", "-e",
        nargs="+",
        choices=EXPORT_FORMATS,
        metavar="FORMAT",
        help=(
            "write results to file(s) — formats: "
            + ", ".join(EXPORT_FORMATS)
            + "  (multiple allowed)"
        ),
    )


def _add_verbose_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="show per-IP detail, filter trace, and API diagnostics",
    )


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="abusecli",
        formatter_class=_Formatter,
        description=textwrap.dedent("""\
            AbuseIPDB CLI  v{version}
            ─────────────────────────────────────────────────────────────────
            Bulk check, report, and filter IP addresses via the AbuseIPDB API.

            API key resolution order:
              1. --token argument
              2. ABUSEIPDB_API_KEY environment variable
              3. .env file in the current directory
              4. interactive prompt (offers to save to .env)
        """).format(version=__version__),
        epilog=textwrap.dedent("""\
            commands at a glance:
              check   query the API for one or more IPs, filter, and export
              report  submit abuse reports for one or more IPs
              load    reload a previous export, re-filter, and re-export

            quick examples:
              abusecli.py check --ips 1.1.1.1 8.8.8.8
              abusecli.py check --ips 1.1.1.1 --risk-level high --export csv json
              abusecli.py report --ips 1.2.3.4 --categories 18 22 --comment "SSH scan"
              abusecli.py load --source results.csv --score 50 --export json

            run abusecli.py <command> --help for full per-command options.
        """),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--token",
        metavar="KEY",
        help="API key — overrides .env and environment variable",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        metavar="<command>",
    )

    _build_check_parser(subparsers)
    _build_report_parser(subparsers)
    _build_load_parser(subparsers)
    _build_categories_parser(subparsers)

    return parser


def _build_check_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "check",
        formatter_class=_Formatter,
        help="query AbuseIPDB for one or more IPs",
        description=textwrap.dedent("""\
            check — query AbuseIPDB for one or more IP addresses
            ─────────────────────────────────────────────────────
            Fetches abuse score, country, ISP, TOR status, and report history
            for each IP. Results are displayed as a table with a risk summary
            and a recent activity panel showing the latest abuse reports.

            IPs can be supplied directly via --ips, read from a plain-text file
            via --from-file (one IP per line, # comments ignored), or both at
            once — duplicates are removed automatically.

            All filter flags are cumulative — only IPs matching every condition
            are kept. Use --verbose to trace each filter step and see full
            per-IP report detail.
        """),
        epilog=textwrap.dedent("""\
            examples:
              abusecli.py check --ips 8.8.8.8
              abusecli.py check --ips 8.8.8.8 1.1.1.1 185.220.101.1
              abusecli.py check --from-file blocklist.txt
              abusecli.py check --from-file blocklist.txt --ips 1.2.3.4
              abusecli.py check --ips 185.220.101.1 --verbose
              abusecli.py check --ips 8.8.8.8 1.1.1.1 --risk-level high
              abusecli.py check --ips 8.8.8.8 1.1.1.1 --score 50 --country-code US
              abusecli.py check --ips 8.8.8.8 1.1.1.1 --max-age 30 --export csv
              abusecli.py check --ips 8.8.8.8 1.1.1.1 --export csv json excel
        """),
    )

    g = p.add_argument_group("input")
    g.add_argument(
        "--ips",
        nargs="+",
        metavar="IP",
        help="one or more IP addresses to check",
    )
    g.add_argument(
        "--from-file",
        metavar="FILE",
        help="plain-text file with one IP per line (# lines ignored)",
    )
    g.add_argument(
        "--max-age",
        type=int,
        default=DEFAULT_MAX_AGE_IN_DAYS,
        metavar="DAYS",
        help=f"only consider reports from the last N days  (default: {DEFAULT_MAX_AGE_IN_DAYS}, max: 365)",
    )
    _add_filter_arguments(p)
    _add_export_argument(p)
    _add_verbose_argument(p)


def _build_report_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "report",
        formatter_class=_Formatter,
        help="submit abuse reports for one or more IPs",
        description=textwrap.dedent("""\
            report — submit abuse reports to AbuseIPDB
            ───────────────────────────────────────────
            Reports one or more IPs with one or more category codes.
            IPs can be given directly via --ips or loaded from a previous
            check/load export via --source (CSV, JSON, Excel, Parquet).

            When using --source, use --min-score to avoid accidentally
            reporting low-confidence IPs. A confirmation table is always
            shown before any API call is made unless --no-confirm is set.
            Use --dry-run to preview the full batch without submitting.

            Category IDs are validated against the known list before any
            API call is made.

            AbuseIPDB category reference:
        """) + CATEGORY_TABLE + "\n\n"
          + "    Full list: https://www.abuseipdb.com/categories",
        epilog=textwrap.dedent("""\
            examples:
              abusecli.py report --ips 1.2.3.4 --categories 18
              abusecli.py report --ips 1.2.3.4 --categories 18 22 --comment "SSH scan"
              abusecli.py report --ips 1.2.3.4 5.6.7.8 --categories 18 22 --verbose
              abusecli.py report --source results.csv --categories 18 22
              abusecli.py report --source results.csv --min-score 75 --categories 18
              abusecli.py report --source results.csv --categories 18 --dry-run
              abusecli.py report --source results.csv --categories 18 --no-confirm
        """),
    )

    g = p.add_argument_group("input")
    g_ex = g.add_mutually_exclusive_group(required=True)
    g_ex.add_argument(
        "--ips",
        nargs="+",
        metavar="IP",
        help="one or more IP addresses to report",
    )
    g_ex.add_argument(
        "--source", "-s",
        metavar="FILE",
        help="load IPs from a previous check/load export (CSV, JSON, Excel, Parquet)",
    )
    g.add_argument(
        "--format", "-f",
        choices=["csv", "json", "excel", "parquet", "auto"],
        default="auto",
        metavar="FORMAT",
        help="source file format — only used with --source  (default: auto)",
    )
    g.add_argument(
        "--min-score",
        type=int,
        metavar="N",
        help="only report IPs with abuse score >= N — only used with --source  (0-100)",
    )

    p.add_argument(
        "--categories",
        nargs="+",
        required=True,
        type=int,
        metavar="ID",
        help="one or more category IDs  (see list above)",
    )
    p.add_argument(
        "--comment",
        type=str,
        default="",
        metavar="TEXT",
        help="free-text comment attached to every report in this batch",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="preview the full batch without submitting any reports",
    )
    p.add_argument(
        "--no-confirm",
        action="store_true",
        help="skip the confirmation prompt and report immediately",
    )
    _add_verbose_argument(p)


def _build_load_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "load",
        formatter_class=_Formatter,
        help="reload a previous export, filter, and re-export",
        description=textwrap.dedent("""\
            load — reload a previous export and apply filters
            ──────────────────────────────────────────────────
            Reads a file produced by a previous "check" or "load" run,
            applies the same filter set available in "check", displays the
            result table, and optionally re-exports to one or more formats.

            Required columns in the source file:
              ipAddress              abuseConfidenceScore

            Optional columns (filled with defaults if absent):
              countryCode (Unknown)  isWhitelisted (false)
              isTor (false)          isPublic (true)

            Format is auto-detected from the file extension unless --format
            is provided explicitly.
        """),
        epilog=textwrap.dedent("""\
            examples:
              abusecli.py load --source results.csv
              abusecli.py load --source results.json --format json
              abusecli.py load --source results.csv --risk-level critical
              abusecli.py load --source results.csv --score 50 --country-code DE
              abusecli.py load --source results.csv --is-tor --verbose
              abusecli.py load --source results.csv --risk-level high --export json csv
        """),
    )

    g = p.add_argument_group("input")
    g.add_argument(
        "--source", "-s",
        required=True,
        metavar="FILE",
        help="source file to load",
    )
    g.add_argument(
        "--format", "-f",
        choices=["csv", "json", "excel", "parquet", "auto"],
        default="auto",
        metavar="FORMAT",
        help="csv | json | excel | parquet | auto  (default: auto)",
    )

    _add_filter_arguments(p)
    _add_export_argument(p)
    _add_verbose_argument(p)


def _build_categories_parser(subparsers) -> None:
    subparsers.add_parser(
        "categories",
        formatter_class=_Formatter,
        help="list all AbuseIPDB category IDs and names",
        description=textwrap.dedent("""\
            categories — list all AbuseIPDB report category IDs
            ─────────────────────────────────────────────────────
            Displays the full list of category IDs accepted by the
            report command. Use these IDs with --categories when
            submitting reports.
        """),
        epilog=textwrap.dedent("""\
            examples:
              abusecli.py categories
              abusecli.py report --ips 1.2.3.4 --categories 18 22
        """),
    )