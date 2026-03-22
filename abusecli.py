#!/usr/bin/env python3
import os
import sys
import json
import getpass
import argparse
import requests

import pandas as pd

from tqdm import tqdm
from pathlib import Path
from dotenv import load_dotenv, set_key

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()


__version__ = 1.0

###########################################################################
## CONSTANTS ##############################################################
###########################################################################

API_URL = "https://api.abuseipdb.com/api/v2/check"
ENV_FILE = ".env"

# Risk level constants
RISK_CRITICAL_MIN = 75
RISK_HIGH_MIN = 50
RISK_MEDIUM_MIN = 25
RISK_LOW_MIN = 0

RISK_LEVELS = {
    "critical": (RISK_CRITICAL_MIN, 100),
    "high": (RISK_HIGH_MIN, RISK_CRITICAL_MIN - 1),
    "medium": (RISK_MEDIUM_MIN, RISK_HIGH_MIN - 1),
    "low": (RISK_LOW_MIN, RISK_MEDIUM_MIN - 1),
}

###########################################################################
## PARSER #################################################################
###########################################################################


def create_parser():
    """Create and configure the argument parser"""
    parser = argparse.ArgumentParser(
        description="AbuseIPDB CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  abusecli.py check --ips 1.1.1.1 8.8.8.8
  """,
    )

    # Global arguments (optional)
    parser.add_argument("--token", help="AbuseIP API Token")

    # Subparsers
    subparsers = parser.add_subparsers(
        dest="command",
        title="Commands",
        description="Available commands",
        help="Use <command> --help for command-specific help",
    )

    # CHECK command
    check_parser = subparsers.add_parser(
        "check", help="Check connectivity to IP addresses"
    )
    check_parser.add_argument(
        "--ips",
        nargs="+",
        required=True,
        metavar="IP",
        help="List of IP addresses to check",
    )
    check_parser.add_argument(
        "--risk-level",
        "-r",
        choices=["critical", "high", "medium", "low"],
        help="Filter by risk level (critical, high, medium, low)",
    )
    check_parser.add_argument(
        "--score",
        "-s",
        type=int,
        help="Only keep IPs with a score above this value (between 0 and 100)",
    )
    check_parser.add_argument(
        "--country-code",
        type=str,
        help="Only keep IPs with the corresponding country code",
    )

    check_parser.add_argument(
        "--is-tor", action="store_true", help="Only keep TOR IP addresses"
    )
    check_parser.add_argument(
        "--is-not-tor", action="store_true", help="Only keep non-TOR IP addresses"
    )

    check_parser.add_argument(
        "--remove-private", action="store_true", help="Only keep public IP addresses"
    )

    check_parser.add_argument(
        "--remove-whitelisted",
        action="store_true",
        help="Only keep non-whitelisted IP addresses",
    )

    check_parser.add_argument(
        "--export",
        "-e",
        nargs="+",
        choices=["csv", "json", "excel", "html", "parquet"],
        metavar="FORMAT",
        help="Export results to file(s). Formats: csv, json, excel, html, parquet. Can specify multiple formats.",
    )

    check_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output, strongly recommanded for debugging.",
    )

    # LOAD command
    load_parser = subparsers.add_parser(
        "load", help="Load IP data from file and apply filters"
    )
    load_parser.add_argument(
        "--source", "-s",
        required=True,
        metavar="FILE",
        help="Source file to load (CSV, JSON, Excel, Parquet)"
    )
    load_parser.add_argument(
        "--format", "-f",
        choices=["csv", "json", "excel", "parquet", "auto"],
        default="auto",
        help="File format (default: auto-detect from extension)"
    )

    # Add all the same filtering arguments as check command
    load_parser.add_argument(
        "--risk-level", "-r", 
        choices=["critical", "high", "medium", "low"],
        help="Filter by risk level (critical, high, medium, low)"
    )
    load_parser.add_argument(
        "--score", 
        type=int,
        help="Only keep IPs with a score above this value (between 0 and 100)",
    )
    load_parser.add_argument(
        "--country-code", 
        type=str,
        help="Only keep IPs with the corresponding country code",
    )
    load_parser.add_argument(
        "--is-tor", action="store_true", help="Only keep TOR IP addresses"
    )
    load_parser.add_argument(
        "--is-not-tor", action="store_true", help="Only keep non-TOR IP addresses"
    )
    load_parser.add_argument(
        "--remove-private", action="store_true", help="Only keep public IP addresses"
    )
    load_parser.add_argument(
        "--remove-whitelisted", action="store_true", help="Only keep non-whitelisted IP addresses"
    )
    load_parser.add_argument(
        "--export", "-e",
        nargs="+",
        choices=["csv", "json", "excel", "html", "parquet"],
        metavar="FORMAT",
        help="Export results to file(s). Formats: csv, json, excel, html, parquet. Can specify multiple formats."
    )
    load_parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show detailed output, strongly recommended for debugging."
    )

    return parser


###########################################################################
## DISPLAY ################################################################
###########################################################################


def print_success(message):
    """Print success message with green [+] prefix"""
    print(f"\033[92m[+]\033[0m {message}")


def print_error(message):
    """Print error message with red [!] prefix"""
    print(f"\033[91m[!]\033[0m {message}")


def print_info(message):
    """Print info message with blue [i] prefix"""
    print(f"\033[94m[i]\033[0m {message}")


def print_warning(message):
    """Print warning message with yellow [!] prefix"""
    print(f"\033[93m[!]\033[0m {message}")


RISK_COLORS = {
    "critical": "red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "green",
}


def build_score_bar(score, width=15):
    """Build a colored progress bar string for an abuse confidence score"""
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
    bar.append("█" * filled, style=color)
    bar.append("░" * empty, style="dim")
    bar.append(f" {score}%", style=f"bold {color}")
    return bar


def display_results(df):
    """Display results as a rich colored table with a summary panel"""
    table = Table(
        title="IP Analysis Results",
        show_lines=True,
        header_style="bold cyan",
        border_style="dim",
    )

    table.add_column("IP Address", style="bold white", no_wrap=True)
    table.add_column("Risk", justify="center")
    table.add_column("Score", justify="center", min_width=20)
    table.add_column("Country", justify="center")
    table.add_column("Whitelisted", justify="center")
    table.add_column("TOR", justify="center")
    table.add_column("Public", justify="center")

    for _, row in df.iterrows():
        risk = str(row.get("risk_level", "N/A"))
        risk_color = RISK_COLORS.get(risk, "white")
        score = int(row.get("abuseConfidenceScore", 0))

        table.add_row(
            str(row.get("ipAddress", "N/A")),
            Text(risk.upper(), style=f"bold {risk_color}"),
            build_score_bar(score),
            str(row.get("countryCode", "N/A")),
            "Yes" if row.get("isWhitelisted") else "No",
            Text("Yes", style="bold red") if row.get("isTor") else Text("No"),
            "Yes" if row.get("isPublic") else Text("No", style="dim"),
        )

    console.print()
    console.print(table)

    # Summary panel
    total = len(df)
    risk_counts = df["risk_level"].value_counts() if "risk_level" in df.columns else pd.Series()

    summary_lines = [f"[bold]Total IPs:[/bold]  {total}"]

    for level in ["critical", "high", "medium", "low"]:
        count = risk_counts.get(level, 0)
        color = RISK_COLORS.get(level, "white")
        bar_width = round(count / total * 20) if total > 0 else 0
        bar = "█" * bar_width + "░" * (20 - bar_width)
        summary_lines.append(f"[{color}]{level.capitalize():10s}[/{color}]  {count:>3d}  [{color}]{bar}[/{color}]")

    if "countryCode" in df.columns:
        unique_countries = df["countryCode"].nunique()
        summary_lines.append(f"[bold]Countries:[/bold]  {unique_countries}")

    if "isTor" in df.columns:
        tor_count = df["isTor"].sum()
        if tor_count > 0:
            summary_lines.append(f"[bold red]TOR nodes:[/bold red] {tor_count}")

    console.print()
    console.print(Panel("\n".join(summary_lines), title="Summary", border_style="cyan", expand=False))
    console.print()


###########################################################################
## API RESPONSE HANDLING ##################################################
###########################################################################


def handle_api_response(
    response, success_message="Operation completed successfully", verbose: bool = False
):
    """Handle API response with proper error management"""
    try:
        response.raise_for_status()
        if verbose:
            print_success(success_message)
        return response.json() if response.content else {"status": "success"}
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 401:
            print_error("Authentication failed. Please check your API token.")
        elif response.status_code == 403:
            print_error(
                "Access forbidden. You don't have permission to perform this action."
            )
        elif response.status_code == 404:
            print_error("Resource not found. Please check the UUID provided.")
        elif response.status_code == 400:
            print_error("Bad request. Please check your input parameters.")
        else:
            print_error(f"HTTP Error {response.status_code}: {http_err}")

        try:
            error_details = response.json()
            print_error(f"API Error Details: {json.dumps(error_details, indent=2)}")
        except requests.exceptions.HTTPError as http_err:
            print_error(f"Response content: {response.text}")
        return None
    except requests.exceptions.RequestException as err:
        print_error(f"Request failed: {err}")
        return None


###########################################################################
## SECRET MANAGEMENT ######################################################
###########################################################################


def load_api_key(args):
    """Load API key from .env, arguments, or ask user"""
    env_path = Path(ENV_FILE)
    if env_path.exists():
        load_dotenv(env_path)

    api_key = None

    # Check argument
    if args.token:
        api_key = args.token
        if args.verbose:
            print_info("API key provided via --token argument")

    # Check environment variable
    elif os.getenv("ABUSEIPDB_API_KEY"):
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if args.verbose:
            print_info("API key loaded from .env")

    # Ask and save
    else:
        print_warning("AbuseIPDB API key not found.")
        print_info("You can get your API key at: https://www.abuseipdb.com/api")

        api_key = getpass.getpass("Enter your AbuseIPDB API key: ").strip()

        if not api_key:
            print_error("API key required to continue.")
            sys.exit(1)

        # Save to .env
        save_choice = input("Do you want to save this key in .env? (y/N): ").lower()
        if save_choice in ["y", "yes"]:
            save_api_key_to_env(api_key=api_key, verbose=args.verbose)
            print_info("API key saved to .env")

    if not api_key:
        print_error("API key required to use AbuseIPDB, aborting...")
        sys.exit(1)

    return api_key


def save_api_key_to_env(api_key, verbose: bool = False):
    """Save API key to .env file"""
    try:
        env_path = Path(ENV_FILE)

        # Create .env file if it doesn't exist
        if not env_path.exists():
            env_path.touch()
            if verbose:
                print_info(f"File {ENV_FILE} created")

        # Add or update API key
        set_key(env_path, "ABUSEIPDB_API_KEY", api_key)

        # Add comment if file is new
        with open(env_path, "r") as f:
            content = f.read()

        if "AbuseIPDB API Key" not in content:
            with open(env_path, "a") as f:
                f.write("\n# AbuseIPDB API Key\n")

    except Exception as e:
        print_error(f"Error saving to file: {e}")


def validate_api_key(api_key):
    """Validate API key format (basic validation)"""
    if not api_key:
        return False

    # AbuseIPDB keys are typically 80 characters
    if len(api_key) < 50:
        print_error("API key seems too short")
        return False

    return True


###########################################################################
## ABUSE API METHODS  #####################################################
###########################################################################


def check_ip_abuse(ip_address, api_key, verbose: bool = False):
    """Check IP abuse score on AbuseIPDB"""
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": ""}

    try:
        response = requests.get(API_URL, headers=headers, params=params)
        return handle_api_response(
            response=response,
            success_message=f"{ip_address} successfully verfifed on AbuseIP",
            verbose=verbose,
        )
    except requests.exceptions.RequestException as e:
        print(f"Error querying {ip_address}: {e}")
        return None


###########################################################################
## DATA MANIPULATION ######################################################
###########################################################################


def add_risk_level_column(df, verbose: bool = False):
    """Add risk_level column based on abuseConfidenceScore"""

    def get_risk_level(score):
        if score >= RISK_CRITICAL_MIN:
            return "critical"
        elif score >= RISK_HIGH_MIN:
            return "high"
        elif score >= RISK_MEDIUM_MIN:
            return "medium"
        else:
            return "low"

    df["risk_level"] = df["abuseConfidenceScore"].apply(get_risk_level)

    if verbose:
        print_info("Added risk_level column based on abuseConfidenceScore")

    return df


def filter_by_risk_level(df, risk_level, verbose: bool = False):
    """Filter DataFrame by risk level"""
    if risk_level is None:
        if verbose:
            print_info("No risk level filter applied")
        return df

    if verbose:
        print_info(f"Applying risk level filter: {risk_level}")

    min_score, max_score = RISK_LEVELS[risk_level]
    filtered_df = df[
        (df["abuseConfidenceScore"] >= min_score)
        & (df["abuseConfidenceScore"] <= max_score)
    ]

    if filtered_df.empty:
        print_warning(f"No IPs found with risk level: {risk_level}")
    elif verbose:
        print_success(f"Found {len(filtered_df)} IPs with risk level: {risk_level}")

    return filtered_df


def filter_by_score(df, min_score, verbose: bool = False):
    """Filter DataFrame by minimum abuse confidence score"""
    if min_score is None:
        if verbose:
            print_info("No score filter applied")
        return df

    if verbose:
        print_info(f"Applying score filter: >= {min_score}")

    if not (0 <= min_score <= 100):
        print_error("Score must be between 0 and 100")
        return df

    filtered_df = df[df["abuseConfidenceScore"] >= min_score]

    if filtered_df.empty:
        print_warning(f"No IPs found with score >= {min_score}")
    elif verbose:
        print_success(f"Found {len(filtered_df)} IPs with score >= {min_score}")

    return filtered_df


def filter_by_country_code(df, country_code, verbose: bool = False):
    """Filter DataFrame by country code"""
    if country_code is None:
        if verbose:
            print_info("No country code filter applied")
        return df

    country_code = country_code.upper()  # Normalize to uppercase

    if verbose:
        print_info(f"Applying country code filter: {country_code}")

    filtered_df = df[df["countryCode"] == country_code]

    if filtered_df.empty:
        print_warning(f"No IPs found for country code: {country_code}")
    elif verbose:
        print_success(f"Found {len(filtered_df)} IPs for country code: {country_code}")

    return filtered_df


def filter_tor_addresses(df, is_tor, is_not_tor, verbose: bool = False):
    """Filter DataFrame by TOR status"""
    if is_tor and is_not_tor:
        print_error("Cannot use both --is-tor and --is-not-tor flags")
        return df

    if is_tor:
        if verbose:
            print_info("Applying TOR filter: keeping only TOR addresses")
        filtered_df = df[df["isTor"] == True]
        if filtered_df.empty:
            print_warning("No TOR IP addresses found")
        elif verbose:
            print_success(f"Found {len(filtered_df)} TOR IP addresses")
        return filtered_df

    if is_not_tor:
        if verbose:
            print_info("Applying TOR filter: removing TOR addresses")
        filtered_df = df[df["isTor"] == False]
        if filtered_df.empty:
            print_warning("No non-TOR IP addresses found")
        elif verbose:
            print_success(f"Found {len(filtered_df)} non-TOR IP addresses")
        return filtered_df

    if verbose:
        print_info("No TOR filter applied")
    return df


def filter_remove_private(df, remove_private, verbose: bool = False):
    """Filter to keep only public IP addresses"""
    if not remove_private:
        if verbose:
            print_info("No private IP filter applied")
        return df

    if verbose:
        print_info("Applying private IP filter: keeping only public addresses")

    filtered_df = df[df["isPublic"] == True]

    if filtered_df.empty:
        print_warning("No public IP addresses found")
    elif verbose:
        print_success(f"Found {len(filtered_df)} public IP addresses")

    return filtered_df


def filter_remove_whitelisted(df, remove_whitelisted, verbose: bool = False):
    """Filter to keep only non-whitelisted IP addresses"""
    if not remove_whitelisted:
        if verbose:
            print_info("No whitelist filter applied")
        return df

    if verbose:
        print_info("Applying whitelist filter: removing whitelisted addresses")

    filtered_df = df[df["isWhitelisted"] == False]

    if filtered_df.empty:
        print_warning("No non-whitelisted IP addresses found")
    elif verbose:
        print_success(f"Found {len(filtered_df)} non-whitelisted IP addresses")

    return filtered_df


def apply_all_filters(df, args):
    """Apply all filtering operations based on command line arguments"""
    if df.empty:
        return df

    original_count = len(df)

    if args.verbose:
        print_info(f"Starting with {original_count} IP addresses")

    # Add risk level column first
    df = add_risk_level_column(df, verbose=args.verbose)

    # Apply filters in sequence
    df = filter_by_risk_level(df, args.risk_level, verbose=args.verbose)
    if args.verbose:
        print_info(f"After risk level filter: {len(df)} IPs remaining")

    df = filter_by_score(df, args.score, verbose=args.verbose)
    if args.verbose:
        print_info(f"After score filter: {len(df)} IPs remaining")

    df = filter_by_country_code(df, args.country_code, verbose=args.verbose)
    if args.verbose:
        print_info(f"After country filter: {len(df)} IPs remaining")

    df = filter_tor_addresses(df, args.is_tor, args.is_not_tor, verbose=args.verbose)
    if args.verbose:
        print_info(f"After TOR filter: {len(df)} IPs remaining")

    df = filter_remove_private(df, args.remove_private, verbose=args.verbose)
    if args.verbose:
        print_info(f"After private IP filter: {len(df)} IPs remaining")

    df = filter_remove_whitelisted(df, args.remove_whitelisted, verbose=args.verbose)
    if args.verbose:
        print_info(f"After whitelist filter: {len(df)} IPs remaining")

    if args.verbose:
        print_success(f"Final result: {len(df)} IP addresses after filtering")
        if not df.empty:
            print_info("Final risk level distribution:")
            print(df["risk_level"].value_counts().to_string())

    return df


###########################################################################
## IMPORT / EXPORT METHODS ################################################
###########################################################################


def export_dataframe(df, formats, base_filename="ip_analysis", verbose: bool = False):
    """
    Export DataFrame to multiple formats using pandas default methods

    Args:
        df: pandas DataFrame to export
        formats: list of format strings ['csv', 'json', 'excel', 'html', 'parquet']
        base_filename: base name for output files (without extension)
        verbose: whether to show detailed output
    """
    if not formats:
        return

    exported_files = []

    for format_type in formats:
        try:
            filename = f"{base_filename}.{format_type}"

            if format_type == "csv":
                df.to_csv(filename, index=False)
                if verbose:
                    print_info(f"Exported to CSV: {filename}")

            elif format_type == "json":
                df.to_json(filename, orient="records", indent=2, date_format="iso")
                if verbose:
                    print_info(f"Exported to JSON: {filename}")

            elif format_type == "excel":
                df.to_excel(filename, index=False, engine="openpyxl")
                if verbose:
                    print_info(f"Exported to Excel: {filename}")

            elif format_type == "html":
                df.to_html(
                    filename,
                    index=False,
                    classes="table table-striped table-bordered",
                    table_id="ip-analysis-table",
                    escape=False,
                )
                if verbose:
                    print_info(f"Exported to HTML: {filename}")

            elif format_type == "parquet":
                df.to_parquet(filename, index=False)
                if verbose:
                    print_info(f"Exported to Parquet: {filename}")

            exported_files.append(filename)

        except Exception as e:
            print_error(f"Failed to export to {format_type}: {str(e)}")

    if exported_files:
        print_success(
            f"Successfully exported to {len(exported_files)} format(s): {', '.join(exported_files)}"
        )

    return exported_files

def load_dataframe_from_file(file_path, file_format="auto", verbose: bool = False):
    """
    Load DataFrame from various file formats
    
    Args:
        file_path: Path to the source file
        file_format: Format of the file ('csv', 'json', 'excel', 'parquet', 'auto')
        verbose: Whether to show detailed output
    
    Returns:
        pandas.DataFrame or None if loading failed
    """
    if not os.path.exists(file_path):
        print_error(f"File not found: {file_path}")
        return None
    
    # Auto-detect format from file extension
    if file_format == "auto":
        extension = Path(file_path).suffix.lower()
        format_mapping = {
            '.csv': 'csv',
            '.json': 'json',
            '.xlsx': 'excel',
            '.xls': 'excel',
            '.parquet': 'parquet',
            '.pq': 'parquet'
        }
        file_format = format_mapping.get(extension)
        
        if not file_format:
            print_error(f"Cannot auto-detect format for file: {file_path}")
            print_info("Supported extensions: .csv, .json, .xlsx, .xls, .parquet, .pq")
            return None
        
        if verbose:
            print_info(f"Auto-detected format: {file_format}")
    
    try:
        if verbose:
            print_info(f"Loading data from {file_path} as {file_format.upper()}")
        
        if file_format == "csv":
            df = pd.read_csv(file_path)
            
        elif file_format == "json":
            df = pd.read_json(file_path)
            
        elif file_format == "excel":
            df = pd.read_excel(file_path)
            
        elif file_format == "parquet":
            df = pd.read_parquet(file_path)
            
        else:
            print_error(f"Unsupported file format: {file_format}")
            return None
        
        if df.empty:
            print_warning("Loaded file is empty")
            return None
        
        if verbose:
            print_success(f"Successfully loaded {len(df)} records from {file_path}")
            print_info(f"Columns: {', '.join(df.columns.tolist())}")
        
        return df
        
    except Exception as e:
        print_error(f"Failed to load file {file_path}: {str(e)}")
        return None

def validate_loaded_dataframe(df, verbose: bool = False):
    """
    Validate that the loaded DataFrame has the required columns for IP analysis
    
    Args:
        df: pandas DataFrame to validate
        verbose: Whether to show detailed output
    
    Returns:
        bool: True if valid, False otherwise
    """
    required_columns = ['ipAddress', 'abuseConfidenceScore']
    optional_columns = ['countryCode', 'isWhitelisted', 'isTor', 'isPublic', 'risk_level']
    
    missing_required = [col for col in required_columns if col not in df.columns]
    
    if missing_required:
        print_error(f"Missing required columns: {', '.join(missing_required)}")
        print_info(f"Available columns: {', '.join(df.columns.tolist())}")
        return False
    
    missing_optional = [col for col in optional_columns if col not in df.columns]
    
    if verbose:
        print_success("Required columns found")
        if missing_optional:
            print_warning(f"Missing optional columns: {', '.join(missing_optional)}")
            print_info("Missing columns will be handled automatically")
    
    return True

###########################################################################
## PROCESSING METHODS #####################################################
###########################################################################


def process_ip_addresses(args, api_key):
    ip_array = []
    success_count = 0
    error_count = 0

    with tqdm(args.ips, desc="Analyzing IPs", unit="IP", colour="green") as pbar:
        for ip in pbar:
            try:
                pbar.set_description(f"Checking {ip}")
                ip_data = check_ip_abuse(
                    ip_address=ip, api_key=api_key, verbose=args.verbose
                ).get("data")

                if ip_data and "reports" in ip_data:
                    del ip_data["reports"]
                    ip_array.append(ip_data)
                    success_count += 1
                    status = "✓"
                else:
                    error_count += 1
                    status = "✗"

                pbar.set_postfix(
                    {"✓": success_count, "✗": error_count, "Status": status}
                )

            except Exception as e:
                error_count += 1
                if args.verbose:
                    print_error(f"Error checking {ip}: {str(e)}")
                pbar.set_postfix({"✓": success_count, "✗": error_count, "Status": "✗"})

    if args.verbose:
        print_info(
            f"API calls completed: {success_count} successful, {error_count} failed"
        )

    # Data processing
    if not ip_array:
        print_error("No valid IP data retrieved")
        return None

    df = pd.DataFrame(ip_array)
    filtered_df = apply_all_filters(df, args)

    if filtered_df.empty:
        print_error("No IP addresses match the specified criteria")
        return None

    # Display results
    columns_order = [
        "ipAddress",
        "risk_level",
        "abuseConfidenceScore",
        "countryCode",
        "isWhitelisted",
        "isTor",
        "isPublic",
    ] + [
        col
        for col in filtered_df.columns
        if col
        not in [
            "ipAddress",
            "risk_level",
            "abuseConfidenceScore",
            "countryCode",
            "isWhitelisted",
            "isTor",
            "isPublic",
        ]
    ]

    display_df = filtered_df[columns_order]

    # Export if requested
    if args.export:
        if args.verbose:
            print_info(f"Exporting to formats: {', '.join(args.export)}")

        # Generate base filename with timestamp
        timestamp = pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"ip_analysis_{timestamp}"

        export_dataframe(
            df=display_df,
            formats=args.export,
            base_filename=base_filename,
            verbose=args.verbose,
        )

    return display_df

def process_loaded_data(args):
    """
    Process data loaded from file with the same filtering capabilities as check command
    
    Args:
        args: Command line arguments from argparse
    
    Returns:
        pandas.DataFrame or None
    """
    # Load the data
    df = load_dataframe_from_file(args.source, args.format, verbose=args.verbose)
    
    if df is None:
        return None
    
    # Validate the DataFrame structure
    if not validate_loaded_dataframe(df, verbose=args.verbose):
        return None
    
    # Add missing columns with default values if needed
    if 'countryCode' not in df.columns:
        df['countryCode'] = 'Unknown'
        if args.verbose:
            print_info("Added missing 'countryCode' column with default value 'Unknown'")
    
    if 'isWhitelisted' not in df.columns:
        df['isWhitelisted'] = False
        if args.verbose:
            print_info("Added missing 'isWhitelisted' column with default value False")
    
    if 'isTor' not in df.columns:
        df['isTor'] = False
        if args.verbose:
            print_info("Added missing 'isTor' column with default value False")
    
    if 'isPublic' not in df.columns:
        df['isPublic'] = True
        if args.verbose:
            print_info("Added missing 'isPublic' column with default value True")
    
    # Apply all filters (same as check command)
    filtered_df = apply_all_filters(df, args)
    
    if filtered_df.empty:
        print_error("No IP addresses match the specified criteria")
        return None
    
    # Display results
    columns_order = ['ipAddress', 'risk_level', 'abuseConfidenceScore', 'countryCode', 
                    'isWhitelisted', 'isTor', 'isPublic'] + \
                   [col for col in filtered_df.columns if col not in 
                    ['ipAddress', 'risk_level', 'abuseConfidenceScore', 'countryCode', 
                     'isWhitelisted', 'isTor', 'isPublic']]
    
    # Only include columns that exist in the DataFrame
    available_columns = [col for col in columns_order if col in filtered_df.columns]
    display_df = filtered_df[available_columns]
    
 
    
    # Export if requested
    if args.export:
        if args.verbose:
            print_info(f"Exporting to formats: {', '.join(args.export)}")
        
        # Generate base filename with timestamp
        timestamp = pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')
        source_name = Path(args.source).stem
        base_filename = f"{source_name}_filtered_{timestamp}"
        
        export_dataframe(
            df=display_df, 
            formats=args.export, 
            base_filename=base_filename,
            verbose=args.verbose
        )
    
    return display_df

###########################################################################
## MAIN ###################################################################
###########################################################################


def main():
    parser = create_parser()

    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help()
        return

    args = parser.parse_args()

    if args.command == "check":
        try:
            api_key = load_api_key(args=args)
        except KeyboardInterrupt:
            print_error("\nOperation aborted by user...")
            return
        except Exception as e:
            print_error(f"Error occured while loading API key: {e}")
            return

        ip_df = process_ip_addresses(args=args, api_key=api_key)
        if ip_df is not None and not ip_df.empty:
            display_results(ip_df)

    elif args.command == "load":
        ip_df = process_loaded_data(args)
        if ip_df is not None and not ip_df.empty:
            display_results(ip_df)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
