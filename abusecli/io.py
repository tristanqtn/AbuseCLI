import os

import pandas as pd

from pathlib import Path

from .constants import (
    IMPORT_EXTENSION_MAP,
    REQUIRED_COLUMNS,
    OPTIONAL_COLUMNS,
    COLUMN_DEFAULTS,
)
from .display import print_success, print_error, print_info, print_warning


def load_dataframe(
    file_path: str, file_format: str = "auto", verbose: bool = False
) -> pd.DataFrame | None:
    if not os.path.exists(file_path):
        print_error(f"File not found: {file_path}")
        return None

    if file_format == "auto":
        extension = Path(file_path).suffix.lower()
        file_format = IMPORT_EXTENSION_MAP.get(extension)

        if not file_format:
            print_error(f"Cannot auto-detect format for: {file_path}")
            print_info(f"Supported extensions: {', '.join(IMPORT_EXTENSION_MAP.keys())}")
            return None

        if verbose:
            print_info(f"Auto-detected format: {file_format}")

    try:
        if verbose:
            print_info(f"Loading {file_path} as {file_format.upper()}")

        readers = {
            "csv": lambda: pd.read_csv(file_path),
            "json": lambda: pd.read_json(file_path),
            "excel": lambda: pd.read_excel(file_path),
            "parquet": lambda: pd.read_parquet(file_path),
        }

        if file_format not in readers:
            print_error(f"Unsupported format: {file_format}")
            return None

        df = readers[file_format]()

        if df.empty:
            print_warning("File is empty")
            return None

        if verbose:
            print_success(f"Loaded {len(df)} records from {file_path}")
            print_info(f"Columns: {', '.join(df.columns.tolist())}")

        return df

    except Exception as e:
        print_error(f"Failed to load {file_path}: {e}")
        return None


def validate_dataframe(df: pd.DataFrame, verbose: bool = False) -> bool:
    missing_required = [col for col in REQUIRED_COLUMNS if col not in df.columns]

    if missing_required:
        print_error(f"Missing required columns: {', '.join(missing_required)}")
        print_info(f"Available columns: {', '.join(df.columns.tolist())}")
        return False

    if verbose:
        missing_optional = [col for col in OPTIONAL_COLUMNS if col not in df.columns]
        print_success("Required columns present")
        if missing_optional:
            print_warning(f"Missing optional columns: {', '.join(missing_optional)}")

    return True


def fill_missing_columns(df: pd.DataFrame, verbose: bool = False) -> pd.DataFrame:
    df = df.copy()
    for col, default in COLUMN_DEFAULTS.items():
        if col not in df.columns:
            df[col] = default
            if verbose:
                print_info(f"Added missing column '{col}' with default: {default!r}")
    return df


def validate_report_source(df: pd.DataFrame, verbose: bool = False) -> bool:
    if "ipAddress" not in df.columns:
        print_error("Missing required column: ipAddress")
        print_info(f"Available columns: {', '.join(df.columns.tolist())}")
        return False
    if verbose:
        print_success("Column 'ipAddress' found")
        if "abuseConfidenceScore" not in df.columns:
            print_warning("No 'abuseConfidenceScore' column — --min-score filter will be skipped")
    return True


def export_dataframe(
    df: pd.DataFrame,
    formats: list[str],
    base_filename: str = "ip_analysis",
    verbose: bool = False,
) -> list[str]:
    if not formats:
        return []

    exported = []

    for fmt in formats:
        try:
            ext_map = {
                "csv": "csv",
                "json": "json",
                "excel": "xlsx",
                "html": "html",
                "parquet": "parquet",
            }
            ext = ext_map.get(fmt, fmt)
            filename = f"{base_filename}.{ext}"

            writers = {
                "csv": lambda: df.to_csv(filename, index=False),
                "json": lambda: df.to_json(filename, orient="records", indent=2, date_format="iso"),
                "excel": lambda: df.to_excel(filename, index=False, engine="openpyxl"),
                "html": lambda: df.to_html(
                    filename,
                    index=False,
                    classes="table table-striped table-bordered",
                    table_id="ip-analysis-table",
                    escape=False,
                ),
                "parquet": lambda: df.to_parquet(filename, index=False),
            }

            if fmt not in writers:
                print_error(f"Unsupported export format: {fmt}")
                continue

            writers[fmt]()
            exported.append(filename)

            if verbose:
                print_info(f"Exported to {fmt.upper()}: {filename}")

        except Exception as e:
            print_error(f"Failed to export as {fmt}: {e}")

    if exported:
        print_success(f"Exported {len(exported)} file(s): {', '.join(exported)}")

    return exported