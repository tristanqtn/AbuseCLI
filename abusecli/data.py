import pandas as pd

from .constants import RISK_LEVELS, RISK_CRITICAL_MIN, RISK_HIGH_MIN, RISK_MEDIUM_MIN
from .display import print_success, print_error, print_info, print_warning


def get_risk_level(score: int) -> str:
    if score >= RISK_CRITICAL_MIN:
        return "critical"
    elif score >= RISK_HIGH_MIN:
        return "high"
    elif score >= RISK_MEDIUM_MIN:
        return "medium"
    return "low"


def add_risk_level_column(df: pd.DataFrame, verbose: bool = False) -> pd.DataFrame:
    df = df.copy()
    df["risk_level"] = df["abuseConfidenceScore"].apply(get_risk_level)
    if verbose:
        print_info("Added risk_level column")
    return df


def filter_by_risk_level(
    df: pd.DataFrame, risk_level: str | None, verbose: bool = False
) -> pd.DataFrame:
    if risk_level is None:
        return df

    if verbose:
        print_info(f"Filtering by risk level: {risk_level}")

    min_score, max_score = RISK_LEVELS[risk_level]
    result = df[
        (df["abuseConfidenceScore"] >= min_score)
        & (df["abuseConfidenceScore"] <= max_score)
    ]

    if result.empty:
        print_warning(f"No IPs found with risk level: {risk_level}")
    elif verbose:
        print_success(f"{len(result)} IPs matched risk level: {risk_level}")

    return result


def filter_by_score(
    df: pd.DataFrame, min_score: int | None, verbose: bool = False
) -> pd.DataFrame:
    if min_score is None:
        return df

    if not (0 <= min_score <= 100):
        print_error("Score threshold must be between 0 and 100")
        return df

    if verbose:
        print_info(f"Filtering by score >= {min_score}")

    result = df[df["abuseConfidenceScore"] >= min_score]

    if result.empty:
        print_warning(f"No IPs found with score >= {min_score}")
    elif verbose:
        print_success(f"{len(result)} IPs matched score >= {min_score}")

    return result


def filter_by_country_code(
    df: pd.DataFrame, country_code: str | None, verbose: bool = False
) -> pd.DataFrame:
    if country_code is None:
        return df

    country_code = country_code.upper()

    if verbose:
        print_info(f"Filtering by country code: {country_code}")

    result = df[df["countryCode"] == country_code]

    if result.empty:
        print_warning(f"No IPs found for country: {country_code}")
    elif verbose:
        print_success(f"{len(result)} IPs matched country: {country_code}")

    return result


def filter_tor(
    df: pd.DataFrame, is_tor: bool, is_not_tor: bool, verbose: bool = False
) -> pd.DataFrame:
    if is_tor and is_not_tor:
        print_error("--is-tor and --is-not-tor are mutually exclusive")
        return df

    if is_tor:
        if verbose:
            print_info("Keeping only TOR addresses")
        result = df[df["isTor"] == True]
        if result.empty:
            print_warning("No TOR addresses found")
        elif verbose:
            print_success(f"{len(result)} TOR addresses found")
        return result

    if is_not_tor:
        if verbose:
            print_info("Removing TOR addresses")
        result = df[df["isTor"] == False]
        if result.empty:
            print_warning("No non-TOR addresses found")
        elif verbose:
            print_success(f"{len(result)} non-TOR addresses found")
        return result

    return df


def filter_remove_private(
    df: pd.DataFrame, remove_private: bool, verbose: bool = False
) -> pd.DataFrame:
    if not remove_private:
        return df

    if verbose:
        print_info("Removing private addresses")

    result = df[df["isPublic"] == True]

    if result.empty:
        print_warning("No public addresses found")
    elif verbose:
        print_success(f"{len(result)} public addresses found")

    return result


def filter_remove_whitelisted(
    df: pd.DataFrame, remove_whitelisted: bool, verbose: bool = False
) -> pd.DataFrame:
    if not remove_whitelisted:
        return df

    if verbose:
        print_info("Removing whitelisted addresses")

    result = df[df["isWhitelisted"] == False]

    if result.empty:
        print_warning("No non-whitelisted addresses found")
    elif verbose:
        print_success(f"{len(result)} non-whitelisted addresses found")

    return result


def apply_all_filters(df: pd.DataFrame, args) -> pd.DataFrame:
    if df.empty:
        return df

    verbose = getattr(args, "verbose", False)

    if verbose:
        print_info(f"Starting with {len(df)} IPs")

    df = add_risk_level_column(df, verbose=verbose)
    df = filter_by_risk_level(df, getattr(args, "risk_level", None), verbose=verbose)
    df = filter_by_score(df, getattr(args, "score", None), verbose=verbose)
    df = filter_by_country_code(df, getattr(args, "country_code", None), verbose=verbose)
    df = filter_tor(
        df,
        getattr(args, "is_tor", False),
        getattr(args, "is_not_tor", False),
        verbose=verbose,
    )
    df = filter_remove_private(df, getattr(args, "remove_private", False), verbose=verbose)
    df = filter_remove_whitelisted(df, getattr(args, "remove_whitelisted", False), verbose=verbose)

    if verbose:
        print_success(f"Final result: {len(df)} IPs after filtering")

    return df


def reorder_columns(df: pd.DataFrame, preferred_order: list[str]) -> pd.DataFrame:
    ordered = [col for col in preferred_order if col in df.columns]
    remaining = [col for col in df.columns if col not in preferred_order]
    return df[ordered + remaining]