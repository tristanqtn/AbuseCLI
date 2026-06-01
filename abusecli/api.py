import json
from datetime import datetime

import requests

from .constants import (
    ABUSEIPDB_BLACKLIST_URL,
    ABUSEIPDB_CHECK_BLOCK_URL,
    ABUSEIPDB_CHECK_URL,
    ABUSEIPDB_REPORT_URL,
    DEFAULT_BLACKLIST_CONFIDENCE,
    DEFAULT_BLACKLIST_LIMIT,
    DEFAULT_MAX_AGE_IN_DAYS,
)
from .display import print_error, print_success

_rate_limits: dict[str, dict] = {}


def _extract_rate_limit(response: requests.Response, endpoint: str) -> None:
    try:
        limit = response.headers.get("X-RateLimit-Limit")
        remaining = response.headers.get("X-RateLimit-Remaining")
        reset = response.headers.get("X-RateLimit-Reset")
        retry_after = response.headers.get("Retry-After")
        if limit is not None:
            _rate_limits[endpoint] = {
                "limit": int(limit),
                "remaining": int(remaining) if remaining is not None else None,
                "reset": int(reset) if reset is not None else None,
                "retry_after": int(retry_after) if retry_after is not None else None,
            }
    except (ValueError, AttributeError):
        pass


def get_rate_limits() -> dict[str, dict]:
    return dict(_rate_limits)


def format_reset_time(reset_epoch: int) -> str:
    delta = int(reset_epoch - datetime.now().timestamp())
    if delta <= 0:
        return "reset imminent"
    hours = delta // 3600
    minutes = (delta % 3600) // 60
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _format_retry_after(seconds: int) -> str:
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def handle_api_response(
    response: requests.Response,
    success_message: str = "Request completed",
    verbose: bool = False,
    endpoint: str = "",
) -> dict | None:
    if endpoint:
        _extract_rate_limit(response, endpoint)

    try:
        response.raise_for_status()
        if verbose:
            print_success(success_message)
        return response.json() if response.content else {"status": "success"}

    except requests.exceptions.HTTPError:
        status = response.status_code
        messages = {
            400: "Bad request. Please check your input parameters.",
            401: "Authentication failed. Please check your API token.",
            403: "Access forbidden. You don't have permission to perform this action.",
            404: "Resource not found.",
            429: "Rate limit exceeded. Please wait before retrying.",
        }
        print_error(messages.get(status, f"HTTP error {status}"))

        if status == 429 and endpoint:
            rl = _rate_limits.get(endpoint, {})
            if rl.get("retry_after"):
                print_error(f"Retry after: {_format_retry_after(rl['retry_after'])}")
            if rl.get("reset"):
                print_error(f"Limit resets in: {format_reset_time(rl['reset'])}")

        try:
            error_details = response.json()
            print_error(f"API details: {json.dumps(error_details, indent=2)}")
        except Exception:
            print_error(f"Response body: {response.text}")

        return None

    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None


def get_blacklist(
    api_key: str,
    confidence_minimum: int = DEFAULT_BLACKLIST_CONFIDENCE,
    limit: int = DEFAULT_BLACKLIST_LIMIT,
    ip_version: int | None = None,
    only_countries: list[str] | None = None,
    except_countries: list[str] | None = None,
    verbose: bool = False,
) -> dict | None:
    headers = {"Key": api_key, "Accept": "application/json"}
    params: dict = {"confidenceMinimum": confidence_minimum, "limit": limit}
    if ip_version:
        params["ipVersion"] = ip_version
    if only_countries:
        params["onlyCountries"] = ",".join(only_countries)
    if except_countries:
        params["exceptCountries"] = ",".join(except_countries)

    try:
        response = requests.get(ABUSEIPDB_BLACKLIST_URL, headers=headers, params=params)
        return handle_api_response(
            response=response,
            success_message="Blacklist retrieved",
            verbose=verbose,
            endpoint="blacklist",
        )
    except requests.exceptions.RequestException as e:
        print_error(f"Error fetching blacklist: {e}")
        return None


def check_ip(
    ip_address: str,
    api_key: str,
    max_age_in_days: int = DEFAULT_MAX_AGE_IN_DAYS,
    verbose: bool = False,
) -> dict | None:
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": max_age_in_days, "verbose": ""}

    try:
        response = requests.get(ABUSEIPDB_CHECK_URL, headers=headers, params=params)
        return handle_api_response(
            response=response,
            success_message=f"{ip_address} verified",
            verbose=verbose,
            endpoint="check",
        )
    except requests.exceptions.RequestException as e:
        print_error(f"Error querying {ip_address}: {e}")
        return None


def check_block(
    network: str,
    api_key: str,
    max_age_in_days: int = 30,
    verbose: bool = False,
) -> dict | None:
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"network": network, "maxAgeInDays": max_age_in_days}

    try:
        response = requests.get(ABUSEIPDB_CHECK_BLOCK_URL, headers=headers, params=params)
        return handle_api_response(
            response=response,
            success_message=f"{network} block checked",
            verbose=verbose,
            endpoint="check-block",
        )
    except requests.exceptions.RequestException as e:
        print_error(f"Error querying block {network}: {e}")
        return None


def report_ip(
    ip_address: str,
    api_key: str,
    categories: list[int],
    comment: str = "",
    verbose: bool = False,
) -> dict | None:
    headers = {"Key": api_key, "Accept": "application/json"}
    payload = {
        "ip": ip_address,
        "categories": ",".join(str(c) for c in categories),
        "comment": comment,
    }

    try:
        response = requests.post(ABUSEIPDB_REPORT_URL, headers=headers, data=payload)
        return handle_api_response(
            response=response,
            success_message=f"{ip_address} reported",
            verbose=verbose,
            endpoint="report",
        )
    except requests.exceptions.RequestException as e:
        print_error(f"Error reporting {ip_address}: {e}")
        return None
