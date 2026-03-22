import json

import requests

from .constants import ABUSEIPDB_CHECK_URL, ABUSEIPDB_REPORT_URL, DEFAULT_MAX_AGE_IN_DAYS
from .display import print_success, print_error


def handle_api_response(
    response: requests.Response,
    success_message: str = "Request completed",
    verbose: bool = False,
) -> dict | None:
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

        try:
            error_details = response.json()
            print_error(f"API details: {json.dumps(error_details, indent=2)}")
        except Exception:
            print_error(f"Response body: {response.text}")

        return None

    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
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
        )
    except requests.exceptions.RequestException as e:
        print_error(f"Error querying {ip_address}: {e}")
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
        )
    except requests.exceptions.RequestException as e:
        print_error(f"Error reporting {ip_address}: {e}")
        return None