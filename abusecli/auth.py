import os
import sys
import getpass

from pathlib import Path
from dotenv import load_dotenv, set_key

from .constants import ENV_FILE, ENV_KEY_NAME
from .display import print_success, print_error, print_info, print_warning


def load_api_key(args) -> str:
    env_path = Path(ENV_FILE)
    if env_path.exists():
        load_dotenv(env_path)

    api_key = None

    if getattr(args, "token", None):
        api_key = args.token
        if getattr(args, "verbose", False):
            print_info("API key provided via --token argument")

    elif os.getenv(ENV_KEY_NAME):
        api_key = os.getenv(ENV_KEY_NAME)
        if getattr(args, "verbose", False):
            print_info("API key loaded from environment / .env")

    else:
        print_warning("AbuseIPDB API key not found.")
        print_info("Get your key at: https://www.abuseipdb.com/api")

        api_key = getpass.getpass("Enter your AbuseIPDB API key: ").strip()

        if not api_key:
            print_error("API key required to continue.")
            sys.exit(1)

        save_choice = input("Save this key to .env? (y/N): ").lower()
        if save_choice in ("y", "yes"):
            save_api_key_to_env(api_key=api_key, verbose=getattr(args, "verbose", False))
            print_info("API key saved to .env")

    if not api_key:
        print_error("API key required. Aborting.")
        sys.exit(1)

    return api_key


def save_api_key_to_env(api_key: str, verbose: bool = False) -> None:
    try:
        env_path = Path(ENV_FILE)

        if not env_path.exists():
            env_path.touch()
            if verbose:
                print_info(f"Created {ENV_FILE}")

        set_key(env_path, ENV_KEY_NAME, api_key)

        with open(env_path, "r") as f:
            content = f.read()

        if "AbuseIPDB API Key" not in content:
            with open(env_path, "a") as f:
                f.write("\n# AbuseIPDB API Key\n")

        if verbose:
            print_success(f"API key saved to {ENV_FILE}")

    except Exception as e:
        print_error(f"Failed to save API key: {e}")


def validate_api_key(api_key: str) -> bool:
    if not api_key:
        return False
    if len(api_key) < 50:
        print_error("API key appears too short (expected ~80 characters)")
        return False
    return True