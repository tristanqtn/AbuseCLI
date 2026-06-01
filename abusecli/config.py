import tomllib
from functools import lru_cache
from pathlib import Path

CONFIG_PATH = Path.home() / ".abusecli.toml"


@lru_cache(maxsize=1)
def load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        with open(CONFIG_PATH, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


def get(key: str, default=None):
    return load_config().get(key, default)
