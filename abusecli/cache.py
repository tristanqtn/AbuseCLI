import json
from datetime import datetime, timedelta
from pathlib import Path

from .constants import DEFAULT_CACHE_TTL_HOURS

CACHE_PATH = Path(__file__).parent.parent / ".abusecli_cache.json"


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save(cache: dict, path: Path) -> None:
    try:
        path.write_text(json.dumps(cache, indent=2, default=str), encoding="utf-8")
    except Exception:
        pass


def get_cached(
    ip: str,
    ttl_hours: int = DEFAULT_CACHE_TTL_HOURS,
    path: Path = CACHE_PATH,
) -> dict | None:
    cache = _load(path)
    entry = cache.get(ip)
    if not entry:
        return None
    try:
        cached_at = datetime.fromisoformat(entry["timestamp"])
        if datetime.now() - cached_at < timedelta(hours=ttl_hours):
            return entry["data"]
    except Exception:
        pass
    return None


def set_cached(ip: str, data: dict, path: Path = CACHE_PATH) -> None:
    cache = _load(path)
    cache[ip] = {
        "timestamp": datetime.now().isoformat(),
        "data": data,
    }
    _save(cache, path)
