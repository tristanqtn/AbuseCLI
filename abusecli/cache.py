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


def _is_expired(entry: dict, now: datetime, ttl_hours: int) -> bool:
    try:
        return now - datetime.fromisoformat(entry["timestamp"]) >= timedelta(hours=ttl_hours)
    except Exception:
        return True


def get_all_entries(path: Path = CACHE_PATH) -> dict:
    return _load(path)


def get_cache_stats(
    ttl_hours: int = DEFAULT_CACHE_TTL_HOURS,
    path: Path = CACHE_PATH,
) -> dict:
    cache = _load(path)
    now = datetime.now()
    timestamps = []
    expired = 0

    for entry in cache.values():
        try:
            cached_at = datetime.fromisoformat(entry["timestamp"])
            timestamps.append(cached_at)
        except Exception:
            pass
        if _is_expired(entry, now, ttl_hours):
            expired += 1

    size_bytes = path.stat().st_size if path.exists() else 0

    return {
        "expired": expired,
        "newest": max(timestamps) if timestamps else None,
        "oldest": min(timestamps) if timestamps else None,
        "path": path,
        "size_bytes": size_bytes,
        "total": len(cache),
        "ttl_hours": ttl_hours,
        "valid": len(cache) - expired,
    }


def clear_cache(path: Path = CACHE_PATH) -> int:
    count = len(_load(path))
    _save({}, path)
    return count


def clean_cache(
    ttl_hours: int = DEFAULT_CACHE_TTL_HOURS,
    path: Path = CACHE_PATH,
) -> int:
    cache = _load(path)
    now = datetime.now()
    stale = [ip for ip, entry in cache.items() if _is_expired(entry, now, ttl_hours)]
    for ip in stale:
        del cache[ip]
    _save(cache, path)
    return len(stale)
