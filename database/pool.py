"""Bounded Psycopg connection pool lifecycle."""

from __future__ import annotations

from threading import Lock

from db_config import DatabaseSettings, get_database_settings


_pool = None
_pool_lock = Lock()


def _build_pool(settings: DatabaseSettings):
    try:
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool
    except ImportError as exc:
        raise RuntimeError(
            "PostgreSQL dependencies are not installed. Run: pip install -r requirements.txt"
        ) from exc

    return ConnectionPool(
        conninfo=settings.database_url,
        min_size=settings.pool_min_size,
        max_size=settings.pool_max_size,
        timeout=settings.pool_timeout_seconds,
        kwargs={"row_factory": dict_row},
        open=False,
        name="sentra-postgresql",
        check=ConnectionPool.check_connection,
    )


def open_database_pool() -> None:
    """Open and verify the PostgreSQL pool. No-op for SQLite development."""
    global _pool
    settings = get_database_settings()
    if not settings.is_postgresql:
        return
    with _pool_lock:
        if _pool is None or _pool.closed:
            _pool = _build_pool(settings)
            _pool.open(wait=True)
        _pool.check()


def get_database_pool():
    settings = get_database_settings()
    if not settings.is_postgresql:
        raise RuntimeError("The PostgreSQL pool is unavailable for the SQLite backend.")
    if _pool is None or _pool.closed:
        open_database_pool()
    return _pool


def close_database_pool() -> None:
    global _pool
    with _pool_lock:
        if _pool is not None:
            _pool.close()
            _pool = None


def database_pool_status() -> dict[str, int | bool]:
    """Return safe lifecycle/usage diagnostics without connection information."""
    with _pool_lock:
        if _pool is None:
            return {"initialized": False, "closed": True}
        stats = _pool.get_stats()
        return {
            "initialized": True,
            "closed": bool(_pool.closed),
            "pool_min": int(stats.get("pool_min", 0)),
            "pool_max": int(stats.get("pool_max", 0)),
            "pool_size": int(stats.get("pool_size", 0)),
            "pool_available": int(stats.get("pool_available", 0)),
            "requests_waiting": int(stats.get("requests_waiting", 0)),
        }
