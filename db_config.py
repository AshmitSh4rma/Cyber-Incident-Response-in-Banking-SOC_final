"""Database configuration without leaking connection credentials."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from dotenv import load_dotenv


load_dotenv(Path(__file__).resolve().parent / ".env", override=False)


POSTGRES_BACKENDS = {"postgres", "postgresql"}
SQLITE_BACKENDS = {"sqlite", "sqlite3"}


class DatabaseConfigurationError(RuntimeError):
    """Raised when database configuration is missing or contradictory."""


@dataclass(frozen=True)
class DatabaseSettings:
    environment: str
    backend: str
    database_url: str | None = field(repr=False)
    sqlite_path: Path
    pool_min_size: int
    pool_max_size: int
    pool_timeout_seconds: float

    @property
    def is_postgresql(self) -> bool:
        return self.backend == "postgresql"

    @property
    def is_sqlite(self) -> bool:
        return self.backend == "sqlite"


def _normalize_postgres_url(value: str) -> str:
    """Normalize only the legacy scheme; preserve credentials and query options."""
    parts = urlsplit(value.strip())
    scheme = parts.scheme.lower()
    if scheme == "postgres":
        scheme = "postgresql"
    if scheme != "postgresql":
        raise DatabaseConfigurationError(
            "DATABASE_URL must use the postgres:// or postgresql:// scheme."
        )
    if not parts.hostname or not parts.path.strip("/"):
        raise DatabaseConfigurationError(
            "DATABASE_URL must include a PostgreSQL host and database name."
        )
    return urlunsplit((scheme, parts.netloc, parts.path, parts.query, parts.fragment))


def _positive_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise DatabaseConfigurationError(f"{name} must be an integer.") from exc
    if value < 1:
        raise DatabaseConfigurationError(f"{name} must be at least 1.")
    return value


@lru_cache(maxsize=1)
def get_database_settings() -> DatabaseSettings:
    environment = os.getenv("ENVIRONMENT", "development").strip().lower()
    raw_url = os.getenv("DATABASE_URL", "").strip()
    requested_backend = os.getenv("DB_BACKEND", "").strip().lower()

    if requested_backend in POSTGRES_BACKENDS:
        backend = "postgresql"
    elif requested_backend in SQLITE_BACKENDS:
        backend = "sqlite"
    elif requested_backend:
        raise DatabaseConfigurationError(
            "DB_BACKEND must be 'postgresql' or 'sqlite'."
        )
    elif raw_url:
        backend = "postgresql"
    else:
        backend = "sqlite"

    if environment in {"production", "prod"} and backend != "postgresql":
        raise DatabaseConfigurationError(
            "Production requires PostgreSQL. Set DB_BACKEND=postgresql and DATABASE_URL."
        )

    database_url: str | None = None
    if backend == "postgresql":
        if not raw_url:
            raise DatabaseConfigurationError(
                "PostgreSQL is selected but DATABASE_URL is missing."
            )
        database_url = _normalize_postgres_url(raw_url)

    repo_root = Path(__file__).resolve().parent
    sqlite_path = Path(
        os.getenv("SQLITE_DATABASE_PATH", str(repo_root / "soc_incidents.db"))
    ).expanduser().resolve()

    pool_min = _positive_int("DB_POOL_MIN_SIZE", 1)
    pool_max = _positive_int("DB_POOL_MAX_SIZE", 5)
    if pool_min > pool_max:
        raise DatabaseConfigurationError(
            "DB_POOL_MIN_SIZE cannot exceed DB_POOL_MAX_SIZE."
        )

    try:
        pool_timeout = float(os.getenv("DB_POOL_TIMEOUT_SECONDS", "10"))
    except ValueError as exc:
        raise DatabaseConfigurationError(
            "DB_POOL_TIMEOUT_SECONDS must be numeric."
        ) from exc
    if pool_timeout <= 0:
        raise DatabaseConfigurationError(
            "DB_POOL_TIMEOUT_SECONDS must be greater than zero."
        )

    return DatabaseSettings(
        environment=environment,
        backend=backend,
        database_url=database_url,
        sqlite_path=sqlite_path,
        pool_min_size=pool_min,
        pool_max_size=pool_max,
        pool_timeout_seconds=pool_timeout,
    )


def reset_database_settings_cache() -> None:
    """Test helper for environment-isolated configuration checks."""
    get_database_settings.cache_clear()
