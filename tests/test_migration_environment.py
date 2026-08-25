import importlib
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from alembic.config import Config

ROOT = Path(__file__).parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

get_settings = importlib.import_module("app.config").get_settings
get_engine = importlib.import_module("app.db").get_engine


ALEMBIC_INI = ROOT / "alembic.ini"
MIGRATION_ENV = ROOT / "migrations" / "env.py"
OWNER_DATABASE_URL = (
    "postgresql+psycopg://health_owner:health_owner_dev_only@127.0.0.1:55432/health_intake"
)


@pytest.fixture(autouse=True)
def reset_settings_and_engine_caches():
    get_settings.cache_clear()
    get_engine.cache_clear()
    yield
    get_engine.cache_clear()
    get_settings.cache_clear()


def test_alembic_ini_points_to_migrations_without_url_or_credentials() -> None:
    config = Config(str(ALEMBIC_INI))

    assert Path(config.get_main_option("script_location")).resolve() == ROOT / "migrations"
    assert config.get_main_option("path_separator") == "os"
    assert config.get_main_option("sqlalchemy.url") in (None, "")

    source = ALEMBIC_INI.read_text(encoding="utf-8")
    assert not re.search(r"(?:postgresql|://|password|DATABASE_URL|DATABASE_OWNER_URL)", source)


def test_migration_environment_uses_owner_metadata_and_disposes_null_pool() -> None:
    source = MIGRATION_ENV.read_text(encoding="utf-8")

    assert "Base.metadata" in source
    assert "database_owner_url" in source
    assert re.search(r"\bDATABASE_URL\b", source) is None
    assert re.search(r"\bdatabase_url\b", source) is None
    assert "NullPool" in source
    assert "compare_type=True" in source
    assert ".dispose()" in source


def test_alembic_current_uses_owner_url_when_runtime_url_is_invalid() -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "APP_ENV": "test",
            "DATABASE_OWNER_URL": OWNER_DATABASE_URL,
            "DATABASE_URL": "postgresql+psycopg://invalid:invalid@127.0.0.1:55432/health_intake",
        }
    )

    result = subprocess.run(
        [
            "uv",
            "--cache-dir",
            ".uv-cache",
            "run",
            "--frozen",
            "alembic",
            "-c",
            str(ALEMBIC_INI),
            "current",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert OWNER_DATABASE_URL not in output
    assert environment["DATABASE_URL"] not in output


def test_settings_and_engine_caches_can_be_reloaded_without_leaking_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_runtime_url = "postgresql+psycopg://first:secret@127.0.0.1:55432/health_intake"
    first_owner_url = "postgresql+psycopg://owner_first:secret@127.0.0.1:55432/health_intake"
    second_runtime_url = "postgresql+psycopg://second:secret@127.0.0.1:55432/health_intake"
    second_owner_url = "postgresql+psycopg://owner_second:secret@127.0.0.1:55432/health_intake"

    monkeypatch.setenv("DATABASE_URL", first_runtime_url)
    monkeypatch.setenv("DATABASE_OWNER_URL", first_owner_url)
    first_settings = get_settings()
    first_engine = get_engine()

    get_settings.cache_clear()
    get_engine.cache_clear()
    monkeypatch.setenv("DATABASE_URL", second_runtime_url)
    monkeypatch.setenv("DATABASE_OWNER_URL", second_owner_url)
    second_settings = get_settings()
    second_engine = get_engine()

    try:
        assert first_settings.database_owner_url.get_secret_value() == first_owner_url
        assert second_settings.database_owner_url.get_secret_value() == second_owner_url
        assert first_engine.url.render_as_string(hide_password=False) == first_runtime_url
        assert second_engine.url.render_as_string(hide_password=False) == second_runtime_url
    finally:
        first_engine.dispose()
        second_engine.dispose()
