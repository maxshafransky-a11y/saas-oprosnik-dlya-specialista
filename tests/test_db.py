import importlib
import inspect
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import text

ROOT = Path(__file__).parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

config = importlib.import_module("app.config")
db = importlib.import_module("app.db")
get_settings = config.get_settings
get_engine = db.get_engine
session_scope = db.session_scope


RUNTIME_DATABASE_URL = (
    "postgresql+psycopg://health_app:health_app_dev_only@127.0.0.1:55432/health_intake"
)
OWNER_DATABASE_URL = (
    "postgresql+psycopg://health_owner:health_owner_dev_only@127.0.0.1:55432/health_intake"
)


@pytest.fixture(autouse=True)
def reset_runtime_caches():
    get_settings.cache_clear()
    get_engine.cache_clear()
    yield
    get_engine.cache_clear()
    get_settings.cache_clear()


def _configure_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", RUNTIME_DATABASE_URL)
    monkeypatch.setenv("DATABASE_OWNER_URL", OWNER_DATABASE_URL)


def test_settings_reads_env_and_masks_urls(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_runtime(monkeypatch)

    settings = get_settings()

    assert settings.app_env == "test"
    assert settings.database_url.get_secret_value() == RUNTIME_DATABASE_URL
    assert settings.database_owner_url.get_secret_value() == OWNER_DATABASE_URL
    assert RUNTIME_DATABASE_URL not in repr(settings)
    assert OWNER_DATABASE_URL not in repr(settings)
    assert "**********" in repr(settings)


def test_runtime_session_connects_as_health_app(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_runtime(monkeypatch)

    with session_scope() as session:
        assert session.execute(text("SELECT current_user")).scalar_one() == "health_app"


def test_session_scope_sets_transaction_local_workspace(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_runtime(monkeypatch)
    workspace_id = uuid4()

    with session_scope(workspace_id) as session:
        value = session.execute(
            text("SELECT current_setting('app.workspace_id', true)")
        ).scalar_one()

    assert value == str(workspace_id)


def test_workspace_context_does_not_leak_to_next_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_runtime(monkeypatch)

    with session_scope(uuid4()) as session:
        session.execute(text("SELECT current_setting('app.workspace_id', true)"))

    with session_scope() as session:
        value = session.execute(
            text("SELECT current_setting('app.workspace_id', true)")
        ).scalar_one()

    assert value in (None, "")


def test_exception_rolls_back_transaction_and_temp_table(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_runtime(monkeypatch)

    with pytest.raises(RuntimeError, match="rollback probe"), session_scope() as session:
        session.execute(
            text("CREATE TEMPORARY TABLE task4_rollback_probe (value integer) ON COMMIT DROP")
        )
        session.execute(text("INSERT INTO task4_rollback_probe VALUES (1)"))
        raise RuntimeError("rollback probe")

    with session_scope() as session:
        assert (
            session.execute(text("SELECT to_regclass('pg_temp.task4_rollback_probe')")).scalar_one()
            is None
        )


def test_runtime_db_module_does_not_reference_owner_url() -> None:
    source = Path(inspect.getfile(db)).read_text(encoding="utf-8")

    assert "DATABASE_OWNER_URL" not in source
    assert "database_owner_url" not in source
