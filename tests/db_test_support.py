from __future__ import annotations

import os
import re
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.pool import NullPool

from app.config import get_settings

_TEST_DATABASE_NAME = re.compile(r"^health_intake_test_[0-9a-f]{32}$")


@pytest.fixture
def migrated_database() -> Iterator[tuple[URL, URL]]:
    owner_url = make_url(
        os.environ.get(
            "DATABASE_OWNER_URL",
            "postgresql+psycopg://health_owner:health_owner_dev_only@127.0.0.1:55432/health_intake",
        )
    )
    runtime_url = make_url(
        os.environ.get(
            "DATABASE_URL",
            "postgresql+psycopg://health_app:health_app_dev_only@127.0.0.1:55432/health_intake",
        )
    )
    database_name = f"health_intake_test_{uuid.uuid4().hex}"
    if _TEST_DATABASE_NAME.fullmatch(database_name) is None:
        raise RuntimeError("generated database name failed validation")

    admin_url = owner_url.set(database="postgres")
    test_owner_url = owner_url.set(database=database_name)
    test_runtime_url = runtime_url.set(database=database_name)
    environment = pytest.MonkeyPatch()
    environment.setenv("APP_ENV", "test")
    environment.setenv("DATABASE_URL", test_runtime_url.render_as_string(hide_password=False))
    environment.setenv("DATABASE_OWNER_URL", test_owner_url.render_as_string(hide_password=False))
    get_settings.cache_clear()

    create_engine_instance = create_engine(
        admin_url, isolation_level="AUTOCOMMIT", poolclass=NullPool
    )
    database_created = False
    try:
        with create_engine_instance.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{database_name}" OWNER "health_owner"'))
        database_created = True

        alembic_config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
        get_settings.cache_clear()
        command.upgrade(alembic_config, "head")
        yield test_owner_url, test_runtime_url
    finally:
        create_engine_instance.dispose()
        environment.undo()
        get_settings.cache_clear()
        if _TEST_DATABASE_NAME.fullmatch(database_name) is None:
            raise RuntimeError("refusing to clean up an unexpected database name")
        if database_created:
            drop_engine_instance = create_engine(
                admin_url, isolation_level="AUTOCOMMIT", poolclass=NullPool
            )
            try:
                with drop_engine_instance.connect() as connection:
                    connection.execute(text(f'DROP DATABASE "{database_name}" WITH (FORCE)'))
            finally:
                drop_engine_instance.dispose()
