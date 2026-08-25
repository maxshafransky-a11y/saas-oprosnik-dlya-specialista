import importlib
import json
import os
import re
import sys
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, Connection, make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.pool import NullPool

ROOT = Path(__file__).parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

get_settings = importlib.import_module("app.config").get_settings


ALEMBIC_INI = ROOT / "alembic.ini"
DATABASE_NAME_RE = re.compile(r"^health_intake_test_[0-9a-f]{32}$")
OWNER_ROLE = "health_owner"
RUNTIME_ROLE = "health_app"
RUNTIME_DATABASE_URL = (
    "postgresql+psycopg://health_app:health_app_dev_only@127.0.0.1:55432/health_intake"
)
OWNER_DATABASE_URL = (
    "postgresql+psycopg://health_owner:health_owner_dev_only@127.0.0.1:55432/health_intake"
)
SCOPED_TABLES = (
    "clients",
    "consents",
    "login_challenges",
    "sessions",
    "questionnaire_responses",
    "answers",
    "submissions",
    "documents",
    "audit_events",
)
READABLE_SCOPED_TABLES = SCOPED_TABLES[:-1]
APP_TABLES = ("workspaces", *SCOPED_TABLES)
EXPECTED_GRANTS = {
    "workspaces": {"SELECT"},
    "clients": {"SELECT", "INSERT", "UPDATE"},
    "consents": {"SELECT", "INSERT"},
    "login_challenges": {"SELECT", "INSERT", "UPDATE"},
    "sessions": {"SELECT", "INSERT", "UPDATE"},
    "questionnaire_responses": {"SELECT", "INSERT", "UPDATE"},
    "answers": {"SELECT", "INSERT", "UPDATE"},
    "submissions": {"SELECT", "INSERT"},
    "documents": {"SELECT", "INSERT", "UPDATE"},
    "audit_events": {"INSERT"},
}


def _url_from_env(name: str, default: str) -> URL:
    return make_url(os.environ.get(name, default))


def _url_text(url: URL) -> str:
    return url.render_as_string(hide_password=False)


def _validated_database_name() -> str:
    database_name = f"health_intake_test_{uuid4().hex}"
    assert DATABASE_NAME_RE.fullmatch(database_name), database_name
    return database_name


def _admin_engine(url: URL):
    return create_engine(url, isolation_level="AUTOCOMMIT", poolclass=NullPool)


def _run_alembic(database_url: URL, action: str) -> None:
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", _url_text(database_url))
    monkeypatch.setenv("DATABASE_OWNER_URL", _url_text(database_url))
    try:
        get_settings.cache_clear()
        config = Config(str(ALEMBIC_INI))
        getattr(command, action)(config, "head" if action == "upgrade" else "base")
    finally:
        get_settings.cache_clear()
        monkeypatch.undo()


@pytest.fixture(scope="module")
def temporary_database():
    owner_url = _url_from_env("DATABASE_OWNER_URL", OWNER_DATABASE_URL)
    runtime_url = _url_from_env("DATABASE_URL", RUNTIME_DATABASE_URL)
    database_name = _validated_database_name()
    admin_url = owner_url.set(database="postgres")
    test_owner_url = owner_url.set(database=database_name)
    test_runtime_url = runtime_url.set(database=database_name)
    environment = pytest.MonkeyPatch()
    environment.setenv("APP_ENV", "test")
    environment.setenv("DATABASE_URL", _url_text(test_runtime_url))
    environment.setenv("DATABASE_OWNER_URL", _url_text(test_owner_url))
    create_engine_instance = _admin_engine(admin_url)
    try:
        with create_engine_instance.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{database_name}" OWNER "{OWNER_ROLE}"'))
    finally:
        create_engine_instance.dispose()

    try:
        yield test_owner_url, test_runtime_url, database_name
    finally:
        environment.undo()
        assert DATABASE_NAME_RE.fullmatch(database_name), database_name
        drop_engine_instance = _admin_engine(admin_url)
        try:
            with drop_engine_instance.connect() as connection:
                connection.execute(text(f'DROP DATABASE IF EXISTS "{database_name}"'))
        finally:
            drop_engine_instance.dispose()


@pytest.fixture(scope="module")
def migrated_database(temporary_database):
    owner_url, runtime_url, _ = temporary_database
    _run_alembic(owner_url, "upgrade")
    return owner_url, runtime_url


@dataclass(frozen=True)
class TenantSeed:
    workspace_id: UUID
    client_id: UUID
    response_id: UUID


@contextmanager
def _transaction(url: URL, workspace_id: UUID | None = None) -> Iterator[Connection]:
    engine = create_engine(url, poolclass=NullPool)
    try:
        with engine.connect() as connection, connection.begin():
            if workspace_id is not None:
                connection.execute(
                    text("SELECT set_config('app.workspace_id', :workspace_id, true)"),
                    {"workspace_id": str(workspace_id)},
                )
            yield connection
    finally:
        engine.dispose()


def _seed_tenants(owner_url: URL) -> tuple[TenantSeed, TenantSeed]:
    tenants = (
        TenantSeed(uuid4(), uuid4(), uuid4()),
        TenantSeed(uuid4(), uuid4(), uuid4()),
    )
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with engine.begin() as connection:
            for index, tenant in enumerate(tenants):
                tag = "a" if index == 0 else "b"
                now = datetime.now(UTC)
                tomorrow = now + timedelta(days=1)
                connection.execute(
                    text(
                        """
                        INSERT INTO workspaces (id, name, public_slug, status, created_at)
                        VALUES (:id, :name, :public_slug, 'active', :created_at)
                        """
                    ),
                    {
                        "id": tenant.workspace_id,
                        "name": f"Tenant {tag.upper()}",
                        "public_slug": f"seed-{tag}-{uuid4().hex}",
                        "created_at": now,
                    },
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO clients
                            (id, workspace_id, email_normalized, email_display,
                             status, last_access_at, created_at)
                        VALUES
                            (:id, :workspace_id, :email_normalized, :email_display,
                             'active', NULL, :created_at)
                        """
                    ),
                    {
                        "id": tenant.client_id,
                        "workspace_id": tenant.workspace_id,
                        "email_normalized": f"{tag}@example.test",
                        "email_display": f"{tag}@example.test",
                        "created_at": now,
                    },
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO consents
                            (id, workspace_id, client_id, policy_version, text_hash,
                             accepted_at, created_at)
                        VALUES
                            (:id, :workspace_id, :client_id, 'v1', :text_hash,
                             :accepted_at, :created_at)
                        """
                    ),
                    {
                        "id": uuid4(),
                        "workspace_id": tenant.workspace_id,
                        "client_id": tenant.client_id,
                        "text_hash": (tag * 64)[:64],
                        "accepted_at": now,
                        "created_at": now,
                    },
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO login_challenges
                            (id, workspace_id, email_normalized, magic_token_hash,
                             code_hash, expires_at, attempt_count, resend_after,
                             consumed_at, invalidated_at, ip_fingerprint, policy_version,
                             consent_text_hash, consent_accepted_at, created_at)
                        VALUES
                            (:id, :workspace_id, :email_normalized, :magic_token_hash,
                             :code_hash, :expires_at, 0, :resend_after,
                             NULL, NULL, :ip_fingerprint, 'v1',
                             :consent_text_hash, :consent_accepted_at, :created_at)
                        """
                    ),
                    {
                        "id": uuid4(),
                        "workspace_id": tenant.workspace_id,
                        "email_normalized": f"{tag}@example.test",
                        "magic_token_hash": bytes([index + 1]) * 32,
                        "code_hash": bytes([index + 2]) * 32,
                        "expires_at": tomorrow,
                        "resend_after": now,
                        "ip_fingerprint": bytes([index + 3]) * 32,
                        "consent_text_hash": (tag * 64)[:64],
                        "consent_accepted_at": now,
                        "created_at": now,
                    },
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO sessions
                            (id, workspace_id, client_id, session_token_hash,
                             idle_expires_at, absolute_expires_at, revoked_at,
                             last_seen_at, created_at)
                        VALUES
                            (:id, :workspace_id, :client_id, :session_token_hash,
                             :idle_expires_at, :absolute_expires_at, NULL,
                             NULL, :created_at)
                        """
                    ),
                    {
                        "id": uuid4(),
                        "workspace_id": tenant.workspace_id,
                        "client_id": tenant.client_id,
                        "session_token_hash": bytes([index + 4]) * 32,
                        "idle_expires_at": tomorrow,
                        "absolute_expires_at": tomorrow + timedelta(days=7),
                        "created_at": now,
                    },
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO questionnaire_responses
                            (id, workspace_id, client_id, questionnaire_version,
                             status, current_revision, last_submitted_version,
                             current_section_key, updated_at, created_at)
                        VALUES
                            (:id, :workspace_id, :client_id, 'v1', 'draft', 0,
                             NULL, 'intro', :updated_at, :created_at)
                        """
                    ),
                    {
                        "id": tenant.response_id,
                        "workspace_id": tenant.workspace_id,
                        "client_id": tenant.client_id,
                        "updated_at": now,
                        "created_at": now,
                    },
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO answers
                            (id, workspace_id, response_id, question_key, value_jsonb,
                             revision, updated_at, created_at)
                        VALUES
                            (:id, :workspace_id, :response_id, 'goal',
                             CAST(:value_jsonb AS jsonb), 0, :updated_at, :created_at)
                        """
                    ),
                    {
                        "id": uuid4(),
                        "workspace_id": tenant.workspace_id,
                        "response_id": tenant.response_id,
                        "value_jsonb": json.dumps({"tenant": tag}),
                        "updated_at": now,
                        "created_at": now,
                    },
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO submissions
                            (id, workspace_id, response_id, version,
                             questionnaire_version, answers_snapshot_jsonb,
                             content_hash, idempotency_key, submitted_at, created_at)
                        VALUES
                            (:id, :workspace_id, :response_id, 1, 'v1',
                             CAST(:answers_snapshot_jsonb AS jsonb), :content_hash,
                             :idempotency_key, :submitted_at, :created_at)
                        """
                    ),
                    {
                        "id": uuid4(),
                        "workspace_id": tenant.workspace_id,
                        "response_id": tenant.response_id,
                        "answers_snapshot_jsonb": json.dumps({"tenant": tag}),
                        "content_hash": (tag * 64)[:64],
                        "idempotency_key": f"{tag}-{uuid4().hex}",
                        "submitted_at": now,
                        "created_at": now,
                    },
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO documents
                            (id, workspace_id, client_id, response_id, question_key,
                             object_key, original_name, declared_mime, detected_mime,
                             size_bytes, sha256, status, scan_attempts, next_scan_at,
                             scan_lease_until, rejection_reason, uploaded_at, ready_at,
                             deleted_at, created_at)
                        VALUES
                            (:id, :workspace_id, :client_id, :response_id, 'proof',
                             :object_key, 'proof.pdf', 'application/pdf', NULL, 1,
                             NULL, 'uploading', 0, NULL, NULL, NULL, NULL, NULL,
                             NULL, :created_at)
                        """
                    ),
                    {
                        "id": uuid4(),
                        "workspace_id": tenant.workspace_id,
                        "client_id": tenant.client_id,
                        "response_id": tenant.response_id,
                        "object_key": f"{tag}/{uuid4().hex}/proof.pdf",
                        "created_at": now,
                    },
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO audit_events
                            (id, workspace_id, client_id, actor_type, event_type,
                             target_type, target_id, occurred_at, request_id,
                             metadata_jsonb, created_at)
                        VALUES
                            (:id, :workspace_id, :client_id, 'client', 'created',
                             'client', :target_id, :occurred_at, :request_id,
                             CAST(:metadata_jsonb AS jsonb), :created_at)
                        """
                    ),
                    {
                        "id": uuid4(),
                        "workspace_id": tenant.workspace_id,
                        "client_id": tenant.client_id,
                        "target_id": tenant.client_id,
                        "occurred_at": now,
                        "request_id": uuid4().hex,
                        "metadata_jsonb": json.dumps({"tenant": tag}),
                        "created_at": now,
                    },
                )
    finally:
        engine.dispose()
    return tenants


@pytest.fixture(scope="module")
def seeded_database(migrated_database):
    owner_url, runtime_url = migrated_database
    return owner_url, runtime_url, _seed_tenants(owner_url)


def test_initial_migration_catalog_and_rls(migrated_database) -> None:
    owner_url, _ = migrated_database
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            tables = {
                row.relname: row
                for row in connection.execute(
                    text(
                        """
                        SELECT c.relname,
                               pg_get_userbyid(c.relowner) AS owner,
                               c.relrowsecurity,
                               c.relforcerowsecurity
                        FROM pg_class AS c
                        JOIN pg_namespace AS n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public' AND c.relkind = 'r'
                        """
                    )
                )
            }
            assert set(tables) == {*APP_TABLES, "alembic_version"}
            assert {row.owner for row in tables.values()} == {OWNER_ROLE}
            assert RUNTIME_ROLE not in {row.owner for row in tables.values()}

            rls_rows = connection.execute(
                text(
                    """
                    SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
                    FROM pg_class AS c
                    JOIN pg_namespace AS n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND c.relname = ANY(:table_names)
                    """
                ),
                {"table_names": list(SCOPED_TABLES)},
            ).all()
            assert {
                row.relname: (row.relrowsecurity, row.relforcerowsecurity) for row in rls_rows
            } == {table: (True, True) for table in SCOPED_TABLES}

            policies = connection.execute(
                text(
                    """
                    SELECT tablename, policyname, cmd, qual, with_check
                    FROM pg_policies
                    WHERE schemaname = 'public'
                    """
                )
            ).all()
            assert len(policies) == len(SCOPED_TABLES)
            assert {row.tablename for row in policies} == set(SCOPED_TABLES)
            for row in policies:
                assert row.policyname == f"{row.tablename}_workspace_isolation"
                assert row.cmd == "ALL"
                assert row.qual == row.with_check
                for fragment in ("workspace_id", "NULLIF", "current_setting", "app.workspace_id"):
                    assert fragment in row.qual
                assert "uuid" in row.qual.lower()

            schema_grants = set(
                connection.execute(
                    text(
                        """
                        SELECT privilege_type
                        FROM pg_namespace AS n
                        CROSS JOIN LATERAL aclexplode(n.nspacl) AS grant_item
                        WHERE n.nspname = 'public'
                          AND grant_item.grantee = CAST(:role AS regrole)
                        """
                    ),
                    {"role": RUNTIME_ROLE},
                ).scalars()
            )
            assert schema_grants == {"USAGE"}

            grant_rows = connection.execute(
                text(
                    """
                    SELECT c.relname, grant_item.privilege_type
                    FROM pg_class AS c
                    JOIN pg_namespace AS n ON n.oid = c.relnamespace
                    CROSS JOIN LATERAL aclexplode(c.relacl) AS grant_item
                    WHERE n.nspname = 'public'
                      AND c.relname = ANY(:table_names)
                      AND grant_item.grantee = CAST(:role AS regrole)
                    """
                ),
                {"table_names": list(APP_TABLES), "role": RUNTIME_ROLE},
            ).all()
            actual_grants = defaultdict(set)
            for row in grant_rows:
                actual_grants[row.relname].add(row.privilege_type)
            assert dict(actual_grants) == EXPECTED_GRANTS
    finally:
        engine.dispose()


def test_runtime_rls_isolates_all_scoped_tables_and_fails_closed(seeded_database) -> None:
    _, runtime_url, tenants = seeded_database
    tenant_a, tenant_b = tenants

    with _transaction(runtime_url, tenant_a.workspace_id) as connection:
        for table_name in READABLE_SCOPED_TABLES:
            rows = (
                connection.execute(text(f"SELECT workspace_id FROM {table_name}")).scalars().all()
            )
            assert rows == [tenant_a.workspace_id], table_name

    with _transaction(runtime_url) as connection:
        for table_name in READABLE_SCOPED_TABLES:
            count = connection.execute(text(f"SELECT count(*) FROM {table_name}")).scalar_one()
            assert count == 0, table_name

    with (
        pytest.raises(DBAPIError, match="row-level security"),
        _transaction(runtime_url, tenant_a.workspace_id) as connection,
    ):
        connection.execute(
            text(
                """
                INSERT INTO login_challenges
                    (id, workspace_id, email_normalized, magic_token_hash,
                     code_hash, expires_at, attempt_count, resend_after,
                     ip_fingerprint, policy_version, consent_text_hash,
                     consent_accepted_at, created_at)
                VALUES
                    (:id, :workspace_id, :email_normalized, :magic_token_hash,
                     :code_hash, :expires_at, 0, :resend_after,
                     :ip_fingerprint, 'v1', :consent_text_hash,
                     :consent_accepted_at, :created_at)
                """
            ),
            {
                "id": uuid4(),
                "workspace_id": tenant_b.workspace_id,
                "email_normalized": "cross-tenant@example.test",
                "magic_token_hash": b"x" * 32,
                "code_hash": b"y" * 32,
                "expires_at": datetime.now(UTC) + timedelta(days=1),
                "resend_after": datetime.now(UTC),
                "ip_fingerprint": b"z" * 32,
                "consent_text_hash": "x" * 64,
                "consent_accepted_at": datetime.now(UTC),
                "created_at": datetime.now(UTC),
            },
        )


def test_runtime_audit_events_are_insert_only_and_rls_protected(seeded_database) -> None:
    owner_url, runtime_url, tenants = seeded_database
    tenant_a, tenant_b = tenants
    audit_id = uuid4()
    now = datetime.now(UTC)

    with _transaction(runtime_url, tenant_a.workspace_id) as connection:
        connection.execute(
            text(
                """
                INSERT INTO audit_events
                    (id, workspace_id, client_id, actor_type, event_type,
                     target_type, target_id, occurred_at, request_id,
                     metadata_jsonb, created_at)
                VALUES
                    (:id, :workspace_id, :client_id, 'client', 'created',
                     'client', :target_id, :occurred_at, :request_id,
                     CAST(:metadata_jsonb AS jsonb), :created_at)
                """
            ),
            {
                "id": audit_id,
                "workspace_id": tenant_a.workspace_id,
                "client_id": tenant_a.client_id,
                "target_id": tenant_a.client_id,
                "occurred_at": now,
                "request_id": uuid4().hex,
                "metadata_jsonb": json.dumps({"tenant": "a"}),
                "created_at": now,
            },
        )

    with (
        pytest.raises(DBAPIError, match="row-level security"),
        _transaction(runtime_url, tenant_a.workspace_id) as connection,
    ):
        connection.execute(
            text(
                """
                INSERT INTO audit_events
                    (id, workspace_id, client_id, actor_type, event_type,
                     target_type, target_id, occurred_at, request_id,
                     metadata_jsonb, created_at)
                VALUES
                    (:id, :workspace_id, :client_id, 'client', 'created',
                     'client', :target_id, :occurred_at, :request_id,
                     CAST(:metadata_jsonb AS jsonb), :created_at)
                """
            ),
            {
                "id": uuid4(),
                "workspace_id": tenant_b.workspace_id,
                "client_id": tenant_b.client_id,
                "target_id": tenant_b.client_id,
                "occurred_at": datetime.now(UTC),
                "request_id": uuid4().hex,
                "metadata_jsonb": json.dumps({"tenant": "b"}),
                "created_at": datetime.now(UTC),
            },
        )

    for statement in (
        "SELECT count(*) FROM audit_events",
        "UPDATE audit_events SET metadata_jsonb = metadata_jsonb WHERE id = :id",
        "DELETE FROM audit_events WHERE id = :id",
    ):
        with (
            pytest.raises(DBAPIError, match="permission denied for table audit_events"),
            _transaction(runtime_url, tenant_a.workspace_id) as connection,
        ):
            connection.execute(text(statement), {"id": audit_id})

    with _transaction(owner_url) as connection:
        row = connection.execute(
            text("SELECT workspace_id FROM audit_events WHERE id = :id"),
            {"id": audit_id},
        ).one()
        assert row.workspace_id == tenant_a.workspace_id


def test_composite_fk_rejects_cross_workspace_parent(seeded_database) -> None:
    _, runtime_url, tenants = seeded_database
    tenant_a, tenant_b = tenants

    with (
        pytest.raises(DBAPIError, match="foreign key constraint"),
        _transaction(runtime_url, tenant_b.workspace_id) as connection,
    ):
        connection.execute(
            text(
                """
                INSERT INTO consents
                    (id, workspace_id, client_id, policy_version, text_hash,
                     accepted_at, created_at)
                VALUES
                    (:id, :workspace_id, :client_id, 'v1', :text_hash,
                     :accepted_at, :created_at)
                """
            ),
            {
                "id": uuid4(),
                "workspace_id": tenant_b.workspace_id,
                "client_id": tenant_a.client_id,
                "text_hash": "f" * 64,
                "accepted_at": datetime.now(UTC),
                "created_at": datetime.now(UTC),
            },
        )


def test_append_only_privileges_are_absent(seeded_database) -> None:
    _, runtime_url, _ = seeded_database
    with _transaction(runtime_url) as connection:
        for table_name in ("consents", "submissions", "audit_events"):
            for privilege in ("UPDATE", "DELETE"):
                allowed = connection.execute(
                    text(
                        """
                        SELECT has_table_privilege(
                            current_user, :table_name, :privilege
                        )
                        """
                    ),
                    {
                        "table_name": f"public.{table_name}",
                        "privilege": privilege,
                    },
                ).scalar_one()
                assert allowed is False, (table_name, privilege)


def test_downgrade_base_and_upgrade_head_stay_in_temp_database(migrated_database) -> None:
    owner_url, _ = migrated_database
    assert DATABASE_NAME_RE.fullmatch(owner_url.database), owner_url.database

    _run_alembic(owner_url, "downgrade")
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            remaining_tables = set(
                connection.execute(
                    text(
                        """
                        SELECT table_name
                        FROM information_schema.tables
                        WHERE table_schema = 'public'
                        """
                    )
                ).scalars()
            )
            assert remaining_tables == {"alembic_version"}
    finally:
        engine.dispose()

    _run_alembic(owner_url, "upgrade")
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            assert set(
                connection.execute(
                    text(
                        """
                        SELECT table_name
                        FROM information_schema.tables
                        WHERE table_schema = 'public'
                        """
                    )
                ).scalars()
            ) == {*APP_TABLES, "alembic_version"}
    finally:
        engine.dispose()
