import importlib
import sys
from pathlib import Path

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    LargeBinary,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, dialect
from sqlalchemy.schema import CreateTable
from sqlalchemy.sql.sqltypes import Enum as SQLAlchemyEnum

ROOT = Path(__file__).parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

Base = importlib.import_module("app.models").Base


EXPECTED_TABLES = {
    "workspaces",
    "clients",
    "consents",
    "login_challenges",
    "sessions",
    "questionnaire_responses",
    "answers",
    "submissions",
    "documents",
    "audit_events",
}
SCOPED_TABLES = EXPECTED_TABLES - {"workspaces"}


def table(name: str):
    return Base.metadata.tables[name]


def unique_column_sets(name: str) -> set[tuple[str, ...]]:
    return {
        tuple(constraint.columns.keys())
        for constraint in table(name).constraints
        if isinstance(constraint, UniqueConstraint)
    }


def composite_fk(
    table_name: str,
    local_columns: tuple[str, ...],
    referred_table: str,
    referred_columns: tuple[str, ...],
) -> bool:
    return any(
        isinstance(constraint, ForeignKeyConstraint)
        and tuple(constraint.column_keys) == local_columns
        and tuple(element.column.name for element in constraint.elements) == referred_columns
        and constraint.elements[0].target_fullname.startswith(f"{referred_table}.")
        for constraint in table(table_name).constraints
    )


def test_metadata_has_exactly_the_approved_tables() -> None:
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_scoped_tables_have_workspace_and_created_at() -> None:
    for table_name in SCOPED_TABLES:
        columns = table(table_name).c
        assert "workspace_id" in columns
        assert "created_at" in columns

    assert "created_at" in table("workspaces").c


def test_sensitive_parent_links_are_workspace_scoped() -> None:
    assert composite_fk("clients", ("workspace_id",), "workspaces", ("id",))
    assert composite_fk(
        "consents", ("workspace_id", "client_id"), "clients", ("workspace_id", "id")
    )
    assert composite_fk(
        "sessions", ("workspace_id", "client_id"), "clients", ("workspace_id", "id")
    )
    assert composite_fk(
        "questionnaire_responses",
        ("workspace_id", "client_id"),
        "clients",
        ("workspace_id", "id"),
    )
    assert composite_fk(
        "answers",
        ("workspace_id", "response_id"),
        "questionnaire_responses",
        ("workspace_id", "id"),
    )
    assert composite_fk(
        "submissions",
        ("workspace_id", "response_id"),
        "questionnaire_responses",
        ("workspace_id", "id"),
    )
    assert composite_fk(
        "documents", ("workspace_id", "client_id"), "clients", ("workspace_id", "id")
    )
    assert composite_fk(
        "documents",
        ("workspace_id", "response_id"),
        "questionnaire_responses",
        ("workspace_id", "id"),
    )
    assert composite_fk(
        "audit_events", ("workspace_id", "client_id"), "clients", ("workspace_id", "id")
    )


def test_required_unique_constraints_exist() -> None:
    assert ("public_slug",) in unique_column_sets("workspaces")
    assert ("workspace_id", "email_normalized") in unique_column_sets("clients")
    assert ("workspace_id", "id") in unique_column_sets("clients")
    assert ("workspace_id", "client_id", "questionnaire_version") in unique_column_sets(
        "questionnaire_responses"
    )
    assert ("workspace_id", "id") in unique_column_sets("questionnaire_responses")
    assert ("response_id", "question_key") in unique_column_sets("answers")
    assert ("response_id", "version") in unique_column_sets("submissions")
    assert ("response_id", "idempotency_key") in unique_column_sets("submissions")


def test_raw_secret_and_ip_columns_are_absent_and_binary_hashes_are_fixed_length() -> None:
    forbidden = {"token", "code", "ip", "raw_token", "raw_code", "raw_ip"}
    all_columns = {
        column.name for model_table in Base.metadata.tables.values() for column in model_table.c
    }
    assert not forbidden & all_columns

    expected_binary_hashes = {
        "login_challenges": {"magic_token_hash", "code_hash", "ip_fingerprint"},
        "sessions": {"session_token_hash"},
    }
    for table_name, column_names in expected_binary_hashes.items():
        for column_name in column_names:
            column = table(table_name).c[column_name]
            assert isinstance(column.type, LargeBinary)
            assert column.type.length == 32

    assert table("consents").c.text_hash.type.length == 64
    assert table("login_challenges").c.consent_text_hash.type.length == 64
    assert table("submissions").c.content_hash.type.length == 64
    assert table("documents").c.sha256.type.length == 64
    assert table("documents").c.size_bytes.type.python_type is int


def test_jsonb_is_limited_to_approved_payload_columns() -> None:
    jsonb_columns = {
        (model_table.name, column.name)
        for model_table in Base.metadata.tables.values()
        for column in model_table.c
        if isinstance(column.type, JSONB)
    }
    assert jsonb_columns == {
        ("answers", "value_jsonb"),
        ("submissions", "answers_snapshot_jsonb"),
        ("audit_events", "metadata_jsonb"),
    }


def test_all_datetime_columns_are_timezone_aware() -> None:
    for model_table in Base.metadata.tables.values():
        for column in model_table.c:
            if isinstance(column.type, DateTime):
                assert column.type.timezone is True, f"{model_table.name}.{column.name}"


def test_postgresql_ddl_compiles_for_every_table() -> None:
    for model_table in Base.metadata.sorted_tables:
        ddl = str(CreateTable(model_table).compile(dialect=dialect()))
        assert f"CREATE TABLE {model_table.name}" in ddl


def test_approved_status_enums_use_exact_values_and_non_native_checks() -> None:
    expected = {
        "questionnaire_responses": {"draft", "submitted", "editing"},
        "documents": {"uploading", "quarantined", "scanning", "ready", "rejected", "deleted"},
    }
    for table_name, values in expected.items():
        status = table(table_name).c.status.type
        assert isinstance(status, SQLAlchemyEnum)
        assert status.native_enum is False
        assert status.create_constraint is True
        assert set(status.enums) == values
        assert any(
            isinstance(constraint, CheckConstraint) and "status" in str(constraint.sqltext)
            for constraint in table(table_name).constraints
        )
