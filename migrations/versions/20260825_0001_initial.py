"""Create the initial health intake schema and tenant isolation."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260825_0001"
down_revision = None
branch_labels = None
depends_on = None


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
WORKSPACE_POLICY_EXPRESSION = (
    "workspace_id = NULLIF(current_setting('app.workspace_id', true), '')::uuid"
)


def upgrade() -> None:
    op.create_table(
        "workspaces",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("public_slug", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=8), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('active', 'disabled')",
            name=op.f("ck_workspaces_workspace_status"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_workspaces")),
        sa.UniqueConstraint("public_slug", name=op.f("uq_workspaces_public_slug")),
    )

    op.create_table(
        "clients",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email_normalized", sa.String(length=320), nullable=False),
        sa.Column("email_display", sa.String(length=320), nullable=False),
        sa.Column("status", sa.String(length=8), nullable=False),
        sa.Column("last_access_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('active', 'disabled')",
            name=op.f("ck_clients_client_status"),
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name=op.f("fk_clients_workspace_id_workspaces"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_clients")),
        sa.UniqueConstraint(
            "workspace_id",
            "email_normalized",
            name=op.f("uq_clients_workspace_id_email_normalized"),
        ),
        sa.UniqueConstraint(
            "workspace_id",
            "id",
            name=op.f("uq_clients_workspace_id_id"),
        ),
    )

    op.create_table(
        "consents",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("client_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("text_hash", sa.String(length=64), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["workspace_id", "client_id"],
            ["clients.workspace_id", "clients.id"],
            name=op.f("fk_consents_workspace_id_client_id_clients"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_consents")),
    )

    op.create_table(
        "login_challenges",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email_normalized", sa.String(length=320), nullable=False),
        sa.Column("magic_token_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column("code_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("resend_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("invalidated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ip_fingerprint", sa.LargeBinary(length=32), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("consent_text_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "consent_accepted_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name=op.f("fk_login_challenges_workspace_id_workspaces"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_login_challenges")),
    )

    op.create_table(
        "sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("client_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("session_token_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["workspace_id", "client_id"],
            ["clients.workspace_id", "clients.id"],
            name=op.f("fk_sessions_workspace_id_client_id_clients"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sessions")),
    )

    op.create_table(
        "questionnaire_responses",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("client_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("questionnaire_version", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=9), nullable=False),
        sa.Column("current_revision", sa.Integer(), nullable=False),
        sa.Column("last_submitted_version", sa.Integer(), nullable=True),
        sa.Column("current_section_key", sa.String(length=100), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('draft', 'submitted', 'editing')",
            name=op.f("ck_questionnaire_responses_questionnaire_response_status"),
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "client_id"],
            ["clients.workspace_id", "clients.id"],
            name=op.f("fk_questionnaire_responses_workspace_id_client_id_clients"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_questionnaire_responses")),
        sa.UniqueConstraint(
            "workspace_id",
            "client_id",
            "questionnaire_version",
            name=op.f("uq_questionnaire_responses_workspace_id_client_id_questionnaire_version"),
        ),
        sa.UniqueConstraint(
            "workspace_id",
            "id",
            name=op.f("uq_questionnaire_responses_workspace_id_id"),
        ),
    )

    op.create_table(
        "answers",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("response_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("question_key", sa.String(length=100), nullable=False),
        sa.Column("value_jsonb", postgresql.JSONB(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["workspace_id", "response_id"],
            [
                "questionnaire_responses.workspace_id",
                "questionnaire_responses.id",
            ],
            name=op.f("fk_answers_workspace_id_response_id_questionnaire_responses"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_answers")),
        sa.UniqueConstraint(
            "response_id",
            "question_key",
            name=op.f("uq_answers_response_id_question_key"),
        ),
    )

    op.create_table(
        "submissions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("response_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("questionnaire_version", sa.String(length=64), nullable=False),
        sa.Column("answers_snapshot_jsonb", postgresql.JSONB(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["workspace_id", "response_id"],
            [
                "questionnaire_responses.workspace_id",
                "questionnaire_responses.id",
            ],
            name=op.f("fk_submissions_workspace_id_response_id_questionnaire_responses"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_submissions")),
        sa.UniqueConstraint(
            "response_id",
            "version",
            name=op.f("uq_submissions_response_id_version"),
        ),
        sa.UniqueConstraint(
            "response_id",
            "idempotency_key",
            name=op.f("uq_submissions_response_id_idempotency_key"),
        ),
    )

    op.create_table(
        "documents",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("client_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("response_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("question_key", sa.String(length=100), nullable=True),
        sa.Column("object_key", sa.String(length=1024), nullable=False),
        sa.Column("original_name", sa.String(length=255), nullable=False),
        sa.Column("declared_mime", sa.String(length=255), nullable=False),
        sa.Column("detected_mime", sa.String(length=255), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=11), nullable=False),
        sa.Column("scan_attempts", sa.Integer(), nullable=False),
        sa.Column("next_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scan_lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.String(length=500), nullable=True),
        sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ready_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('uploading', 'quarantined', 'scanning', 'ready', 'rejected', 'deleted')",
            name=op.f("ck_documents_document_status"),
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "client_id"],
            ["clients.workspace_id", "clients.id"],
            name=op.f("fk_documents_workspace_id_client_id_clients"),
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "response_id"],
            [
                "questionnaire_responses.workspace_id",
                "questionnaire_responses.id",
            ],
            name=op.f("fk_documents_workspace_id_response_id_questionnaire_responses"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_documents")),
    )

    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("client_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_type", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_id", sa.String(length=128), nullable=False),
        sa.Column("metadata_jsonb", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["workspace_id", "client_id"],
            ["clients.workspace_id", "clients.id"],
            name=op.f("fk_audit_events_workspace_id_client_id_clients"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )

    for table_name in SCOPED_TABLES:
        op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {table_name}_workspace_isolation ON {table_name} "
            f"USING ({WORKSPACE_POLICY_EXPRESSION}) "
            f"WITH CHECK ({WORKSPACE_POLICY_EXPRESSION})"
        )

    op.execute("GRANT USAGE ON SCHEMA public TO health_app")
    op.execute("GRANT SELECT ON TABLE workspaces TO health_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON TABLE clients TO health_app")
    op.execute("GRANT SELECT, INSERT ON TABLE consents TO health_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON TABLE login_challenges TO health_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON TABLE sessions TO health_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON TABLE questionnaire_responses TO health_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON TABLE answers TO health_app")
    op.execute("GRANT SELECT, INSERT ON TABLE submissions TO health_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON TABLE documents TO health_app")
    op.execute("GRANT INSERT ON TABLE audit_events TO health_app")


def downgrade() -> None:
    for table_name in reversed(SCOPED_TABLES):
        op.drop_table(table_name)
    op.drop_table("workspaces")
    op.execute("REVOKE USAGE ON SCHEMA public FROM health_app")
