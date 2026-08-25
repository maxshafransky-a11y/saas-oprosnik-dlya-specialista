import importlib
import sys
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, fields
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

ROOT = Path(__file__).parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pytest_plugins = ("tests.db_test_support",)

auth_service = importlib.import_module("app.auth_service")
models = importlib.import_module("app.models")
preauth = importlib.import_module("app.preauth")
security = importlib.import_module("app.security")

AuthenticatedSession = auth_service.AuthenticatedSession
ChallengeUnavailable = auth_service.ChallengeUnavailable
IssuedChallenge = auth_service.IssuedChallenge
SessionPrincipal = auth_service.SessionPrincipal
authenticate_magic_token = auth_service.authenticate_magic_token
authenticate_otp = auth_service.authenticate_otp
authenticate_session = auth_service.authenticate_session
issue_login_challenge = auth_service.issue_login_challenge
revoke_session = auth_service.revoke_session
AuditEvent = models.AuditEvent
Client = models.Client
ClientStatus = models.ClientStatus
Consent = models.Consent
LoginChallenge = models.LoginChallenge
SessionRecord = models.Session
Workspace = models.Workspace
ConsentTicket = preauth.ConsentTicket
generate_session_token = security.generate_session_token
hash_session_token = security.hash_session_token


BASE_NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
SECRET = "auth-service-test-secret"


@contextmanager
def _runtime_session(runtime_url, workspace_id):
    engine = create_engine(runtime_url, poolclass=NullPool)
    try:
        with Session(engine) as session, session.begin():
            session.execute(
                text("SELECT set_config('app.workspace_id', :workspace_id, true)"),
                {"workspace_id": str(workspace_id)},
            )
            yield session
    finally:
        engine.dispose()


def _seed_workspace(owner_url, *, email=None, status=ClientStatus.ACTIVE):
    workspace_id = uuid4()
    client_id = uuid4() if email is not None else None
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with Session(engine) as session, session.begin():
            session.add(
                Workspace(
                    id=workspace_id,
                    name="Auth test workspace",
                    public_slug=f"auth-{workspace_id.hex}",
                )
            )
            session.flush()
            if email is not None:
                session.add(
                    Client(
                        id=client_id,
                        workspace_id=workspace_id,
                        email_normalized=email,
                        email_display=email,
                        status=status,
                        created_at=BASE_NOW,
                    )
                )
    finally:
        engine.dispose()
    return workspace_id, client_id


def _seed_client(owner_url, workspace_id, email, status):
    client_id = uuid4()
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with Session(engine) as session, session.begin():
            session.add(
                Client(
                    id=client_id,
                    workspace_id=workspace_id,
                    email_normalized=email,
                    email_display=email,
                    status=status,
                    created_at=BASE_NOW,
                )
            )
    finally:
        engine.dispose()
    return client_id


def _consent(workspace_id, now=BASE_NOW, *, expires_after=timedelta(minutes=29)):
    return ConsentTicket(
        workspace_id=workspace_id,
        policy_version="policy-v1",
        text_hash="a" * 64,
        accepted_at=now - timedelta(minutes=1),
        expires_at=now + expires_after,
    )


def _issue(runtime_url, workspace_id, *, email, ip_address, now=BASE_NOW):
    with _runtime_session(runtime_url, workspace_id) as session:
        return issue_login_challenge(
            session,
            workspace_id=workspace_id,
            email=email,
            ip_address=ip_address,
            consent=_consent(workspace_id, now),
            secret=SECRET,
            now=now,
        )


def _owner_rows(owner_url, model, workspace_id):
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with Session(engine) as session:
            return session.scalars(select(model).where(model.workspace_id == workspace_id)).all()
    finally:
        engine.dispose()


def _owner_update_session(owner_url, session_id, **values):
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with Session(engine) as session, session.begin():
            record = session.get(SessionRecord, session_id)
            for name, value in values.items():
                setattr(record, name, value)
    finally:
        engine.dispose()


def _wrong_code(otp):
    return "999999" if otp != "999999" else "888888"


def _authenticate_magic(
    runtime_url, workspace_id, challenge, *, now=BASE_NOW, request_id="login-1"
):
    with _runtime_session(runtime_url, workspace_id) as session:
        return authenticate_magic_token(
            session,
            token=challenge.magic_token,
            secret=SECRET,
            request_id=request_id,
            now=now,
        )


def _authenticate_otp(runtime_url, workspace_id, challenge, *, now=BASE_NOW, request_id="otp-1"):
    with _runtime_session(runtime_url, workspace_id) as session:
        return authenticate_otp(
            session,
            workspace_id=workspace_id,
            challenge_id=challenge.challenge_id,
            code=challenge.otp,
            secret=SECRET,
            request_id=request_id,
            now=now,
        )


def test_issue_login_challenge_uses_postgresql_fixture(migrated_database):
    owner_url, runtime_url = migrated_database
    workspace_id = uuid4()
    now = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
    consent = ConsentTicket(
        workspace_id=workspace_id,
        policy_version="policy-v1",
        text_hash="a" * 64,
        accepted_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=29),
    )

    owner_engine = create_engine(owner_url)
    try:
        with Session(owner_engine) as session, session.begin():
            session.add(
                Workspace(
                    id=workspace_id,
                    name="Auth test workspace",
                    public_slug=f"auth-{workspace_id.hex}",
                )
            )
    finally:
        owner_engine.dispose()

    runtime_engine = create_engine(runtime_url)
    try:
        with Session(runtime_engine) as session, session.begin():
            session.execute(
                text("SELECT set_config('app.workspace_id', :workspace_id, true)"),
                {"workspace_id": str(workspace_id)},
            )
            result = issue_login_challenge(
                session,
                workspace_id=workspace_id,
                email="client@example.com",
                ip_address="192.0.2.10",
                consent=consent,
                secret="test-secret",
                now=now,
            )

    finally:
        runtime_engine.dispose()

    assert result.challenge_id


def test_issue_persists_only_fixed_size_secrets_and_returns_neutral_shape(migrated_database):
    owner_url, runtime_url = migrated_database
    workspace_id, _ = _seed_workspace(owner_url)
    result = _issue(
        runtime_url,
        workspace_id,
        email=" Alice@Example.COM ",
        ip_address="2001:0db8:0:0:0:0:0:1",
    )

    assert isinstance(result, IssuedChallenge)
    assert tuple(field.name for field in fields(result)) == (
        "challenge_id",
        "magic_token",
        "otp",
        "expires_at",
        "resend_after",
    )
    with pytest.raises(FrozenInstanceError):
        result.otp = "000000"  # type: ignore[misc]

    challenge = _owner_rows(owner_url, LoginChallenge, workspace_id)[0]
    assert challenge.email_normalized == "alice@example.com"
    assert len(challenge.magic_token_hash) == 32
    assert len(challenge.code_hash) == 32
    assert len(challenge.ip_fingerprint) == 32
    assert result.magic_token.encode() not in challenge.magic_token_hash
    assert result.otp.encode() not in challenge.code_hash
    assert result.magic_token not in repr(challenge)
    assert result.otp not in repr(challenge)


def test_issue_cooldown_replacement_and_persisted_email_ip_limits(migrated_database):
    owner_url, runtime_url = migrated_database
    workspace_id, _ = _seed_workspace(owner_url)
    email = "limit@example.com"
    _issue(runtime_url, workspace_id, email=email, ip_address="192.0.2.20")

    with pytest.raises(ChallengeUnavailable) as cooldown_error:
        _issue(
            runtime_url,
            workspace_id,
            email=email,
            ip_address="192.0.2.20",
            now=BASE_NOW + timedelta(seconds=30),
        )
    details = f"{cooldown_error.value} {cooldown_error.value.args!r} {vars(cooldown_error.value)!r}"
    assert email not in details
    assert "192.0.2.20" not in details
    assert "client" not in details

    replacement = _issue(
        runtime_url,
        workspace_id,
        email=email,
        ip_address="192.0.2.20",
        now=BASE_NOW + timedelta(seconds=61),
    )
    challenges = sorted(
        _owner_rows(owner_url, LoginChallenge, workspace_id), key=lambda row: row.created_at
    )
    assert len(challenges) == 2
    assert challenges[0].invalidated_at == replacement.resend_after - timedelta(seconds=60)
    assert challenges[1].id == replacement.challenge_id

    for index in range(2, 5):
        _issue(
            runtime_url,
            workspace_id,
            email=email,
            ip_address="192.0.2.20",
            now=BASE_NOW + timedelta(seconds=61 * index),
        )
    with pytest.raises(ChallengeUnavailable):
        _issue(
            runtime_url,
            workspace_id,
            email=email,
            ip_address="192.0.2.20",
            now=BASE_NOW + timedelta(seconds=305),
        )
    assert len(_owner_rows(owner_url, LoginChallenge, workspace_id)) == 5

    for index in range(25):
        _issue(
            runtime_url,
            workspace_id,
            email=f"ip-{index}@example.com",
            ip_address="192.0.2.20",
            now=BASE_NOW + timedelta(seconds=400),
        )
    with pytest.raises(ChallengeUnavailable):
        _issue(
            runtime_url,
            workspace_id,
            email="ip-limit@example.com",
            ip_address="192.0.2.20",
            now=BASE_NOW + timedelta(seconds=400),
        )


def test_invalid_consent_is_the_same_neutral_challenge_failure(migrated_database):
    owner_url, runtime_url = migrated_database
    workspace_id, _ = _seed_workspace(owner_url)
    invalid = _consent(workspace_id, BASE_NOW, expires_after=timedelta(seconds=-1))

    with (
        _runtime_session(runtime_url, workspace_id) as session,
        pytest.raises(ChallengeUnavailable) as error,
    ):
        issue_login_challenge(
            session,
            workspace_id=workspace_id,
            email="secret@example.com",
            ip_address="192.0.2.21",
            consent=invalid,
            secret=SECRET,
            now=BASE_NOW,
        )
    details = f"{error.value} {error.value.args!r} {vars(error.value)!r}"
    assert details == "challenge unavailable ('challenge unavailable',) {}"
    assert "secret@example.com" not in details
    assert "192.0.2.21" not in details


def test_otp_attempts_are_persisted_and_expiry_is_fail_closed(migrated_database):
    owner_url, runtime_url = migrated_database
    workspace_id, _ = _seed_workspace(owner_url)
    challenge = _issue(
        runtime_url,
        workspace_id,
        email="attempts@example.com",
        ip_address="192.0.2.22",
    )
    wrong_code = _wrong_code(challenge.otp)

    with _runtime_session(runtime_url, workspace_id) as session:
        assert (
            authenticate_otp(
                session,
                workspace_id=workspace_id,
                challenge_id=challenge.challenge_id,
                code="abc123",
                secret=SECRET,
                request_id="malformed-code",
                now=BASE_NOW,
            )
            is None
        )
    assert _owner_rows(owner_url, LoginChallenge, workspace_id)[0].attempt_count == 0

    for attempt in range(1, 6):
        with _runtime_session(runtime_url, workspace_id) as session:
            assert (
                authenticate_otp(
                    session,
                    workspace_id=workspace_id,
                    challenge_id=challenge.challenge_id,
                    code=wrong_code,
                    secret=SECRET,
                    request_id=f"wrong-{attempt}",
                    now=BASE_NOW + timedelta(seconds=attempt),
                )
                is None
            )
        stored = _owner_rows(owner_url, LoginChallenge, workspace_id)[0]
        assert stored.attempt_count == attempt
        assert (stored.invalidated_at is not None) is (attempt == 5)

    expiring = _issue(
        runtime_url,
        workspace_id,
        email="expired@example.com",
        ip_address="192.0.2.23",
        now=BASE_NOW + timedelta(seconds=10),
    )
    with _runtime_session(runtime_url, workspace_id) as session:
        assert (
            authenticate_otp(
                session,
                workspace_id=workspace_id,
                challenge_id=expiring.challenge_id,
                code=expiring.otp,
                secret=SECRET,
                request_id="expired",
                now=expiring.expires_at,
            )
            is None
        )
    expired_row = [
        row
        for row in _owner_rows(owner_url, LoginChallenge, workspace_id)
        if row.id == expiring.challenge_id
    ][0]
    assert expired_row.attempt_count == 0
    assert expired_row.consumed_at is None


def test_magic_and_otp_consume_each_challenge_only_once(migrated_database):
    owner_url, runtime_url = migrated_database
    workspace_id, _ = _seed_workspace(owner_url)
    magic_first = _issue(
        runtime_url,
        workspace_id,
        email="magic-first@example.com",
        ip_address="192.0.2.24",
    )
    magic_result = _authenticate_magic(runtime_url, workspace_id, magic_first)
    assert isinstance(magic_result, AuthenticatedSession)
    with _runtime_session(runtime_url, workspace_id) as session:
        assert (
            authenticate_otp(
                session,
                workspace_id=workspace_id,
                challenge_id=magic_first.challenge_id,
                code=magic_first.otp,
                secret=SECRET,
                request_id="otp-after-magic",
                now=BASE_NOW + timedelta(seconds=1),
            )
            is None
        )

    otp_first = _issue(
        runtime_url,
        workspace_id,
        email="otp-first@example.com",
        ip_address="192.0.2.25",
        now=BASE_NOW + timedelta(seconds=61),
    )
    otp_result = _authenticate_otp(
        runtime_url,
        workspace_id,
        otp_first,
        now=BASE_NOW + timedelta(seconds=61),
    )
    assert isinstance(otp_result, AuthenticatedSession)
    with _runtime_session(runtime_url, workspace_id) as session:
        assert (
            authenticate_magic_token(
                session,
                token=otp_first.magic_token,
                secret=SECRET,
                request_id="magic-after-otp",
                now=BASE_NOW + timedelta(seconds=62),
            )
            is None
        )

    challenges = _owner_rows(owner_url, LoginChallenge, workspace_id)
    assert all(row.consumed_at is not None for row in challenges)
    assert len(_owner_rows(owner_url, SessionRecord, workspace_id)) == 2


def test_new_client_login_is_atomic_and_records_consent_session_and_audit(migrated_database):
    owner_url, runtime_url = migrated_database
    workspace_id, _ = _seed_workspace(owner_url)
    challenge = _issue(
        runtime_url,
        workspace_id,
        email="new-client@example.com",
        ip_address="192.0.2.26",
    )
    result = _authenticate_magic(runtime_url, workspace_id, challenge)

    assert isinstance(result, AuthenticatedSession)
    clients = _owner_rows(owner_url, Client, workspace_id)
    consents = _owner_rows(owner_url, Consent, workspace_id)
    sessions = _owner_rows(owner_url, SessionRecord, workspace_id)
    audits = _owner_rows(owner_url, AuditEvent, workspace_id)
    assert len(clients) == len(consents) == len(sessions) == len(audits) == 1
    assert clients[0].id == result.client_id
    assert consents[0].client_id == result.client_id
    assert sessions[0].id == result.session_id
    assert sessions[0].session_token_hash == hash_session_token(result.token)
    assert audits[0].event_type == "login"
    assert audits[0].target_type == "session"
    assert audits[0].target_id == result.session_id
    assert audits[0].metadata_jsonb == {}
    assert "new-client@example.com" not in str(audits[0].metadata_jsonb)
    assert result.token not in str(audits[0].metadata_jsonb)


def test_existing_client_is_reused_and_disabled_client_gets_no_session(migrated_database):
    owner_url, runtime_url = migrated_database
    workspace_id, existing_id = _seed_workspace(
        owner_url, email="existing@example.com", status=ClientStatus.ACTIVE
    )
    disabled_id = _seed_client(
        owner_url, workspace_id, "disabled@example.com", ClientStatus.DISABLED
    )

    existing_challenge = _issue(
        runtime_url,
        workspace_id,
        email="existing@example.com",
        ip_address="192.0.2.27",
    )
    existing_result = _authenticate_otp(runtime_url, workspace_id, existing_challenge)
    assert isinstance(existing_result, AuthenticatedSession)
    assert existing_result.client_id == existing_id

    disabled_challenge = _issue(
        runtime_url,
        workspace_id,
        email="disabled@example.com",
        ip_address="192.0.2.28",
        now=BASE_NOW + timedelta(seconds=61),
    )
    assert (
        _authenticate_magic(
            runtime_url,
            workspace_id,
            disabled_challenge,
            now=BASE_NOW + timedelta(seconds=61),
            request_id="disabled-login",
        )
        is None
    )

    clients = _owner_rows(owner_url, Client, workspace_id)
    assert {client.id for client in clients} == {existing_id, disabled_id}
    assert (
        next(client for client in clients if client.id == disabled_id).status
        == ClientStatus.DISABLED
    )
    assert len(_owner_rows(owner_url, Consent, workspace_id)) == 1
    assert len(_owner_rows(owner_url, SessionRecord, workspace_id)) == 1
    assert len(_owner_rows(owner_url, AuditEvent, workspace_id)) == 1


def test_session_parse_hash_workspace_touch_expiry_and_revoke(migrated_database):
    owner_url, runtime_url = migrated_database
    workspace_id, _ = _seed_workspace(owner_url)
    other_workspace_id, _ = _seed_workspace(owner_url)
    challenge = _issue(
        runtime_url,
        workspace_id,
        email="session@example.com",
        ip_address="192.0.2.29",
    )
    authenticated = _authenticate_magic(runtime_url, workspace_id, challenge)
    assert isinstance(authenticated, AuthenticatedSession)

    with _runtime_session(runtime_url, workspace_id) as session:
        assert authenticate_session(session, token="malformed", now=BASE_NOW) is None
        assert (
            authenticate_session(
                session,
                token=generate_session_token(workspace_id, authenticated.session_id),
                now=BASE_NOW,
            )
            is None
        )
        assert (
            authenticate_session(
                session,
                token=generate_session_token(other_workspace_id, authenticated.session_id),
                now=BASE_NOW,
            )
            is None
        )
        principal = authenticate_session(
            session, token=authenticated.token, now=BASE_NOW + timedelta(days=1)
        )
    assert isinstance(principal, SessionPrincipal)
    assert principal.idle_expires_at == BASE_NOW + timedelta(days=15)
    assert principal.absolute_expires_at == BASE_NOW + timedelta(days=30)
    stored = _owner_rows(owner_url, SessionRecord, workspace_id)[0]
    assert stored.last_seen_at == BASE_NOW + timedelta(days=1)
    assert stored.idle_expires_at == BASE_NOW + timedelta(days=15)

    with _runtime_session(runtime_url, workspace_id) as session:
        principal = authenticate_session(
            session, token=authenticated.token, now=BASE_NOW + timedelta(days=10)
        )
    assert principal is not None
    assert principal.idle_expires_at == BASE_NOW + timedelta(days=24)
    with _runtime_session(runtime_url, workspace_id) as session:
        principal = authenticate_session(
            session, token=authenticated.token, now=BASE_NOW + timedelta(days=20)
        )
    assert principal is not None
    assert principal.idle_expires_at == BASE_NOW + timedelta(days=30)

    with _runtime_session(runtime_url, workspace_id) as session:
        assert (
            revoke_session(
                session,
                token=authenticated.token,
                request_id="logout-1",
                now=BASE_NOW + timedelta(days=21),
            )
            is True
        )
    with _runtime_session(runtime_url, workspace_id) as session:
        assert (
            authenticate_session(
                session, token=authenticated.token, now=BASE_NOW + timedelta(days=22)
            )
            is None
        )
        assert (
            revoke_session(
                session,
                token=authenticated.token,
                request_id="logout-2",
                now=BASE_NOW + timedelta(days=22),
            )
            is False
        )
    logout_events = [
        event
        for event in _owner_rows(owner_url, AuditEvent, workspace_id)
        if event.event_type == "logout"
    ]
    assert len(logout_events) == 1
    assert logout_events[0].target_id == authenticated.session_id
    assert logout_events[0].metadata_jsonb == {}

    idle_challenge = _issue(
        runtime_url,
        workspace_id,
        email="idle@example.com",
        ip_address="192.0.2.30",
        now=BASE_NOW + timedelta(days=1),
    )
    idle_session = _authenticate_magic(
        runtime_url, workspace_id, idle_challenge, now=BASE_NOW + timedelta(days=1)
    )
    assert idle_session is not None
    _owner_update_session(
        owner_url,
        idle_session.session_id,
        idle_expires_at=BASE_NOW + timedelta(days=2),
        absolute_expires_at=BASE_NOW + timedelta(days=10),
    )
    with _runtime_session(runtime_url, workspace_id) as session:
        assert (
            authenticate_session(
                session, token=idle_session.token, now=BASE_NOW + timedelta(days=2)
            )
            is None
        )
        assert (
            revoke_session(
                session,
                token=idle_session.token,
                request_id="idle-logout",
                now=BASE_NOW + timedelta(days=2),
            )
            is False
        )

    absolute_challenge = _issue(
        runtime_url,
        workspace_id,
        email="absolute@example.com",
        ip_address="192.0.2.31",
        now=BASE_NOW + timedelta(days=3),
    )
    absolute_session = _authenticate_magic(
        runtime_url,
        workspace_id,
        absolute_challenge,
        now=BASE_NOW + timedelta(days=3),
    )
    assert absolute_session is not None
    _owner_update_session(
        owner_url,
        absolute_session.session_id,
        idle_expires_at=BASE_NOW + timedelta(days=20),
        absolute_expires_at=BASE_NOW + timedelta(days=4),
    )
    with _runtime_session(runtime_url, workspace_id) as session:
        assert (
            authenticate_session(
                session,
                token=absolute_session.token,
                now=BASE_NOW + timedelta(days=4),
            )
            is None
        )


def test_request_id_is_validated_before_auth_mutation(migrated_database):
    owner_url, runtime_url = migrated_database
    workspace_id, _ = _seed_workspace(owner_url)
    challenge = _issue(
        runtime_url,
        workspace_id,
        email="request-id@example.com",
        ip_address="192.0.2.32",
    )

    for request_id in ("", "x" * 129):
        with (
            _runtime_session(runtime_url, workspace_id) as session,
            pytest.raises(ValueError, match="invalid request_id"),
        ):
            authenticate_magic_token(
                session,
                token=challenge.magic_token,
                secret=SECRET,
                request_id=request_id,
                now=BASE_NOW,
            )
    row = _owner_rows(owner_url, LoginChallenge, workspace_id)[0]
    assert row.consumed_at is None
    assert row.invalidated_at is None


def test_login_side_effects_rollback_with_the_caller_transaction(migrated_database):
    owner_url, runtime_url = migrated_database
    workspace_id, _ = _seed_workspace(owner_url)
    challenge = _issue(
        runtime_url,
        workspace_id,
        email="rollback@example.com",
        ip_address="192.0.2.33",
    )
    engine = create_engine(runtime_url, poolclass=NullPool)
    session = Session(engine)
    try:
        session.begin()
        session.execute(
            text("SELECT set_config('app.workspace_id', :workspace_id, true)"),
            {"workspace_id": str(workspace_id)},
        )
        result = authenticate_magic_token(
            session,
            token=challenge.magic_token,
            secret=SECRET,
            request_id="rollback-login",
            now=BASE_NOW,
        )
        assert isinstance(result, AuthenticatedSession)
        with pytest.raises(DBAPIError):
            session.execute(text("SELECT 1 / 0"))
        session.rollback()
    finally:
        session.close()
        engine.dispose()

    assert _owner_rows(owner_url, Client, workspace_id) == []
    assert _owner_rows(owner_url, Consent, workspace_id) == []
    assert _owner_rows(owner_url, SessionRecord, workspace_id) == []
    assert _owner_rows(owner_url, AuditEvent, workspace_id) == []
    stored_challenge = _owner_rows(owner_url, LoginChallenge, workspace_id)[0]
    assert stored_challenge.consumed_at is None
    assert stored_challenge.invalidated_at is None
