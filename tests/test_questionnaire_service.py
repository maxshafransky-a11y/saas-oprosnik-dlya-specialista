from __future__ import annotations

import sys
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier
from uuid import UUID, uuid4

sys.path.insert(0, str(Path(__file__).parents[1]))

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.pool import NullPool

from app import questionnaire_service
from app.answers import IncompleteQuestionnaire
from app.models import Client, ClientStatus, Workspace, WorkspaceStatus
from app.questionnaire import load_questionnaire

pytest_plugins = ("tests.db_test_support",)


def _seed_client(owner_url: URL) -> tuple[UUID, UUID]:
    workspace_id = uuid4()
    client_id = uuid4()
    engine = create_engine(owner_url)
    try:
        with DbSession(engine) as session:
            session.add(
                Workspace(
                    id=workspace_id,
                    name="Test workspace",
                    public_slug=f"test-{workspace_id.hex}",
                    status=WorkspaceStatus.ACTIVE,
                )
            )
            session.flush()
            session.execute(
                text("SELECT set_config('app.workspace_id', :workspace_id, false)"),
                {"workspace_id": str(workspace_id)},
            )
            session.add(
                Client(
                    id=client_id,
                    workspace_id=workspace_id,
                    email_normalized=f"{client_id.hex}@example.test",
                    email_display=f"{client_id.hex}@example.test",
                    status=ClientStatus.ACTIVE,
                )
            )
            session.commit()
    finally:
        engine.dispose()
    return workspace_id, client_id


def test_get_questionnaire_state_bootstraps_response(migrated_database) -> None:
    owner_url, runtime_url = migrated_database
    workspace_id, client_id = _seed_client(owner_url)
    engine = create_engine(runtime_url)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    try:
        with DbSession(engine) as session:
            session.execute(
                text("SELECT set_config('app.workspace_id', :workspace_id, false)"),
                {"workspace_id": str(workspace_id)},
            )
            state = questionnaire_service.get_questionnaire_state(
                session,
                workspace_id=workspace_id,
                client_id=client_id,
                template=load_questionnaire(),
                now=now,
            )

            assert state.response_id is not None
            assert state.template_version == "health-profile-v1"
            assert state.status.value == "draft"
            assert state.current_revision == 0
            assert state.last_submitted_version is None
            assert state.current_section_key is None
            assert state.answers == {}
    finally:
        engine.dispose()


@pytest.fixture
def questionnaire_context(migrated_database) -> Iterator[tuple[object, URL, UUID, UUID]]:
    owner_url, runtime_url = migrated_database
    workspace_id, client_id = _seed_client(owner_url)
    engine = create_engine(runtime_url, poolclass=NullPool)
    try:
        yield engine, runtime_url, workspace_id, client_id
    finally:
        engine.dispose()


@contextmanager
def _runtime_session(engine: object, workspace_id: UUID) -> Iterator[DbSession]:
    with DbSession(engine) as session:
        _set_workspace(session, workspace_id)
        yield session


def _set_workspace(session: DbSession, workspace_id: UUID) -> None:
    session.execute(
        text("SELECT set_config('app.workspace_id', :workspace_id, false)"),
        {"workspace_id": str(workspace_id)},
    )


def _question(template, key: str):
    return next(
        question
        for section in template.sections
        for question in section.questions
        if question.key == key
    )


def _section_for(template, key: str) -> str:
    return next(
        section.key
        for section in template.sections
        if any(question.key == key for question in section.questions)
    )


def _payload(question, *, value: object | None = None, alternate: bool = False) -> dict:
    if value is None:
        if question.type in {"text", "date_or_age", "textarea"}:
            value = "Второй ответ" if alternate else "Ответ"
        elif question.type == "number":
            value = 171 if alternate else 170
        elif question.type == "single_choice":
            index = 1 if alternate and len(question.options) > 1 else 0
            value = question.options[index]
        elif question.type == "multi_choice":
            value = [question.options[-1] if alternate else question.options[0]]
        elif question.type == "scale":
            value = question.scale.max if alternate else question.scale.min
    answer = {"value": value}
    if question.comment_enabled:
        answer["comment"] = ""
    return answer


def _answer_payloads(template, *, gender: str) -> dict[str, dict]:
    payloads = {}
    for section in template.sections:
        for question in section.questions:
            if question.type == "document_upload":
                continue
            if question.key == "gender":
                payloads[question.key] = _payload(question, value=gender)
            elif question.condition is not None and question.condition.equals != gender:
                continue
            else:
                payloads[question.key] = _payload(question)
    return payloads


def _save_payloads(session, workspace_id, client_id, template, payloads, revision: int) -> int:
    for section in template.sections:
        changes = {
            question.key: payloads[question.key]
            for question in section.questions
            if question.key in payloads
        }
        if changes:
            result = questionnaire_service.save_answers(
                session,
                workspace_id=workspace_id,
                client_id=client_id,
                template=template,
                section_key=section.key,
                changes=changes,
                expected_revision=revision,
            )
            revision = result.new_revision
    return revision


def _owner_rows(owner_url: URL, workspace_id: UUID, query: str) -> list[dict]:
    engine = create_engine(owner_url, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            connection.execute(
                text("SELECT set_config('app.workspace_id', :workspace_id, false)"),
                {"workspace_id": str(workspace_id)},
            )
            return [dict(row) for row in connection.execute(text(query)).mappings()]
    finally:
        engine.dispose()


def _submission_rows(owner_url: URL, workspace_id: UUID) -> list[dict]:
    return _owner_rows(
        owner_url,
        workspace_id,
        "SELECT id, version, answers_snapshot_jsonb, content_hash, idempotency_key "
        "FROM submissions ORDER BY version",
    )


def _audit_rows(owner_url: URL, workspace_id: UUID) -> list[dict]:
    return _owner_rows(
        owner_url,
        workspace_id,
        "SELECT event_type, target_type, target_id, request_id, metadata_jsonb "
        "FROM audit_events ORDER BY created_at",
    )


def _complete_questionnaire(session, workspace_id, client_id, template) -> int:
    state = questionnaire_service.get_questionnaire_state(
        session,
        workspace_id=workspace_id,
        client_id=client_id,
        template=template,
    )
    payloads = _answer_payloads(template, gender="Женский")
    return _save_payloads(
        session, workspace_id, client_id, template, payloads, state.current_revision
    )


def test_bootstrap_is_race_safe_and_state_resumes(migrated_database, questionnaire_context) -> None:
    owner_url, _ = migrated_database
    engine, _, workspace_id, client_id = questionnaire_context
    template = load_questionnaire()
    barrier = Barrier(2)

    def bootstrap() -> UUID:
        with _runtime_session(engine, workspace_id) as session:
            barrier.wait()
            state = questionnaire_service.get_questionnaire_state(
                session,
                workspace_id=workspace_id,
                client_id=client_id,
                template=template,
            )
            session.commit()
            return state.response_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        response_ids = list(executor.map(lambda _: bootstrap(), range(2)))
    assert response_ids[0] == response_ids[1]

    with _runtime_session(engine, workspace_id) as session:
        state = questionnaire_service.get_questionnaire_state(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
        )
        question = template.sections[0].questions[0]
        questionnaire_service.save_answers(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            section_key=template.sections[0].key,
            changes={question.key: _payload(question)},
            expected_revision=state.current_revision,
        )
        session.commit()

    with _runtime_session(engine, workspace_id) as session:
        resumed = questionnaire_service.get_questionnaire_state(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
        )
        assert resumed.response_id == response_ids[0]
        assert resumed.current_revision == 1
        assert resumed.answers[question.key] == _payload(question)
        resumed.answers[question.key]["value"] = "detached"
        again = questionnaire_service.get_questionnaire_state(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
        )
        assert again.answers[question.key] == _payload(question)


def test_save_answers_is_typed_batched_and_visibility_checked(questionnaire_context) -> None:
    engine, _, workspace_id, client_id = questionnaire_context
    template = load_questionnaire()
    gender = _question(template, "gender")
    female_question = next(
        question
        for section in template.sections
        for question in section.questions
        if question.condition is not None and question.condition.equals == "Женский"
    )
    male_question = next(
        question
        for section in template.sections
        for question in section.questions
        if question.condition is not None and question.condition.equals == "Мужской"
    )

    with _runtime_session(engine, workspace_id) as session:
        state = questionnaire_service.get_questionnaire_state(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
        )
        gender_result = questionnaire_service.save_answers(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            section_key=_section_for(template, gender.key),
            changes={gender.key: _payload(gender, value="Женский")},
            expected_revision=state.current_revision,
        )
        assert gender_result.new_revision == 1
        result = questionnaire_service.save_answers(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            section_key=_section_for(template, female_question.key),
            changes={female_question.key: _payload(female_question)},
            expected_revision=gender_result.new_revision,
        )
        assert result.new_revision == 2
        assert result.changed_answers == {female_question.key: _payload(female_question)}
        deleted = questionnaire_service.save_answers(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            section_key=_section_for(template, gender.key),
            changes={gender.key: _payload(gender, value="Мужской")},
            expected_revision=result.new_revision,
        )
        assert deleted.new_revision == 3
        assert deleted.changed_answers == {gender.key: _payload(gender, value="Мужской")}

        with pytest.raises(ValueError):
            questionnaire_service.save_answers(
                session,
                workspace_id=workspace_id,
                client_id=client_id,
                template=template,
                section_key=_section_for(template, female_question.key),
                changes={female_question.key: _payload(female_question)},
                expected_revision=deleted.new_revision,
            )

        restored = questionnaire_service.save_answers(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            section_key=_section_for(template, female_question.key),
            changes={male_question.key: _payload(male_question)},
            expected_revision=deleted.new_revision,
        )
        assert restored.new_revision == 4
        assert restored.changed_answers == {male_question.key: _payload(male_question)}

        cleared = questionnaire_service.save_answers(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            section_key=_section_for(template, male_question.key),
            changes={male_question.key: None},
            expected_revision=restored.new_revision,
        )
        assert cleared.new_revision == 5
        assert cleared.changed_answers == {male_question.key: None}

        with pytest.raises(ValueError):
            questionnaire_service.save_answers(
                session,
                workspace_id=workspace_id,
                client_id=client_id,
                template=template,
                section_key=_section_for(template, gender.key),
                changes={female_question.key: _payload(female_question)},
                expected_revision=cleared.new_revision,
            )

        with pytest.raises(ValueError):
            questionnaire_service.save_answers(
                session,
                workspace_id=workspace_id,
                client_id=client_id,
                template=template,
                section_key="unknown-section",
                changes={gender.key: _payload(gender, value="Женский")},
                expected_revision=cleared.new_revision,
            )

        document = next(
            question
            for section in template.sections
            for question in section.questions
            if question.type == "document_upload"
        )
        with pytest.raises(ValueError):
            questionnaire_service.save_answers(
                session,
                workspace_id=workspace_id,
                client_id=client_id,
                template=template,
                section_key=_section_for(template, document.key),
                changes={document.key: {"value": "file"}},
                expected_revision=cleared.new_revision,
            )

        unchanged = questionnaire_service.get_questionnaire_state(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
        )
        assert unchanged.current_revision == cleared.new_revision
        assert gender.key in unchanged.answers
        assert female_question.key in unchanged.answers
        assert male_question.key not in unchanged.answers


def test_stale_revision_conflicts_without_last_write_wins(questionnaire_context) -> None:
    engine, _, workspace_id, client_id = questionnaire_context
    template = load_questionnaire()
    question = template.sections[0].questions[0]
    section_key = template.sections[0].key
    with _runtime_session(engine, workspace_id) as session:
        questionnaire_service.get_questionnaire_state(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
        )
        session.commit()

    with (
        _runtime_session(engine, workspace_id) as first,
        _runtime_session(engine, workspace_id) as second,
    ):
        questionnaire_service.save_answers(
            first,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            section_key=section_key,
            changes={question.key: _payload(question)},
            expected_revision=0,
        )
        first.commit()
        with pytest.raises(questionnaire_service.RevisionConflict) as conflict:
            questionnaire_service.save_answers(
                second,
                workspace_id=workspace_id,
                client_id=client_id,
                template=template,
                section_key=section_key,
                changes={question.key: _payload(question, alternate=True)},
                expected_revision=0,
            )
        assert conflict.value.current_revision == 1
        second.rollback()

    with _runtime_session(engine, workspace_id) as session:
        state = questionnaire_service.get_questionnaire_state(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
        )
        assert state.current_revision == 1
        assert state.answers[question.key] == _payload(question)


def test_submit_excludes_hidden_stale_answer_and_creates_v1(
    migrated_database, questionnaire_context
) -> None:
    owner_url, _ = migrated_database
    engine, _, workspace_id, client_id = questionnaire_context
    template = load_questionnaire()
    gender = _question(template, "gender")
    male_question = next(
        question
        for section in template.sections
        for question in section.questions
        if question.condition is not None and question.condition.equals == "Мужской"
    )
    female_question = next(
        question
        for section in template.sections
        for question in section.questions
        if question.condition is not None and question.condition.equals == "Женский"
    )
    with _runtime_session(engine, workspace_id) as session:
        state = questionnaire_service.get_questionnaire_state(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
        )
        first = questionnaire_service.save_answers(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            section_key=_section_for(template, gender.key),
            changes={gender.key: _payload(gender, value="Мужской")},
            expected_revision=state.current_revision,
        )
        second = questionnaire_service.save_answers(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            section_key=_section_for(template, male_question.key),
            changes={male_question.key: _payload(male_question)},
            expected_revision=first.new_revision,
        )
        third = questionnaire_service.save_answers(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            section_key=_section_for(template, gender.key),
            changes={gender.key: _payload(gender, value="Женский")},
            expected_revision=second.new_revision,
        )
        revision = _save_payloads(
            session,
            workspace_id,
            client_id,
            template,
            _answer_payloads(template, gender="Женский"),
            third.new_revision,
        )
        result = questionnaire_service.submit_response(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            expected_revision=revision,
            idempotency_key="a" * 32,
            request_id="b" * 32,
            now=datetime(2026, 1, 2, tzinfo=UTC),
        )
        session.commit()

    assert result.version == 1
    assert result.repeated is False
    submissions = _submission_rows(owner_url, workspace_id)
    assert len(submissions) == 1
    assert submissions[0]["version"] == 1
    assert female_question.key in submissions[0]["answers_snapshot_jsonb"]
    assert male_question.key not in submissions[0]["answers_snapshot_jsonb"]
    assert len(_audit_rows(owner_url, workspace_id)) == 1


def test_missing_required_answers_do_not_submit_or_audit(
    migrated_database, questionnaire_context
) -> None:
    owner_url, _ = migrated_database
    engine, _, workspace_id, client_id = questionnaire_context
    template = load_questionnaire()
    with _runtime_session(engine, workspace_id) as session:
        state = questionnaire_service.get_questionnaire_state(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
        )
        session.commit()
    with _runtime_session(engine, workspace_id) as session:
        with pytest.raises(IncompleteQuestionnaire):
            questionnaire_service.submit_response(
                session,
                workspace_id=workspace_id,
                client_id=client_id,
                template=template,
                expected_revision=state.current_revision,
                idempotency_key="c" * 32,
                request_id="d" * 32,
            )
        session.rollback()
    with _runtime_session(engine, workspace_id) as session:
        unchanged = questionnaire_service.get_questionnaire_state(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
        )
        assert unchanged.status.value == "draft"
    assert _submission_rows(owner_url, workspace_id) == []
    assert _audit_rows(owner_url, workspace_id) == []


def test_idempotent_submit_is_single_append_and_other_key_is_read_only(
    migrated_database, questionnaire_context
) -> None:
    owner_url, _ = migrated_database
    engine, _, workspace_id, client_id = questionnaire_context
    template = load_questionnaire()
    with _runtime_session(engine, workspace_id) as session:
        revision = _complete_questionnaire(session, workspace_id, client_id, template)
        first = questionnaire_service.submit_response(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            expected_revision=revision,
            idempotency_key="e" * 32,
            request_id="f" * 32,
        )
        session.commit()
    with _runtime_session(engine, workspace_id) as session:
        repeated = questionnaire_service.submit_response(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            expected_revision=0,
            idempotency_key="e" * 32,
            request_id="1" * 32,
        )
        assert repeated.repeated is True
        assert repeated.submission_id == first.submission_id
        assert repeated.content_hash == first.content_hash
        session.commit()
    with _runtime_session(engine, workspace_id) as session:
        with pytest.raises(questionnaire_service.ResponseReadOnly):
            questionnaire_service.submit_response(
                session,
                workspace_id=workspace_id,
                client_id=client_id,
                template=template,
                expected_revision=revision,
                idempotency_key="2" * 32,
                request_id="3" * 32,
            )
        session.rollback()
    assert len(_submission_rows(owner_url, workspace_id)) == 1
    assert len(_audit_rows(owner_url, workspace_id)) == 1


def test_concurrent_idempotent_submit_is_single_append_and_audit(
    migrated_database, questionnaire_context
) -> None:
    owner_url, _ = migrated_database
    engine, _, workspace_id, client_id = questionnaire_context
    template = load_questionnaire()
    with _runtime_session(engine, workspace_id) as session:
        revision = _complete_questionnaire(session, workspace_id, client_id, template)
        session.commit()

    barrier = Barrier(2)
    idempotency_key = "a" * 32

    def submit(request_id: str):
        with _runtime_session(engine, workspace_id) as session:
            barrier.wait()
            result = questionnaire_service.submit_response(
                session,
                workspace_id=workspace_id,
                client_id=client_id,
                template=template,
                expected_revision=revision,
                idempotency_key=idempotency_key,
                request_id=request_id,
            )
            session.commit()
            return result

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(submit, ("b" * 32, "c" * 32)))

    assert sorted(result.repeated for result in results) == [False, True]
    assert len(_submission_rows(owner_url, workspace_id)) == 1
    assert len(_audit_rows(owner_url, workspace_id)) == 1


def test_edit_is_idempotent_and_new_submission_preserves_v1(
    migrated_database, questionnaire_context
) -> None:
    owner_url, _ = migrated_database
    engine, _, workspace_id, client_id = questionnaire_context
    template = load_questionnaire()
    with _runtime_session(engine, workspace_id) as session:
        revision = _complete_questionnaire(session, workspace_id, client_id, template)
        first = questionnaire_service.submit_response(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            expected_revision=revision,
            idempotency_key="4" * 32,
            request_id="5" * 32,
        )
        session.commit()

    question = template.sections[0].questions[0]
    with _runtime_session(engine, workspace_id) as session:
        editing = questionnaire_service.start_editing(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            request_id="6" * 32,
        )
        assert editing.status.value == "editing"
        second_edit = questionnaire_service.start_editing(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            request_id="7" * 32,
        )
        assert second_edit.status.value == "editing"
        saved = questionnaire_service.save_answers(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            section_key=template.sections[0].key,
            changes={question.key: _payload(question, alternate=True)},
            expected_revision=editing.current_revision,
        )
        second = questionnaire_service.submit_response(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            expected_revision=saved.new_revision,
            idempotency_key="8" * 32,
            request_id="9" * 32,
        )
        session.commit()

    rows = _submission_rows(owner_url, workspace_id)
    assert [row["version"] for row in rows] == [1, 2]
    assert rows[0]["id"] == first.submission_id
    assert rows[0]["content_hash"] == first.content_hash
    assert rows[0]["answers_snapshot_jsonb"] != rows[1]["answers_snapshot_jsonb"]
    assert second.version == 2
    audits = _audit_rows(owner_url, workspace_id)
    assert [row["event_type"] for row in audits] == [
        "questionnaire_submitted",
        "questionnaire_edit_started",
        "questionnaire_submitted",
    ]

    with _runtime_session(engine, workspace_id) as session:
        with pytest.raises(questionnaire_service.ResponseReadOnly):
            questionnaire_service.save_answers(
                session,
                workspace_id=workspace_id,
                client_id=client_id,
                template=template,
                section_key=template.sections[0].key,
                changes={question.key: _payload(question)},
                expected_revision=saved.new_revision,
            )
        session.rollback()


def test_invalid_identifiers_fail_before_response_or_audit_mutation(
    migrated_database, questionnaire_context
) -> None:
    owner_url, _ = migrated_database
    engine, _, workspace_id, client_id = questionnaire_context
    template = load_questionnaire()
    secret = "not-a-valid-secret"
    with _runtime_session(engine, workspace_id) as session:
        with pytest.raises(questionnaire_service.InvalidIdentifier) as error:
            questionnaire_service.submit_response(
                session,
                workspace_id=workspace_id,
                client_id=client_id,
                template=template,
                expected_revision=0,
                idempotency_key=secret,
                request_id="a" * 32,
            )
        assert secret not in str(error.value)
        with pytest.raises(questionnaire_service.InvalidIdentifier):
            questionnaire_service.start_editing(
                session,
                workspace_id=workspace_id,
                client_id=client_id,
                template=template,
                request_id="A" * 32,
            )
        session.rollback()
    assert _submission_rows(owner_url, workspace_id) == []
    assert _audit_rows(owner_url, workspace_id) == []


def test_rollback_removes_submission_status_and_audit(
    migrated_database, questionnaire_context
) -> None:
    owner_url, _ = migrated_database
    engine, _, workspace_id, client_id = questionnaire_context
    template = load_questionnaire()
    with _runtime_session(engine, workspace_id) as session:
        revision = _complete_questionnaire(session, workspace_id, client_id, template)
        session.commit()
        _set_workspace(session, workspace_id)
        questionnaire_service.submit_response(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
            expected_revision=revision,
            idempotency_key="a" * 32,
            request_id="b" * 32,
        )
        session.rollback()
    with _runtime_session(engine, workspace_id) as session:
        state = questionnaire_service.get_questionnaire_state(
            session,
            workspace_id=workspace_id,
            client_id=client_id,
            template=template,
        )
        assert state.status.value == "draft"
        assert state.last_submitted_version is None
    assert _submission_rows(owner_url, workspace_id) == []
    assert _audit_rows(owner_url, workspace_id) == []
