"""Transactional questionnaire lifecycle services."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.answers import (
    build_submission_snapshot,
    is_question_visible,
    normalize_answer,
    snapshot_sha256,
)
from app.models import (
    Answer,
    AuditEvent,
    QuestionnaireResponse,
    QuestionnaireResponseStatus,
    Submission,
)
from app.questionnaire import QuestionnaireTemplate

_IDENTIFIER_RE = re.compile(r"[0-9a-f]{32}")
_DELETED_ANSWER = {"__deleted__": True}


class ResponseReadOnly(Exception):
    pass


class InvalidResponseState(Exception):
    pass


class InvalidIdentifier(Exception):
    pass


class RevisionConflict(Exception):
    def __init__(self, current_revision: int) -> None:
        self.current_revision = current_revision
        super().__init__(current_revision)


@dataclass(frozen=True, slots=True)
class QuestionnaireState:
    response_id: UUID
    template_version: str
    status: QuestionnaireResponseStatus
    current_revision: int
    last_submitted_version: int | None
    current_section_key: str | None
    answers: dict[str, dict[str, object]]


@dataclass(frozen=True, slots=True)
class SaveResult:
    response_id: UUID
    new_revision: int
    current_section_key: str
    updated_at: datetime
    changed_answers: dict[str, dict[str, object] | None]


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    submission_id: UUID
    version: int
    content_hash: str
    submitted_at: datetime
    repeated: bool


def _validate_ids(workspace_id: UUID, client_id: UUID) -> None:
    if not isinstance(workspace_id, UUID) or not isinstance(client_id, UUID):
        raise InvalidIdentifier()


def _copy_answer(answer: Mapping[str, object]) -> dict[str, object]:
    return copy.deepcopy(dict(answer))


def _copy_answers(answers: Mapping[str, Mapping[str, object]]) -> dict[str, dict[str, object]]:
    return {key: _copy_answer(answer) for key, answer in answers.items()}


def _now(value: datetime | None) -> datetime:
    return value if value is not None else datetime.now(UTC)


def _insert_response(
    session: Session,
    *,
    workspace_id: UUID,
    client_id: UUID,
    template_version: str,
    now: datetime,
) -> None:
    session.execute(
        insert(QuestionnaireResponse)
        .values(
            id=uuid4(),
            workspace_id=workspace_id,
            client_id=client_id,
            questionnaire_version=template_version,
            status=QuestionnaireResponseStatus.DRAFT.value,
            current_revision=0,
            last_submitted_version=None,
            current_section_key=None,
            updated_at=now,
            created_at=now,
        )
        .on_conflict_do_nothing(
            index_elements=["workspace_id", "client_id", "questionnaire_version"]
        )
    )


def _get_response(
    session: Session,
    *,
    workspace_id: UUID,
    client_id: UUID,
    template_version: str,
    for_update: bool = False,
) -> QuestionnaireResponse | None:
    statement = select(QuestionnaireResponse).where(
        QuestionnaireResponse.workspace_id == workspace_id,
        QuestionnaireResponse.client_id == client_id,
        QuestionnaireResponse.questionnaire_version == template_version,
    )
    if for_update:
        statement = statement.with_for_update()
    return session.scalars(statement).one_or_none()


def _get_or_create_response(
    session: Session,
    *,
    workspace_id: UUID,
    client_id: UUID,
    template_version: str,
    now: datetime,
    for_update: bool = False,
) -> QuestionnaireResponse:
    _insert_response(
        session,
        workspace_id=workspace_id,
        client_id=client_id,
        template_version=template_version,
        now=now,
    )
    response = _get_response(
        session,
        workspace_id=workspace_id,
        client_id=client_id,
        template_version=template_version,
        for_update=for_update,
    )
    if response is None:
        raise InvalidResponseState()
    return response


def _load_answers(
    session: Session, *, workspace_id: UUID, response_id: UUID
) -> dict[str, dict[str, object]]:
    rows = session.scalars(
        select(Answer).where(
            Answer.workspace_id == workspace_id,
            Answer.response_id == response_id,
        )
    ).all()
    return {
        row.question_key: _copy_answer(row.value_jsonb)
        for row in rows
        if row.value_jsonb != _DELETED_ANSWER
    }


def _state(
    response: QuestionnaireResponse, answers: Mapping[str, Mapping[str, object]]
) -> QuestionnaireState:
    return QuestionnaireState(
        response_id=response.id,
        template_version=response.questionnaire_version,
        status=response.status,
        current_revision=response.current_revision,
        last_submitted_version=response.last_submitted_version,
        current_section_key=response.current_section_key,
        answers=_copy_answers(answers),
    )


def get_questionnaire_state(
    session: Session,
    *,
    workspace_id: UUID,
    client_id: UUID,
    template: QuestionnaireTemplate,
    now: datetime | None = None,
) -> QuestionnaireState:
    _validate_ids(workspace_id, client_id)
    response = _get_or_create_response(
        session,
        workspace_id=workspace_id,
        client_id=client_id,
        template_version=template.version,
        now=_now(now),
    )
    return _state(
        response,
        _load_answers(session, workspace_id=workspace_id, response_id=response.id),
    )


def _validate_revision(expected_revision: int) -> None:
    if isinstance(expected_revision, bool) or not isinstance(expected_revision, int):
        raise ValueError("invalid revision")
    if expected_revision < 0:
        raise ValueError("invalid revision")


def _validate_identifier(value: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise InvalidIdentifier()


def _question_maps(
    template: QuestionnaireTemplate,
) -> tuple[dict[str, object], dict[str, set[str]]]:
    questions: dict[str, object] = {}
    section_questions: dict[str, set[str]] = {}
    for section in template.sections:
        keys = {question.key for question in section.questions}
        section_questions[section.key] = keys
        questions.update({question.key: question for question in section.questions})
    return questions, section_questions


def _normalize_changes(
    template: QuestionnaireTemplate,
    *,
    section_key: str,
    changes: Mapping[str, object],
) -> dict[str, dict[str, object] | None]:
    if not isinstance(changes, Mapping) or not changes:
        raise ValueError("changes must be a non-empty mapping")
    questions, section_questions = _question_maps(template)
    if section_key not in section_questions:
        raise ValueError("invalid section")

    normalized: dict[str, dict[str, object] | None] = {}
    for key, payload in changes.items():
        if not isinstance(key, str) or key not in questions:
            raise ValueError("unknown question")
        if key not in section_questions[section_key]:
            raise ValueError("question is outside section")
        question = questions[key]
        if question.type == "document_upload":
            raise ValueError("document upload is not an answer")
        normalized[key] = None if payload is None else normalize_answer(question, payload)
    return normalized


def _assert_mutable(response: QuestionnaireResponse) -> None:
    if response.status == QuestionnaireResponseStatus.SUBMITTED:
        raise ResponseReadOnly()
    if response.status not in {
        QuestionnaireResponseStatus.DRAFT,
        QuestionnaireResponseStatus.EDITING,
    }:
        raise InvalidResponseState()


def _assert_revision(response: QuestionnaireResponse, expected_revision: int) -> None:
    if response.current_revision != expected_revision:
        raise RevisionConflict(response.current_revision)


def _locked_response(
    session: Session,
    *,
    workspace_id: UUID,
    client_id: UUID,
    template: QuestionnaireTemplate,
    now: datetime,
) -> QuestionnaireResponse:
    return _get_or_create_response(
        session,
        workspace_id=workspace_id,
        client_id=client_id,
        template_version=template.version,
        now=now,
        for_update=True,
    )


def save_answers(
    session: Session,
    *,
    workspace_id: UUID,
    client_id: UUID,
    template: QuestionnaireTemplate,
    section_key: str,
    changes: Mapping[str, object],
    expected_revision: int,
    now: datetime | None = None,
) -> SaveResult:
    _validate_ids(workspace_id, client_id)
    _validate_revision(expected_revision)
    normalized = _normalize_changes(
        template,
        section_key=section_key,
        changes=changes,
    )
    timestamp = _now(now)
    response = _locked_response(
        session,
        workspace_id=workspace_id,
        client_id=client_id,
        template=template,
        now=timestamp,
    )
    _assert_mutable(response)
    _assert_revision(response, expected_revision)

    working_answers = _load_answers(session, workspace_id=workspace_id, response_id=response.id)
    proposed_answers = _copy_answers(working_answers)
    for key, answer in normalized.items():
        if answer is None:
            proposed_answers.pop(key, None)
        else:
            proposed_answers[key] = _copy_answer(answer)
    questions, _ = _question_maps(template)
    if any(not is_question_visible(questions[key], proposed_answers) for key in normalized):
        raise ValueError("question is not visible")

    answer_rows = {
        row.question_key: row
        for row in session.scalars(
            select(Answer).where(
                Answer.workspace_id == workspace_id,
                Answer.response_id == response.id,
            )
        ).all()
    }
    new_revision = response.current_revision + 1
    for key, answer in normalized.items():
        row = answer_rows.get(key)
        if answer is None:
            if row is not None:
                # ponytail: tombstone; health_app lacks DELETE. Add it in the next migration.
                row.value_jsonb = copy.deepcopy(_DELETED_ANSWER)
                row.revision = new_revision
                row.updated_at = timestamp
            continue
        if row is None:
            session.add(
                Answer(
                    id=uuid4(),
                    workspace_id=workspace_id,
                    response_id=response.id,
                    question_key=key,
                    value_jsonb=_copy_answer(answer),
                    revision=new_revision,
                    updated_at=timestamp,
                    created_at=timestamp,
                )
            )
        else:
            row.value_jsonb = _copy_answer(answer)
            row.revision = new_revision
            row.updated_at = timestamp

    response.current_revision = new_revision
    response.current_section_key = section_key
    response.updated_at = timestamp
    session.flush()
    return SaveResult(
        response_id=response.id,
        new_revision=new_revision,
        current_section_key=section_key,
        updated_at=timestamp,
        changed_answers={
            key: None if answer is None else _copy_answer(answer)
            for key, answer in normalized.items()
        },
    )


def _submission_result(submission: Submission, *, repeated: bool) -> SubmissionResult:
    return SubmissionResult(
        submission_id=submission.id,
        version=submission.version,
        content_hash=submission.content_hash,
        submitted_at=submission.submitted_at,
        repeated=repeated,
    )


def submit_response(
    session: Session,
    *,
    workspace_id: UUID,
    client_id: UUID,
    template: QuestionnaireTemplate,
    expected_revision: int,
    idempotency_key: str,
    request_id: str,
    now: datetime | None = None,
) -> SubmissionResult:
    _validate_ids(workspace_id, client_id)
    _validate_revision(expected_revision)
    _validate_identifier(idempotency_key)
    _validate_identifier(request_id)
    timestamp = _now(now)
    response = _locked_response(
        session,
        workspace_id=workspace_id,
        client_id=client_id,
        template=template,
        now=timestamp,
    )
    existing = session.scalars(
        select(Submission).where(
            Submission.workspace_id == workspace_id,
            Submission.response_id == response.id,
            Submission.idempotency_key == idempotency_key,
        )
    ).one_or_none()
    if existing is not None:
        return _submission_result(existing, repeated=True)

    _assert_mutable(response)
    _assert_revision(response, expected_revision)
    working_answers = _load_answers(session, workspace_id=workspace_id, response_id=response.id)
    snapshot = build_submission_snapshot(template, working_answers)
    version = (response.last_submitted_version or 0) + 1
    submission_id = uuid4()
    content_hash = snapshot_sha256(snapshot)
    session.add(
        Submission(
            id=submission_id,
            workspace_id=workspace_id,
            response_id=response.id,
            version=version,
            questionnaire_version=template.version,
            answers_snapshot_jsonb=copy.deepcopy(snapshot),
            content_hash=content_hash,
            idempotency_key=idempotency_key,
            submitted_at=timestamp,
        )
    )
    response.status = QuestionnaireResponseStatus.SUBMITTED
    response.last_submitted_version = version
    session.add(
        AuditEvent(
            id=uuid4(),
            workspace_id=workspace_id,
            client_id=client_id,
            actor_type="client",
            event_type="questionnaire_submitted",
            target_type="submission",
            target_id=submission_id,
            occurred_at=timestamp,
            request_id=request_id,
            metadata_jsonb={"version": version, "template_version": template.version},
        )
    )
    session.flush()
    return SubmissionResult(
        submission_id=submission_id,
        version=version,
        content_hash=content_hash,
        submitted_at=timestamp,
        repeated=False,
    )


def start_editing(
    session: Session,
    *,
    workspace_id: UUID,
    client_id: UUID,
    template: QuestionnaireTemplate,
    request_id: str,
    now: datetime | None = None,
) -> QuestionnaireState:
    _validate_ids(workspace_id, client_id)
    _validate_identifier(request_id)
    timestamp = _now(now)
    response = _locked_response(
        session,
        workspace_id=workspace_id,
        client_id=client_id,
        template=template,
        now=timestamp,
    )
    if response.status == QuestionnaireResponseStatus.DRAFT:
        raise InvalidResponseState()
    if response.status == QuestionnaireResponseStatus.SUBMITTED:
        if response.last_submitted_version is None:
            raise InvalidResponseState()
        response.status = QuestionnaireResponseStatus.EDITING
        session.add(
            AuditEvent(
                id=uuid4(),
                workspace_id=workspace_id,
                client_id=client_id,
                actor_type="client",
                event_type="questionnaire_edit_started",
                target_type="response",
                target_id=response.id,
                occurred_at=timestamp,
                request_id=request_id,
                metadata_jsonb={
                    "from_version": response.last_submitted_version,
                    "template_version": template.version,
                },
            )
        )
        session.flush()
    elif response.status != QuestionnaireResponseStatus.EDITING:
        raise InvalidResponseState()

    return _state(
        response,
        _load_answers(session, workspace_id=workspace_id, response_id=response.id),
    )
