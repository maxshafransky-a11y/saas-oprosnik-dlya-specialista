from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from typing import NoReturn

from app.questionnaire import Question, QuestionnaireTemplate


class InvalidAnswer(ValueError):
    def __init__(self, question_key: str, code: str) -> None:
        self.question_key = question_key
        self.code = code
        super().__init__(question_key, code)


class IncompleteQuestionnaire(ValueError):
    def __init__(self, missing_keys: list[str]) -> None:
        self.missing_keys = missing_keys
        super().__init__(missing_keys)


def _invalid(question: Question, code: str) -> NoReturn:
    raise InvalidAnswer(question.key, code)


def _text_value(question: Question, value: object, limit: int) -> str:
    if not isinstance(value, str):
        _invalid(question, "value_type")
    value = value.strip()
    if not value:
        _invalid(question, "empty")
    if len(value) > limit:
        _invalid(question, "too_long")
    return value


def _comment_value(question: Question, value: object) -> str:
    if not isinstance(value, str):
        _invalid(question, "comment_type")
    value = value.strip()
    if len(value) > 2_000:
        _invalid(question, "comment_too_long")
    return value


def normalize_answer(question: Question, payload: object) -> dict[str, object]:
    if question.type == "document_upload":
        _invalid(question, "document_upload")
    if not isinstance(payload, Mapping):
        _invalid(question, "payload_type")

    expected_keys = {"value", "comment"} if question.comment_enabled else {"value"}
    if set(payload) != expected_keys:
        _invalid(question, "keys")

    value = payload["value"]
    if question.type in {"text", "date_or_age"}:
        normalized_value = _text_value(question, value, 500)
    elif question.type == "textarea":
        normalized_value = _text_value(question, value, 10_000)
    elif question.type == "number":
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or value <= 0
            or (isinstance(value, float) and not math.isfinite(value))
        ):
            _invalid(question, "number")
        normalized_value = int(value) if isinstance(value, float) and value.is_integer() else value
    elif question.type == "single_choice":
        if not isinstance(value, str):
            _invalid(question, "choice")
        normalized_value = value.strip()
        if question.options is None or normalized_value not in question.options:
            _invalid(question, "choice")
    elif question.type == "multi_choice":
        if not isinstance(value, list) or not value:
            _invalid(question, "choices")
        selected: list[str] = []
        for option in value:
            if not isinstance(option, str):
                _invalid(question, "choices")
            option = option.strip()
            if question.options is None or option not in question.options:
                _invalid(question, "choices")
            if option in selected:
                _invalid(question, "duplicate_choices")
            selected.append(option)
        normalized_value = [option for option in question.options if option in selected]
    elif question.type == "scale":
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or question.scale is None
            or not question.scale.min <= value <= question.scale.max
        ):
            _invalid(question, "scale")
        normalized_value = value
    else:
        _invalid(question, "unsupported_type")

    normalized = {"value": normalized_value}
    if question.comment_enabled:
        normalized["comment"] = _comment_value(question, payload["comment"])
    return normalized


def is_question_visible(
    question: Question,
    answers: Mapping[str, dict[str, object]],
) -> bool:
    if question.condition is None:
        return True
    controlling_answer = answers.get(question.condition.question_key)
    return (
        isinstance(controlling_answer, Mapping)
        and controlling_answer.get("value") == question.condition.equals
    )


def build_submission_snapshot(
    template: QuestionnaireTemplate,
    answers: Mapping[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    normalized_answers: dict[str, dict[str, object]] = {}
    snapshot: dict[str, dict[str, object]] = {}
    missing_keys: list[str] = []

    for section in template.sections:
        for question in section.questions:
            if question.type == "document_upload" or not is_question_visible(
                question, normalized_answers
            ):
                continue
            if question.key not in answers:
                if question.required:
                    missing_keys.append(question.key)
                continue
            try:
                normalized = normalize_answer(question, answers[question.key])
            except InvalidAnswer:
                if question.required:
                    missing_keys.append(question.key)
                    continue
                raise
            normalized_answers[question.key] = normalized
            snapshot[question.key] = normalized

    if missing_keys:
        raise IncompleteQuestionnaire(missing_keys)
    return snapshot


def canonical_snapshot_bytes(snapshot: Mapping[str, dict[str, object]]) -> bytes:
    return json.dumps(
        dict(snapshot),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def snapshot_sha256(snapshot: Mapping[str, dict[str, object]]) -> str:
    return hashlib.sha256(canonical_snapshot_bytes(snapshot)).hexdigest()
