import copy
import hashlib
import math
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.answers import (  # noqa: E402
    IncompleteQuestionnaire,
    InvalidAnswer,
    build_submission_snapshot,
    canonical_snapshot_bytes,
    is_question_visible,
    normalize_answer,
    snapshot_sha256,
)
from app.questionnaire import load_questionnaire  # noqa: E402


def test_normalize_answer_trims_text() -> None:
    question = load_questionnaire().sections[0].questions[0]

    assert normalize_answer(question, {"value": "  Anna  "}) == {"value": "Anna"}


def _questionnaire():
    return load_questionnaire()


def _questions(template):
    return {
        question.key: question for section in template.sections for question in section.questions
    }


def _valid_answers(template, gender_index: int = 0) -> dict[str, dict[str, object]]:
    answers = {}
    for question in _questions(template).values():
        if question.type == "document_upload":
            continue
        if question.type in {"text", "date_or_age", "textarea"}:
            value: object = "ok"
        elif question.type == "number":
            value = 1
        elif question.type == "single_choice":
            value = question.options[0]
        elif question.type == "multi_choice":
            value = [question.options[0]]
        elif question.type == "scale":
            value = question.scale.min
        else:
            raise AssertionError(question.type)
        if question.key == "gender":
            value = question.options[gender_index]
        answer = {"value": value}
        if question.comment_enabled:
            answer["comment"] = ""
        answers[question.key] = answer
    return answers


def test_exact_envelope_and_comment_preservation() -> None:
    template = _questionnaire()
    questions = _questions(template)
    text = questions["full_name"]
    gender = questions["gender"]

    assert normalize_answer(text, {"value": " Anna\nSmith "}) == {"value": "Anna\nSmith"}
    assert normalize_answer(gender, {"value": gender.options[1], "comment": "  keep\nthis  "}) == {
        "value": gender.options[1],
        "comment": "keep\nthis",
    }
    with pytest.raises(InvalidAnswer) as missing_comment:
        normalize_answer(gender, {"value": gender.options[1]})
    assert missing_comment.value.question_key == "gender"
    assert missing_comment.value.code == "keys"
    with pytest.raises(InvalidAnswer) as extra_key:
        normalize_answer(text, {"value": "Anna", "comment": "old"})
    assert extra_key.value.question_key == "full_name"
    assert extra_key.value.code == "keys"


@pytest.mark.parametrize("key", ["full_name", "birth_date_or_age"])
def test_text_types_require_trimmed_non_empty_values_and_have_500_limit(key: str) -> None:
    question = _questions(_questionnaire())[key]
    assert normalize_answer(question, {"value": " x "}) == {"value": "x"}
    assert normalize_answer(question, {"value": "x" * 500}) == {"value": "x" * 500}
    for value in ("", "  \n\t", "x" * 501):
        with pytest.raises(InvalidAnswer):
            normalize_answer(question, {"value": value})


def test_textarea_has_10000_character_limit() -> None:
    question = _questions(_questionnaire())["typical_day"]
    assert normalize_answer(question, {"value": "x" * 10_000}) == {"value": "x" * 10_000}
    with pytest.raises(InvalidAnswer):
        normalize_answer(question, {"value": "x" * 10_001})


def test_number_accepts_only_finite_positive_non_bool_numbers() -> None:
    question = _questions(_questionnaire())["height_cm"]
    assert normalize_answer(question, {"value": 1}) == {"value": 1}
    assert normalize_answer(question, {"value": 1.0}) == {"value": 1}
    assert normalize_answer(question, {"value": 1.5}) == {"value": 1.5}
    huge = 10**400
    assert normalize_answer(question, {"value": huge}) == {"value": huge}
    for value in (True, 0, -1, math.nan, math.inf, "1"):
        with pytest.raises(InvalidAnswer):
            normalize_answer(question, {"value": value})


def test_choice_values_are_template_members_and_multi_choice_is_canonical() -> None:
    questions = _questions(_questionnaire())
    single = questions["gender"]
    multi = questions["goals"]
    first, third = multi.options[0], multi.options[2]

    assert normalize_answer(single, {"value": f" {single.options[0]} ", "comment": ""}) == {
        "value": single.options[0],
        "comment": "",
    }
    with pytest.raises(InvalidAnswer):
        normalize_answer(single, {"value": "not an option", "comment": ""})
    assert normalize_answer(
        multi,
        {"value": [third, f" {first} "], "comment": ""},
    ) == {"value": [first, third], "comment": ""}
    for value in ([], [first, first], ["not an option"]):
        with pytest.raises(InvalidAnswer):
            normalize_answer(multi, {"value": value, "comment": ""})


def test_scale_boundaries_and_comments() -> None:
    question = _questions(_questionnaire())["change_readiness"]
    assert normalize_answer(question, {"value": 1, "comment": ""}) == {
        "value": 1,
        "comment": "",
    }
    assert (
        normalize_answer(question, {"value": 10, "comment": "x" * 2_000})["comment"] == "x" * 2_000
    )
    for value in (0, 11, True, 1.0):
        with pytest.raises(InvalidAnswer):
            normalize_answer(question, {"value": value, "comment": ""})
    with pytest.raises(InvalidAnswer):
        normalize_answer(question, {"value": 1, "comment": "x" * 2_001})
    with pytest.raises(InvalidAnswer):
        normalize_answer(question, {"value": 1, "comment": 42})


def test_document_upload_is_rejected() -> None:
    question = _questions(_questionnaire())["documents"]

    with pytest.raises(InvalidAnswer) as error:
        normalize_answer(question, {"value": "file"})
    assert (error.value.question_key, error.value.code) == ("documents", "document_upload")
    assert "file" not in str(error.value)


def test_visibility_uses_normalized_gender_and_defaults_unconditional_visible() -> None:
    questions = _questions(_questionnaire())
    gender = questions["gender"]
    female = questions["female_health"]
    male = questions["male_health"]
    other = next(
        option
        for option in gender.options
        if option not in {female.condition.equals, male.condition.equals}
    )

    assert is_question_visible(questions["full_name"], {})
    assert is_question_visible(female, {"gender": {"value": female.condition.equals}})
    assert not is_question_visible(female, {"gender": {"value": male.condition.equals}})
    assert is_question_visible(male, {"gender": {"value": male.condition.equals}})
    assert not is_question_visible(male, {"gender": {"value": female.condition.equals}})
    assert not is_question_visible(female, {"gender": {"value": other}})
    assert not is_question_visible(male, {})


def test_snapshot_excludes_hidden_documents_unknown_optional_answers() -> None:
    template = _questionnaire()
    answers = _valid_answers(template, gender_index=1)
    answers.pop("additional_context")
    answers["female_health"] = {"value": "stale hidden answer"}
    answers["unknown"] = {"value": "ignored"}
    before = copy.deepcopy(answers)

    snapshot = build_submission_snapshot(template, answers)

    assert answers == before
    assert "female_health" not in snapshot
    assert "documents" not in snapshot
    assert "additional_context" not in snapshot
    assert "unknown" not in snapshot
    assert "male_health" in snapshot


def test_hidden_required_answer_does_not_block_submission() -> None:
    template = _questionnaire()
    answers = _valid_answers(template, gender_index=1)
    answers.pop("female_health")

    snapshot = build_submission_snapshot(template, answers)

    assert "female_health" not in snapshot


def test_visible_required_missing_and_invalid_keys_are_reported_in_template_order() -> None:
    template = _questionnaire()
    answers = _valid_answers(template)
    answers.pop("full_name")
    answers["location"] = {"value": "  "}

    with pytest.raises(IncompleteQuestionnaire) as error:
        build_submission_snapshot(template, answers)

    assert error.value.missing_keys == ["full_name", "location"]


def test_canonical_bytes_and_hash_are_stable_and_non_ascii() -> None:
    first = {"b": {"value": [1, 2]}, "a": {"value": "\u044f"}}
    second = {"a": {"value": "\u044f"}, "b": {"value": [1, 2]}}
    before = copy.deepcopy(first)
    expected = '{"a":{"value":"\u044f"},"b":{"value":[1,2]}}'.encode("utf-8")

    assert canonical_snapshot_bytes(first) == expected
    assert canonical_snapshot_bytes(first) == canonical_snapshot_bytes(second)
    assert snapshot_sha256(first) == hashlib.sha256(expected).hexdigest()
    assert first == before
