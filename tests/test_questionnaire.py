import importlib
import json
import re
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).parents[1]
CANONICAL_PATH = ROOT / "docs/superpowers/specs/2026-08-25-health-intake-questionnaire-source.md"
TEMPLATE_PATH = ROOT / "app/questionnaire_v1.json"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
load_questionnaire = importlib.import_module("app.questionnaire").load_questionnaire


EXPECTED_KEYS = (
    "full_name",
    "birth_date_or_age",
    "height_cm",
    "weight_kg",
    "gender",
    "location",
    "contact",
    "typical_day",
    "activity_level",
    "chronic_fatigue",
    "goals",
    "success_outcome",
    "health_conditions",
    "medications_supplements",
    "food_allergies",
    "operations_infections",
    "recent_tests",
    "family_history",
    "meal_day",
    "cravings",
    "overeating",
    "liked_foods",
    "avoided_foods",
    "diet_history",
    "bowel_frequency",
    "gi_symptoms",
    "skin_hair_nails",
    "edema_thirst",
    "sleep_schedule",
    "sleep_quality",
    "stress_level",
    "mood_symptoms",
    "psychological_practices",
    "female_health",
    "male_health",
    "sexual_health_history",
    "physical_activity",
    "water_drinks",
    "substances",
    "support",
    "weight_history",
    "change_readiness",
    "change_barriers",
    "additional_context",
    "food_diary_readiness",
    "documents",
)
TYPE_MAP = {
    "Краткий ответ": "text",
    "Абзац": "textarea",
    "Множественный выбор": "single_choice",
    "Флажки (checkbox)": "multi_choice",
    "Шкала": "scale",
    "Загрузка файлов": "document_upload",
}
SECTION_COUNTS = (7, 3, 2, 6, 6, 4, 5, 3, 5, 5)
QUESTION_FIELDS = {
    "source_number",
    "key",
    "type",
    "label",
    "helper",
    "required",
    "options",
    "unit",
    "scale",
    "condition",
    "comment_enabled",
}


def _markdown_value(value: str) -> str:
    value = value.strip()
    if value.startswith("`") and value.endswith("`"):
        return value[1:-1]
    return value


def _canonical_contract() -> dict:
    lines = CANONICAL_PATH.read_text(encoding="utf-8").splitlines()
    section_pattern = re.compile(r"^## (\d+)\. (.+) — (\d+) вопрос(?:а|ов)$")
    question_pattern = re.compile(r"^### (\d+)\. (.+)$")
    sections: list[dict] = []
    current_question: dict | None = None

    for line in lines:
        section_match = section_pattern.match(line)
        if section_match:
            current_question = None
            sections.append(
                {
                    "number": int(section_match.group(1)),
                    "title": section_match.group(2),
                    "declared_count": int(section_match.group(3)),
                    "questions": [],
                }
            )
            continue

        question_match = question_pattern.match(line)
        if question_match:
            current_question = {
                "source_number": int(question_match.group(1)),
                "label": question_match.group(2),
            }
            sections[-1]["questions"].append(current_question)
            continue

        if current_question is None:
            continue
        if line.startswith("- Тип: "):
            current_question["source_type"] = _markdown_value(line.removeprefix("- Тип: "))
        elif line.startswith("- Подсказка: "):
            current_question["helper"] = _markdown_value(line.removeprefix("- Подсказка: "))
        elif line.startswith("- Варианты: "):
            raw_options = line.removeprefix("- Варианты: ").removesuffix(".")
            current_question["options"] = [
                _markdown_value(option) for option in raw_options.split(";")
            ]
        elif line.startswith("- Диапазон: "):
            raw_scale = _markdown_value(line.removeprefix("- Диапазон: ").removesuffix("."))
            minimum, maximum = raw_scale.split("-", maxsplit=1)
            current_question["scale"] = {"min": int(minimum), "max": int(maximum)}
        elif line.startswith("- UX-условие: "):
            condition_match = re.search(r"при выборе `([^`]+)`", line)
            assert condition_match
            current_question["condition"] = {
                "question_key": "gender",
                "equals": condition_match.group(1),
            }

    def blockquote(heading: str) -> str:
        start = lines.index(heading)
        return next(line.removeprefix("> ") for line in lines[start + 1 :] if line.startswith("> "))

    questions = [question for section in sections for question in section["questions"]]
    return {
        "intro": blockquote("## Вступление"),
        "completion": blockquote("## Завершение"),
        "sections": sections,
        "questions": questions,
    }


def _read_json() -> dict:
    return json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))


def _load_invalid_payload(payload: dict) -> None:
    path = ROOT / ".uv-cache" / "questionnaire-invalid-test.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    try:
        load_questionnaire(path)
    finally:
        path.unlink(missing_ok=True)


def test_template_matches_canonical_markdown() -> None:
    expected = _canonical_contract()
    payload = _read_json()
    template = load_questionnaire()

    assert template.model_dump(exclude_none=True) == payload
    assert set(payload) == {"version", "title", "intro", "completion", "sections"}
    assert payload["version"] == "health-profile-v1"
    assert payload["title"] == "Профиль здоровья"
    assert payload["intro"] == expected["intro"]
    assert payload["completion"] == expected["completion"]
    assert len(payload["sections"]) == 10
    assert [len(section["questions"]) for section in payload["sections"]] == list(SECTION_COUNTS)
    assert sum(SECTION_COUNTS) == 46
    assert [section["title"] for section in payload["sections"]] == [
        section["title"] for section in expected["sections"]
    ]

    actual_questions = [
        question for section in payload["sections"] for question in section["questions"]
    ]
    assert len(actual_questions) == 46
    assert [question["source_number"] for question in actual_questions] == list(range(1, 47))
    assert [question["key"] for question in actual_questions] == list(EXPECTED_KEYS)

    for actual, canonical in zip(actual_questions, expected["questions"], strict=True):
        assert set(actual) <= QUESTION_FIELDS
        assert actual["source_number"] == canonical["source_number"]
        assert actual["label"] == canonical["label"]
        expected_type = TYPE_MAP[canonical["source_type"]]
        if canonical["source_number"] == 2:
            expected_type = "date_or_age"
        elif canonical["source_number"] in {3, 4}:
            expected_type = "number"
        assert actual["type"] == expected_type
        for field in ("helper", "options", "scale", "condition"):
            if field in canonical:
                assert actual[field] == canonical[field]
            else:
                assert field not in actual


def test_requiredness_conditions_and_comment_policy() -> None:
    questions = [
        question for section in _read_json()["sections"] for question in section["questions"]
    ]

    for question in questions:
        number = question["source_number"]
        assert question["required"] is (number <= 43 or number == 45)
        assert question["comment_enabled"] is (
            question["type"] in {"single_choice", "multi_choice", "scale"}
        )

    by_number = {question["source_number"]: question for question in questions}
    assert by_number[34]["condition"] == {"question_key": "gender", "equals": "Женский"}
    assert by_number[35]["condition"] == {"question_key": "gender", "equals": "Мужской"}
    assert by_number[46]["type"] == "document_upload"
    assert by_number[46]["required"] is False
    assert not {"options", "unit", "scale", "condition"} & by_number[46].keys()


def test_loader_rejects_duplicate_key() -> None:
    payload = _read_json()
    payload["sections"][0]["questions"][1]["key"] = payload["sections"][0]["questions"][0]["key"]

    with pytest.raises(ValidationError):
        _load_invalid_payload(payload)


def test_loader_rejects_malformed_type_specific_shape() -> None:
    payload = _read_json()
    payload["sections"][0]["questions"][0]["options"] = ["неожиданный вариант"]

    with pytest.raises(ValidationError):
        _load_invalid_payload(payload)
