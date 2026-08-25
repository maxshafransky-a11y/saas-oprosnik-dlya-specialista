import json
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

QuestionType = Literal[
    "text",
    "textarea",
    "number",
    "date_or_age",
    "single_choice",
    "multi_choice",
    "scale",
    "document_upload",
]
CHOICE_TYPES = {"single_choice", "multi_choice"}
COMMENT_TYPES = CHOICE_TYPES | {"scale"}
SECTION_COUNTS = (7, 3, 2, 6, 6, 4, 5, 3, 5, 5)
INTRO = (
    "Добро пожаловать! Пожалуйста, отвечайте честно, всё конфиденциально. "
    "После каждого вопроса есть варианты для вашего удобства."
)
COMPLETION = (
    "Спасибо за ваши ответы! Всё используется только для персональных рекомендаций. "
    "Я свяжусь с вами для обсуждения вашей стратегии!"
)

TEMPLATE_PATH = Path(__file__).with_name("questionnaire_v1.json")


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question_key: StrictStr
    equals: StrictStr


class Scale(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min: StrictInt
    max: StrictInt

    @model_validator(mode="after")
    def validate_range(self) -> "Scale":
        if self.min >= self.max:
            raise ValueError("scale min must be less than max")
        return self


class Question(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_number: StrictInt
    key: StrictStr
    type: QuestionType
    label: StrictStr
    helper: StrictStr | None = None
    required: StrictBool
    options: list[StrictStr] | None = None
    unit: StrictStr | None = None
    scale: Scale | None = None
    condition: Condition | None = None
    comment_enabled: StrictBool

    @field_validator("key", "label")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("text fields must not be empty")
        return value

    @field_validator("options")
    @classmethod
    def validate_options(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        if not value or any(not option.strip() for option in value):
            raise ValueError("options must be non-empty")
        if len(value) != len(set(value)):
            raise ValueError("options must be unique")
        return value

    @model_validator(mode="after")
    def validate_shape(self) -> "Question":
        if self.type in CHOICE_TYPES:
            if self.options is None:
                raise ValueError("choice questions require options")
        elif self.options is not None:
            raise ValueError("options are only valid for choice questions")

        if self.type == "scale":
            if self.scale is None:
                raise ValueError("scale questions require scale")
        elif self.scale is not None:
            raise ValueError("scale is only valid for scale questions")

        if self.type == "number":
            if self.source_number not in {3, 4}:
                raise ValueError("number is only valid for questions 3 and 4")
            expected_unit = {3: "см", 4: "кг"}[self.source_number]
            if self.unit != expected_unit:
                raise ValueError("height and weight units are fixed")
        elif self.unit is not None:
            raise ValueError("unit is only valid for number questions")

        if self.source_number == 2 and self.type != "date_or_age":
            raise ValueError("question 2 must be date_or_age")
        if self.source_number in {3, 4} and self.type != "number":
            raise ValueError("questions 3 and 4 must be number")
        if self.source_number in {31, 42}:
            expected_scale = {31: (0, 10), 42: (1, 10)}[self.source_number]
            if self.type != "scale" or (self.scale.min, self.scale.max) != expected_scale:
                raise ValueError("scale range is fixed")
        elif self.type == "scale":
            raise ValueError("scale is only valid for questions 31 and 42")

        expected_required = self.source_number <= 43 or self.source_number == 45
        if self.required is not expected_required:
            raise ValueError("requiredness does not match questionnaire policy")
        if self.comment_enabled is not (self.type in COMMENT_TYPES):
            raise ValueError("comment policy does not match question type")

        expected_condition = {
            34: Condition(question_key="gender", equals="Женский"),
            35: Condition(question_key="gender", equals="Мужской"),
        }.get(self.source_number)
        if self.condition != expected_condition:
            raise ValueError("condition does not match questionnaire policy")

        if self.source_number == 46 and self.type != "document_upload":
            raise ValueError("question 46 must be document_upload")
        if self.type == "document_upload" and self.source_number != 46:
            raise ValueError("document_upload is only valid for question 46")
        return self


class Section(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: StrictStr
    title: StrictStr
    questions: list[Question]

    @field_validator("key", "title")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("section text fields must not be empty")
        return value


class QuestionnaireTemplate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: StrictStr
    title: StrictStr
    intro: StrictStr
    completion: StrictStr
    sections: list[Section]

    @model_validator(mode="after")
    def validate_contract(self) -> "QuestionnaireTemplate":
        if self.version != "health-profile-v1":
            raise ValueError("unsupported questionnaire version")
        if self.title != "Профиль здоровья":
            raise ValueError("questionnaire title is fixed")
        if self.intro != INTRO or self.completion != COMPLETION:
            raise ValueError("questionnaire texts are fixed")
        if len(self.sections) != 10:
            raise ValueError("questionnaire must have exactly 10 sections")
        if tuple(len(section.questions) for section in self.sections) != SECTION_COUNTS:
            raise ValueError("section question counts do not match questionnaire policy")
        section_keys = [section.key for section in self.sections]
        if len(section_keys) != len(set(section_keys)):
            raise ValueError("section keys must be unique")

        questions = [question for section in self.sections for question in section.questions]
        if len(questions) != 46:
            raise ValueError("questionnaire must have exactly 46 questions")
        source_numbers = [question.source_number for question in questions]
        if source_numbers != list(range(1, 47)):
            raise ValueError("source numbers must be the sequence 1..46")
        keys = [question.key for question in questions]
        if len(keys) != len(set(keys)):
            raise ValueError("question keys must be unique")
        return self


def load_questionnaire(path: Path = TEMPLATE_PATH) -> QuestionnaireTemplate:
    with Path(path).open(encoding="utf-8") as file:
        return QuestionnaireTemplate.model_validate(json.load(file))
