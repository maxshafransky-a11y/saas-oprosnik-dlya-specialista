from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parents[1]))

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from app.questionnaire import load_questionnaire


def _render() -> str:
    root = Path(__file__).parents[1]
    environment = Environment(
        loader=FileSystemLoader(root / "templates"),
        undefined=StrictUndefined,
        autoescape=True,
    )
    template = load_questionnaire()
    active_section = template.sections[4]
    state = SimpleNamespace(
        answers={},
        progress_percent=0,
        completed_count=0,
        question_count=46,
        current_revision=0,
    )
    return environment.get_template("questionnaire.html").render(
        template=template,
        active_section=active_section,
        active_section_index=5,
        section_intro="Расскажите о привычном рационе.",
        state=state,
        documents=[],
        csrf_token="test-csrf-token",
    )


def test_questionnaire_template_is_russian_semantic_and_wide() -> None:
    html = _render()
    css = (Path(__file__).parents[1] / "static" / "app.css").read_text(encoding="utf-8")

    assert '<html lang="ru">' in html
    assert 'id="main-content"' in html
    assert 'aria-label="Навигация по анкете"' in html
    assert html.count('class="question-card"') == 6
    assert 'type="radio"' in html
    assert 'name="cravings__comment"' in html
    assert "width: min(100%, 65rem)" in css
    assert "grid-template-columns: 1fr" in css
    assert "prefers-reduced-motion" in css


def test_questionnaire_template_uses_radio_not_multi_select_for_single_choice() -> None:
    html = _render()

    assert 'name="cravings"' in html
    assert 'type="checkbox" name="cravings"' not in html
