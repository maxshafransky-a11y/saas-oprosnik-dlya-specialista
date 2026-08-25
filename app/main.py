from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.questionnaire import load_questionnaire

ROOT = Path(__file__).parents[1]

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; base-uri 'self'; form-action 'self'; "
        "frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self'"
    ),
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


def create_app() -> FastAPI:
    application = FastAPI(
        title="Health Intake",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
    templates = Jinja2Templates(directory=ROOT / "templates")

    @application.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    @application.get("/health", include_in_schema=False)
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @application.get("/questionnaire", name="questionnaire")
    async def questionnaire(request: Request, section: str | None = None):
        questionnaire_template = load_questionnaire()
        sections = questionnaire_template.sections
        if section is None:
            active_index = 0
        else:
            active_index = next(
                (index for index, item in enumerate(sections) if item.key == section),
                None,
            )
            if active_index is None:
                raise HTTPException(status_code=404, detail="section not found")
        active_section = sections[active_index]
        state = SimpleNamespace(
            answers={},
            progress_percent=0,
            completed_count=0,
            question_count=46,
            current_revision=0,
        )
        return templates.TemplateResponse(
            request=request,
            name="questionnaire.html",
            context={
                "template": questionnaire_template,
                "active_section": active_section,
                "active_section_index": active_index + 1,
                "section_intro": questionnaire_template.intro,
                "state": state,
            },
        )

    return application


app = create_app()
