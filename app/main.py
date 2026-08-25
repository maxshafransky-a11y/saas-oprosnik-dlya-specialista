from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.access import (
    CONSENT_COOKIE_NAME,
    CONSENT_TEXT,
    CONSENT_TTL_SECONDS,
    find_active_workspace,
    issue_workspace_consent,
    verify_workspace_consent,
)
from app.answers import is_question_visible
from app.config import get_settings
from app.db import session_scope
from app.questionnaire import Question, load_questionnaire
from app.questionnaire_service import RevisionConflict, get_questionnaire_state, save_answers
from app.web_auth import (
    AuthenticatedRequest,
    build_csrf_token,
    require_authenticated_session,
    valid_csrf_token,
)

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

    def access_workspace(public_slug: str):
        with session_scope() as session:
            workspace = find_active_workspace(session, public_slug)
            if workspace is None:
                raise HTTPException(status_code=404, detail="invite not found")
            return SimpleNamespace(
                id=workspace.id,
                name=workspace.name,
                public_slug=workspace.public_slug,
            )

    def render_access(
        request: Request,
        workspace,
        *,
        mode: str,
        error: str | None = None,
        status_code: int = 200,
    ):
        return templates.TemplateResponse(
            request=request,
            name="access.html",
            context={
                "workspace_name": workspace.name,
                "public_slug": workspace.public_slug,
                "consent_text": CONSENT_TEXT,
                "mode": mode,
                "error": error,
            },
            status_code=status_code,
        )

    def secure_cookie() -> bool:
        return get_settings().app_env.strip().casefold() not in {"development", "test"}

    @application.get("/i/{public_slug}", name="invite")
    def invite(request: Request, public_slug: str):
        workspace = access_workspace(public_slug)
        return render_access(request, workspace, mode="consent")

    @application.post("/i/{public_slug}/consent", name="accept_consent")
    async def accept_consent(request: Request, public_slug: str):
        workspace = access_workspace(public_slug)
        if request.headers.get("origin") not in {None, str(request.base_url).rstrip("/")}:
            raise HTTPException(status_code=403, detail="invalid origin")
        form = await request.form()
        if form.get("consent") != "on":
            return render_access(
                request,
                workspace,
                mode="consent",
                error="Поставьте галочку, чтобы продолжить.",
                status_code=422,
            )
        token = issue_workspace_consent(
            get_settings().app_secret_key.get_secret_value(),
            workspace.id,
        )
        response = RedirectResponse(
            url=f"/i/{workspace.public_slug}/access",
            status_code=303,
        )
        response.set_cookie(
            CONSENT_COOKIE_NAME,
            token,
            max_age=CONSENT_TTL_SECONDS,
            secure=secure_cookie(),
            httponly=True,
            samesite="lax",
            path="/i",
        )
        return response

    @application.get("/i/{public_slug}/access", name="access")
    def access(request: Request, public_slug: str):
        workspace = access_workspace(public_slug)
        token = request.cookies.get(CONSENT_COOKIE_NAME)
        try:
            if not token:
                raise ValueError("missing consent")
            verify_workspace_consent(
                get_settings().app_secret_key.get_secret_value(),
                token,
                workspace.id,
            )
        except (TypeError, ValueError):
            return RedirectResponse(url=f"/i/{workspace.public_slug}", status_code=303)
        return render_access(request, workspace, mode="email")

    def section_index(template, section_key: str | None) -> int:
        if section_key is None:
            return 0
        index = next(
            (index for index, item in enumerate(template.sections) if item.key == section_key),
            None,
        )
        if index is None:
            raise HTTPException(status_code=404, detail="section not found")
        return index

    def form_text(value: object) -> str:
        return value if isinstance(value, str) else ""

    def form_value(question: Question, form) -> object:
        if question.type == "multi_choice":
            return [item for item in form.getlist(question.key) if isinstance(item, str)]
        raw = form_text(form.get(question.key))
        if question.type == "scale":
            try:
                return int(raw)
            except ValueError:
                return raw
        if question.type == "number":
            try:
                return int(raw) if raw.isdigit() else float(raw)
            except ValueError:
                return raw
        return raw

    def form_changes(section, state, form) -> dict[str, object]:
        changes: dict[str, object] = {}
        for question in section.questions:
            if question.type == "document_upload" or not is_question_visible(
                question, state.answers
            ):
                continue
            value = form_value(question, form)
            if (
                not question.required
                and question.type in {"text", "date_or_age", "textarea"}
                and not value
            ):
                changes[question.key] = None
                continue
            payload: dict[str, object] = {"value": value}
            if question.comment_enabled:
                payload["comment"] = form_text(form.get(f"{question.key}__comment"))
            changes[question.key] = payload
        return changes

    def render_questionnaire(
        request: Request,
        context: AuthenticatedRequest,
        requested_section: str | None,
    ):
        questionnaire_template = load_questionnaire()
        sections = questionnaire_template.sections
        state = get_questionnaire_state(
            context.session,
            workspace_id=context.principal.workspace_id,
            client_id=context.principal.client_id,
            template=questionnaire_template,
        )
        section = requested_section or state.current_section_key
        active_index = section_index(questionnaire_template, section)
        active_section = sections[active_index]
        question_count = sum(len(item.questions) for item in sections)
        completed_count = len(state.answers)
        view_state = SimpleNamespace(
            answers=state.answers,
            progress_percent=round(completed_count / question_count * 100),
            completed_count=completed_count,
            question_count=question_count,
            current_revision=state.current_revision,
        )
        return templates.TemplateResponse(
            request=request,
            name="questionnaire.html",
            context={
                "template": questionnaire_template,
                "active_section": active_section,
                "active_section_index": active_index + 1,
                "section_intro": questionnaire_template.intro,
                "state": view_state,
                "csrf_token": build_csrf_token(
                    context.principal.session_id,
                    get_settings().app_secret_key.get_secret_value(),
                ),
            },
        )

    @application.get("/questionnaire", name="questionnaire")
    def questionnaire(
        request: Request,
        section: str | None = None,
        context: AuthenticatedRequest = Depends(require_authenticated_session),  # noqa: B008
    ):
        return render_questionnaire(request, context, section)

    @application.get("/q/{section_key}", name="questionnaire_section")
    def questionnaire_section(
        request: Request,
        section_key: str,
        context: AuthenticatedRequest = Depends(require_authenticated_session),  # noqa: B008
    ):
        return render_questionnaire(request, context, section_key)

    async def save_questionnaire(
        request: Request,
        context: AuthenticatedRequest,
        requested_section: str | None,
    ):
        form = await request.form()
        if request.headers.get("origin") not in {None, str(request.base_url).rstrip("/")}:
            raise HTTPException(status_code=403, detail="invalid origin")
        if not valid_csrf_token(
            context.principal.session_id,
            form_text(form.get("csrf_token")),
            get_settings().app_secret_key.get_secret_value(),
        ):
            raise HTTPException(status_code=403, detail="invalid csrf token")

        form_section = form_text(form.get("section_key")) or None
        if requested_section is not None and form_section != requested_section:
            raise HTTPException(status_code=400, detail="section mismatch")
        template = load_questionnaire()
        state = get_questionnaire_state(
            context.session,
            workspace_id=context.principal.workspace_id,
            client_id=context.principal.client_id,
            template=template,
        )
        active_key = requested_section or form_section or state.current_section_key
        active_index = section_index(template, active_key)
        try:
            expected_revision = int(form_text(form.get("revision")))
            save_answers(
                context.session,
                workspace_id=context.principal.workspace_id,
                client_id=context.principal.client_id,
                template=template,
                section_key=template.sections[active_index].key,
                changes=form_changes(template.sections[active_index], state, form),
                expected_revision=expected_revision,
            )
        except RevisionConflict:
            raise HTTPException(
                status_code=409, detail="answers changed; reload and retry"
            ) from None
        except (TypeError, ValueError):
            raise HTTPException(status_code=422, detail="invalid answers") from None

        next_index = min(active_index + 1, len(template.sections) - 1)
        return RedirectResponse(
            url=f"/q/{template.sections[next_index].key}",
            status_code=303,
        )

    @application.post("/questionnaire", name="save_questionnaire")
    async def save_questionnaire_route(
        request: Request,
        section: str | None = None,
        context: AuthenticatedRequest = Depends(require_authenticated_session),  # noqa: B008
    ):
        return await save_questionnaire(request, context, section)

    @application.post("/q/{section_key}", name="save_questionnaire_section")
    async def save_questionnaire_section_route(
        request: Request,
        section_key: str,
        context: AuthenticatedRequest = Depends(require_authenticated_session),  # noqa: B008
    ):
        return await save_questionnaire(request, context, section_key)

    return application


app = create_app()
