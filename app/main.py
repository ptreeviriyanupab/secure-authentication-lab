import os
import secrets
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app import database, security

BASE_DIR = Path(__file__).parent

app = FastAPI(title="Secure Web Authentication Demo")

SESSION_SECRET = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)
if not os.environ.get("SESSION_SECRET"):
    print(
        "[warning] SESSION_SECRET not set; using a random key for this run. "
        "Sessions will not survive a restart. Set SESSION_SECRET in your "
        "Codespaces/environment for stable sessions."
    )

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="session",
    same_site="lax",
    https_only=os.environ.get("HTTPS_ONLY", "false").lower() == "true",
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.on_event("startup")
def on_startup() -> None:
    database.init_db()


def current_user(request: Request) -> str | None:
    return request.session.get("username")


@app.get("/")
def root(request: Request):
    if current_user(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return RedirectResponse(url="/login", status_code=303)


@app.get("/register")
def register_form(request: Request):
    if current_user(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse(
        "register.html", {"request": request, "error": None, "username": ""}
    )


@app.post("/register")
def register_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    username = username.strip()

    error = security.validate_username(username)
    if not error:
        error = security.validate_password(password)
    if not error and password != confirm_password:
        error = "Passwords do not match."
    if not error and database.get_user_by_username(username) is not None:
        error = "That username is already taken."

    if error:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": error, "username": username},
            status_code=400,
        )

    password_hash = security.hash_password(password)
    database.create_user(username, password_hash)

    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": None,
            "info": "Account created successfully. Please log in.",
            "username": username,
        },
    )


@app.get("/login")
def login_form(request: Request):
    if current_user(request):
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse(
        "login.html", {"request": request, "error": None, "info": None, "username": ""}
    )


@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    username = username.strip()
    generic_error = "Invalid username or password."

    if security.is_locked_out(username):
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Too many failed attempts. Try again in a minute.",
                "info": None,
                "username": username,
            },
            status_code=429,
        )

    user = database.get_user_by_username(username)
    # Always run verify_password (even with a dummy hash) so response timing
    # doesn't reveal whether the username exists.
    stored_hash = user["password_hash"] if user else security.hash_password("dummy-password")
    valid = security.verify_password(stored_hash, password)

    if not user or not valid:
        security.record_failed_attempt(username)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": generic_error, "info": None, "username": username},
            status_code=401,
        )

    security.clear_failed_attempts(username)
    request.session.clear()
    request.session["username"] = user["username"]
    return RedirectResponse(url="/dashboard", status_code=303)


@app.get("/dashboard")
def dashboard(request: Request):
    username = current_user(request)
    if not username:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        "dashboard.html", {"request": request, "username": username}
    )


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)
