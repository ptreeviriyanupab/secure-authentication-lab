# Secure Web Authentication (FastAPI + Argon2id + SQLite)

A deliberately minimal registration/login demo, designed to be typed and
run by students in a single 1-hour class session. No CSS, no HTML
templates, no sessions/cookies -- just three plain Python files.

```
Registration Page --> FastAPI --> Argon2id hash --> SQLite
Login Page        --> FastAPI --> Argon2id verify --> Login success/failure
```

## Files

- **security.py** -- `hash_password()` / `verify_password()`, using
  Argon2id. This is the same standalone password-hashing script students
  write and test on their own (with `input()`/`print()`) *before* this
  class -- reused here as-is, just imported instead of run directly.
- **database.py** -- three small functions (`init_db`, `create_user`,
  `get_user`) using the stdlib `sqlite3` module. All queries are
  parameterized (`?` placeholders) to avoid SQL injection.
- **main.py** -- the FastAPI app. Each route returns a plain HTML string
  directly (via `HTMLResponse`) -- no Jinja2, no template files, no CSS.

## What's intentionally left out (for time, not by best practice)

This is a teaching example for the *hashing + verification* flow, not a
production auth system. It has no session cookies, no login-protected
pages, no rate limiting, and no styling. For a real application you would
add session management (e.g. `starlette.middleware.sessions`), CSRF
protection, and login throttling.

## Run locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

Visit http://127.0.0.1:8000, register an account, then log in with the
same username/password.

## Run in GitHub Codespaces

1. Open this repo in a Codespace (`.devcontainer/devcontainer.json`
   installs dependencies automatically).
2. Start the app:

   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

3. Open the forwarded port 8000 from the **Ports** tab.

`users.db` is created automatically in the project root on first run.
