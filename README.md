# Secure Web Authentication (FastAPI + Argon2id + SQLite)

A minimal full-stack registration/login app demonstrating secure password
storage and session handling.

```
Registration Page --> FastAPI --> Argon2id hash --> SQLite
Login Page        --> FastAPI --> Argon2id verify --> Login success/failure
```

## Stack

- **FastAPI** + Jinja2 server-rendered HTML (no separate frontend build)
- **SQLite** for storage (stdlib `sqlite3`, parameterized queries only)
- **argon2-cffi** for password hashing (Argon2id, the library default)
- **Starlette `SessionMiddleware`** for signed, HttpOnly session cookies

## Security notes

- Passwords are hashed with Argon2id (`time_cost=3`, `memory_cost=64MiB`,
  `parallelism=2`) and never stored or logged in plaintext.
- Login returns the same generic "Invalid username or password" message and
  always runs a hash verification (even for unknown usernames) to avoid
  leaking which part was wrong or timing-based user enumeration.
- A small in-memory lockout blocks a username after 5 failed attempts for 60
  seconds. This is a per-process demo only — back it with Redis or the
  database for a real deployment.
- Session cookie is signed (`itsdangerous` via `SessionMiddleware`),
  `HttpOnly`, `SameSite=Lax`. Set `HTTPS_ONLY=true` once you're serving over
  HTTPS (e.g. behind the Codespaces HTTPS proxy) to also mark it `Secure`.
- Set a stable `SESSION_SECRET` env var in real use; otherwise a random key
  is generated per process start and existing sessions are invalidated on
  restart.

## Run in GitHub Codespaces

1. Push this project to a GitHub repo and open it in a Codespace (or use
   "Open in Codespaces" from the repo page). The `.devcontainer/devcontainer.json`
   will install dependencies automatically.
2. Once the container is ready, start the app:

   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

3. Codespaces will prompt to open a forwarded-port preview on port 8000 —
   open it (or check the "Ports" tab) to reach the app in your browser.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Visit http://127.0.0.1:8000, register an account, then log in.

The SQLite file is created at `app/data/app.db` on first run.
