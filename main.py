import sqlite3
from html import escape

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse

import database
import security

app = FastAPI()


@app.on_event("startup")
def on_startup():
    database.init_db()


# ---------------------------------------------------------
# Home page: links to Register and Login
# ---------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <h1>Secure Web Authentication Demo</h1>
    <p><a href="/register">Register</a> | <a href="/login">Login</a></p>
    """


# ---------------------------------------------------------
# Registration
# ---------------------------------------------------------
@app.get("/register", response_class=HTMLResponse)
def register_form():
    return """
    <h1>Register</h1>
    <form method="post" action="/register">
        Username: <input type="text" name="username"><br><br>
        Password: <input type="password" name="password"><br><br>
        Confirm Password: <input type="password" name="confirm_password"><br><br>
        <input type="submit" value="Register">
    </form>
    <p><a href="/login">Already have an account? Log in</a></p>
    """


@app.post("/register", response_class=HTMLResponse)
def register(
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    if password != confirm_password:
        return """
        <p>Passwords do not match.</p>
        <p><a href="/register">Try again</a></p>
        """

    # Argon2id hashing happens here -- only the hash is ever stored.
    password_hash = security.hash_password(password)

    try:
        database.create_user(username, password_hash)
    except sqlite3.IntegrityError:
        return f"""
        <p>Username "{escape(username)}" is already taken.</p>
        <p><a href="/register">Try again</a></p>
        """

    return f"""
    <p>User "{escape(username)}" registered successfully.</p>
    <p><a href="/login">Go to Login</a></p>
    """


# ---------------------------------------------------------
# Login
# ---------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
def login_form():
    return """
    <h1>Login</h1>
    <form method="post" action="/login">
        Username: <input type="text" name="username"><br><br>
        Password: <input type="password" name="password"><br><br>
        <input type="submit" value="Login">
    </form>
    <p><a href="/register">Need an account? Register</a></p>
    """


@app.post("/login", response_class=HTMLResponse)
def login(username: str = Form(...), password: str = Form(...)):
    user = database.get_user(username)

    if user is None:
        return """
        <p>Login failed: incorrect username or password.</p>
        <p><a href="/login">Try again</a></p>
        """

    stored_username, stored_hash = user

    # Argon2id verification happens here -- the plaintext password
    # is never stored, only compared against the saved hash.
    if security.verify_password(password, stored_hash):
        return f"<p>Login successful. Welcome, {escape(stored_username)}!</p>"

    return """
    <p>Login failed: incorrect username or password.</p>
    <p><a href="/login">Try again</a></p>
    """
