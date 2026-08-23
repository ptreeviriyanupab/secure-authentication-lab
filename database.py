import sqlite3

DB_NAME = "users.db"


# ---------------------------------------------------------
# Create the users table if it doesn't exist yet
# ---------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------
# Insert a new user (username, Argon2id password hash)
# ---------------------------------------------------------
# Raises sqlite3.IntegrityError if the username already exists,
# because "username" has a UNIQUE constraint.
def create_user(username: str, password_hash: str):
    conn = sqlite3.connect(DB_NAME)
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------
# Look up a user by username
# ---------------------------------------------------------
# Returns (username, password_hash) or None if not found.
def get_user(username: str):
    conn = sqlite3.connect(DB_NAME)
    row = conn.execute(
        "SELECT username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()
    return row
