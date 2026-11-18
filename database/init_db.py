from pathlib import Path
import sqlite3

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = DATABASE_DIR / "phishing_triage.db"
SCHEMA_PATH = DATABASE_DIR / "schema.sql"

def initialize_database():
    DATABASE_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    try:
        connection.execute("PRAGMA foreign_keys = ON;")
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        connection.executescript(schema)
        connection.commit()
        print(f"Database initialized successfully: {DATABASE_PATH}")
    finally:
        connection.close()

if __name__ == "__main__":
    initialize_database()
