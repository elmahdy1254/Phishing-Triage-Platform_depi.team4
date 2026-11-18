
import sqlite3
from pathlib import Path

from flask import current_app, g


def get_db():
    """Get a database connection for the current Flask request."""

    if "db" not in g:
        db_path = current_app.config["DATABASE"]

        g.db = sqlite3.connect(
            db_path,
            timeout=10
        )

        # Return rows as dictionaries-like objects
        g.db.row_factory = sqlite3.Row

        # Enable foreign key constraints
        g.db.execute("PRAGMA foreign_keys = ON")

    return g.db


def close_db(error=None):
    """Close the database connection after the request."""

    db = g.pop("db", None)

    if db is not None:
        db.close()


def init_app(app):
    """Configure the database for the Flask application."""

    project_root = Path(app.root_path)

    app.config["DATABASE"] = str(
        project_root / "database" / "phishing_triage.db"
    )

    app.teardown_appcontext(close_db)
