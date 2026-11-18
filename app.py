from flask import Flask
from database.db import init_app, get_db

app = Flask(__name__)

init_app(app)

@app.route("/db-test")
def db_test():
    db = get_db()

    tables = db.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        AND name NOT LIKE 'sqlite_%'
        ORDER BY name
    """).fetchall()

    return {
        "status": "connected",
        "tables": [table["name"] for table in tables],
        "total_tables": len(tables)
    }