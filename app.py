from flask import Flask, render_template
from database.db import init_app, get_db

app = Flask(__name__)

init_app(app)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze")
def analyze():
    return render_template("analyze.html")


@app.route("/history")
def history():
    return render_template("history.html")


@app.route("/report")
def report():
    return render_template("report.html")


@app.route("/settings")
def settings():
    return render_template("settings.html")


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


@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(debug=True)
