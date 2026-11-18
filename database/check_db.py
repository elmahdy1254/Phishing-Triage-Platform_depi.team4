
import sqlite3

conn = sqlite3.connect("database/phishing_triage.db")

query = """
SELECT name
FROM sqlite_master
WHERE type = 'table'
AND name NOT LIKE 'sqlite_%'
ORDER BY name;
"""

tables = conn.execute(query).fetchall()

print("Database Tables:")
for table in tables:
    print(f"- {table[0]}")

print(f"\nTotal tables: {len(tables)}")

conn.close()
