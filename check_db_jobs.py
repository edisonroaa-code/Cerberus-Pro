import psycopg
import os

db_url = "postgresql://postgres:xxpjcman@127.0.0.1:5432/postgres"

try:
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pid, status, kind, finished_at, error FROM jobs ORDER BY finished_at DESC NULLS FIRST LIMIT 10")
            rows = cur.fetchall()
            print(f"{'PID':<20} | {'Status':<10} | {'Kind':<10} | {'Finished At':<25} | {'Error'}")
            print("-" * 100)
            for row in rows:
                print(f"{str(row[0]):<20} | {str(row[1]):<10} | {str(row[2]):<10} | {str(row[3]):<25} | {str(row[4])}")
except Exception as e:
    print(f"Error connecting to database: {e}")
