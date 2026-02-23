"""
Database helpers for the iSH Flask server.
Import this module from flask_api.py or other server scripts.
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "leads.db")


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(db_path: str = DB_PATH):
    """Create all tables if they do not already exist."""
    conn = get_connection(db_path)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS leads (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            data      TEXT    NOT NULL,
            source    TEXT    NOT NULL DEFAULT 'unknown',
            timestamp TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            type      TEXT    NOT NULL,
            payload   TEXT,
            timestamp TEXT    NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()


def log_event(event_type: str, payload: str = "", db_path: str = DB_PATH):
    """Insert a generic event record."""
    import datetime

    conn = get_connection(db_path)
    conn.execute(
        "INSERT INTO events (type, payload, timestamp) VALUES (?, ?, ?)",
        (event_type, payload, datetime.datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_schema()
    print(f"Database initialised at {DB_PATH}")
