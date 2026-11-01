from __future__ import annotations

import sqlite3
from pathlib import Path

BASE_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS programs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    format TEXT,
    arch TEXT,
    bits INTEGER,
    endian TEXT,
    image_base TEXT,
    language TEXT,
    profile TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE (sha256, profile)
);

CREATE TABLE IF NOT EXISTS functions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    entry TEXT NOT NULL,
    name TEXT NOT NULL,
    namespace TEXT,
    signature TEXT,
    return_type TEXT,
    parameters_json TEXT NOT NULL DEFAULT '[]',
    size INTEGER,
    decompiled TEXT,
    callers_json TEXT NOT NULL DEFAULT '[]',
    callees_json TEXT NOT NULL DEFAULT '[]',
    strings_json TEXT NOT NULL DEFAULT '[]',
    xrefs_json TEXT NOT NULL DEFAULT '[]',
    is_external INTEGER NOT NULL DEFAULT 0,
    is_thunk INTEGER NOT NULL DEFAULT 0,
    decompilation_error TEXT,
    UNIQUE (program_id, entry)
);

CREATE INDEX IF NOT EXISTS idx_functions_program_name
    ON functions(program_id, name);
CREATE INDEX IF NOT EXISTS idx_functions_program_entry
    ON functions(program_id, entry);

CREATE TABLE IF NOT EXISTS exports (
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    address TEXT,
    ordinal INTEGER,
    UNIQUE (program_id, name, address)
);

CREATE TABLE IF NOT EXISTS imports (
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    library TEXT,
    address TEXT,
    UNIQUE (program_id, name, library, address)
);

CREATE TABLE IF NOT EXISTS strings (
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    value TEXT NOT NULL,
    encoding TEXT,
    UNIQUE (program_id, address, value)
);

CREATE INDEX IF NOT EXISTS idx_strings_program_value
    ON strings(program_id, value);

CREATE TABLE IF NOT EXISTS patch_plans (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    target_address TEXT,
    file_offset INTEGER NOT NULL,
    original_bytes TEXT NOT NULL,
    new_bytes TEXT NOT NULL,
    reason TEXT NOT NULL,
    authorization TEXT,
    profile TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    applied_at TEXT,
    patched_path TEXT,
    backup_path TEXT,
    plan_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_patch_plans_program
    ON patch_plans(program_id, created_at);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    program_id TEXT,
    question TEXT NOT NULL,
    answer TEXT,
    packet_json TEXT,
    warnings_json TEXT NOT NULL DEFAULT '[]',
    model TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    action TEXT NOT NULL,
    subject TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    actor TEXT NOT NULL DEFAULT 'local'
);
"""

FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS functions_fts USING fts5(
    name,
    signature,
    decompiled,
    content='functions',
    content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS functions_ai AFTER INSERT ON functions BEGIN
    INSERT INTO functions_fts(rowid, name, signature, decompiled)
    VALUES (new.id, new.name, new.signature, new.decompiled);
END;

CREATE TRIGGER IF NOT EXISTS functions_ad AFTER DELETE ON functions BEGIN
    INSERT INTO functions_fts(functions_fts, rowid, name, signature, decompiled)
    VALUES ('delete', old.id, old.name, old.signature, old.decompiled);
END;

CREATE TRIGGER IF NOT EXISTS functions_au AFTER UPDATE ON functions BEGIN
    INSERT INTO functions_fts(functions_fts, rowid, name, signature, decompiled)
    VALUES ('delete', old.id, old.name, old.signature, old.decompiled);
    INSERT INTO functions_fts(rowid, name, signature, decompiled)
    VALUES (new.id, new.name, new.signature, new.decompiled);
END;
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def init_db(db_path: str | Path) -> None:
    connection = connect(db_path)
    try:
        connection.executescript(BASE_SCHEMA)
        try:
            fts_exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='functions_fts'"
            ).fetchone()
            if not fts_exists:
                connection.executescript(FTS_SCHEMA)
        except sqlite3.OperationalError:
            # FTS5 is optional; searches fall back to LIKE.
            pass
        connection.commit()
    finally:
        connection.close()


def has_fts(connection: sqlite3.Connection) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='functions_fts'"
    ).fetchone()
    return row is not None
