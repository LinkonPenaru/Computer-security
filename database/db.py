"""
database/db.py
==============
SQLite database — schema creation, connection management, and raw-query helpers.

Tables
------
  hospital_keys   : per-hospital AES and HMAC-SHA256 keys (prototype storage)
  users           : 20 simulated system actors
  system_patients : 6 patient actors who can manage their own consent
  consent_policies: fine-grained (patient × hospital × role) consent records
  ehr_records     : encrypted EHR records — NO plaintext content stored
  search_index    : HMAC-protected keyword token → record_id mappings
  audit_log       : timestamped event log
"""

import sqlite3
import os
import sys

# Resolve project root so this module works when run directly
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config.settings import DATABASE_PATH


# ─── Connection ────────────────────────────────────────────────────────────────

def get_connection() -> sqlite3.Connection:
    """
    Open and return a SQLite connection.
    Row factory is set so rows can be accessed as dicts.
    """
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # better concurrency
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ─── Schema ────────────────────────────────────────────────────────────────────

SCHEMA = """
-- Hospital cryptographic keys (60% prototype: stored in DB)
-- Future 40%: replaced by MPC / Shamir secret sharing
CREATE TABLE IF NOT EXISTS hospital_keys (
    hospital_id   TEXT PRIMARY KEY,
    ehr_key_b64   TEXT NOT NULL,
    search_key_b64 TEXT NOT NULL,
    created_at    TEXT DEFAULT (datetime('now'))
);

-- System actors: ~20 simulated users
CREATE TABLE IF NOT EXISTS users (
    user_id    TEXT PRIMARY KEY,
    user_hash  TEXT NOT NULL UNIQUE,   -- SHA-256(user_id) — used in cloud layer
    full_name  TEXT,
    role       TEXT NOT NULL,          -- Doctor | Nurse | Researcher | Patient
    hospital_id TEXT NOT NULL,         -- Hospital_A | Hospital_B | Hospital_C
    status     TEXT DEFAULT 'ACTIVE',  -- ACTIVE | INACTIVE
    created_at TEXT DEFAULT (datetime('now'))
);

-- Patient actors who manage their own consent (distinct from 10k MIMIC records)
CREATE TABLE IF NOT EXISTS system_patients (
    patient_id       TEXT PRIMARY KEY,   -- PATIENT_001 … PATIENT_006
    patient_hash     TEXT NOT NULL UNIQUE, -- SHA-256(patient_id)
    assigned_hospital TEXT NOT NULL,
    created_at       TEXT DEFAULT (datetime('now'))
);

-- Consent policies: (patient × hospital × role) granularity
CREATE TABLE IF NOT EXISTS consent_policies (
    policy_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_hash   TEXT    NOT NULL,
    hospital_id    TEXT    NOT NULL,
    role           TEXT    NOT NULL DEFAULT 'Doctor',
    access_granted INTEGER NOT NULL DEFAULT 1,   -- 1=granted, 0=revoked
    valid_from     TEXT    DEFAULT (datetime('now')),
    valid_until    TEXT,                         -- NULL means no expiry
    status         TEXT    DEFAULT 'ACTIVE',     -- ACTIVE | REVOKED
    updated_at     TEXT    DEFAULT (datetime('now')),
    UNIQUE(patient_hash, hospital_id, role)
);

-- EHR cloud storage — NEVER contains plaintext EHR content
CREATE TABLE IF NOT EXISTS ehr_records (
    record_id      TEXT PRIMARY KEY,
    patient_hash   TEXT NOT NULL,   -- SHA-256 of patient_id
    hospital_id    TEXT NOT NULL,
    encrypted_ehr  TEXT NOT NULL,   -- base64 AES-256-GCM ciphertext
    nonce          TEXT NOT NULL,   -- base64 nonce
    tag            TEXT NOT NULL,   -- base64 GCM authentication tag
    admit_date     TEXT,
    discharge_date TEXT,
    department     TEXT DEFAULT 'General',
    sensitivity    TEXT DEFAULT 'Confidential',
    keyword_count  INTEGER DEFAULT 0,
    created_at     TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ehr_patient  ON ehr_records(patient_hash);
CREATE INDEX IF NOT EXISTS idx_ehr_hospital ON ehr_records(hospital_id);

-- Protected search index: HMAC token → record mapping
CREATE TABLE IF NOT EXISTS search_index (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    hospital_id  TEXT NOT NULL,
    search_token TEXT NOT NULL,   -- HMAC-SHA256(search_key, keyword)
    record_id    TEXT NOT NULL,
    FOREIGN KEY (record_id) REFERENCES ehr_records(record_id)
);
CREATE INDEX IF NOT EXISTS idx_search_token ON search_index(hospital_id, search_token);

-- Audit / event log
CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    DEFAULT (datetime('now')),
    event_type   TEXT    NOT NULL,
    user_id      TEXT,
    patient_hash TEXT,
    details      TEXT,
    success      INTEGER DEFAULT 1   -- 1=success, 0=failure
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp DESC);

-- ── 40% Extension Tables ─────────────────────────────────────────────────────

-- MPC Shamir (2,3) sessions — stores per-session shares
CREATE TABLE IF NOT EXISTS mpc_sessions (
    session_id     TEXT PRIMARY KEY,
    created_at     TEXT DEFAULT (datetime('now')),
    secret_hash    TEXT NOT NULL,          -- SHA-256 of secret (for verification only)
    share_a_x      INTEGER,               -- x-coordinate for Hospital_A
    share_a_y_hex  TEXT,                  -- y value as hex
    share_b_x      INTEGER,
    share_b_y_hex  TEXT,
    share_c_x      INTEGER,
    share_c_y_hex  TEXT,
    prime_hex      TEXT,
    threshold      INTEGER DEFAULT 2,
    n_shares       INTEGER DEFAULT 3,
    purpose        TEXT DEFAULT 'key_derivation',
    notes          TEXT
);

-- Delegation tokens — HMAC-SHA256-signed time-limited access grants
CREATE TABLE IF NOT EXISTS delegation_tokens (
    token_id      TEXT PRIMARY KEY,        -- delegation_id UUID
    delegator     TEXT NOT NULL,           -- user granting access
    delegatee     TEXT NOT NULL,           -- user receiving access
    patient_id    TEXT NOT NULL,
    hospital_id   TEXT NOT NULL,
    role          TEXT NOT NULL,
    scope         TEXT DEFAULT 'search',   -- 'search' | 'decrypt' | 'all'
    issued_at     TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    full_token_json TEXT NOT NULL,         -- full signed token serialised as JSON
    revoked       INTEGER DEFAULT 0,       -- 1 = manually revoked
    created_at    TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_del_delegatee  ON delegation_tokens(delegatee);
CREATE INDEX IF NOT EXISTS idx_del_patient    ON delegation_tokens(patient_id);
CREATE INDEX IF NOT EXISTS idx_del_expires    ON delegation_tokens(expires_at);

-- Protected policy representations — HMAC commitments of policy attributes
CREATE TABLE IF NOT EXISTS protected_policies (
    policy_id           TEXT PRIMARY KEY,
    patient_id          TEXT NOT NULL,      -- logical patient id (app-side only)
    protected_hospital  TEXT NOT NULL,      -- HMAC(K_policy, hospital_id)
    protected_role      TEXT NOT NULL,      -- HMAC(K_policy, role)
    protected_status    TEXT NOT NULL,      -- HMAC(K_policy, status)
    protected_patient   TEXT NOT NULL,      -- HMAC(K_policy, patient_id)
    created_at          TEXT DEFAULT (datetime('now')),
    updated_at          TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_pp_patient ON protected_policies(patient_id);
"""


def init_db():
    """Create all tables if they don't exist yet."""
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


# ─── Generic helpers ───────────────────────────────────────────────────────────

def fetchall(sql: str, params: tuple = ()) -> list:
    """Execute a SELECT and return all rows as list-of-dicts."""
    conn = get_connection()
    try:
        cur = conn.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def fetchone(sql: str, params: tuple = ()) -> dict | None:
    """Execute a SELECT and return the first row as a dict, or None."""
    conn = get_connection()
    try:
        cur = conn.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def execute(sql: str, params: tuple = ()) -> int:
    """Execute an INSERT/UPDATE/DELETE. Returns lastrowid."""
    conn = get_connection()
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def executemany(sql: str, params_list: list):
    """Execute a batch INSERT/UPDATE."""
    conn = get_connection()
    try:
        conn.executemany(sql, params_list)
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Database initialised at: {DATABASE_PATH}")
