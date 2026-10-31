"""SQLite database layer for CloudLeak AI (stdlib only)."""
import hashlib
import os
import secrets
import sqlite3
import time

DB_PATH = os.environ.get("CLOUDLEAK_DB", os.path.join(os.path.dirname(__file__), "cloudleak.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS organizations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS org_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'viewer',
  created_at INTEGER NOT NULL,
  UNIQUE(org_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON org_members(user_id);
CREATE TABLE IF NOT EXISTS workspaces (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  org_id INTEGER REFERENCES organizations(id),
  workspace_id INTEGER,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id),
  workspace_id INTEGER,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft',
  created_at INTEGER NOT NULL,
  completed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_audits_org ON audits(org_id);
CREATE TABLE IF NOT EXISTS uploaded_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  file_type TEXT NOT NULL,
  content TEXT NOT NULL,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_audit ON uploaded_files(audit_id);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  file_id INTEGER REFERENCES uploaded_files(id) ON DELETE SET NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  evidence_file TEXT,
  evidence_line INTEGER,
  evidence_snippet TEXT,
  recommendation TEXT NOT NULL,
  estimated_monthly_waste REAL,
  waste_illustrative INTEGER NOT NULL DEFAULT 0,
  confidence REAL NOT NULL DEFAULT 0.7,
  status TEXT NOT NULL DEFAULT 'open',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(org_id);
CREATE INDEX IF NOT EXISTS idx_findings_audit ON findings(audit_id);
CREATE TABLE IF NOT EXISTS remediation_plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  action_level TEXT NOT NULL,
  root_cause TEXT NOT NULL,
  recommended_action TEXT NOT NULL,
  original_config TEXT,
  proposed_config TEXT,
  expected_monthly_savings REAL,
  security_improvement TEXT,
  complexity TEXT,
  side_effects TEXT,
  rollback_instructions TEXT,
  confidence REAL NOT NULL DEFAULT 0.7,
  status TEXT NOT NULL DEFAULT 'proposed',
  source TEXT NOT NULL DEFAULT 'deterministic',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_remediation_org ON remediation_plans(org_id);
CREATE TABLE IF NOT EXISTS cloud_resources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  service TEXT NOT NULL,
  resource_name TEXT NOT NULL,
  region TEXT,
  category TEXT NOT NULL,
  monthly_cost REAL NOT NULL,
  potential_savings REAL NOT NULL DEFAULT 0,
  is_demo INTEGER NOT NULL DEFAULT 0,
  note TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_resources_org ON cloud_resources(org_id);
CREATE TABLE IF NOT EXISTS ai_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL,
  prompt TEXT NOT NULL,
  response TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  is_read INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
"""


def now() -> int:
    return int(time.time())


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120_000).hex()
    return digest, salt


def verify_password(password: str, salt: str, expected: str) -> bool:
    digest, _ = hash_password(password, salt)
    return secrets.compare_digest(digest, expected)


def row2dict(row: sqlite3.Row) -> dict:
    return {k: row[k] for k in row.keys()}
