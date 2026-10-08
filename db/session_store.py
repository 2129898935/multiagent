"""会话元数据持久化（对齐 M1）：把散落的会话信息收口到 sessions 表。"""
import sqlite3
from datetime import datetime
from pathlib import Path

_db_path = Path(__file__).parents[1] / "data" / "sessions.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    repo_url TEXT,
    status TEXT DEFAULT 'pending',   -- pending/running/done/failed
    created_at TEXT,
    finished_at TEXT,
    error TEXT,
    token_usage INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0
)
"""


def _conn() -> sqlite3.Connection:
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_db_path))
    conn.execute(_SCHEMA)
    return conn


def create_session(thread_id: str, user_id: str, repo_url: str | None = None) -> None:
    """任务开始时写入 pending 记录。"""
    conn = _conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO sessions (id, user_id, repo_url, status, created_at) "
            "VALUES (?, ?, ?, 'pending', ?)",
            (thread_id, user_id, repo_url, datetime.now().isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def update_session_status(thread_id: str, status: str, error: str | None = None) -> None:
    """更新会话状态（running/done/failed），完成时写 finished_at。"""
    conn = _conn()
    try:
        finished = datetime.now().isoformat() if status in ("done", "failed") else None
        conn.execute(
            "UPDATE sessions SET status=?, error=?, finished_at=COALESCE(?, finished_at) WHERE id=?",
            (status, error, finished, thread_id),
        )
        conn.commit()
    finally:
        conn.close()


def get_session(thread_id: str):
    """查询单个会话。"""
    conn = _conn()
    try:
        row = conn.execute("SELECT * FROM sessions WHERE id=?", (thread_id,)).fetchone()
        if not row:
            return None
        cols = [d[0] for d in conn.execute("SELECT * FROM sessions LIMIT 0").description]
        return dict(zip(cols, row))
    finally:
        conn.close()
