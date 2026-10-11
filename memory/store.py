"""长期记忆存储层（M3）：SQLite CRUD，按 user_id 隔离。

冲突处理：同 user + 同 type + 同 content 的重复记忆，只刷新 updated_at（时间戳新覆盖旧）。
"""
import sqlite3
from datetime import datetime
from pathlib import Path


class MemoryType:
    USER_PREFERENCE = "USER_PREFERENCE"  # 用户偏好（如保守升级）
    IGNORED_CVE = "IGNORED_CVE"          # 用户判定的误报 CVE
    WHITELIST = "WHITELIST"              # 白名单包
    DECISION = "DECISION"                # 历史升级决策


_db_path = Path(__file__).parents[1] / "data" / "memories.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT,
    updated_at TEXT
)
"""


def _conn() -> sqlite3.Connection:
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_db_path))
    conn.execute(_SCHEMA)
    return conn


def add_memory(user_id: str, type_: str, content: str) -> None:
    """写入一条记忆；若 (user_id, type, content) 已存在，则只刷新 updated_at。"""
    content = content.strip()
    if not content:
        return
    now = datetime.now().isoformat()
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT id FROM memories WHERE user_id=? AND type=? AND content=?",
            (user_id, type_, content),
        ).fetchone()
        if row:
            conn.execute("UPDATE memories SET updated_at=? WHERE id=?", (now, row[0]))
        else:
            conn.execute(
                "INSERT INTO memories (user_id, type, content, created_at, updated_at) VALUES (?,?,?,?,?)",
                (user_id, type_, content, now, now),
            )
        conn.commit()
    finally:
        conn.close()


def list_memories(user_id: str, type_: str | None = None, limit: int = 20) -> list[dict]:
    """按 user 召回记忆（可选按类型过滤），按更新时间倒序。"""
    conn = _conn()
    try:
        if type_:
            rows = conn.execute(
                "SELECT id, user_id, type, content, created_at, updated_at FROM memories "
                "WHERE user_id=? AND type=? ORDER BY updated_at DESC LIMIT ?",
                (user_id, type_, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, user_id, type, content, created_at, updated_at FROM memories "
                "WHERE user_id=? ORDER BY updated_at DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
        keys = ["id", "user_id", "type", "content", "created_at", "updated_at"]
        return [dict(zip(keys, r)) for r in rows]
    finally:
        conn.close()


def delete_memory(memory_id: int) -> None:
    """删除一条记忆。"""
    conn = _conn()
    try:
        conn.execute("DELETE FROM memories WHERE id=?", (memory_id,))
        conn.commit()
    finally:
        conn.close()
