"""长期记忆召回层（M3）：新任务按 user_id 召回记忆，格式化成可注入 prompt 的文本。

MVP：按 user 取全部记忆（数量少，够用）；语义召回（embedding 相似度）留作进阶。
"""
from memory.store import list_memories

_TYPE_LABEL = {
    "USER_PREFERENCE": "偏好",
    "IGNORED_CVE": "忽略的CVE",
    "WHITELIST": "白名单",
    "DECISION": "决策",
}


def retrieve_memories(user_id: str, limit: int = 10) -> str:
    """召回指定用户的记忆，返回可注入 prompt 的文本（无记忆返回空串）。"""
    if not user_id:
        return ""
    memories = list_memories(user_id, limit=limit)
    if not memories:
        return ""
    lines = ["【用户长期记忆】"]
    for m in memories:
        label = _TYPE_LABEL.get(m["type"], m["type"])
        lines.append(f"- [{label}] {m['content']}")
    return "\n".join(lines)
