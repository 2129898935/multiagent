"""M3 —— 长期记忆存储/召回单元测试。"""
import memory.store as ms
from memory.retrieve import retrieve_memories


def test_add_and_list_by_user(monkeypatch, tmp_path):
    monkeypatch.setattr(ms, "_db_path", tmp_path / "memories.db")
    ms.add_memory("alice", "USER_PREFERENCE", "偏好保守升级")
    ms.add_memory("alice", "IGNORED_CVE", "CVE-2020-1234 是误报")
    ms.add_memory("bob", "WHITELIST", "requests")

    alice = ms.list_memories("alice")
    assert len(alice) == 2
    assert {m["type"] for m in alice} == {"USER_PREFERENCE", "IGNORED_CVE"}

    bob = ms.list_memories("bob")
    assert len(bob) == 1
    assert bob[0]["content"] == "requests"


def test_duplicate_not_inserted(monkeypatch, tmp_path):
    monkeypatch.setattr(ms, "_db_path", tmp_path / "memories.db")
    ms.add_memory("alice", "USER_PREFERENCE", "保守升级")
    ms.add_memory("alice", "USER_PREFERENCE", "保守升级")  # 重复
    assert len(ms.list_memories("alice")) == 1  # 不重复插入，只刷新时间戳


def test_delete(monkeypatch, tmp_path):
    monkeypatch.setattr(ms, "_db_path", tmp_path / "memories.db")
    ms.add_memory("alice", "DECISION", "升级到 requests 2.32")
    m = ms.list_memories("alice")[0]
    ms.delete_memory(m["id"])
    assert ms.list_memories("alice") == []


def test_filter_by_type(monkeypatch, tmp_path):
    monkeypatch.setattr(ms, "_db_path", tmp_path / "memories.db")
    ms.add_memory("alice", "USER_PREFERENCE", "保守升级")
    ms.add_memory("alice", "IGNORED_CVE", "CVE-1")
    prefs = ms.list_memories("alice", type_="USER_PREFERENCE")
    assert len(prefs) == 1
    assert prefs[0]["content"] == "保守升级"


def test_retrieve_formats(monkeypatch, tmp_path):
    monkeypatch.setattr(ms, "_db_path", tmp_path / "memories.db")
    ms.add_memory("alice", "USER_PREFERENCE", "偏好保守升级")
    text = retrieve_memories("alice")
    assert "【用户长期记忆】" in text
    assert "保守升级" in text


def test_retrieve_empty():
    assert retrieve_memories("nobody") == ""
    assert retrieve_memories("") == ""
