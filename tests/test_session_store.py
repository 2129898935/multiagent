"""M1 —— 会话元数据持久化单元测试。"""
import db.session_store as ss


def test_session_lifecycle(monkeypatch, tmp_path):
    monkeypatch.setattr(ss, "_db_path", tmp_path / "sessions.db")

    ss.create_session("t1", "alice")
    s = ss.get_session("t1")
    assert s["status"] == "pending"
    assert s["user_id"] == "alice"

    ss.update_session_status("t1", "running")
    assert ss.get_session("t1")["status"] == "running"

    ss.update_session_status("t1", "failed", "boom")
    s = ss.get_session("t1")
    assert s["status"] == "failed"
    assert s["error"] == "boom"
    assert s["finished_at"] is not None


def test_get_missing_returns_none(monkeypatch, tmp_path):
    monkeypatch.setattr(ss, "_db_path", tmp_path / "sessions.db")
    assert ss.get_session("nope") is None
