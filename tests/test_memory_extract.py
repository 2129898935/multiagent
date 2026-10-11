"""M3 —— 记忆提取的 JSON 解析单元测试（不依赖 LLM）。"""
from memory.extract import _parse_memories


def test_parse_valid_json():
    assert _parse_memories('[{"type": "USER_PREFERENCE", "content": "保守升级"}]') == [
        {"type": "USER_PREFERENCE", "content": "保守升级"}
    ]


def test_parse_markdown_wrapped():
    assert _parse_memories('```json\n[{"type": "DECISION", "content": "升级到2.32"}]\n```') == [
        {"type": "DECISION", "content": "升级到2.32"}
    ]


def test_parse_empty_array():
    assert _parse_memories("[]") == []


def test_parse_invalid_type_filtered():
    assert _parse_memories('[{"type": "RANDOM", "content": "x"}]') == []


def test_parse_plain_text():
    assert _parse_memories("没有值得记的") == []


def test_parse_ignores_empty_content():
    assert _parse_memories('[{"type": "WHITELIST", "content": ""}]') == []
