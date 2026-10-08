"""SBOM 生成工具（对齐 M11）。"""
import json
from pathlib import Path

from langchain_core.tools import tool

from api.context import get_session_context


@tool
def write_sbom(packages: list[dict]) -> str:
    """把依赖清单写成 CycloneDX 格式的 sbom.json。"""
    session_dir = get_session_context() or "."
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {"type": "library", "name": p.get("name", ""), "version": p.get("version", "")}
            for p in packages
        ],
    }
    path = Path(session_dir) / "sbom.json"
    path.write_text(json.dumps(sbom, ensure_ascii=False, indent=2), encoding="utf-8")
    return f"SBOM 已生成：{path}"
