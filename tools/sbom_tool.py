"""CycloneDX SBOM 生成工具。"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from langchain_core.tools import tool

from api.context import get_session_context


def _purl(package: dict) -> str | None:
    name = str(package.get("name") or "").strip()
    version = str(package.get("version") or "").strip()
    if not name:
        return None
    ecosystem = str(package.get("ecosystem") or "PyPI").lower()
    purl_type = {"pypi": "pypi", "npm": "npm", "maven": "maven", "go": "golang"}.get(ecosystem)
    if not purl_type:
        return None
    value = f"pkg:{purl_type}/{quote(name, safe='@:/')}"
    if version:
        value += f"@{quote(version, safe='.+-_')}"
    return value


def build_sbom(packages: list[dict]) -> dict:
    """构造可验证的 CycloneDX 1.6 JSON 对象。"""
    components = []
    for package in packages:
        name = str(package.get("name") or "").strip()
        version = str(package.get("version") or "").strip()
        if not name:
            continue
        component = {
            "type": "library",
            "bom-ref": f"{name}@{version}" if version else name,
            "name": name,
        }
        if version:
            component["version"] = version
        purl = _purl(package)
        if purl:
            component["purl"] = purl
        components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {"components": [{"type": "application", "name": "DepGuard Agent"}]},
        },
        "components": components,
    }


@tool
def write_sbom(packages: list[dict]) -> str:
    """把依赖清单写成 CycloneDX 1.6 格式的 sbom.json。"""
    session_dir = get_session_context() or "."
    path = Path(session_dir) / "sbom.json"
    path.write_text(json.dumps(build_sbom(packages), ensure_ascii=False, indent=2), encoding="utf-8")
    return f"SBOM 已生成：{path}"
