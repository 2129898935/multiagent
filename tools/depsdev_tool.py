"""deps.dev 数据源工具（对齐 M11）：查询包的许可证、依赖、版本信息。"""
import json

import httpx
from langchain_core.tools import tool

DEPSDEV_BASE = "https://api.deps.dev/v3alpha"


@tool
def query_package_info(name: str, system: str = "pypi") -> str:
    """查询 deps.dev 上某个包的许可证、维护性等概要信息。

    system 取值：pypi / npm / maven / go。
    """
    try:
        resp = httpx.get(f"{DEPSDEV_BASE}/systems/{system}/packages/{name}", timeout=10)
        resp.raise_for_status()
        d = resp.json()
        versions = d.get("versions", [])
        latest = versions[-1] if versions else {}
        return json.dumps(
            {
                "name": d.get("packageKey", {}).get("name"),
                "system": d.get("packageKey", {}).get("system"),
                "versions_count": len(versions),
                "latest_licenses": latest.get("licenses", []),
            },
            ensure_ascii=False,
        )
    except Exception as e:
        return f"deps.dev 查询失败：{e}"


@tool
def query_dependencies(name: str, version: str, system: str = "pypi") -> str:
    """查询 deps.dev 上某个包某个版本的直接依赖列表。"""
    try:
        url = f"{DEPSDEV_BASE}/systems/{system}/packages/{name}/versions/{version}:dependencies"
        resp = httpx.get(url, timeout=10)
        resp.raise_for_status()
        d = resp.json()
        nodes = d.get("nodes", [])
        deps = [
            {
                "name": n.get("versionKey", {}).get("name"),
                "version": n.get("versionKey", {}).get("version"),
            }
            for n in nodes
            if n.get("relation") == "DIRECT"
        ]
        return json.dumps(deps, ensure_ascii=False)
    except Exception as e:
        return f"deps.dev 查询失败：{e}"
