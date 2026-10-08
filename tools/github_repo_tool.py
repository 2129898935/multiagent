"""GitHub 仓库工具（对齐 M11）：查询仓库维护性信号。"""
import json

import httpx
from langchain_core.tools import tool

GITHUB_API = "https://api.github.com"


@tool
def query_repo_health(owner: str, repo: str) -> str:
    """查询 GitHub 仓库的维护性信号（star / open issues / 最后推送时间 / 是否归档）。"""
    try:
        resp = httpx.get(f"{GITHUB_API}/repos/{owner}/{repo}", timeout=10)
        resp.raise_for_status()
        d = resp.json()
        return json.dumps(
            {
                "full_name": d.get("full_name"),
                "stars": d.get("stargazers_count"),
                "open_issues": d.get("open_issues_count"),
                "pushed_at": d.get("pushed_at"),
                "archived": d.get("archived"),
            },
            ensure_ascii=False,
        )
    except Exception as e:
        return f"GitHub 仓库查询失败：{e}"
