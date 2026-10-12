"""阶段 5：依赖升级规划子智能体。"""
from agent.prompts import sub_agents_content
from tools.depsdev_tool import query_dependencies, query_package_info
from tools.github_repo_tool import query_releases, query_repo_health
from tools.osv_tool import query_osv_vulns

_cfg = sub_agents_content["upgrade_planning"]
upgrade_planning_agent = {
    "name": _cfg["name"],
    "description": _cfg["description"],
    "system_prompt": _cfg["system_prompt"],
    "tools": [query_osv_vulns, query_package_info, query_dependencies, query_repo_health, query_releases],
}
