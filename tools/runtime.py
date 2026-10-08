"""工具权限分级表 + 统一执行入口的雏形。

背景（对齐 M5）：
    工具直接 @tool，无权限模型，写操作（生成文件/PDF）和只读操作（搜索/查表）
    混在一起。这里先落一张权限表，给每个工具打危险等级，后续可挂统一 execute_tool
    包装（权限检查 → 参数校验 → 超时 → 限额 → 错误分类 → 埋点）。
"""

# read = 只读；write = 写文件；dangerous = 不可逆，需人工审批
TOOL_PERMISSIONS = {
    "internet_search": "read",
    "list_sql_tables": "read",
    "get_table_data": "read",
    "execute_sql_query": "read",   # 只读，但仍要过 SQL 白名单
    "generate_markdown": "write",
    "convert_md_to_pdf": "write",
    "create_pr": "dangerous",      # DepGuard 后续会用
}


def get_permission(tool_name: str) -> str:
    """返回工具的危险等级，未登记的工具默认按只读处理（最保守）。"""
    return TOOL_PERMISSIONS.get(tool_name, "read")
