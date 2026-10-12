"""阶段 6：报告生成与证据审查子智能体。"""
from agent.prompts import sub_agents_content
from tools.markdown_tools import generate_markdown
from tools.pdf_tools import convert_md_to_pdf
from tools.sbom_tool import write_sbom

_cfg = sub_agents_content["report_review"]
report_review_agent = {
    "name": _cfg["name"],
    "description": _cfg["description"],
    "system_prompt": _cfg["system_prompt"],
    "tools": [write_sbom, generate_markdown, convert_md_to_pdf],
}
