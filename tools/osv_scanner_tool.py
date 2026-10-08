"""osv-scanner 本地基准工具（对齐 M11/M12）：调用本机 CLI 做交叉验证。

osv-scanner 是 Google 官方的本地依赖扫描器（Go 编写），
用于交叉验证依赖数量、许可证，并作为 M12 评测的「真实值」基准。
安装：go install github.com/google/osv-scanner/cmd/osv-scanner@latest
     或到 https://github.com/google/osv-scanner/releases 下载二进制。
"""
import subprocess

from langchain_core.tools import tool


@tool
def scan_repo_with_osv_scanner(path: str) -> str:
    """调用本地 osv-scanner 扫描指定目录，返回 JSON 结果（用于基准交叉验证）。"""
    try:
        r = subprocess.run(
            ["osv-scanner", "--format", "json", "-r", path],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if r.returncode == 0:
            return r.stdout[:5000]
        return f"osv-scanner 返回非零：{r.stderr[:500]}"
    except FileNotFoundError:
        return "未安装 osv-scanner，请先安装（go install 或下载二进制）"
    except Exception as e:
        return f"osv-scanner 执行失败：{e}"
