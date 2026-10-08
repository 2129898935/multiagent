"""进度检测：判断 Agent 是否「一直在动但没推进」（假推进/死循环）。

背景（对齐 M7）：
    光限制最大 Loop 次数只能兜底「跑太久」，拦不住「看起来一直在调用工具、但内容
    原地打转」的假推进。这里用「同工具同参数连续重复」和「结果连续完全相同」两个
    信号叠加判断任务是否卡住。

注：第一版只做独立可测的纯逻辑检测器，接线到主循环是第二步（先确定性、后框架）。
"""
import hashlib


class ProgressDetector:
    def __init__(self, max_repeats: int = 3) -> None:
        self.max_repeats = max_repeats
        self._history: list[tuple[str, str, str]] = []  # [(tool_name, args_hash, result_hash)]

    @staticmethod
    def _hash(obj) -> str:
        return hashlib.md5(str(obj).encode("utf-8")).hexdigest()

    def observe(self, tool_name: str, args: dict, result: str) -> None:
        """记录一次工具调用，只保留最近 20 条。"""
        entry = (tool_name, self._hash(args), self._hash(str(result)[:500]))
        self._history.append(entry)
        self._history = self._history[-20:]

    def is_stuck(self) -> bool:
        """判断是否卡住（未达阈值不算）。"""
        if len(self._history) < self.max_repeats:
            return False
        recent = self._history[-self.max_repeats:]
        # 信号一：同工具 + 同参数，连续重复
        if len({(n, a) for (n, a, _) in recent}) == 1:
            return True
        # 信号二：结果连续完全相同（在打转）
        if len({r for (_, _, r) in recent}) == 1:
            return True
        return False
