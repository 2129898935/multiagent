"""M7 —— 死循环/进度检测单元测试。"""
from agent.loop_guard import ProgressDetector


def test_same_tool_same_args_stuck():
    d = ProgressDetector(max_repeats=3)
    for _ in range(3):
        d.observe("internet_search", {"query": "房价"}, "结果A")
    assert d.is_stuck() is True  # 同工具同参数连续 3 次 → 卡住


def test_changing_args_not_stuck():
    d = ProgressDetector(max_repeats=3)
    for page in [1, 2, 3]:
        d.observe("get_table_data", {"page": page}, f"第{page}页数据")
    assert d.is_stuck() is False  # 参数在变、结果在变 → 正常推进


def test_same_result_stuck():
    d = ProgressDetector(max_repeats=3)
    d.observe("internet_search", {"query": "a"}, "相同结果")
    d.observe("internet_search", {"query": "b"}, "相同结果")
    d.observe("internet_search", {"query": "c"}, "相同结果")
    assert d.is_stuck() is True  # 换着参数问但结果完全相同 → 打转


def test_below_threshold_not_stuck():
    d = ProgressDetector(max_repeats=3)
    d.observe("internet_search", {"query": "a"}, "结果")
    d.observe("internet_search", {"query": "a"}, "结果")
    assert d.is_stuck() is False  # 只有 2 次，未到阈值
