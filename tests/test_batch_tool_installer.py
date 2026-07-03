from pathlib import Path

from core.tool_manager import ToolManager


def test_read_tool_file_ignores_comments_and_blank_lines(tmp_path: Path):
    tools_file = tmp_path / "tools.txt"
    tools_file.write_text("""
# comment
https://github.com/example/one.git

https://github.com/example/two.git
""", encoding="utf-8")
    manager = ToolManager()
    assert manager._read_tool_file(str(tools_file)) == [
        "https://github.com/example/one.git",
        "https://github.com/example/two.git",
    ]


def test_read_tool_file_accepts_single_dash_prefix(tmp_path: Path):
    tools_file = tmp_path / "tools.txt"
    tools_file.write_text("https://github.com/example/one.git\n", encoding="utf-8")
    manager = ToolManager()
    assert manager._read_tool_file("-" + str(tools_file)) == ["https://github.com/example/one.git"]
