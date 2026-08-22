#!/usr/bin/env python3
"""为 LinkMesh 全部代码文件添加 .license-header.tpl 许可头注释（幂等）。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TPL = os.path.join(ROOT, ".license-header.tpl")

with open(TPL, "r", encoding="utf-8") as f:
    body = f.read().rstrip("\n")

MARKER = "LinkMesh - 可以在多个操作系统上运行的内网穿透工具"


def comment_style(path: str):
    if path.endswith(".rs") or path.endswith(".kt") or path.endswith(".kts"):
        return "//"
    if path.endswith(".sh") or path.endswith(".toml"):
        return "#"
    if path.endswith(".xml"):
        return "xml"
    return None


def make_header(style: str) -> str:
    if style == "xml":
        return "<!--\n" + body + "\n-->\n\n"
    return "\n".join(style + " " + line if line else style for line in body.split("\n")) + "\n\n"


def process(path: str) -> bool:
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    if MARKER in content:
        return False  # 已含许可头

    style = comment_style(path)
    if style is None:
        return False

    header = make_header(style)
    lines = content.split("\n")
    # 保留文件原有换行风格
    nl = "\r\n" if "\r\n" in content else "\n"

    if style == "xml" and content.startswith("<?xml"):
        # XML 声明必须位于文件最前，许可头插在其后
        idx = content.index("\n") + 1
        new_content = content[:idx] + header + content[idx:]
    elif style == "#" and content.startswith("#!"):
        # shebang 必须位于文件最前
        idx = content.index("\n") + 1
        new_content = content[:idx] + header + content[idx:]
    else:
        new_content = header + content

    # 清理可能引入的空行堆积
    new_content = new_content.replace("\n\n\n", "\n\n")

    with open(path, "w", encoding="utf-8", newline=nl) as f:
        f.write(new_content)
    return True


def main():
    targets = []
    for root, dirs, files in os.walk(ROOT):
        # 跳过构建产物与版本控制目录
        dirs[:] = [d for d in dirs if d not in (".git", "target", "build", ".gradle",
                                                ".dsh", ".opencode", ".sdk-cache",
                                                ".transfer", "test-results", "intermediates")]
        for fn in files:
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, ROOT)
            if rel == ".license-header.tpl":
                continue
            if rel.endswith((".rs", ".kt", ".kts", ".sh", ".toml", ".xml")):
                # XML 只处理 AndroidManifest 与源码 res（排除 build 中间产物已由 dirs 排除）
                targets.append(p)

    changed = []
    for p in sorted(targets):
        try:
            if process(p):
                changed.append(os.path.relpath(p, ROOT))
        except Exception as e:  # noqa: BLE001
            print(f"ERROR {p}: {e}", file=sys.stderr)
    print(f"已处理 {len(changed)} 个文件:")
    for c in changed:
        print("  " + c)


if __name__ == "__main__":
    main()
