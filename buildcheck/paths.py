"""Windows 逻辑路径规范化与抽象重解析点。

规范化规则（纯词法，不触碰文件系统）：
- 统一分隔符为反斜杠，剥离 ``\\\\?\\`` 扩展前缀；
- 支持驱动器根（``C:\\``，盘符大写）与 UNC 根（``\\\\server\\share``）；
- 相对路径一律锚定到默认根 ``C:\\``，保证确定性；
- 词法化简 ``.`` / ``..``（根之上的 ``..`` 丢弃）；
- 大小写按 Windows 语义折叠（casefold，盘符保持大写）。

重解析点（交接点/符号链接）只用夹具提供的抽象节点表示：
``ReparseTable`` 以前缀映射描述，解析带跳数上限与循环检测；
声明为不透明（opaque）的节点不可解析，调用方应据此判"无权作判定"。
"""
from __future__ import annotations


class ReparseLoop(Exception):
    """重解析点解析出现循环或超过跳数上限。"""


class UnresolvableReparse(Exception):
    """路径落在不透明重解析节点之下，无权解析。"""


def normalize(path: str) -> str:
    """把逻辑路径规范化为 Windows 规范形（大小写折叠、根规范）。"""
    if not path or not path.strip():
        raise ValueError("empty logical path")
    p = path.strip().replace("/", "\\")
    if p.startswith("\\\\?\\"):
        p = p[4:]
    if p.startswith("\\\\"):
        parts = [seg for seg in p.split("\\") if seg]
        if len(parts) < 2:
            raise ValueError(f"bad UNC path: {path!r}")
        root = "\\\\" + parts[0].casefold() + "\\" + parts[1].casefold()
        rest = parts[2:]
    elif len(p) >= 2 and p[0].isalpha() and p[1] == ":":
        root = p[0].upper() + ":"
        rest = [seg for seg in p[2:].split("\\") if seg]
    else:
        root = "C:"
        rest = [seg for seg in p.split("\\") if seg]
    out: list[str] = []
    for seg in rest:
        if seg == ".":
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg.casefold())
    return root + ("\\" + "\\".join(out) if out else "\\")


class ReparseTable:
    """夹具提供的抽象重解析节点表。

    links:  规范化前缀 -> 规范化目标前缀（可链式）。
    opaque: 规范化前缀集合，其下路径不可解析（如被替换的缓存挂载点）。
    """

    def __init__(self, links: dict[str, str] | None = None,
                 opaque: tuple[str, ...] | list[str] | frozenset[str] = ()):
        self._links = {normalize(k): normalize(v) for k, v in (links or {}).items()}
        self._opaque = {normalize(p) for p in opaque}

    def _under(self, path: str, prefix: str) -> bool:
        return path == prefix or path.startswith(prefix + "\\")

    def _longest_link(self, path: str) -> tuple[str, str] | None:
        best: tuple[str, str] | None = None
        for prefix, dest in self._links.items():
            if self._under(path, prefix) and (best is None or len(prefix) > len(best[0])):
                best = (prefix, dest)
        return best

    def resolve(self, path: str, max_hops: int = 32) -> str:
        """解析重解析点，返回最终规范化路径。

        命中不透明节点抛 UnresolvableReparse；循环或超跳数抛 ReparseLoop。
        """
        target = normalize(path)
        seen = {target}
        for _ in range(max_hops):
            hit = self._longest_link(target)
            if hit is None:
                if any(self._under(target, op) for op in self._opaque):
                    raise UnresolvableReparse(target)
                return target
            prefix, dest = hit
            target = dest + target[len(prefix):]
            if target in seen:
                raise ReparseLoop(target)
            seen.add(target)
        raise ReparseLoop(target)
