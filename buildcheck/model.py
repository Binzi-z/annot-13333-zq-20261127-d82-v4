"""构建声明模型：分类输入、动作、声明集合（含相同子图合并）与世界状态。"""
from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field

from .paths import ReparseTable, normalize


def digest(text: str) -> str:
    """短内容摘要，用于声明/记录中的指纹。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


class Category(enum.Enum):
    """声明输入的四个类别，缓存键按类别分别处理。"""

    SOURCE = "source"      # 源文件
    TOOL = "tool"          # 工具版本（同名工具按字节摘要区分）
    PLATFORM = "platform"  # 目标平台
    ENV = "env"            # 公开环境槽


@dataclass(frozen=True)
class DeclaredInput:
    category: Category
    key: str     # SOURCE: 规范化路径；TOOL: 折叠后工具名；PLATFORM: "platform"；ENV: 折叠后槽名
    digest: str  # 声明时摘要（PLATFORM/ENV 为取值摘要）

    def canonical(self) -> str:
        return f"{self.category.value}|{self.key}|{self.digest}"


def src(path: str, dg: str, reparse: ReparseTable | None = None) -> DeclaredInput:
    key = (reparse or ReparseTable()).resolve(path)
    return DeclaredInput(Category.SOURCE, key, dg)


def tool(name: str, bytes_digest: str) -> DeclaredInput:
    return DeclaredInput(Category.TOOL, name.casefold(), bytes_digest)


def platform_input(platform: str) -> DeclaredInput:
    return DeclaredInput(Category.PLATFORM, "platform", digest("platform|" + platform))


def env_input(slot: str, value: str) -> DeclaredInput:
    return DeclaredInput(Category.ENV, slot.casefold(), digest("env|" + value))


@dataclass(frozen=True)
class Action:
    name: str
    outputs: tuple[str, ...]  # 规范化路径
    inputs: tuple[DeclaredInput, ...]

    def signature(self) -> str:
        """与动作名无关的内容签名，用于合并相同子图。"""
        outs = ";".join(sorted(self.outputs))
        ins = ";".join(sorted(i.canonical() for i in self.inputs))
        return digest(f"A|{outs}|{ins}")


def make_action(name: str, outputs: tuple[str, ...] | list[str],
                inputs: tuple[DeclaredInput, ...] | list[DeclaredInput],
                reparse: ReparseTable | None = None) -> Action:
    rt = reparse or ReparseTable()
    return Action(name, tuple(rt.resolve(o) for o in outputs), tuple(inputs))


class Declaration:
    """动作集合。构造时合并相同子图（签名一致仅保留字典序最小名），
    因此重排声明或重复声明相同子图不会改变结果。"""

    def __init__(self, actions: list[Action] | tuple[Action, ...],
                 reparse: ReparseTable | None = None):
        self.reparse = reparse or ReparseTable()
        merged: dict[str, Action] = {}
        for a in actions:
            sig = a.signature()
            if sig in merged:
                if a.name < merged[sig].name:
                    merged[sig] = a
            else:
                merged[sig] = a
        self.actions = tuple(sorted(merged.values(), key=lambda a: a.name))
        self._by_output: dict[str, Action] = {}
        for a in self.actions:
            for o in a.outputs:
                if o in self._by_output:
                    raise ValueError(f"duplicate output {o!r}: "
                                     f"{self._by_output[o].name} vs {a.name}")
                self._by_output[o] = a
        self.stats = {"producer_lookups": 0}

    def producer(self, path: str) -> Action | None:
        self.stats["producer_lookups"] += 1
        return self._by_output.get(path)


@dataclass
class World:
    """实际世界状态：文件/工具的真实摘要、平台、公开环境槽取值摘要。"""

    files: dict[str, str] = field(default_factory=dict)
    tools: dict[str, str] = field(default_factory=dict)
    platform: str = ""
    env: dict[str, str] = field(default_factory=dict)

    def diff(self, other: "World") -> set[tuple[Category, str]]:
        """返回 self 相对 other 发生变化的 (类别, 键) 集合。"""
        out: set[tuple[Category, str]] = set()
        for k in self.files.keys() | other.files.keys():
            if self.files.get(k) != other.files.get(k):
                out.add((Category.SOURCE, k))
        for k in self.tools.keys() | other.tools.keys():
            if self.tools.get(k) != other.tools.get(k):
                out.add((Category.TOOL, k))
        for k in self.env.keys() | other.env.keys():
            if self.env.get(k) != other.env.get(k):
                out.add((Category.ENV, k))
        if self.platform != other.platform:
            out.add((Category.PLATFORM, "platform"))
        return out


def make_world(files: dict[str, str] | None = None,
               tools: dict[str, str] | None = None,
               platform: str = "",
               env: dict[str, str] | None = None,
               reparse: ReparseTable | None = None) -> World:
    """构造世界状态，键一律规范化（文件走路径规范，工具/环境槽折叠大小写）。"""
    rt = reparse or ReparseTable()
    return World(
        files={rt.resolve(k): v for k, v in (files or {}).items()},
        tools={k.casefold(): v for k, v in (tools or {}).items()},
        platform=platform,
        env={k.casefold(): v for k, v in (env or {}).items()},
    )
