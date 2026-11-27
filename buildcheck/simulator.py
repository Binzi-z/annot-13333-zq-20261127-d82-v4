"""读记录模拟器：按声明与世界状态产出每个动作实际消费的摘要。

支持三种故障注入：
- undeclared: 动作实际消费了未声明的输入（如把平台标记写进产物）；
- replaced:   动作的读记录被缓存命中结果替换（透明清单或不透明）；
- skip:       动作完全没有读记录。
"""
from __future__ import annotations

from dataclasses import dataclass

from .model import Action, Category, Declaration, DeclaredInput, World, digest


@dataclass(frozen=True)
class Consumed:
    category: Category
    key: str     # 可以是未规范化的原始键，由核对器负责规范化（模拟真实记录）
    digest: str


@dataclass(frozen=True)
class CacheHit:
    """缓存命中替换的读记录。manifest_digest 为 None 表示不透明结果。"""

    manifest_digest: str | None


class ReadRecord:
    def __init__(self) -> None:
        self.entries: dict[str, tuple[Consumed, ...] | CacheHit] = {}
        self.stats = {"record_lookups": 0}

    def get(self, action_name: str):
        self.stats["record_lookups"] += 1
        return self.entries.get(action_name)


def expected_manifest(action: Action) -> str:
    """动作声明输入的规范清单摘要，用于核对缓存命中清单。"""
    return digest("M|" + ";".join(sorted(i.canonical() for i in action.inputs)))


def _actual_digest(decl: Declaration, inp: DeclaredInput, world: World) -> str:
    c = inp.category
    if c is Category.PLATFORM:
        return digest("platform|" + world.platform)
    if c is Category.ENV:
        return world.env.get(inp.key, inp.digest)
    if c is Category.TOOL:
        if decl.producer(inp.key) is not None:
            return inp.digest  # 自造工具属中间产物，按声明一致
        return world.tools.get(inp.key, inp.digest)
    # SOURCE：中间产物按声明一致；叶子源文件取世界真实摘要
    if decl.producer(inp.key) is not None:
        return inp.digest
    return world.files.get(inp.key, inp.digest)


def simulate(decl: Declaration, world: World,
             undeclared: dict[str, tuple[Consumed, ...] | list[Consumed]] | None = None,
             replaced: dict[str, str | None] | None = None,
             skip: tuple[str, ...] | list[str] = ()) -> ReadRecord:
    """对声明中每个动作生成读记录。"""
    rec = ReadRecord()
    undeclared = undeclared or {}
    replaced = replaced or {}
    skipped = set(skip)
    for a in decl.actions:
        if a.name in skipped:
            continue
        if a.name in replaced:
            rec.entries[a.name] = CacheHit(replaced[a.name])
            continue
        consumed = [Consumed(inp.category, inp.key, _actual_digest(decl, inp, world))
                    for inp in a.inputs]
        consumed.extend(undeclared.get(a.name, ()))
        rec.entries[a.name] = tuple(consumed)
    return rec
