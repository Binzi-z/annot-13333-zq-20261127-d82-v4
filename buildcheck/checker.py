"""核对器：闭包内逐动作比对声明与实际消费摘要，输出三态判定。

判定语义：
- SHAREABLE       可共享缓存：实际消费全部已声明且摘要一致；
- MUST_INVALIDATE 必须失效：摘要不一致、消费了未声明输入，或上游已失效；
- NO_AUTHORITY    无权作判定：读记录缺失/被不透明缓存结果替换、
                  或路径落在不可解析的重解析节点之下。

传播沿消费者方向进行，优先级 MUST_INVALIDATE > NO_AUTHORITY > SHAREABLE。
漏声明依赖链：从未声明输入出发，沿消费关系到目标输出的最短路径（BFS）。
"""
from __future__ import annotations

import enum
from collections import deque
from dataclasses import dataclass, field

from .closure import Closure, input_closure
from .model import Category, Declaration, World
from .paths import UnresolvableReparse, normalize
from .simulator import CacheHit, ReadRecord, expected_manifest


class Verdict(enum.Enum):
    SHAREABLE = "shareable"
    MUST_INVALIDATE = "must_invalidate"
    NO_AUTHORITY = "no_authority"


_RANK = {Verdict.SHAREABLE: 0, Verdict.NO_AUTHORITY: 1, Verdict.MUST_INVALIDATE: 2}


@dataclass
class Report:
    target: str
    verdicts: dict[str, Verdict]
    undeclared_chains: list[tuple[str, ...]]
    closure: Closure
    over_declared: dict[str, tuple[str, ...]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def shortest_chain(self) -> tuple[str, ...] | None:
        return self.undeclared_chains[0] if self.undeclared_chains else None


def _resolve_record_key(decl: Declaration, cat: Category, key: str) -> str:
    if cat is Category.PLATFORM:
        return "platform"
    if cat is Category.ENV:
        return key.casefold()
    if cat is Category.TOOL:
        return key.casefold()
    return decl.reparse.resolve(normalize(key))  # 可能抛 UnresolvableReparse


def check(decl: Declaration, record: ReadRecord, target: str) -> Report:
    closure = input_closure(decl, target)
    local: dict[str, Verdict] = {}
    undeclared: list[tuple[str, Category, str]] = []
    over: dict[str, tuple[str, ...]] = {}
    notes: list[str] = []

    for name in closure.actions:
        action = closure.action_map[name]
        entry = record.get(name)
        if entry is None:
            local[name] = Verdict.NO_AUTHORITY
            notes.append(f"{name}: 读记录缺失")
            continue
        if isinstance(entry, CacheHit):
            if entry.manifest_digest is None:
                local[name] = Verdict.NO_AUTHORITY
                notes.append(f"{name}: 读记录被不透明缓存结果替换")
            elif entry.manifest_digest != expected_manifest(action):
                local[name] = Verdict.MUST_INVALIDATE
                notes.append(f"{name}: 缓存清单与声明不一致")
            else:
                local[name] = Verdict.SHAREABLE
            continue

        declared = {(i.category, i.key): i.digest for i in action.inputs}
        consumed_keys: set[tuple[Category, str]] = set()
        bad = False
        opaque = False
        for c in entry:
            try:
                key = _resolve_record_key(decl, c.category, c.key)
            except UnresolvableReparse:
                opaque = True
                continue
            ck = (c.category, key)
            consumed_keys.add(ck)
            if ck not in declared:
                undeclared.append((name, c.category, key))
                bad = True
            elif declared[ck] != c.digest:
                bad = True
                notes.append(f"{name}: {c.category.value}:{key} 摘要不一致")
        missing = set(declared) - consumed_keys
        if missing:
            over[name] = tuple(sorted(f"{c.value}:{k}" for c, k in missing))
        if opaque:
            local[name] = Verdict.NO_AUTHORITY
            notes.append(f"{name}: 记录含不可解析的重解析路径")
        else:
            local[name] = Verdict.MUST_INVALIDATE if bad else Verdict.SHAREABLE

    verdicts = _propagate(closure, local)
    chains = _shortest_chains(closure, undeclared)
    return Report(closure.target, verdicts, chains, closure, over, notes)


def _consumers(closure: Closure) -> dict[str, set[str]]:
    cons: dict[str, set[str]] = {n: set() for n in closure.actions}
    for n, deps in closure.edges.items():
        for d in deps:
            cons[d].add(n)
    return cons


def _propagate(closure: Closure, local: dict[str, Verdict]) -> dict[str, Verdict]:
    """沿消费者方向传播失效/无权判定（队列式，与验证器的 DFS 不同）。"""
    cons = _consumers(closure)
    verdicts = dict(local)
    queue: deque[str] = deque(sorted(
        n for n, v in verdicts.items() if v is not Verdict.SHAREABLE))
    while queue:
        n = queue.popleft()
        for m in cons[n]:
            if _RANK[verdicts[m]] < _RANK[verdicts[n]]:
                verdicts[m] = verdicts[n]
                queue.append(m)
    return verdicts


def _shortest_chains(closure: Closure,
                     undeclared: list[tuple[str, Category, str]]) -> list[tuple[str, ...]]:
    """每个漏声明输入到目标输出的最短依赖链；列表按长度升序。"""
    cons = _consumers(closure)
    # 目标输出的生产者
    producer_of_target = None
    for n, a in closure.action_map.items():
        if closure.target in a.outputs:
            producer_of_target = n
            break
    chains: list[tuple[str, ...]] = []
    for action_name, cat, key in undeclared:
        path = _bfs_path(action_name, producer_of_target, cons)
        chain = (f"{cat.value}:{key}",) + tuple(f"action:{n}" for n in path) \
            + (f"output:{closure.target}",)
        chains.append(chain)
    chains.sort(key=lambda c: (len(c), c))
    return chains


def _bfs_path(start: str, goal: str | None, cons: dict[str, set[str]]) -> list[str]:
    if goal is None:
        return [start]
    prev: dict[str, str | None] = {start: None}
    queue: deque[str] = deque([start])
    while queue:
        n = queue.popleft()
        if n == goal:
            break
        for m in sorted(cons.get(n, ())):
            if m not in prev:
                prev[m] = n
                queue.append(m)
    if goal not in prev:
        return [start]
    path: list[str] = []
    n: str | None = goal
    while n is not None:
        path.append(n)
        n = prev[n]
    path.reverse()
    return path


def _action_leafsets(closure: Closure, decl: Declaration) -> dict[str, set[tuple[Category, str]]]:
    """闭包内每个动作的传递叶子输入集合（不动点，断环安全）。"""
    leafsets: dict[str, set[tuple[Category, str]]] = {}
    for n, a in closure.action_map.items():
        own: set[tuple[Category, str]] = set()
        for inp in a.inputs:
            if inp.category in (Category.SOURCE, Category.TOOL) \
                    and decl.producer(inp.key) is not None:
                continue  # 中间产物，经生产者边传递
            own.add((inp.category, inp.key))
        leafsets[n] = own
    changed = True
    while changed:
        changed = False
        for n, deps in closure.edges.items():
            for d in deps:
                merged = leafsets[n] | leafsets[d]
                if merged != leafsets[n]:
                    leafsets[n] = merged
                    changed = True
    return leafsets


def reclassify(decl: Declaration, target: str,
               old_world: World, new_world: World,
               baseline: Report) -> Report:
    """增量重判：仅按世界差异重判受影响动作，未受影响动作复用基线判定。

    不读取任何读记录（record 不参与），访问量只与闭包规模相关。
    仅改变平台 -> 平台无关子树整体复用；同名工具换字节 -> 所有相关后继失效。
    """
    changed = old_world.diff(new_world)
    closure = baseline.closure
    leafsets = _action_leafsets(closure, decl)
    verdicts: dict[str, Verdict] = {}
    notes = list(baseline.notes)
    for n in closure.actions:
        if leafsets[n] & changed:
            verdicts[n] = Verdict.MUST_INVALIDATE
        else:
            verdicts[n] = baseline.verdicts[n]  # 复用，不重新核对
    reused = sum(1 for n in closure.actions
                 if not (leafsets[n] & changed))
    notes.append(f"增量重判：变化键 {len(changed)} 个，复用 {reused} 个动作的基线判定")
    return Report(closure.target, verdicts, list(baseline.undeclared_chains),
                  closure, dict(baseline.over_declared), notes)
