"""对照验证器：与核对器不同的遍历方法与全量依赖重算。

差异点：
- 核对器按需（demand-driven）从目标 BFS 推导闭包，只在闭包内核对；
- 验证器对声明中的全部动作做局部判定（全量重算，含不相关依赖），
  再用迭代 DFS 沿消费者边做污染可达，最后用反向 DFS 收集目标闭包。
两者对同一目标的判定应完全一致，否则说明实现存在分歧。
"""
from __future__ import annotations

from .checker import Report, Verdict, check
from .model import Category, Declaration
from .paths import UnresolvableReparse, normalize
from .simulator import CacheHit, ReadRecord, expected_manifest

_RANK = {Verdict.SHAREABLE: 0, Verdict.NO_AUTHORITY: 1, Verdict.MUST_INVALIDATE: 2}


def _local_verdict(decl: Declaration, record: ReadRecord, action) -> Verdict:
    entry = record.get(action.name)
    if entry is None:
        return Verdict.NO_AUTHORITY
    if isinstance(entry, CacheHit):
        if entry.manifest_digest is None:
            return Verdict.NO_AUTHORITY
        return (Verdict.SHAREABLE
                if entry.manifest_digest == expected_manifest(action)
                else Verdict.MUST_INVALIDATE)
    declared = {(i.category, i.key): i.digest for i in action.inputs}
    for c in entry:
        if c.category is Category.PLATFORM:
            key = "platform"
        elif c.category in (Category.ENV, Category.TOOL):
            key = c.key.casefold()
        else:
            try:
                key = decl.reparse.resolve(normalize(c.key))
            except UnresolvableReparse:
                return Verdict.NO_AUTHORITY
        ck = (c.category, key)
        if ck not in declared or declared[ck] != c.digest:
            return Verdict.MUST_INVALIDATE
    return Verdict.SHAREABLE


def verify(decl: Declaration, record: ReadRecord, target: str) -> dict[str, Verdict]:
    """全量重算所有动作的判定，返回目标闭包内的部分。"""
    actions = {a.name: a for a in decl.actions}

    # 1) 全量局部判定（包括与目标无关的动作——这是与按需核对的核心差别）
    verdicts = {n: _local_verdict(decl, record, a) for n, a in actions.items()}

    # 2) 全图消费者边
    consumers: dict[str, set[str]] = {n: set() for n in actions}
    for a in decl.actions:
        for inp in a.inputs:
            if inp.category in (Category.SOURCE, Category.TOOL):
                p = decl.producer(inp.key)
                if p is not None:
                    consumers[p.name].add(a.name)

    # 3) 迭代 DFS 污染可达（核对器用的是队列传播）
    for seed in sorted(n for n, v in verdicts.items() if v is not Verdict.SHAREABLE):
        stack = [seed]
        while stack:
            n = stack.pop()
            for m in consumers[n]:
                if _RANK[verdicts[m]] < _RANK[verdicts[n]]:
                    verdicts[m] = verdicts[n]
                    stack.append(m)

    # 4) 反向 DFS 收集目标闭包（核对器用的是正向 BFS）
    tpath = decl.reparse.resolve(normalize(target))
    root = decl.producer(tpath)
    if root is None:
        raise KeyError(f"no action produces {tpath!r}")
    seen: set[str] = set()
    stack = [root.name]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        for inp in actions[n].inputs:
            if inp.category in (Category.SOURCE, Category.TOOL):
                p = decl.producer(inp.key)
                if p is not None:
                    stack.append(p.name)
    return {n: verdicts[n] for n in seen}


def cross_check(decl: Declaration, record: ReadRecord, target: str,
                ) -> tuple[Report, list[str]]:
    """同时运行核对器与验证器，返回 (核对报告, 分歧列表)。"""
    report = check(decl, record, target)
    verified = verify(decl, record, target)
    mismatches = []
    if set(verified) != set(report.verdicts):
        mismatches.append(
            f"closure mismatch: checker={sorted(report.verdicts)} "
            f"verifier={sorted(verified)}")
    for n in sorted(set(report.verdicts) & set(verified)):
        if report.verdicts[n] is not verified[n]:
            mismatches.append(
                f"{n}: checker={report.verdicts[n].value} "
                f"verifier={verified[n].value}")
    return report, mismatches
