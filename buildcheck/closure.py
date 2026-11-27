"""输入闭包推导：从指定输出出发，按声明反向收集全部传递输入。

- 按需推导（demand-driven），只访问闭包内的动作，不相关依赖零访问；
-  visited 集合断环，声明中的环不会导致不终止；
- 结果规范化排序并给出内容摘要：重排声明、合并相同子图后摘要稳定；
- 标注平台相关动作集合，供"仅改变平台时复用平台无关子树"使用。
"""
from __future__ import annotations

from collections import deque

from .model import Action, Category, Declaration, DeclaredInput, digest
from .paths import normalize


class Closure:
    __slots__ = ("target", "actions", "action_map", "edges", "leaves",
                 "platform_dependent", "digest")

    def __init__(self, target: str, action_map: dict[str, Action],
                 edges: dict[str, frozenset[str]], leaves: tuple[DeclaredInput, ...],
                 platform_dependent: frozenset[str], cdigest: str):
        self.target = target
        self.actions = tuple(sorted(action_map))
        self.action_map = action_map
        self.edges = edges                      # 动作名 -> 其闭包内生产者动作名
        self.leaves = leaves                    # 排序后的叶子输入（非任何动作产物）
        self.platform_dependent = platform_dependent
        self.digest = cdigest                   # 子图身份摘要


def input_closure(decl: Declaration, target: str) -> Closure:
    """推导 target 的输入闭包（BFS，与验证器的 DFS 遍历不同）。"""
    tpath = decl.reparse.resolve(normalize(target))
    root = decl.producer(tpath)
    if root is None:
        raise KeyError(f"no action produces {tpath!r}")

    action_map: dict[str, Action] = {}
    edges: dict[str, frozenset[str]] = {}
    leaves: dict[str, DeclaredInput] = {}
    seen: set[str] = set()
    queue: deque[Action] = deque([root])
    while queue:
        a = queue.popleft()
        if a.name in seen:  # 断环：环上的回边不再展开
            continue
        seen.add(a.name)
        action_map[a.name] = a
        deps: set[str] = set()
        for inp in a.inputs:
            producer = None
            if inp.category in (Category.SOURCE, Category.TOOL):
                producer = decl.producer(inp.key)
            if producer is None:
                leaves[inp.canonical()] = inp
            else:
                deps.add(producer.name)
                if producer.name not in seen:
                    queue.append(producer)
        edges[a.name] = frozenset(deps)

    # 平台相关性：自身声明了平台输入，或依赖了平台相关动作（不动点传播）。
    pdep = {n for n, a in action_map.items()
            if any(i.category is Category.PLATFORM for i in a.inputs)}
    changed = True
    while changed:
        changed = False
        for n, deps in edges.items():
            if n not in pdep and deps & pdep:
                pdep.add(n)
                changed = True

    lines = [f"A|{n}" for n in sorted(action_map)]
    lines += [f"L|{c}" for c in sorted(leaves)]
    ordered_leaves = tuple(leaves[c] for c in sorted(leaves))
    return Closure(tpath, action_map, edges, ordered_leaves,
                   frozenset(pdep), digest("\n".join(lines)))
