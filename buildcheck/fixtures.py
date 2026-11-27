"""夹具：公共生成器、断环、缓存结果被替换、十万条不相关依赖。

主夹具场景（对应题面）：
    schema.def --[codegen]--> gen/api.h --+--> compile_main --> main.obj --+
                                          +--> compile_util --> util.obj --+--> link --> app.exe
    compile_util 的子任务把平台标记写进了 util.obj（未声明消费 PLATFORM），
    而缓存只按源码命中 —— 核对器必须找出这条最短漏声明链。
路径故意混用大小写/正斜杠，并经抽象重解析节点 C:\\sdk -> D:\\toolchain\\sdk，
以检验规范化不会误命中。
"""
from __future__ import annotations

from .model import (Action, Category, Declaration, World, digest, env_input,
                    make_action, make_world, platform_input, src, tool)
from .paths import ReparseTable, normalize
from .simulator import Consumed, ReadRecord, simulate

PLATFORM = "win32-x64"


def make_reparse() -> ReparseTable:
    return ReparseTable(links={r"C:\sdk": r"D:\ToolChain\SDK"})


def base_actions(rt: ReparseTable) -> list[Action]:
    return [
        make_action("codegen", [r"C:\gen\api.h"], (
            src(r"C:\src\schema.def", "dg-schema", rt),
            tool("CodeGen", "tg-1"),
        ), rt),
        make_action("compile_main", [r"C:\out\main.obj"], (
            src(r"C:\Src\Main.C", "dg-main", rt),            # 大小写混合
            src(r"C:/gen/api.h", "dg-api", rt),              # 正斜杠
            src(r"C:\sdk\include\sdk.h", "dg-sdk", rt),      # 经重解析节点
            tool("cc", "tc-1"),
        ), rt),
        make_action("compile_util", [r"C:\out\util.obj"], (
            src(r"C:\src\util.c", "dg-util", rt),
            src(r"C:\gen\api.h", "dg-api", rt),
            tool("cc", "tc-1"),
        ), rt),
        make_action("link", [r"C:\out\app.exe"], (
            src(r"C:\out\main.obj", "dg-mainobj", rt),
            src(r"C:\out\util.obj", "dg-utilobj", rt),
            tool("link", "tl-1"),
            platform_input(PLATFORM),
            env_input("PUBLIC_SDK_VERSION", "10.0.22000"),
        ), rt),
    ]


def base_declaration() -> Declaration:
    rt = make_reparse()
    return Declaration(base_actions(rt), reparse=rt)


def base_world(decl: Declaration) -> World:
    return make_world(
        files={
            r"C:\src\schema.def": "dg-schema",
            r"C:\src\main.c": "dg-main",
            r"C:\src\util.c": "dg-util",
            r"D:\toolchain\sdk\include\sdk.h": "dg-sdk",  # 重解析目标侧
        },
        tools={"codegen": "tg-1", "cc": "tc-1", "link": "tl-1"},
        platform=PLATFORM,
        env={"public_sdk_version": digest("env|10.0.22000")},
        reparse=decl.reparse,
    )


def platform_leak() -> dict[str, tuple[Consumed, ...]]:
    """子任务把平台标记写进 util.obj：compile_util 实际消费了未声明的平台。"""
    return {"compile_util": (
        Consumed(Category.PLATFORM, "platform", digest("platform|" + PLATFORM)),)}


def case_mangled_reads() -> dict[str, tuple[Consumed, ...]]:
    """记录里的路径大小写/斜杠与声明不同，规范化后必须匹配（不得误命中）。"""
    return {"compile_main": (
        Consumed(Category.SOURCE, r"c:\SRC\main.c", "dg-main"),
        Consumed(Category.SOURCE, r"C:\SDK\Include\SDK.H", "dg-sdk"),
    )}


def base_record(decl: Declaration, world: World, **kwargs) -> ReadRecord:
    rec = simulate(decl, world, **kwargs)
    decl.stats["producer_lookups"] = 0  # 模拟器访问量不计入核对指标
    return rec


def cycle_declaration() -> Declaration:
    """a <-> b 互相声明对方产物为输入：闭包推导必须断环终止。"""
    rt = ReparseTable()
    return Declaration([
        make_action("a", [r"C:\x\a.out"], (src(r"C:\x\b.out", "dg-b", rt),), rt),
        make_action("b", [r"C:\x\b.out"], (src(r"C:\x\a.out", "dg-a", rt),), rt),
    ], reparse=rt)


def opaque_declaration() -> Declaration:
    """输入落在不透明重解析节点之下：核对器应判无权作判定。"""
    from .model import DeclaredInput
    rt = ReparseTable(opaque=(r"C:\mounted\cache",))
    # 声明侧保留未解析路径（声明本身合法，解析失败发生在记录核对时）
    blob = DeclaredInput(Category.SOURCE, normalize(r"C:\mounted\cache\blob.bin"),
                         "dg-blob")
    return Declaration([
        make_action("use_opaque", [r"C:\x\o.out"], (blob,), rt),
    ], reparse=rt)


def noise_declaration(n: int = 100_000) -> Declaration:
    """主夹具 + n 条与目标无关的依赖，用于检验误命中与增量访问量。"""
    rt = make_reparse()
    actions = base_actions(rt)
    actions.extend(
        make_action(f"noise_{i}", [rf"C:\noise\{i}.out"],
                    (src(rf"C:\noise\{i}.in", f"dg-noise-{i}", rt),), rt)
        for i in range(n)
    )
    return Declaration(actions, reparse=rt)


def noise_world(decl: Declaration) -> World:
    w = base_world(decl)
    # 不相关依赖的世界状态从缺，模拟器回退声明摘要即可
    return w
