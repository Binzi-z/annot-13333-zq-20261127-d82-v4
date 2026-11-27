"""演示入口：python -m buildcheck

依次运行：平台标记泄漏核对、仅改平台的增量复用、同名工具换字节失效、
缓存结果被替换、断环、十万条不相关依赖的访问量，以及验证器对照。
"""
from __future__ import annotations

import dataclasses

from . import fixtures as fx
from .checker import Verdict, check, reclassify
from .model import Category
from .simulator import simulate
from .verifier import cross_check, verify

TARGET = r"C:\out\app.exe"


def _show(title: str, verdicts: dict[str, Verdict]) -> None:
    print(f"[{title}]")
    for n in sorted(verdicts):
        print(f"  {n:<14} {verdicts[n].value}")


def main() -> None:
    # 1) 平台标记泄漏：缓存只按源码命中会误中，核对器必须抓出漏声明链
    decl = fx.base_declaration()
    world = fx.base_world(decl)
    rec = fx.base_record(decl, world, undeclared=fx.platform_leak(),
                         replaced=None)
    # 记录里混入大小写/斜杠不同的路径，验证规范化不误命中
    rec2 = fx.base_record(decl, world, undeclared={
        **fx.platform_leak(),
        "compile_main": fx.case_mangled_reads()["compile_main"],
    })
    report, mism = cross_check(decl, rec2, TARGET)
    _show("平台标记泄漏核对", report.verdicts)
    print("  最短漏声明链:", " -> ".join(report.shortest_chain or ()))
    print("  验证器分歧:", mism or "无")

    # 2) 仅改变平台：平台无关子树复用
    clean = fx.base_record(decl, world)
    baseline = check(decl, clean, TARGET)
    world2 = dataclasses.replace(world, platform="arm64-ec")
    decl.stats["producer_lookups"] = 0
    inc = reclassify(decl, TARGET, world, world2, baseline)
    _show("仅改变平台 (win32-x64 -> arm64-ec)", inc.verdicts)
    print(" ", inc.notes[-1], "| 生产者查询:", decl.stats["producer_lookups"])

    # 3) 同名工具换字节：所有相关后继失效
    world3 = dataclasses.replace(world, tools={**world.tools, "codegen": "tg-2"})
    inc3 = reclassify(decl, TARGET, world, world3, baseline)
    _show("同名工具 codegen 换字节", inc3.verdicts)

    # 4) 缓存结果被替换：不透明 -> 无权作判定；清单不符 -> 必须失效
    rec_opaque = fx.base_record(decl, world, replaced={"codegen": None})
    r4, _ = cross_check(decl, rec_opaque, TARGET)
    _show("codegen 记录被不透明缓存替换", r4.verdicts)
    rec_bad = fx.base_record(decl, world, replaced={"codegen": "deadbeef"})
    r5, _ = cross_check(decl, rec_bad, TARGET)
    _show("codegen 缓存清单与声明不符", r5.verdicts)

    # 5) 断环
    cdecl = fx.cycle_declaration()
    crec = simulate(cdecl, fx.make_world(platform=fx.PLATFORM, reparse=cdecl.reparse))
    rc, mc = cross_check(cdecl, crec, r"C:\x\a.out")
    _show("断环 (a <-> b)", rc.verdicts)
    print("  验证器分歧:", mc or "无")

    # 6) 不透明重解析节点
    odecl = fx.opaque_declaration()
    orec = simulate(odecl, fx.make_world(reparse=odecl.reparse))
    ro, _ = cross_check(odecl, orec, r"C:\x\o.out")
    _show("不透明重解析节点", ro.verdicts)

    # 7) 十万条不相关依赖：误命中与增量访问量
    ndecl = fx.noise_declaration(100_000)
    nworld = fx.noise_world(ndecl)
    nrec = fx.base_record(ndecl, nworld, undeclared=fx.platform_leak())
    ndecl.stats["producer_lookups"] = 0
    nrec.stats["record_lookups"] = 0
    nreport = check(ndecl, nrec, TARGET)  # 核对器：按需推导
    chk_prod = ndecl.stats["producer_lookups"]
    chk_rec = nrec.stats["record_lookups"]
    ndecl.stats["producer_lookups"] = 0
    nrec.stats["record_lookups"] = 0
    nver = verify(ndecl, nrec, TARGET)    # 验证器：全量重算
    nmm = [f"{n}: {nreport.verdicts[n]} vs {nver[n]}"
           for n in nreport.verdicts if nreport.verdicts[n] is not nver.get(n)]
    print("[十万条不相关依赖]")
    print(f"  闭包动作数: {len(nreport.closure.actions)}"
          f" | 核对器生产者查询: {chk_prod} 记录查询: {chk_rec}"
          f" | 验证器生产者查询: {ndecl.stats['producer_lookups']}"
          f" 记录查询: {nrec.stats['record_lookups']}")
    print("  最短漏声明链:", " -> ".join(nreport.shortest_chain or ()))
    print("  验证器分歧:", nmm or "无")


if __name__ == "__main__":
    main()
