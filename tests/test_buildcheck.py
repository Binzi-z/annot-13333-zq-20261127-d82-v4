"""buildcheck 的单元测试：覆盖题面全部需求点。"""
from __future__ import annotations

import dataclasses
import random
import unittest

from buildcheck import fixtures as fx
from buildcheck.checker import Verdict, check, reclassify
from buildcheck.closure import input_closure
from buildcheck.model import (Category, Declaration, make_action, src, tool)
from buildcheck.paths import (ReparseLoop, ReparseTable, UnresolvableReparse,
                              normalize)
from buildcheck.simulator import simulate
from buildcheck.verifier import cross_check, verify

TARGET = r"C:\out\app.exe"


class TestPaths(unittest.TestCase):
    def test_case_and_separator_normalization(self):
        self.assertEqual(normalize(r"C:\Src\Main.C"), r"C:\src\main.c")
        self.assertEqual(normalize("C:/Src/Main.C"), r"C:\src\main.c")
        self.assertEqual(normalize(r"c:\SRC"), r"C:\src")

    def test_roots(self):
        self.assertEqual(normalize(r"\\Server\Share\X.Y"), r"\\server\share\x.y")
        self.assertEqual(normalize(r"\\?\D:\A\B"), r"D:\a\b")
        self.assertEqual(normalize("E:\\"), "E:\\")

    def test_dot_segments(self):
        self.assertEqual(normalize(r"C:\a\.\b\..\c"), r"C:\a\c")
        self.assertEqual(normalize(r"C:\..\x"), r"C:\x")  # 根之上 .. 丢弃

    def test_relative_anchored(self):
        self.assertEqual(normalize("foo/bar.txt"), r"C:\foo\bar.txt")

    def test_reparse_resolve(self):
        rt = ReparseTable(links={r"C:\sdk": r"D:\ToolChain\SDK"})
        self.assertEqual(rt.resolve(r"C:\SDK\Inc\a.h"),
                         r"D:\toolchain\sdk\inc\a.h")

    def test_reparse_loop(self):
        rt = ReparseTable(links={r"C:\a": r"C:\b", r"C:\b": r"C:\a"})
        with self.assertRaises(ReparseLoop):
            rt.resolve(r"C:\a\x")

    def test_reparse_opaque(self):
        rt = ReparseTable(opaque=(r"C:\mounted",))
        with self.assertRaises(UnresolvableReparse):
            rt.resolve(r"C:\mounted\x.bin")
        self.assertEqual(rt.resolve(r"C:\other\x.bin"), r"C:\other\x.bin")


class TestClosure(unittest.TestCase):
    def setUp(self):
        self.decl = fx.base_declaration()

    def test_closure_contents(self):
        clo = input_closure(self.decl, TARGET)
        self.assertEqual(set(clo.actions),
                         {"codegen", "compile_main", "compile_util", "link"})
        leaf_keys = {(i.category, i.key) for i in clo.leaves}
        self.assertIn((Category.PLATFORM, "platform"), leaf_keys)
        self.assertIn((Category.ENV, "public_sdk_version"), leaf_keys)
        self.assertIn((Category.TOOL, "codegen"), leaf_keys)
        self.assertIn((Category.SOURCE, r"D:\toolchain\sdk\include\sdk.h"),
                      leaf_keys)  # 重解析已解析
        # 中间产物不是叶子
        self.assertNotIn((Category.SOURCE, r"C:\gen\api.h"), leaf_keys)

    def test_platform_dependence(self):
        clo = input_closure(self.decl, TARGET)
        self.assertEqual(clo.platform_dependent, frozenset({"link"}))
        self.assertNotIn("compile_util", clo.platform_dependent)

    def test_common_generator_shared_once(self):
        # 公共生成器 codegen 被两个编译动作共享，闭包中只出现一次
        clo = input_closure(self.decl, TARGET)
        self.assertEqual(clo.actions.count("codegen"), 1)

    def test_cycle_terminates(self):
        clo = input_closure(fx.cycle_declaration(), r"C:\x\a.out")
        self.assertEqual(set(clo.actions), {"a", "b"})

    def test_order_independent_digest(self):
        rt = fx.make_reparse()
        actions = fx.base_actions(rt)
        digests = set()
        for seed in range(8):
            shuffled = list(actions)
            random.Random(seed).shuffle(shuffled)
            d = Declaration(shuffled, reparse=rt)
            digests.add(input_closure(d, TARGET).digest)
        self.assertEqual(len(digests), 1)

    def test_identical_subgraph_merge_stable(self):
        rt = fx.make_reparse()
        actions = fx.base_actions(rt)
        single = Declaration(actions, reparse=rt)
        # 同一子图以不同名字重复声明两次 -> 合并后动作数不变、结果确定
        dup = [dataclasses.replace(a, name=f"zz_dup_{a.name}") for a in actions]
        merged = Declaration(actions + dup, reparse=rt)
        self.assertEqual(len(merged.actions), len(single.actions))
        self.assertEqual(input_closure(merged, TARGET).digest,
                         input_closure(single, TARGET).digest)
        # 同一声明多重集（含重复子图）无论顺序如何，合并结果都稳定
        pool = actions + [dataclasses.replace(a, name=f"d_{a.name}")
                          for a in actions]
        digests = set()
        for seed in range(8):
            shuffled = list(pool)
            random.Random(seed).shuffle(shuffled)
            digests.add(input_closure(Declaration(shuffled, reparse=rt),
                                      TARGET).digest)
        self.assertEqual(len(digests), 1)


class TestCheck(unittest.TestCase):
    def setUp(self):
        self.decl = fx.base_declaration()
        self.world = fx.base_world(self.decl)

    def test_clean_build_shareable(self):
        rec = fx.base_record(self.decl, self.world)
        report, mism = cross_check(self.decl, rec, TARGET)
        self.assertEqual(mism, [])
        self.assertTrue(all(v is Verdict.SHAREABLE
                            for v in report.verdicts.values()))
        self.assertEqual(report.undeclared_chains, [])

    def test_platform_marker_leak(self):
        rec = fx.base_record(self.decl, self.world,
                             undeclared=fx.platform_leak())
        report, mism = cross_check(self.decl, rec, TARGET)
        self.assertEqual(mism, [])
        self.assertIs(report.verdicts["compile_util"], Verdict.MUST_INVALIDATE)
        self.assertIs(report.verdicts["link"], Verdict.MUST_INVALIDATE)
        self.assertIs(report.verdicts["codegen"], Verdict.SHAREABLE)
        self.assertIs(report.verdicts["compile_main"], Verdict.SHAREABLE)
        self.assertEqual(report.shortest_chain, (
            "platform:platform", "action:compile_util", "action:link",
            f"output:{normalize(TARGET)}"))

    def test_case_mangled_reads_not_false_hits(self):
        # 记录路径大小写/斜杠不同：规范化后不得误报漏声明
        rec = fx.base_record(self.decl, self.world,
                             undeclared=fx.case_mangled_reads())
        report = check(self.decl, rec, TARGET)
        self.assertIs(report.verdicts["compile_main"], Verdict.SHAREABLE)
        self.assertEqual(report.undeclared_chains, [])

    def test_tool_digest_mismatch_invalidates(self):
        # 世界里的 codegen 字节变了，记录如实反映 -> 全部后继失效
        world2 = dataclasses.replace(
            self.world, tools={**self.world.tools, "codegen": "tg-2"})
        rec = fx.base_record(self.decl, world2)
        report, mism = cross_check(self.decl, rec, TARGET)
        self.assertEqual(mism, [])
        self.assertTrue(all(v is Verdict.MUST_INVALIDATE
                            for v in report.verdicts.values()))

    def test_missing_record_no_authority(self):
        rec = fx.base_record(self.decl, self.world, skip=("compile_util",))
        report, mism = cross_check(self.decl, rec, TARGET)
        self.assertEqual(mism, [])
        self.assertIs(report.verdicts["compile_util"], Verdict.NO_AUTHORITY)
        self.assertIs(report.verdicts["link"], Verdict.NO_AUTHORITY)
        self.assertIs(report.verdicts["codegen"], Verdict.SHAREABLE)

    def test_cache_replaced_opaque(self):
        rec = fx.base_record(self.decl, self.world,
                             replaced={"codegen": None})
        report, mism = cross_check(self.decl, rec, TARGET)
        self.assertEqual(mism, [])
        self.assertIs(report.verdicts["codegen"], Verdict.NO_AUTHORITY)
        self.assertIs(report.verdicts["link"], Verdict.NO_AUTHORITY)

    def test_cache_replaced_manifest_mismatch(self):
        rec = fx.base_record(self.decl, self.world,
                             replaced={"codegen": "deadbeef"})
        report = check(self.decl, rec, TARGET)
        self.assertIs(report.verdicts["codegen"], Verdict.MUST_INVALIDATE)
        self.assertIs(report.verdicts["link"], Verdict.MUST_INVALIDATE)

    def test_cache_replaced_manifest_match_shareable(self):
        from buildcheck.simulator import expected_manifest
        gen = next(a for a in self.decl.actions if a.name == "codegen")
        rec = fx.base_record(self.decl, self.world,
                             replaced={"codegen": expected_manifest(gen)})
        report, mism = cross_check(self.decl, rec, TARGET)
        self.assertEqual(mism, [])
        self.assertTrue(all(v is Verdict.SHAREABLE
                            for v in report.verdicts.values()))

    def test_opaque_reparse_no_authority(self):
        decl = fx.opaque_declaration()
        rec = simulate(decl, fx.make_world(reparse=decl.reparse))
        report, mism = cross_check(decl, rec, r"C:\x\o.out")
        self.assertEqual(mism, [])
        self.assertIs(report.verdicts["use_opaque"], Verdict.NO_AUTHORITY)

    def test_cycle_fixture_agrees(self):
        decl = fx.cycle_declaration()
        rec = simulate(decl, fx.make_world(platform=fx.PLATFORM,
                                           reparse=decl.reparse))
        report, mism = cross_check(decl, rec, r"C:\x\a.out")
        self.assertEqual(mism, [])
        self.assertEqual(set(report.verdicts), {"a", "b"})


class TestIncremental(unittest.TestCase):
    def setUp(self):
        self.decl = fx.base_declaration()
        self.world = fx.base_world(self.decl)
        rec = fx.base_record(self.decl, self.world)
        self.baseline = check(self.decl, rec, TARGET)

    def test_platform_only_change_reuses_platform_free_subtree(self):
        world2 = dataclasses.replace(self.world, platform="arm64-ec")
        inc = reclassify(self.decl, TARGET, self.world, world2, self.baseline)
        self.assertIs(inc.verdicts["link"], Verdict.MUST_INVALIDATE)
        for n in ("codegen", "compile_main", "compile_util"):
            self.assertIs(inc.verdicts[n], Verdict.SHAREABLE)

    def test_tool_bytes_change_invalidates_all_successors(self):
        world2 = dataclasses.replace(
            self.world, tools={**self.world.tools, "codegen": "tg-2"})
        inc = reclassify(self.decl, TARGET, self.world, world2, self.baseline)
        self.assertTrue(all(v is Verdict.MUST_INVALIDATE
                            for v in inc.verdicts.values()))

    def test_unrelated_change_reuses_everything(self):
        world2 = dataclasses.replace(
            self.world, env={"public_sdk_version": self.world.env[
                "public_sdk_version"], "other_slot": "x"})
        # other_slot 不在声明中 -> diff 为空键集（env 键不同但都不在闭包）
        inc = reclassify(self.decl, TARGET, self.world, world2, self.baseline)
        self.assertEqual(inc.verdicts, self.baseline.verdicts)

    def test_env_slot_change_invalidates_link_only(self):
        world2 = dataclasses.replace(
            self.world, env={"public_sdk_version": "changed"})
        inc = reclassify(self.decl, TARGET, self.world, world2, self.baseline)
        self.assertIs(inc.verdicts["link"], Verdict.MUST_INVALIDATE)
        self.assertIs(inc.verdicts["codegen"], Verdict.SHAREABLE)


class TestNoiseScale(unittest.TestCase):
    """十万条不相关依赖：闭包推导与核对不得被拖慢或误命中。"""

    @classmethod
    def setUpClass(cls):
        cls.decl = fx.noise_declaration(100_000)
        cls.world = fx.noise_world(cls.decl)

    def test_closure_bounded_access(self):
        self.decl.stats["producer_lookups"] = 0
        clo = input_closure(self.decl, TARGET)
        self.assertEqual(len(clo.actions), 4)
        # 生产者查询只与闭包规模相关，与 100k 条不相关依赖无关
        self.assertLess(self.decl.stats["producer_lookups"], 50)

    def test_check_bounded_access_and_verdict(self):
        rec = fx.base_record(self.decl, self.world,
                             undeclared=fx.platform_leak())
        self.decl.stats["producer_lookups"] = 0
        rec.stats["record_lookups"] = 0
        report = check(self.decl, rec, TARGET)
        self.assertLess(self.decl.stats["producer_lookups"], 50)
        self.assertEqual(rec.stats["record_lookups"], 4)  # 只查闭包内动作
        self.assertIs(report.verdicts["compile_util"], Verdict.MUST_INVALIDATE)
        # 不相关依赖不进入判定
        self.assertFalse(any(n.startswith("noise_") for n in report.verdicts))

    def test_verifier_full_recompute_agrees(self):
        rec = fx.base_record(self.decl, self.world,
                             undeclared=fx.platform_leak())
        report = check(self.decl, rec, TARGET)
        verified = verify(self.decl, rec, TARGET)  # 全量重算 100k 动作
        self.assertEqual(report.verdicts, verified)


if __name__ == "__main__":
    unittest.main()
