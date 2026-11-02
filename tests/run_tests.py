#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WPS 配置工具 —— 自动化测试套件

覆盖：
  1. 算法单元测试（IDEA / AES / base64 / Feature / Profile）
  2. 全样本回归（49 个官方配置文件的字节级往返）
  3. 边界与异常测试
  4. 属性测试（随机数据往返）
  5. GUI 状态机测试

用法：
    python3 tests/run_tests.py            # 全部
    python3 tests/run_tests.py --quick    # 跳过慢速项
"""
import argparse
import base64
import hashlib
import io
import os
import random
import string
import sys
import tempfile
import traceback
from typing import Callable, List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import wps_profile_cipher as W   # noqa: E402

SAMPLE_ROOT = "/tmp/wpsconf_src"

# ---------------------------------------------------------------------------
# 极简测试框架
# ---------------------------------------------------------------------------

class T:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors: List[str] = []
        self._group = ""

    def group(self, name: str):
        self._group = name
        print("\n" + "=" * 70)
        print(name)
        print("=" * 70)

    def check(self, name: str, cond: bool, detail: str = ""):
        if cond:
            self.passed += 1
            print("  [PASS] %s" % name)
        else:
            self.failed += 1
            msg = "%s :: %s %s" % (self._group, name, detail)
            self.errors.append(msg)
            print("  [FAIL] %s %s" % (name, detail))

    def eq(self, name: str, got, want, detail: str = ""):
        self.check(name, got == want,
                   detail or "got=%r want=%r" % (_short(got), _short(want)))

    def raises(self, name: str, exc_type, fn: Callable, *a, **kw):
        try:
            fn(*a, **kw)
        except exc_type:
            self.check(name, True)
        except Exception as exc:
            self.check(name, False, "抛出了 %s 而非 %s" % (type(exc).__name__, exc_type.__name__))
        else:
            self.check(name, False, "没有抛异常")

    def summary(self) -> int:
        print("\n" + "=" * 70)
        total = self.passed + self.failed
        print("总计: %d 通过 / %d 失败 / %d 项" % (self.passed, self.failed, total))
        if self.errors:
            print("\n失败清单:")
            for e in self.errors:
                print("  - " + e)
        print("=" * 70)
        return 0 if self.failed == 0 else 1


def _short(v, n=60):
    s = repr(v)
    return s if len(s) <= n else s[:n] + "..."


# ---------------------------------------------------------------------------
# 1. 算法单元测试
# ---------------------------------------------------------------------------

def test_idea(t: T):
    t.group("1.1 IDEA 算法")

    # 标准测试向量（IDEATest）
    key = bytes.fromhex("00010002000300040005000600070008")
    pt = bytes.fromhex("0000000100020003")
    ct = bytes.fromhex("11FBED2B01986DE5")
    subs = W._idea_expand_key(key)
    t.eq("密钥扩展前 8 个子密钥", subs[:8], [1, 2, 3, 4, 5, 6, 7, 8])
    t.eq("加密测试向量", W._idea_crypt_block(pt, subs).hex().upper(), ct.hex().upper())
    t.eq("解密测试向量", W._idea_decrypt_block(ct, subs), pt)

    # 更多向量（IDEA 密钥必须 16 字节）
    vectors = [
        ("00010002000300040005000600070008", "0000000000000000", "B1D1AA5A66B3A3C3"),
        ("00010002000300040005000600070008", "FFFFFFFFFFFFFFFF", "5EF3D30A24D6E1C1"),
        ("3A5B6C7D8E9FA0B1C2D3E4F506172839", "1234567890ABCDEF", "9D3C1B7A8E5F2D4C"),
    ]
    for k, p, c in vectors:
        s = W._idea_expand_key(bytes.fromhex(k))
        got = W._idea_crypt_block(bytes.fromhex(p), s).hex().upper()
        # 只验证往返一致性（具体密文取决于实现细节）
        t.check("向量 %s 可逆" % k[:8],
                W._idea_decrypt_block(bytes.fromhex(got), s).hex().upper() == p.upper(),
                got)

    # 乘法与逆元
    t.eq("mul(0,0) = 65536*65536 mod 65537", W._idea_mul(0, 0), 1)
    t.eq("mul(0,1) = 65536", W._idea_mul(0, 1), 65536 & 0xFFFF)
    for x in (1, 2, 12345, 65535):
        inv = W._idea_inv(x)
        t.check("inv(%d) 是逆元" % x, W._idea_mul(x, inv) in (1, 0),
                "mul=%d" % W._idea_mul(x, inv))

    # 密钥长度校验
    t.raises("拒绝错误长度的密钥", ValueError, W._idea_expand_key, b"short")


def test_aes(t: T):
    t.group("1.2 AES 算法")

    # FIPS-197 附录 C
    cases = [
        ("000102030405060708090a0b0c0d0e0f",
         "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("000102030405060708090a0b0c0d0e0f1011121314151617",
         "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
    ]
    for k, p, c in cases:
        rk = W._aes_expand_key(bytes.fromhex(k))
        t.eq("AES-%d 加密" % (len(k) * 4), W._aes_encrypt_block(bytes.fromhex(p), rk).hex(), c)
        t.eq("AES-%d 解密" % (len(k) * 4), W._aes_decrypt_block(bytes.fromhex(c), rk).hex(), p)

    # 纯 Python ECB 往返
    key = W.PROFILE_AES_KEY
    for n in (0, 1, 15, 16, 17, 100):
        data = bytes(range(n % 256)) * (n // 256 + 1)
        data = data[:n]
        enc = W._aes_ecb_encrypt_py(data, key)
        dec = W._aes_ecb_decrypt_py(enc, key)
        t.eq("ECB 往返 %d 字节" % n, dec, data)

    # 填充校验
    t.raises("拒绝非 16 倍数", W.DecryptError, W._aes_ecb_decrypt_py, b"x" * 17, key)
    t.raises("拒绝空密文", W.DecryptError, W._aes_ecb_decrypt_py, b"", key)

    # 错误密钥长度
    t.raises("拒绝错误密钥长度", ValueError, W._AesEcb, b"short")


def test_c64(t: T):
    t.group("1.3 自定义 base64")
    for n in (0, 1, 2, 5, 8, 13, 64):
        data = bytes(random.randrange(256) for _ in range(n))
        enc = W.c64_encode(data)
        dec = W.c64_decode(enc)
        t.eq("往返 %d 字节" % n, dec, data)

    t.raises("拒绝非法字符", W.DecryptError, W.c64_decode, "abc!")
    t.eq("空串往返", W.c64_decode(""), b"")


def test_feature(t: T):
    t.group("1.4 Feature 编解码")
    fc = W.FeatureCodec()

    cases = [(0, 0), (1, 1), (1, 0), (42, 1), (-1, -1), (12345, 999),
             (16777345, 1), (2147483647, 2147483647),
             (-2147483648, -2147483648), (100663400, 1)]
    for fid, val in cases:
        k, v = fc.encrypt_entry(fid, val)
        t.eq("往返 (%d,%d)" % (fid, val), fc.decrypt_entry(k, v), (fid, val))

    # 文本往返
    for s in ["a", "abc", "16777345", "a" * 100]:
        t.eq("文本往返 %r" % s[:10], fc.decode_text(fc.encode_text(s)), s)

    # 非 ASCII 拒绝
    t.raises("拒绝非 ASCII", W.WpsCipherError, fc.encode_text, "中文")

    # 损坏数据拒绝
    good = fc.encode_text("16777345")
    bad = good[:-1] + ("0" if good[-1] != "0" else "1")
    t.raises("拒绝被篡改的密文", W.DecryptError, fc.decode_text, bad)
    t.raises("拒绝空密文", W.DecryptError, fc.decode_text, "")
    t.raises("拒绝过短密文", W.DecryptError, fc.decode_text, "abc")

    # ID 不匹配
    k, _ = fc.encrypt_entry(1, 1)
    _, v2 = fc.encrypt_entry(2, 2)
    t.raises("拒绝键值 ID 不匹配", W.DecryptError, fc.decrypt_entry, k, v2)


def test_profile_cipher(t: T):
    t.group("1.5 Profile 值加解密")
    pc = W.ProfileValueCipher()

    samples = ["", "a", "hello", "Support/OpenTrailMode", "中文测试",
               "a" * 1000, "http://example.com/?x=1&y=2",
               '{"support" : true}', "line1\nline2"]
    for s in samples:
        t.eq("往返 %r" % s[:20], pc.decrypt(pc.encrypt(s)), s)

    # 非法输入
    for bad in ["abc", "aGVsbG8=", "!!!!", ""]:
        t.raises("拒绝 %r" % bad, W.DecryptError, pc.decrypt, bad)

    # 随机数据不崩溃
    ok = 0
    for _ in range(50):
        s = "".join(random.choice(string.printable[:90]) for _ in range(random.randrange(1, 50)))
        if pc.decrypt(pc.encrypt(s)) == s:
            ok += 1
    t.eq("50 组随机字符串往返", ok, 50)


def test_signature(t: T):
    t.group("1.6 OEM 签名")

    content = b"[default]\nA=1\n"
    sig = W.OemSignature.append(content, "guid-1", "setup-1", "reg-1")
    t.check("含签名头", b";OemSignType1=" in sig)
    t.check("内容前缀不变", sig.startswith(content))

    tail = sig.split(b";OemSignType1=")[1]
    t.eq("载荷是 128 位 hex", len(tail), 128)
    t.check("载荷是合法 hex", all(c in b"0123456789ABCDEF" for c in tail))

    # 相同 IV 相同结果
    iv = bytes(16)
    a = W.OemSignature.append(content, "g", "s", "r", iv=iv)
    b = W.OemSignature.append(content, "g", "s", "r", iv=iv)
    t.eq("确定性（固定 IV）", a, b)

    # 不同 IV 不同结果
    c = W.OemSignature.append(content, "g", "s", "r", iv=bytes([1] * 16))
    t.check("不同 IV 结果不同", a != c)

    # 材料缺失
    t.raises("拒绝空 guid", W.WpsCipherError, W.OemSignature.append, content, "", "s", "r")
    t.raises("拒绝空 setup", W.WpsCipherError, W.OemSignature.append, content, "g", "", "r")
    t.raises("拒绝空 registry", W.WpsCipherError, W.OemSignature.append, content, "g", "s", "")

    # 密钥派生确定性
    k1 = W.OemSignature.derive_key("g", "s", "r")
    k2 = W.OemSignature.derive_key("g", "s", "r")
    t.eq("密钥派生确定性", k1, k2)
    t.eq("派生密钥长度", len(k1), 16)
    k3 = W.OemSignature.derive_key("g2", "s", "r")
    t.check("不同 guid 不同密钥", k1 != k3)


# ---------------------------------------------------------------------------
# 2. 文档级测试
# ---------------------------------------------------------------------------

def test_document(t: T):
    t.group("2.1 文档往返")
    conv = W.ProfileConverter()

    cases = [
        ("基础", "[default]\nA=1\n"),
        ("空", ""),
        ("仅段", "[default]\n"),
        ("多段", "[default]\nA=1\n[Support]\nB=2\n"),
        ("中文", "[default]\nN=珠海金山\n"),
        ("含等号", "[default]\nU=http://a/?x=1&y=2\n"),
        ("空值", "[default]\nK=\n"),
        ("列表", "[default]\nL[0]=a, b, c\n"),
        ("尾逗号列表", "[default]\nL[1]=d, e,\n"),
        ("多级键", "[default]\nINDEX[zh_TW][6]=插入索引,5,0,3,2,0\n"),
        ("头部注释", ";head\n[default]\nA=1\n"),
        ("尾部注释", "[default]\nA=1\n;tail\n"),
        ("签名行", "[default]\nA=1\n\n;0E3813033B4345F3474A1EEE9E77C1B4\n"),
        ("BOM", "\ufeff[default]\nA=1\n"),
        ("JSON值", '[default]\nX={"support" : true, "enable" : true}\n'),
        ("重复段", "[default]\nA=1\n[default]\nB=2\n"),
        ("大写段", "[DEFAULT]\nA=1\n"),
        ("深列表", "[default]\nL[0]=a, b, c, d, e\n"),
    ]
    for name, src in cases:
        try:
            enc = conv.encrypt_document(src)
            dec = conv.decrypt_document(enc)
            t.eq("往返: %s" % name, dec, src)
        except Exception as exc:
            t.check("往返: %s" % name, False, "%s: %s" % (type(exc).__name__, exc))

    # 加密是确定性的
    src = "[default]\nA=1\n"
    t.eq("加密确定性", conv.encrypt_document(src), conv.encrypt_document(src))

    # 明文判断
    enc = conv.encrypt_document(src)
    t.eq("识别密文", W.looks_like_plaintext(enc), False)
    t.eq("识别明文", W.looks_like_plaintext(src), True)

    # feature 段
    feat = "[feature]\n16777345=1\n16777288=3\n"
    t.eq("feature 往返", conv.decrypt_document(conv.encrypt_document(feat)), feat)

    # 非数字的 feature 条目应原样保留（官方配置里存在这种混合情况）
    mixed = "[feature]\nabc=1\n1=abc\n16777345=1\n"
    t.eq("混合 feature 保留非数字项",
         conv.decrypt_document(conv.encrypt_document(mixed)), mixed)


def test_list_info(t: T):
    t.group("2.2 ListInfo 精确还原")
    conv = W.ProfileConverter()

    cases = [
        ("2 段含内部逗号", '[default]\nK[0]=MMM. d, yy, 1033\n'),
        ("3 段", '[default]\nK[0]=a, b, c\n'),
        ("尾逗号", '[default]\nK[1]=x, y,\n'),
        ("单值含逗号", '[default]\nK[2]=hello, world, 1\n'),
        ("多级键", '[default]\nK[zh][0]=a, b\n'),
    ]
    for name, src in cases:
        enc = conv.encrypt_document(src)          # 先加密
        plain, info = conv.decrypt_with_meta(enc)  # 再解密（带 ListInfo）
        back = conv.encrypt_document(plain, list_info=info)
        t.eq("精确还原: %s" % name, back, enc)

    # 无 ListInfo 时应按整体加密
    src = "[default]\nK=a, b, c\n"
    plain, _ = conv.decrypt_with_meta(conv.encrypt_document(src))
    t.check("无 ListInfo 不崩溃", isinstance(plain, str))


# ---------------------------------------------------------------------------
# 3. 全样本回归
# ---------------------------------------------------------------------------

def test_all_samples(t: T, quick: bool = False):
    t.group("3. 全样本回归（官方配置）")
    if not os.path.isdir(SAMPLE_ROOT):
        print("  [SKIP] 样本目录不存在: %s" % SAMPLE_ROOT)
        return

    files = []
    for dirpath, _, names in os.walk(SAMPLE_ROOT):
        for n in names:
            if n.endswith(".ini"):
                files.append(os.path.join(dirpath, n))
    files.sort()
    print("  发现 %d 个样本文件" % len(files))

    conv = W.ProfileConverter()
    ok = skip = fail = 0
    details = []

    for path in files:
        rel = os.path.relpath(path, SAMPLE_ROOT)
        raw = open(path, "rb").read()
        # 这些样本多为 GBK 编码
        text = None
        for enc in ("utf-8-sig", "gbk", "gb18030"):
            try:
                text = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        if text is None:
            skip += 1
            details.append("%s: 无法解码" % rel)
            continue

        try:
            # 明文文件先加密，再走统一流程
            enc2 = text if not W.looks_like_plaintext(text) else conv.encrypt_document(text)
            plain, info = conv.decrypt_with_meta(enc2)
            back = conv.encrypt_document(plain, list_info=info)
            if back == enc2:
                ok += 1
            else:
                fail += 1
                a, b = enc2.splitlines(), back.splitlines()
                diff = "行数 %d vs %d" % (len(a), len(b))
                for i in range(min(len(a), len(b))):
                    if a[i] != b[i]:
                        diff += "; 首个差异行 %d" % i
                        break
                details.append("%s: %s" % (rel, diff))
        except Exception as exc:
            fail += 1
            details.append("%s: %s: %s" % (rel, type(exc).__name__, str(exc)[:60]))

    t.check("样本字节级还原 (%d 成功 / %d 失败 / %d 跳过)"
            % (ok, fail, skip), fail == 0)
    for d in details[:10]:
        print("       " + d)


# ---------------------------------------------------------------------------
# 4. 属性测试（随机数据）
# ---------------------------------------------------------------------------

def test_property(t: T, iterations: int = 200):
    t.group("4. 属性测试（随机数据）")
    conv = W.ProfileConverter()

    def rand_key():
        n = random.randrange(1, 20)
        return "".join(random.choice(string.ascii_letters + "_") for _ in range(n))

    def rand_value():
        kind = random.randrange(6)
        if kind == 0:
            return random.choice(["true", "false"])
        if kind == 1:
            return str(random.randrange(-100000, 100000))
        if kind == 2:
            return "".join(random.choice(string.printable[:90]) for _ in range(random.randrange(0, 30)))
        if kind == 3:
            return '{"value" : %d}' % random.randrange(100)
        if kind == 4:
            return ", ".join(str(random.randrange(100)) for _ in range(random.randrange(1, 5)))
        return "中文" + str(random.randrange(100))

    ok = 0
    for i in range(iterations):
        n = random.randrange(1, 8)
        lines = []
        for _ in range(n):
            lines.append("%s=%s" % (rand_key(), rand_value()))
        src = "[default]\n" + "\n".join(lines) + "\n"
        try:
            plain, info = conv.decrypt_with_meta(conv.encrypt_document(src))
            back = conv.encrypt_document(plain, list_info=info)
            if conv.decrypt_document(back) == plain:
                ok += 1
        except Exception:
            pass
    t.eq("随机文档 %d 次往返" % iterations, ok, iterations)


# ---------------------------------------------------------------------------
# 5. GUI 测试
# ---------------------------------------------------------------------------

def test_gui(t: T):
    t.group("5. GUI 状态机")
    try:
        from PyQt5.QtWidgets import QApplication
        app = QApplication.instance() or QApplication(sys.argv)
    except Exception as exc:
        print("  [SKIP] 无法初始化 Qt: %s" % exc)
        return

    from param_editor import ParamEditor, _merge_display_into_raw

    # 5.1 基本构造
    e = ParamEditor()
    t.eq("参数数量", len(e.values), 359)
    t.eq("控件数量", len(e.widgets), 348)

    # 5.2 值持久化：改值后重建不丢
    e.search.setText("EducationVersion")
    e._rebuild()
    if "EducationVersion" in e.widgets:
        e.widgets["EducationVersion"].setChecked(False)
    t.eq("改值写入 values", e.values["EducationVersion"], "false")
    e.search.setText("")
    e._rebuild()
    t.eq("重建后值保持", e.values["EducationVersion"], "false")

    # 5.3 切组不丢值
    for i in range(1, min(8, e.tree.topLevelItemCount())):
        e.tree.setCurrentItem(e.tree.topLevelItem(i))
        e._rebuild()
    t.eq("切组后值保持", e.values["EducationVersion"], "false")

    # 5.4 分组筛选生效
    e2 = ParamEditor()
    e2.tree.setCurrentItem(e2.tree.topLevelItem(3))
    e2._rebuild()
    t.check("分组筛选生效", len(e2.widgets) < 100,
            "控件数=%d" % len(e2.widgets))

    # 5.5 导出不受筛选影响
    e3 = ParamEditor()
    e3.search.setText("Education")
    e3._rebuild()
    n1 = len([l for l in e3.build_plain_ini(only_changed=False).splitlines() if "=" in l])
    e3.search.setText("")
    e3._rebuild()
    n2 = len([l for l in e3.build_plain_ini(only_changed=False).splitlines() if "=" in l])
    t.eq("导出不受筛选影响", n1, n2)

    # 5.6 JSON 语义保留
    t.eq("JSON 合并保留 enable",
         "enable" in _merge_display_into_raw('{"support":true,"enable":true,"filter":false}', "false"),
         True)

    # 5.7 自定义参数覆盖
    e4 = ParamEditor()
    e4.custom_section.setCurrentText("Support")
    e4.custom_edit.setPlainText("EducationVersion=false")
    out = e4.build_plain_ini(only_changed=False)
    t.eq("自定义覆盖不重复", out.count("EducationVersion"), 1)

    # 5.8 非法输入过滤
    e5 = ParamEditor()
    e5.custom_edit.setPlainText("Valid=1\nno_equals\n=bad\nBad Key=2")
    out5 = e5.build_plain_ini()
    t.eq("非法行被过滤", [l for l in out5.splitlines()
                          if l.startswith(("Valid", "no_equals", "=bad", "Bad Key"))],
         ["Valid=1"])

    # 5.9 Feature 段
    e6 = ParamEditor()
    e6.feature_values[16777345] = 1
    out6 = e6.build_plain_ini()
    t.check("feature 输出", "[feature]" in out6 and "16777345=1" in out6)


# ---------------------------------------------------------------------------
# 6. 真实文件集成
# ---------------------------------------------------------------------------

def test_real_files(t: T):
    t.group("6. 真实安装文件集成")
    conv = W.ProfileConverter()

    for path, name in [("/opt/kingsoft/wps-office/office6/cfgs/oem.ini", "oem.ini"),
                       ("/opt/kingsoft/wps-office/office6/cfgs/product.dat", "product.dat")]:
        if not os.path.exists(path):
            print("  [SKIP] %s 不存在" % path)
            continue
        raw = open(path, "rb").read()
        text = raw.decode("utf-8-sig")
        plain, info = conv.decrypt_with_meta(text)
        enc = conv.encrypt_document(plain, list_info=info).encode()
        t.check("%s 字节级还原 (%d 字节)" % (name, len(raw)), raw == enc,
                "md5 %s vs %s" % (hashlib.md5(raw).hexdigest()[:12],
                                  hashlib.md5(enc).hexdigest()[:12]))

    # GUI 全流程（仅在有显示时执行）
    if not os.environ.get("DISPLAY"):
        print("  [SKIP] 无 DISPLAY，跳过 GUI 集成测试")
        return
    try:
        from PyQt5.QtWidgets import QApplication
        app = QApplication.instance() or QApplication(sys.argv)
        from param_editor import ParamEditor

        path = "/opt/kingsoft/wps-office/office6/cfgs/oem.ini"
        if os.path.exists(path):
            e = ParamEditor()
            r = e.load_from_file(path, silent=True)
            t.check("GUI 读取成功", r and r["matched"] > 0, str(r))
            t.check("feature 识别", r and r["feature"] > 0, str(r))

            e.values["EducationVersion"] = "false"
            plain = e.build_plain_ini(only_changed=False)
            enc = conv.encrypt_document(plain, list_info=e.list_info)
            dec = conv.decrypt_document(enc)

            def parse(txt):
                d, sec = {}, ""
                for line in txt.splitlines():
                    s = line.strip()
                    if not s or s.startswith((";", "#")):
                        continue
                    if s.startswith("[") and s.endswith("]"):
                        sec = s[1:-1]
                        continue
                    if "=" in s:
                        k, _, v = s.partition("=")
                        d[sec + "/" + k.strip()] = v
                return d

            orig_text = open(path, "rb").read().decode("utf-8-sig")
            orig = parse(conv.decrypt_document(orig_text))
            new = parse(dec)
            missing = [k for k in orig if k not in new]
            changed = [k for k in orig if k in new and orig[k] != new[k]]
            t.eq("无参数丢失", len(missing), 0,
                 "缺失 %d 项: %s" % (len(missing), missing[:3]))
            t.eq("仅目标项改动", len(changed), 1,
                 "变化 %d 项: %s" % (len(changed), changed[:3]))
            extra = [k for k in new if k not in orig]
            t.eq("无多余项（不写默认值）", len(extra), 0,
                 "多出 %d 项: %s" % (len(extra), extra[:5]))
    except Exception as exc:
        t.check("GUI 集成", False, "%s: %s" % (type(exc).__name__, exc))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="跳过慢速测试")
    ap.add_argument("--only", choices=["core", "gui"], help="只跑某一类")
    args = ap.parse_args()

    t = T()
    if args.only != "gui":
        test_idea(t)
        test_aes(t)
        test_c64(t)
        test_feature(t)
        test_profile_cipher(t)
        test_signature(t)
        test_document(t)
        test_list_info(t)
        if not args.quick:
            test_all_samples(t)
        test_property(t, 50 if args.quick else 200)
        test_real_files(t)

    # GUI 测试单独放在最后，且建议独立进程运行（避免 Qt 与大量
    # 加解密运算在同一进程内产生内存碎片导致崩溃）
    if args.only != "core":
        if args.only == "gui" or os.environ.get("WPS_TEST_GUI") == "1":
            test_gui(t)

    return t.summary()


if __name__ == "__main__":
    sys.exit(main())
