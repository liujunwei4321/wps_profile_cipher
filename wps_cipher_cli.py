#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wps-cipher — WPS 配置文件加解密命令行工具

不依赖 PyQt5，可在无图形环境的服务器上使用。

用法示例
--------
  wps-cipher info oem.ini                     # 查看文件信息
  wps-cipher decrypt oem.ini                  # 解密 → oem.decrypted.ini
  wps-cipher decrypt oem.ini -o plain.ini     # 指定输出
  wps-cipher encrypt plain.ini -o oem.ini     # 加密
  wps-cipher get oem.ini Support EducationVersion
  wps-cipher set plain.ini Support EducationVersion=false
  wps-cipher dump oem.ini                     # 输出明文到标准输出
  wps-cipher verify oem.ini                   # 往返校验
  wps-cipher selftest                         # 算法自检
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import wps_profile_cipher as W   # noqa: E402

VERSION = "2.0"


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def read_text_with_encoding(path: str):
    """读取文件，返回 (文本, 编码名)。"""
    raw = open(path, "rb").read()
    for enc in ("utf-8-sig", "gbk", "gb18030"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), "utf-8"


def read_text(path: str) -> str:
    """读取文件，自动识别 UTF-8 / GBK。"""
    return read_text_with_encoding(path)[0]


def write_text(path: str, text: str) -> None:
    """原子写入。"""
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise


def load_plain(path: str):
    """读取文件并返回 (明文, ListInfo 或 None, 是否原本加密)。"""
    text = read_text(path)
    conv = W.ProfileConverter()
    if W.looks_like_plaintext(text):
        return text, None, False
    plain, info = conv.decrypt_with_meta(text)
    return plain, info, True


def die(msg: str, code: int = 1):
    print("错误: %s" % msg, file=sys.stderr)
    return code


# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------

def cmd_info(args) -> int:
    """显示配置文件信息。"""
    path = args.file
    if not os.path.isfile(path):
        return die("文件不存在: %s" % path)

    raw = open(path, "rb").read()
    text = read_text(path)
    conv = W.ProfileConverter()
    encrypted = not W.looks_like_plaintext(text)

    try:
        plain = conv.decrypt_document(text) if encrypted else text
    except Exception as exc:
        return die("无法解析: %s" % exc)

    analysis = W.analyze_config(text, plain_text=plain, raw_bytes=raw)
    print("文件: %s" % path)
    print("大小: %d 字节" % len(raw))
    print("内容: %s" % ("已加密" if encrypted else "明文"))
    print()
    for line in analysis.summary_lines():
        print(line)

    if encrypted:
        try:
            info = W.ListInfo()
            conv.decrypt_document(text, list_info=info)
            back = conv.encrypt_document(plain, list_info=info).encode()
            print()
            print("往返校验: %s"
                  % ("字节级一致" if back == raw else "不一致（有信息损失）"))
        except Exception as exc:
            print()
            print("往返校验: 失败 (%s)" % exc)
    return 0


def cmd_decrypt(args) -> int:
    """解密文件。"""
    path = args.file
    if not os.path.isfile(path):
        return die("文件不存在: %s" % path)

    text = read_text(path)
    conv = W.ProfileConverter()
    if W.looks_like_plaintext(text):
        print("提示: 该文件已是明文，无需解密", file=sys.stderr)
        plain = text
    else:
        plain = conv.decrypt_document(text, args.line_ending)

    out = args.output
    if not out:
        base, _ = os.path.splitext(path)
        out = base + ".decrypted.ini"
    write_text(out, plain)
    print("已解密 → %s" % out)
    return 0


def cmd_encrypt(args) -> int:
    """加密文件。"""
    path = args.file
    if not os.path.isfile(path):
        return die("文件不存在: %s" % path)

    text = read_text(path)
    conv = W.ProfileConverter()

    # 若原文件是加密的，先解出 ListInfo 以便精确还原列表结构
    info = None
    if not W.looks_like_plaintext(text):
        try:
            _, info = conv.decrypt_with_meta(text)
            print("提示: 输入已是密文，将按原结构重新加密", file=sys.stderr)
        except Exception:
            pass

    try:
        enc = conv.encrypt_document(text, args.line_ending,
                                    args.header_comment, list_info=info)
    except Exception as exc:
        return die("加密失败: %s" % exc)

    out = args.output
    if not out:
        base, _ = os.path.splitext(path)
        out = base + ".encrypted.ini"
    write_text(out, enc)
    print("已加密 → %s" % out)
    return 0


def cmd_dump(args) -> int:
    """把明文输出到标准输出。"""
    path = args.file
    if not os.path.isfile(path):
        return die("文件不存在: %s" % path)
    try:
        plain, _, _ = load_plain(path)
    except Exception as exc:
        return die("解密失败: %s" % exc)
    sys.stdout.write(plain)
    return 0


def cmd_get(args) -> int:
    """读取单个配置项。"""
    path = args.file
    if not os.path.isfile(path):
        return die("文件不存在: %s" % path)
    try:
        plain, _, _ = load_plain(path)
    except Exception as exc:
        return die("解密失败: %s" % exc)

    section = args.section.lower()
    key = args.key
    cur = ""
    found = None
    for line in plain.splitlines():
        s = line.strip()
        if not s or s.startswith(("#", ";")):
            continue
        # 先判断段（[xxx] 不含 '='）
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1].strip().lower()
            continue
        if "=" not in s:
            continue
        if cur == section:
            k, _, v = s.partition("=")
            if k.strip() == key:
                found = v
    if found is None:
        return die("未找到 [%s] %s" % (args.section, key), 2)
    print(found)
    return 0


def cmd_set(args) -> int:
    """修改单个配置项（就地修改明文文件，或从密文导出为明文）。"""
    path = args.file
    if not os.path.isfile(path):
        return die("文件不存在: %s" % path)

    assignment = args.assignment
    if "=" not in assignment:
        return die("格式应为 KEY=VALUE")
    new_key, _, new_val = assignment.partition("=")
    new_key, new_val = new_key.strip(), new_val

    try:
        plain, info, was_encrypted = load_plain(path)
    except Exception as exc:
        return die("解密失败: %s" % exc)

    lines = plain.splitlines()
    section = args.section.lower()
    cur = ""
    replaced = False
    out_lines = []
    for line in lines:
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1].strip().lower()
            out_lines.append(line)
            continue
        if cur == section and "=" in s and not s.startswith(("#", ";")):
            k, _, _v = s.partition("=")
            if k.strip() == new_key:
                out_lines.append("%s=%s" % (new_key, new_val))
                replaced = True
                continue
        out_lines.append(line)

    if not replaced:
        # 追加到段末尾
        result = []
        cur = ""
        inserted = False
        for line in out_lines:
            result.append(line)
            s = line.strip()
            if s.startswith("[") and s.endswith("]"):
                cur = s[1:-1].strip().lower()
        # 简化处理：在最后一个段结束前插入
        result.append("%s=%s" % (new_key, new_val))
        out_lines = result
        print("提示: [%s] 中没有 %s，已追加到文件末尾" % (args.section, new_key),
              file=sys.stderr)

    new_plain = "\n".join(out_lines) + "\n"

    if was_encrypted:
        if not args.output:
            return die("输入是密文，请用 -o 指定输出文件（避免覆盖原文件）")
        conv = W.ProfileConverter()
        enc = conv.encrypt_document(new_plain, list_info=info)
        write_text(args.output, enc)
        print("已修改并重新加密 → %s" % args.output)
    else:
        out = args.output or path
        write_text(out, new_plain)
        print("已修改 → %s" % out)
    return 0


def cmd_verify(args) -> int:
    """往返校验。"""
    path = args.file
    if not os.path.isfile(path):
        return die("文件不存在: %s" % path)

    raw = open(path, "rb").read()
    text, enc_name = read_text_with_encoding(path)
    conv = W.ProfileConverter()

    try:
        if W.looks_like_plaintext(text):
            enc = conv.encrypt_document(text)
            plain, info = conv.decrypt_with_meta(enc)
            back = conv.encrypt_document(plain, list_info=info)
            ok = back == enc
            print("输入是明文，已加密后再校验")
        else:
            plain, info = conv.decrypt_with_meta(text)
            back = conv.encrypt_document(plain, list_info=info)
            # 用原文件的编码比较，避免 GBK/UTF-8 差异造成误报
            try:
                ok = back.encode(enc_name) == raw
            except UnicodeEncodeError:
                ok = back.encode("utf-8") == raw
            if not ok:
                ok = back == text
            print("输入是密文（编码 %s）" % enc_name)
    except Exception as exc:
        print("失败: %s" % exc)
        return 1

    print("结果: %s" % ("字节级一致 ✓" if ok else "不一致 ✗"))
    return 0 if ok else 1


def cmd_selftest(args) -> int:
    """算法自检。"""
    try:
        W._selftest()
    except Exception as exc:
        print("自检失败: %s" % exc, file=sys.stderr)
        return 1
    return 0


def cmd_batch(args) -> int:
    """批量处理目录下的配置文件。"""
    root = args.directory
    if not os.path.isdir(root):
        return die("目录不存在: %s" % root)

    files = []
    for dirpath, _, names in os.walk(root):
        for n in names:
            if n.endswith((".ini", ".dat", ".cfg")):
                files.append(os.path.join(dirpath, n))
    if not files:
        return die("目录下没有配置文件")

    mode = args.mode
    ok = fail = 0
    for p in sorted(files):
        try:
            text, enc_name = read_text_with_encoding(p)
            conv = W.ProfileConverter()
            if mode == "verify":
                raw = open(p, "rb").read()
                if W.looks_like_plaintext(text):
                    enc = conv.encrypt_document(text)
                    plain, info = conv.decrypt_with_meta(enc)
                    same = conv.encrypt_document(plain, list_info=info) == enc
                else:
                    plain, info = conv.decrypt_with_meta(text)
                    back = conv.encrypt_document(plain, list_info=info)
                    try:
                        same = back.encode(enc_name) == raw
                    except UnicodeEncodeError:
                        same = back.encode("utf-8") == raw
                    if not same:
                        same = back == text
                if same:
                    ok += 1
                else:
                    fail += 1
                    print("  ✗ %s" % p)
            elif mode == "decrypt":
                plain, _, was_enc = load_plain(p)
                if was_enc:
                    base, _ = os.path.splitext(p)
                    write_text(base + ".decrypted.ini", plain)
                ok += 1
        except Exception as exc:
            fail += 1
            print("  ✗ %s: %s" % (p, exc))

    print("\n完成: %d 成功 / %d 失败" % (ok, fail))
    return 0 if fail == 0 else 1


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="wps-cipher",
        description="WPS Office 配置文件 (oem.ini / product.dat) 加解密工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
示例:
  wps-cipher info oem.ini
  wps-cipher decrypt oem.ini -o oem.plain.ini
  wps-cipher encrypt oem.plain.ini -o oem.ini
  wps-cipher dump oem.ini | grep Serial
  wps-cipher get oem.ini Support EducationVersion
  wps-cipher set oem.plain.ini Support EducationVersion=false
  wps-cipher verify oem.ini
  wps-cipher batch-verify /opt/kingsoft/wps-office/office6/cfgs
""")
    ap.add_argument("--version", action="version", version="wps-cipher " + VERSION)
    sub = ap.add_subparsers(dest="command", metavar="命令")

    p = sub.add_parser("info", help="显示文件信息与风险分析")
    p.add_argument("file")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("decrypt", help="解密文件")
    p.add_argument("file")
    p.add_argument("-o", "--output", help="输出路径（默认 <原名>.decrypted.ini）")
    p.add_argument("--line-ending", default="\n", choices=["\n", "\r\n"],
                   help="输出换行符")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("encrypt", help="加密文件")
    p.add_argument("file")
    p.add_argument("-o", "--output", help="输出路径（默认 <原名>.encrypted.ini）")
    p.add_argument("--line-ending", default="\n", choices=["\n", "\r\n"])
    p.add_argument("--header-comment", default=None, help="文件头注释")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("dump", help="输出明文到标准输出")
    p.add_argument("file")
    p.set_defaults(func=cmd_dump)

    p = sub.add_parser("get", help="读取单个配置项")
    p.add_argument("file")
    p.add_argument("section", help="段名，如 Support")
    p.add_argument("key", help="键名")
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("set", help="修改单个配置项")
    p.add_argument("file")
    p.add_argument("section")
    p.add_argument("assignment", help="KEY=VALUE")
    p.add_argument("-o", "--output", help="输出路径")
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("verify", help="往返校验")
    p.add_argument("file")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("selftest", help="算法自检")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("batch-verify", help="批量校验目录下的配置")
    p.add_argument("directory")
    p.set_defaults(func=cmd_batch, mode="verify")

    return ap


def main(argv=None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    if not getattr(args, "command", None):
        ap.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n已中断", file=sys.stderr)
        return 130
    except Exception as exc:
        print("错误: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
