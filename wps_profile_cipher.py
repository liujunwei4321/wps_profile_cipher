#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wps_profile_cipher.py
=====================
WPS Office 配置文件 (oem.ini / product.dat) 加解密与签名核心库。

零第三方依赖：IDEA 与 AES 均为内置实现，仅用 Python 标准库。
若系统装有 pycryptodome，AES 会自动使用它加速（约 165 倍），
未安装时自动降级为内置纯 Python 实现，功能完全等价。

算法来源: https://github.com/NixaVulpi/WPSProfileCipher

三个编解码器
------------
1. FeatureCodec        [feature] 段
       IDEA-ECB，密钥 = MD5("wps")
       明文 → 补零到 8 字节 → IDEA 加密 → 追加 (md5[0], md5[8], 0x01)
            → 首字节与 trailer 首字节交换 bit0/bit4 → 自定义 base64
2. ProfileValueCipher  普通键值
       AES-256-ECB，固定密钥，PKCS#7 填充
       base64 后替换 '+'→'_'  '/'→'-'  '='→'.'
3. OemSignature        OemSignType1 签名
       MD5(content + ";OemSignType1=") 大写十六进制
       密钥由 MachineGuid + salt + 两处 InstallPartialData 派生
       payload = (IV ^ IV_MASK) + AES-CBC(digest, key, IV)
"""

import base64
import binascii
import hashlib
import os
import re
from typing import Dict, List, Optional, Sequence, Tuple

__all__ = [
    "FeatureCodec",
    "ProfileValueCipher",
    "OemSignature",
    "IniDocument",
    "IniSection",
    "IniEntry",
    "ProfileConverter",
    "ConfigAnalysis",
    "SignatureInfo",
    "analyze_config",
    "ListInfo",
    "unwrap_value",
    "looks_like_plaintext",
    "WpsCipherError",
    "DecryptError",
    "HAS_PYCRYPTODOME",
]

# ----------------------------------------------------------------------------
# 常量
# ----------------------------------------------------------------------------

FEATURE_KEY_SEED = b"wps"
PROFILE_AES_KEY = b"F9AF610AE6164C73B78B0A99D8B72890"   # 32 字节 → AES-256
C64_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"

SIGNATURE_HEADER = ";OemSignType1="
IV_MASK = b"S3kP06v2Ne04lDeX"
KEY_SALT = b"9B0p3z7GcKf2XtR5L6Y8Q1W4E7R3T6Y8"
KEY_MASK = b"k8Se2hXt6ZDKrkWTQNrZGs3w4TBT10Jt"

BLOCK_SIZE = 8          # IDEA 块大小
AES_BLOCK = 16

# 检测 pycryptodome
try:
    from Crypto.Cipher import AES as _AES  # type: ignore
    HAS_PYCRYPTODOME = True
except Exception:                            # pragma: no cover
    _AES = None
    HAS_PYCRYPTODOME = False


class WpsCipherError(Exception):
    """本库所有可预期错误的基类。"""


class DecryptError(WpsCipherError):
    """解密失败：数据不是合法的密文。"""


# ----------------------------------------------------------------------------
# IDEA（纯 Python）
# ----------------------------------------------------------------------------

IDEA_MOD = 0x10001      # 65537


def _idea_mul(a: int, b: int) -> int:
    """IDEA 乘法 mod 65537，其中 0 代表 65536（即 -1 mod 65537）。"""
    a &= 0xFFFF
    b &= 0xFFFF
    if a == 0:
        a = IDEA_MOD - 1
    if b == 0:
        b = IDEA_MOD - 1
    r = (a * b) % IDEA_MOD
    return 0 if r == IDEA_MOD - 1 else r


_IDEA_INV_CACHE: Dict[int, int] = {}


def _idea_inv(x: int) -> int:
    """乘法逆元 mod 65537。0 的逆元是 0。带缓存（解密时高频调用）。"""
    if x == 0:
        return 0
    r = _IDEA_INV_CACHE.get(x)
    if r is None:
        r = pow(x, IDEA_MOD - 2, IDEA_MOD)
        _IDEA_INV_CACHE[x] = r
    return r


def _idea_expand_key(key: bytes) -> List[int]:
    """16 字节密钥 → 52 个 16-bit 子密钥。"""
    if len(key) != 16:
        raise ValueError("IDEA key must be 16 bytes, got %d" % len(key))
    reg = int.from_bytes(key, "big")
    mask = (1 << 128) - 1
    subs: List[int] = []
    for j in range(52):
        subs.append((reg >> (16 * (7 - (j % 8)))) & 0xFFFF)
        if j % 8 == 7:
            reg = ((reg << 25) | (reg >> (128 - 25))) & mask
    return subs


def _idea_crypt_block(block: bytes, subs: Sequence[int]) -> bytes:
    x1 = int.from_bytes(block[0:2], "big")
    x2 = int.from_bytes(block[2:4], "big")
    x3 = int.from_bytes(block[4:6], "big")
    x4 = int.from_bytes(block[6:8], "big")

    for r in range(8):
        b = 6 * r
        y1 = _idea_mul(x1, subs[b + 0])
        y2 = (x2 + subs[b + 1]) & 0xFFFF
        y3 = (x3 + subs[b + 2]) & 0xFFFF
        y4 = _idea_mul(x4, subs[b + 3])
        t0 = _idea_mul(y1 ^ y3, subs[b + 4])
        t1 = _idea_mul(((y2 ^ y4) + t0) & 0xFFFF, subs[b + 5])
        t0 = (t0 + t1) & 0xFFFF
        x1 = y1 ^ t1
        x2 = y3 ^ t1
        x3 = y2 ^ t0
        x4 = y4 ^ t0

    out = (
        _idea_mul(x1, subs[48]),
        (x3 + subs[49]) & 0xFFFF,
        (x2 + subs[50]) & 0xFFFF,
        _idea_mul(x4, subs[51]),
    )
    return b"".join(w.to_bytes(2, "big") for w in out)


def _idea_decrypt_block(block: bytes, subs: Sequence[int]) -> bytes:
    o1 = int.from_bytes(block[0:2], "big")
    o2 = int.from_bytes(block[2:4], "big")
    o3 = int.from_bytes(block[4:6], "big")
    o4 = int.from_bytes(block[6:8], "big")

    x1 = _idea_mul(o1, _idea_inv(subs[48]))
    x3 = (o2 - subs[49]) & 0xFFFF
    x2 = (o3 - subs[50]) & 0xFFFF
    x4 = _idea_mul(o4, _idea_inv(subs[51]))

    for r in range(7, -1, -1):
        b = 6 * r
        t0 = _idea_mul(x1 ^ x2, subs[b + 4])
        t1 = _idea_mul(((x3 ^ x4) + t0) & 0xFFFF, subs[b + 5])
        t0 = (t0 + t1) & 0xFFFF
        y1 = x1 ^ t1
        y3 = x2 ^ t1
        y2 = x3 ^ t0
        y4 = x4 ^ t0
        x1 = _idea_mul(y1, _idea_inv(subs[b + 0]))
        x2 = (y2 - subs[b + 1]) & 0xFFFF
        x3 = (y3 - subs[b + 2]) & 0xFFFF
        x4 = _idea_mul(y4, _idea_inv(subs[b + 3]))

    return b"".join(w.to_bytes(2, "big") for w in (x1, x2, x3, x4))


# ----------------------------------------------------------------------------
# 自定义 base64
# ----------------------------------------------------------------------------

def c64_encode(data: bytes) -> str:
    out: List[str] = []
    acc = 0
    nbits = 0
    for byte in data:
        acc |= byte << nbits
        nbits += 8
        while nbits >= 6:
            out.append(C64_ALPHABET[acc & 0x3F])
            acc >>= 6
            nbits -= 6
    if nbits:
        out.append(C64_ALPHABET[acc & 0x3F])
    return "".join(out)


def c64_decode(text: str) -> bytes:
    out = bytearray()
    acc = 0
    nbits = 0
    for ch in text:
        idx = C64_ALPHABET.find(ch)
        if idx < 0:
            raise DecryptError("非法的 Feature 编码字符: %r" % ch)
        acc |= idx << nbits
        nbits += 6
        while nbits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            nbits -= 8
    return bytes(out)


# ----------------------------------------------------------------------------
# FeatureCodec
# ----------------------------------------------------------------------------

class FeatureCodec:
    """[feature] 段编解码，条目形式 <feature_id>=<value>，均为十进制整数。"""

    def __init__(self) -> None:
        self._subs = _idea_expand_key(hashlib.md5(FEATURE_KEY_SEED).digest())

    @staticmethod
    def _swap_bits(payload: bytes) -> bytes:
        if len(payload) < 3:
            raise DecryptError("Feature 数据过短")
        buf = bytearray(payload)
        trailer = len(buf) - 3
        for bit in (0, 4):
            mask = 1 << bit
            if (buf[0] & mask) != (buf[trailer] & mask):
                buf[0] ^= mask
                buf[trailer] ^= mask
        return bytes(buf)

    def encode_text(self, plain: str) -> str:
        try:
            raw = plain.encode("ascii")
        except UnicodeEncodeError:
            raise WpsCipherError("Feature 文本必须是 ASCII: %r" % plain)

        padded = bytearray(((len(raw) // BLOCK_SIZE) + 1) * BLOCK_SIZE)
        padded[: len(raw)] = raw
        enc = b"".join(
            _idea_crypt_block(bytes(padded[o:o + BLOCK_SIZE]), self._subs)
            for o in range(0, len(padded), BLOCK_SIZE)
        )
        digest = hashlib.md5(enc).digest()
        framed = bytearray(enc) + bytes([digest[0], digest[8], 1])
        return c64_encode(self._swap_bits(bytes(framed)))

    def decode_text(self, cipher: str) -> str:
        if not cipher:
            raise DecryptError("Feature 密文为空")
        framed = self._swap_bits(c64_decode(cipher))
        if len(framed) < BLOCK_SIZE + 3 or (len(framed) - 3) % BLOCK_SIZE != 0:
            raise DecryptError("Feature 数据长度非法")

        enc_size = len(framed) - 3
        enc = framed[:enc_size]
        digest = hashlib.md5(enc).digest()
        if (framed[enc_size] != digest[0]
                or framed[enc_size + 1] != digest[8]
                or framed[enc_size + 2] != 1):
            raise DecryptError("Feature 校验失败（数据已损坏或不是密文）")

        plain = b"".join(
            _idea_decrypt_block(enc[o:o + BLOCK_SIZE], self._subs)
            for o in range(0, enc_size, BLOCK_SIZE)
        )
        try:
            return plain.split(b"\x00")[0].decode("ascii")
        except UnicodeDecodeError:
            raise DecryptError("Feature 明文不是合法 ASCII")

    def encrypt_entry(self, feature_id: int, value: int) -> Tuple[str, str]:
        fid = str(int(feature_id))
        return self.encode_text(fid), self.encode_text("%s:%d" % (fid, int(value)))

    def decrypt_entry(self, key: str, value: str) -> Tuple[int, int]:
        fid_text = self.decode_text(key)
        decoded = self.decode_text(value)
        sep = decoded.find(":")
        if sep < 0:
            raise DecryptError("Feature 值缺少 ID 前缀")
        try:
            fid = int(fid_text)
            embedded = int(decoded[:sep])
            val = int(decoded[sep + 1:])
        except ValueError:
            raise DecryptError("Feature 条目不是整数: %r" % decoded)
        if embedded != fid:
            raise DecryptError("Feature 键与值的 ID 不一致 (%d vs %d)" % (fid, embedded))
        return fid, val


# ----------------------------------------------------------------------------
# AES（优先 pycryptodome，否则纯 Python）
# ----------------------------------------------------------------------------

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)
_INV_SBOX = bytes(256)
_inv = bytearray(256)
for _i, _v in enumerate(_SBOX):
    _inv[_v] = _i
_INV_SBOX = bytes(_inv)

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul_gf(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p & 0xFF


def _aes_expand_key(key: bytes) -> List[bytes]:
    nk = len(key) // 4
    if nk not in (4, 6, 8):
        raise ValueError("AES key must be 16/24/32 bytes")
    nr = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    return [bytes(sum(words[4 * r:4 * r + 4], [])) for r in range(nr + 1)]


def _aes_encrypt_block(block: bytes, rk: List[bytes]) -> bytes:
    s = list(block)

    def add_key(k):
        for i in range(16):
            s[i] ^= k[i]

    def sub_bytes():
        for i in range(16):
            s[i] = _SBOX[s[i]]

    def shift_rows():
        # 状态按列优先存储：s[r + 4c]
        for r in range(1, 4):
            row = [s[r + 4 * c] for c in range(4)]
            row = row[r:] + row[:r]
            for c in range(4):
                s[r + 4 * c] = row[c]

    def mix_columns():
        for c in range(4):
            i = 4 * c
            a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
            s[i + 0] = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3
            s[i + 1] = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3
            s[i + 2] = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)
            s[i + 3] = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3)

    nr = len(rk) - 1
    add_key(rk[0])
    for rnd in range(1, nr):
        sub_bytes()
        shift_rows()
        mix_columns()
        add_key(rk[rnd])
    sub_bytes()
    shift_rows()
    add_key(rk[nr])
    return bytes(s)


def _aes_decrypt_block(block: bytes, rk: List[bytes]) -> bytes:
    s = list(block)

    def add_key(k):
        for i in range(16):
            s[i] ^= k[i]

    def inv_sub_bytes():
        for i in range(16):
            s[i] = _INV_SBOX[s[i]]

    def inv_shift_rows():
        for r in range(1, 4):
            row = [s[r + 4 * c] for c in range(4)]
            row = row[-r:] + row[:-r]
            for c in range(4):
                s[r + 4 * c] = row[c]

    def inv_mix_columns():
        for c in range(4):
            i = 4 * c
            a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
            s[i + 0] = (_mul_gf(a0, 14) ^ _mul_gf(a1, 11)
                        ^ _mul_gf(a2, 13) ^ _mul_gf(a3, 9))
            s[i + 1] = (_mul_gf(a0, 9) ^ _mul_gf(a1, 14)
                        ^ _mul_gf(a2, 11) ^ _mul_gf(a3, 13))
            s[i + 2] = (_mul_gf(a0, 13) ^ _mul_gf(a1, 9)
                        ^ _mul_gf(a2, 14) ^ _mul_gf(a3, 11))
            s[i + 3] = (_mul_gf(a0, 11) ^ _mul_gf(a1, 13)
                        ^ _mul_gf(a2, 9) ^ _mul_gf(a3, 14))

    nr = len(rk) - 1
    add_key(rk[nr])
    for rnd in range(nr - 1, 0, -1):
        inv_shift_rows()
        inv_sub_bytes()
        add_key(rk[rnd])
        inv_mix_columns()
    inv_shift_rows()
    inv_sub_bytes()
    add_key(rk[0])
    return bytes(s)


def _aes_ecb_encrypt_py(data: bytes, key: bytes) -> bytes:
    rk = _aes_expand_key(key)
    pad = AES_BLOCK - len(data) % AES_BLOCK
    data = data + bytes([pad]) * pad
    return b"".join(_aes_encrypt_block(data[o:o + AES_BLOCK], rk)
                    for o in range(0, len(data), AES_BLOCK))


def _aes_ecb_decrypt_py(data: bytes, key: bytes) -> bytes:
    if not data or len(data) % AES_BLOCK:
        raise DecryptError("AES 密文长度必须是 16 的倍数（当前 %d）" % len(data))
    rk = _aes_expand_key(key)
    out = b"".join(_aes_decrypt_block(data[o:o + AES_BLOCK], rk)
                   for o in range(0, len(data), AES_BLOCK))
    pad = out[-1]
    if not 1 <= pad <= AES_BLOCK or not out.endswith(bytes([pad]) * pad):
        raise DecryptError("AES 填充校验失败（不是合法密文）")
    return out[:-pad]


class _AesEcb:
    """AES-ECB 封装，自动选择实现。"""

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key 长度必须是 16/24/32 字节")
        self.key = key
        self._rk = None if HAS_PYCRYPTODOME else _aes_expand_key(key)

    def encrypt(self, data: bytes) -> bytes:
        if HAS_PYCRYPTODOME:
            pad = AES_BLOCK - len(data) % AES_BLOCK
            return _AES.new(self.key, _AES.MODE_ECB).encrypt(
                data + bytes([pad]) * pad)
        return _aes_ecb_encrypt_py(data, self.key)

    def decrypt(self, data: bytes) -> bytes:
        if HAS_PYCRYPTODOME:
            if not data or len(data) % AES_BLOCK:
                raise DecryptError(
                    "AES 密文长度必须是 16 的倍数（当前 %d）" % len(data))
            out = _AES.new(self.key, _AES.MODE_ECB).decrypt(data)
            pad = out[-1]
            if not 1 <= pad <= AES_BLOCK or not out.endswith(bytes([pad]) * pad):
                raise DecryptError("AES 填充校验失败（不是合法密文）")
            return out[:-pad]
        return _aes_ecb_decrypt_py(data, self.key)


def _aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-CBC + PKCS#7（用于 OEM 签名）。"""
    pad = AES_BLOCK - len(data) % AES_BLOCK
    padded = data + bytes([pad]) * pad
    if HAS_PYCRYPTODOME:
        return _AES.new(key, _AES.MODE_CBC, iv).encrypt(padded)
    rk = _aes_expand_key(key)
    out = bytearray()
    prev = iv
    for o in range(0, len(padded), AES_BLOCK):
        block = bytes(a ^ b for a, b in zip(padded[o:o + AES_BLOCK], prev))
        prev = _aes_encrypt_block(block, rk)
        out.extend(prev)
    return bytes(out)


# ----------------------------------------------------------------------------
# ProfileValueCipher
# ----------------------------------------------------------------------------

class ProfileValueCipher:
    """普通键值加解密（AES-256-ECB + base64 变体）。"""

    def __init__(self) -> None:
        self._aes = _AesEcb(PROFILE_AES_KEY)

    def encrypt(self, plain: str) -> str:
        raw = self._aes.encrypt(plain.encode("utf-8"))
        return (base64.b64encode(raw).decode("ascii")
                .replace("+", "_").replace("/", "-").replace("=", "."))

    def decrypt(self, cipher: str) -> str:
        if not cipher:
            raise DecryptError("密文为空")
        std = cipher.replace("_", "+").replace("-", "/").replace(".", "=")
        # 允许末尾缺少 padding（WPS 有些条目会省略）
        pad = (-len(std)) % 4
        if pad:
            std += "=" * pad
        try:
            raw = base64.b64decode(std)
        except (binascii.Error, ValueError) as exc:
            raise DecryptError("不是合法的 base64 变体: %s" % exc)
        data = self._aes.decrypt(raw)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise DecryptError("解密结果不是合法 UTF-8（可能不是密文）")


# ----------------------------------------------------------------------------
# OemSignature
# ----------------------------------------------------------------------------

class OemSignature:
    """OemSignType1 签名。"""

    IV_SIZE = 16

    @staticmethod
    def derive_key(machine_guid: str, setup_partial: str,
                   registry_partial: str) -> bytes:
        seed = (machine_guid.encode("utf-8") + KEY_SALT
                + setup_partial.encode("utf-8")
                + registry_partial.encode("utf-8"))
        digest_hex = hashlib.md5(seed).hexdigest().upper().encode("ascii")
        return bytes(digest_hex[i] ^ KEY_MASK[i] for i in range(16))

    @classmethod
    def append(cls, content: bytes, machine_guid: str, setup_partial: str,
               registry_partial: str, iv: Optional[bytes] = None) -> bytes:
        if not machine_guid or not setup_partial or not registry_partial:
            raise WpsCipherError("签名需要 MachineGuid 与两处 InstallPartialData")
        if iv is None:
            iv = os.urandom(cls.IV_SIZE)
        if len(iv) != cls.IV_SIZE:
            raise ValueError("IV 必须是 16 字节")

        digest_hex = hashlib.md5(
            content + SIGNATURE_HEADER.encode("ascii")).hexdigest().upper()
        key = cls.derive_key(machine_guid, setup_partial, registry_partial)
        enc = _aes_cbc_encrypt(digest_hex.encode("ascii"), key, iv)

        payload = bytearray(iv)
        for i in range(cls.IV_SIZE):
            payload[i] ^= IV_MASK[i]
        payload.extend(enc)
        return (content + SIGNATURE_HEADER.encode("ascii")
                + payload.hex().upper().encode("ascii"))


# ----------------------------------------------------------------------------
# 值解包 / 明文判断
# ----------------------------------------------------------------------------

_WRAPPER_FIELDS = ("value", "support", "enable", "filter", "url", "version")
_JSON_KEY_RE = re.compile(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*:\s*')


def unwrap_value(raw: str) -> str:
    """把 {"value":1} 这类包装拆成纯值，用于界面显示与比较。

    注意：这只用于「读出来看」，写回时必须用原始字符串，
    否则会丢失 support/enable/filter 等多字段语义。
    """
    s = (raw or "").strip()
    if not s.startswith("{"):
        return s
    import json as _json
    try:
        obj = _json.loads(s)
    except Exception:
        return s
    if not isinstance(obj, dict):
        return s
    for field in _WRAPPER_FIELDS:
        if field in obj:
            v = obj[field]
            if isinstance(v, bool):
                return "true" if v else "false"
            return str(v)
    return s


def is_wrapped(raw: str) -> bool:
    """值是否是 JSON 包装形式。"""
    s = (raw or "").strip()
    return s.startswith("{") and s.endswith("}")


def looks_like_plaintext(text: str) -> bool:
    """判断一段 INI 文本是否已经是明文。

    判据：尝试对第一个非 feature 的值做 AES 解密，
    成功则认为是密文，失败则是明文。比字符集启发式可靠。
    """
    conv = ProfileConverter()
    for line in text.splitlines():
        s = line.strip().lstrip("\ufeff")
        if not s or s.startswith(("#", ";", "[")) or "=" not in s:
            continue
        key, _, value = s.partition("=")
        value = value.strip()
        if not value:
            continue
        try:
            conv.value_cipher.decrypt(value)
        except Exception:
            return True
        else:
            return False
    return True


# ----------------------------------------------------------------------------
# INI 文档
# ----------------------------------------------------------------------------

class IniEntry:
    """一条 KEY=VALUE。

    同时记录它前面紧邻的注释行 / 空行，以便逐字节还原原文件。
    """
    __slots__ = ("key", "value", "leading")

    def __init__(self, key: str, value: str, leading: Optional[List[str]] = None) -> None:
        self.key = key
        self.value = value
        self.leading: List[str] = leading or []   # 前置行（注释/空行），原样保存

    def __repr__(self) -> str:
        return "IniEntry(%r, %r)" % (self.key, self.value)


class IniSection:
    __slots__ = ("name", "entries", "leading")

    def __init__(self, name: str, leading: Optional[List[str]] = None) -> None:
        self.name = name
        self.entries: List[IniEntry] = []
        self.leading: List[str] = leading or []   # 段名之前的行


class IniDocument:
    """行级保序的 INI 文档模型。

    每个 section / entry 都记录其**前置行**（注释与空行），
    序列化时原样写回，因此能逐字节还原任何格式的 oem.ini
    （包括段中间穿插大量注释的安装器配置）。
    """

    def __init__(self) -> None:
        self.sections: List[IniSection] = []
        self.head: List[str] = []        # 首个 section 之前的全部行
        self.tail: List[str] = []        # 最后一个条目之后的全部行
        self.had_bom: bool = False
        self.ends_with_newline: bool = True
        self.line_ending: str = "\n"

    @classmethod
    def parse(cls, text: str) -> "IniDocument":
        doc = cls()
        if text.startswith("\ufeff"):
            doc.had_bom = True
            text = text[1:]

        # 探测换行风格
        crlf = text.count("\r\n")
        lf = text.count("\n") - crlf
        doc.line_ending = "\r\n" if crlf >= lf and crlf else "\n"
        doc.ends_with_newline = text.endswith(("\n", "\r"))

        lines = text.split("\n")
        # 去掉因 split 产生的末尾空元素
        if lines and lines[-1] == "":
            lines.pop()
        # 逐行还原为不带 \r 的形式
        lines = [l[:-1] if l.endswith("\r") else l for l in lines]

        current: Optional[IniSection] = None
        pending: List[str] = []          # 待归属的注释/空行

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith((";", "#")):
                pending.append(line)
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                sec = IniSection(stripped[1:-1].strip(), pending)
                doc.sections.append(sec)
                current = sec
                pending = []
                continue
            if "=" not in line:
                # 非标准行：当作注释保留
                pending.append(line)
                continue
            if current is None:
                raise WpsCipherError("INI 格式错误：条目出现在任何 [section] 之前")
            key, _, value = line.partition("=")
            current.entries.append(IniEntry(key.strip(), value, pending))
            pending = []

        # 剩余行：若还没遇到过 section，则都是文件头；否则是文件尾
        if not doc.sections:
            doc.head = pending
        else:
            doc.tail = pending
        return doc

    def serialize(self, line_ending: str = "\n") -> str:
        out: List[str] = []

        def emit(line: str):
            out.append(line + line_ending)

        for line in self.head:
            emit(line)
        for sec in self.sections:
            for line in sec.leading:
                emit(line)
            emit("[%s]" % sec.name)
            for e in sec.entries:
                for line in e.leading:
                    emit(line)
                emit("%s=%s" % (e.key, e.value))
        for line in self.tail:
            emit(line)

        text = "".join(out)
        if not self.ends_with_newline and text.endswith(line_ending):
            text = text[:-len(line_ending)]
        if self.had_bom:
            text = "\ufeff" + text
        return text

    def find_section(self, name: str) -> Optional[IniSection]:
        for section in self.sections:
            if section.name.lower() == name.lower():
                return section
        return None

    def find_section(self, name: str) -> Optional[IniSection]:
        for section in self.sections:
            if section.name.lower() == name.lower():
                return section
        return None


# ----------------------------------------------------------------------------
# 列表值处理
# ----------------------------------------------------------------------------

_NUMERIC_INDEX_RE = re.compile(r"\[\d+\]$")


def has_numeric_index_suffix(key: str) -> bool:
    """判断键是否以 [数字] 结尾，用于识别「值按逗号拆成多项」的列表项。

    注意：INDEX[zh_TW][6] 这类键虽然以 [6] 结尾，但它是「带语言和序号的多级键」，
    其值 '插入索引,5,0,3,2,0' 是一个整体，不能按逗号拆开。
    因此额外要求：去掉结尾 [数字] 后，剩余部分不再以 [ 结尾。
    """
    m = _NUMERIC_INDEX_RE.search(key)
    if not m:
        return False
    head = key[: m.start()]
    # INDEX[zh_TW][6] -> head = "INDEX[zh_TW]" ，仍以 ] 结尾 => 不是列表项
    if head.endswith("]"):
        return False
    return True


def _find_trailing_list_separators(text: str) -> set:
    """找出值以逗号结尾的条目（section\\0key）。"""
    result = set()
    section = ""
    for raw_line in text.splitlines():
        line = raw_line.lstrip("\ufeff")
        stripped = line.strip()
        if not stripped or stripped[0] in ";#":
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            continue
        if "=" not in line or not section:
            continue
        key, _, value = line.partition("=")
        if value.rstrip().endswith(","):
            result.add(section + "\0" + key.strip())
    return result


def _split_plain_by_count(value: str, count: int):
    """把明文按「已知段数」切成 count 份。

    WPS 的列表项通常是「一个含逗号的格式串 + 若干独立数字」，
    所以当按 ", " 切出的份数多于 count 时，**从右往左**合并，
    保留右侧的独立项、把左侧合并成一个。

    例：count=2
        'MMM. d, yy, 1033' -> ['MMM. d, yy', '1033']
        'a, b, c'          -> ['a, b', 'c']
    """
    if count <= 1:
        return [value]

    for sep in (", ", ","):
        parts = value.split(sep)
        if len(parts) == count:
            return [p.strip() for p in parts]
        if len(parts) > count:
            # 从右往左合并：右侧 count-1 段各占一份，左侧全部合并
            keep = parts[len(parts) - (count - 1):]
            head = sep.join(parts[: len(parts) - (count - 1)])
            return [p.strip() for p in [head] + keep]

    return [value]


def _transform_list(value: str, count: int, fn, sep: str = ", ",
                    trailing: bool = False, tail_space: str = "") -> str:
    """按已知段数把明文切分、逐段应用 fn、再用原分隔符拼回。"""
    body = value
    if trailing and body.rstrip().endswith(","):
        body = body.rstrip()[:-1]

    parts = _split_plain_by_count(body, count)
    out = sep.join(fn(p.strip()) for p in parts)
    if trailing:
        out += "," + tail_space
    return out


# ----------------------------------------------------------------------------
# 文档级转换
# ----------------------------------------------------------------------------

def _looks_like_plain_list(value: str) -> bool:
    """[已弃用] 明文层无法可靠判断列表，请用 ListInfo 元数据。

    保留此函数仅为向后兼容；新代码一律使用 _transform_list + ListInfo。
    """
    return False


class ListInfo:
    """记录「哪些键的值是逗号分隔的多个密文」。

    关键：只记录**段数**与分隔符，加密时按段数把明文切成同样份数。
    不能靠逗号猜——'MMM. d, yy, 1033' 是 2 段（第 1 段自身含逗号），
    而 'a, b, c' 是 3 段，光看明文无法区分。
    """

    def __init__(self) -> None:
        # key -> (段数, 分隔符, 是否以逗号结尾, 结尾逗号后的空白)
        self._items: Dict[str, Tuple[int, str, bool, str]] = {}
        # 原本就是明文的条目（段\0键）
        self._plain: set = set()
        # Feature 段原本是密文的条目：段\0fid -> (raw_key, raw_value)
        self._feature_raw: Dict[str, Tuple[str, str]] = {}

    def mark(self, section: str, key: str, count: int, sep: str,
             trailing: bool, tail_space: str = "") -> None:
        self._items[section + "\0" + key] = (count, sep, trailing, tail_space)

    def get(self, section: str, key: str):
        return self._items.get(section + "\0" + key)

    def mark_plain(self, section: str, key: str) -> None:
        self._plain.add(section + "\0" + key)

    def is_plain(self, section: str, key: str) -> bool:
        return (section + "\0" + key) in self._plain

    def mark_feature_cipher(self, section: str, fid: str,
                            raw_key: str, raw_value: str) -> None:
        """记录 Feature 段原本就是密文的条目，加密时原样还原。"""
        self._feature_raw[section + "\0" + fid] = (raw_key, raw_value)

    def get_feature_raw(self, section: str, fid: str):
        return self._feature_raw.get(section + "\0" + fid)

    def __bool__(self) -> bool:
        return bool(self._items) or bool(self._plain)

    def __len__(self) -> int:
        return len(self._items) + len(self._plain)


def _is_single_cipher(cipher: "ProfileValueCipher", value: str,
                      trailing_comma: bool) -> bool:
    """判断含逗号的值整体是否就是一个合法密文。"""
    probe = value.rstrip()
    if trailing_comma and probe.endswith(","):
        probe = probe[:-1]
    try:
        cipher.decrypt(probe)
    except Exception:
        return False
    return True


class ProfileConverter:
    """oem.ini 级别的整体加解密。"""

    def __init__(self) -> None:
        self.value_cipher = ProfileValueCipher()
        self.feature_codec = FeatureCodec()

    def decrypt_document(self, cipher_text: str, line_ending: str = "\n",
                         list_info: Optional[ListInfo] = None) -> str:
        """解密。若传入 list_info，会记录每行的列表结构供加密时复用。

        对个别「已经是明文」的条目（官方配置里确实存在这种混合情况，
        例如 IsUsingBetaVersion=false 与其它加密项共存）保留原样，
        不中断整体解密——WPS 自身也是按项容错解析的。
        """
        doc = IniDocument.parse(cipher_text)

        for section in doc.sections:
            if section.name.lower() == "feature":
                for entry in section.entries:
                    if entry.key.lstrip("-").isdigit():
                        continue          # 已是明文数字 ID
                    try:
                        fid, val = self.feature_codec.decrypt_entry(entry.key, entry.value)
                    except WpsCipherError:
                        continue
                    # 记录：这个键原本是密文，加密时应还原成同样的密文
                    if list_info is not None:
                        list_info.mark_feature_cipher(section.name, str(fid),
                                                      entry.key, entry.value)
                    entry.key = str(fid)
                    entry.value = str(val)
            else:
                for entry in section.entries:
                    try:
                        plain_key = self.value_cipher.decrypt(entry.key)
                    except WpsCipherError:
                        # 键本身是明文，整条保留
                        if list_info is not None:
                            list_info.mark_plain(section.name, entry.key)
                        continue
                    entry.key = plain_key
                    if not entry.value:
                        continue
                    try:
                        count, sep, trailing, tail_space, is_list = \
                            self._analyze_list_value(entry.value)
                        if is_list:
                            if list_info is not None:
                                list_info.mark(section.name, entry.key, count, sep,
                                               trailing, tail_space)
                            entry.value = _transform_list(
                                entry.value, count, self.value_cipher.decrypt,
                                sep, trailing, tail_space)
                        else:
                            entry.value = self.value_cipher.decrypt(entry.value)
                    except WpsCipherError:
                        # 值本身是明文，保留原样
                        if list_info is not None:
                            list_info.mark_plain(section.name, entry.key)
        return doc.serialize(line_ending)

    def _analyze_list_value(self, value: str):
        """判断密文值是否由多个密文用 ", " 连接。

        返回 (段数, 分隔符, 是否以逗号结尾, 结尾空白, 是否列表)。
        依据 WPS 实际数据：列表项用 ", " 分隔，每段都是独立密文。
        """
        trimmed = value.rstrip()
        tail_space = value[len(trimmed):]
        trailing = trimmed.endswith(",")
        probe = trimmed[:-1] if trailing else trimmed

        if "," not in probe:
            try:
                self.value_cipher.decrypt(probe)
                return 1, ", ", trailing, tail_space, False
            except Exception:
                raise DecryptError("无法解密的值: %r" % value[:60])

        # 优先按 ", "（逗号+空格）拆，这是 WPS 的真实分隔符
        parts = probe.split(", ")
        if len(parts) >= 2:
            ok = True
            for p in parts:
                try:
                    self.value_cipher.decrypt(p)
                except Exception:
                    ok = False
                    break
            if ok:
                return len(parts), ", ", trailing, tail_space, True

        # 退化：按 "," 拆
        parts2 = [p.strip() for p in probe.split(",") if p.strip()]
        if len(parts2) >= 2:
            ok = True
            for p in parts2:
                try:
                    self.value_cipher.decrypt(p)
                except Exception:
                    ok = False
                    break
            if ok:
                return len(parts2), ",", trailing, tail_space, True

        try:
            self.value_cipher.decrypt(probe)
            return 1, ", ", trailing, tail_space, False
        except Exception:
            raise DecryptError("无法解密的值: %r" % value[:60])

    def encrypt_document(self, plain_text: str, line_ending: str = "\n",
                         header_comment: Optional[str] = None,
                         list_info: Optional[ListInfo] = None) -> str:
        """加密。若传入 list_info（来自同一份文件的解密），
        会按记录的结构还原列表值；否则所有值都作为整体加密。"""
        if header_comment and ("\n" in header_comment or "\r" in header_comment):
            raise WpsCipherError("头部注释不能包含换行")

        doc = IniDocument.parse(plain_text)

        for section in doc.sections:
            if section.name.lower() == "feature":
                for entry in section.entries:
                    # Feature 段的键可能是数字 ID，也可能仍是密文
                    # （官方明文配置里就有这种：key 是密文、value 是密文）
                    if entry.key.lstrip("-").isdigit():
                        # 若原本就是密文，且值没变，直接还原原密文
                        raw = (list_info.get_feature_raw(section.name, entry.key)
                               if list_info else None)
                        if raw is not None:
                            try:
                                same = int(entry.value) == int(
                                    self.feature_codec.decrypt_entry(*raw)[1])
                            except Exception:
                                same = False
                            if same:
                                entry.key, entry.value = raw
                                continue
                        try:
                            fid = int(entry.key)
                            val = int(entry.value)
                        except ValueError:
                            continue
                        entry.key, entry.value = self.feature_codec.encrypt_entry(fid, val)
                    else:
                        continue
            else:
                for entry in section.entries:
                    # 原本就是明文的条目（解密时标记过）保持明文
                    if list_info is not None and list_info.is_plain(section.name, entry.key):
                        continue
                    meta = list_info.get(section.name, entry.key) if list_info else None
                    entry.key = self.value_cipher.encrypt(entry.key)
                    if meta is not None:
                        count, sep, trailing, tail_space = meta
                        entry.value = _transform_list(
                            entry.value, count, self.value_cipher.encrypt,
                            sep, trailing, tail_space)
                    else:
                        entry.value = self.value_cipher.encrypt(entry.value)

        output = doc.serialize(line_ending)
        if header_comment:
            output = ";" + header_comment + line_ending + line_ending + output
        return output

    def sign_document(self, cipher_text: str, machine_guid: str,
                      setup_partial: str, registry_partial: str) -> str:
        signed = OemSignature.append(cipher_text.encode("utf-8"), machine_guid,
                                     setup_partial, registry_partial)
        return signed.decode("latin-1")

    # -- 便捷 API：一次调用完成「解密 + 记录结构」----------------------------

    def decrypt_with_meta(self, cipher_text: str, line_ending: str = "\n"):
        """解密并返回 (明文, ListInfo)。加密时把 ListInfo 传回即可精确还原。"""
        info = ListInfo()
        plain = self.decrypt_document(cipher_text, line_ending, list_info=info)
        return plain, info


# ----------------------------------------------------------------------------
# 配置分析
# ----------------------------------------------------------------------------

LICENSE_KEYS = (
    "PresetSerialNumber", "SerialInfo", "NormalSerialNumber",
    "ProductIdentifier", "ProductIdentifierCollect", "ActivateCode",
    "LicenseKey", "SubPlatform", "ProductDefinition",
)

FEATURE_KEYS = (
    "OfdComponent", "forbidEditInForceLogin", "WPS365ForceLogin",
    "AccountWPS365ForceLogin", "AutoOpenEduWorkbench", "CompanyTabButton",
    "PromeDocerTabButton", "InstallWithXieZuo", "SetupLogo", "PipeNumber",
    "OfficialMode", "OfficialModeEntry", "OfficialTemplateEntry",
    "OfficialPrintingEntry", "CommonOfficeAssistant", "OnlineWithoutCloudDoc",
    "ChangePromethusMode", "PromeDefaultUseIndependMode", "GlobalInfoCollect",
    "ReduceOfficialTemplateCount", "ShowCloseTabTips", "IsCreateNewFile",
    "CopyrightVersion", "IsNeedSystemChecker", "EnableOemFileAesSignatureVerification",
    "DisableMainResourceVerification",
)


class SignatureInfo:
    def __init__(self, kind: str, line: str, line_no: int) -> None:
        self.kind = kind
        self.line = line
        self.line_no = line_no

    @property
    def hex_len(self) -> int:
        return len(self.line.lstrip(";").strip())

    @property
    def byte_len(self) -> int:
        return self.hex_len // 2

    def __repr__(self) -> str:
        return "SignatureInfo(%s, %d bytes)" % (self.kind, self.byte_len)


class ConfigAnalysis:
    def __init__(self) -> None:
        self.signatures: List[SignatureInfo] = []
        self.license_keys: List[str] = []
        self.feature_keys: List[str] = []
        self.sections: List[str] = []
        self.entry_count = 0
        self.feature_entry_count = 0
        self.has_bom = False
        self.line_ending = "LF"
        self.warnings: List[str] = []
        self.notes: List[str] = []
        self.encrypted: Optional[bool] = None

    @property
    def risk_level(self) -> str:
        if any(s.kind == "VendorAes" for s in self.signatures):
            return "高"
        if any(s.kind == "OemSignType1" for s in self.signatures):
            return "中"
        if self.license_keys:
            return "中"
        return "低"

    def summary_lines(self) -> List[str]:
        out = ["风险等级: %s" % self.risk_level, ""]
        out.append("文件结构")
        out.append("  段数量: %d  (%s)"
                   % (len(self.sections), ", ".join(self.sections) or "无"))
        out.append("  条目总数: %d" % self.entry_count)
        out.append("  [feature] 条目: %d" % self.feature_entry_count)
        out.append("  BOM: %s" % ("有" if self.has_bom else "无"))
        out.append("  换行符: %s" % self.line_ending)
        if self.encrypted is not None:
            out.append("  内容: %s" % ("已加密" if self.encrypted else "明文"))
        out.append("")

        out.append("签名检测")
        if not self.signatures:
            out.append("  未检测到签名行")
            out.append("  → 修改后重新加密即可，WPS 不做签名校验")
        else:
            for sig in self.signatures:
                out.append("  第 %d 行: %s  (%d 字节 / %d hex)"
                           % (sig.line_no, sig.kind, sig.byte_len, sig.hex_len))
            if any(s.kind == "VendorAes" for s in self.signatures):
                out.append("  → 厂商 AES 签名，改动内容后签名将不再匹配")
                out.append("     WPS 可能拒绝加载或回退默认配置，请先备份")
            elif any(s.kind == "OemSignType1" for s in self.signatures):
                out.append("  → OemSignType1 签名，需要目标机器三要素才能重签")
        out.append("")

        out.append("授权相关字段")
        if self.license_keys:
            for k in self.license_keys:
                out.append("  ⚠ %s" % k)
            out.append("  → 与激活状态有关，建议不要修改")
        else:
            out.append("  未发现授权字段")
            out.append("  → 可安全修改功能开关")
        out.append("")

        out.append("功能开关字段")
        out.extend("  · %s" % k for k in self.feature_keys) if self.feature_keys \
            else out.append("  无")
        out.append("")

        if self.warnings:
            out.append("警告")
            out.extend("  ! %s" % w for w in self.warnings)
            out.append("")
        if self.notes:
            out.append("说明")
            out.extend("  - %s" % n for n in self.notes)
        return out


def analyze_config(cipher_text: str, plain_text: Optional[str] = None,
                   raw_bytes: Optional[bytes] = None) -> ConfigAnalysis:
    result = ConfigAnalysis()

    if raw_bytes is not None:
        result.has_bom = raw_bytes.startswith(b"\xef\xbb\xbf")
        crlf = raw_bytes.count(b"\r\n")
        bare_lf = raw_bytes.count(b"\n") - crlf
    else:
        result.has_bom = cipher_text.startswith("\ufeff")
        crlf = cipher_text.count("\r\n")
        bare_lf = cipher_text.count("\n") - crlf

    if crlf and bare_lf:
        result.line_ending = "混合 (CRLF %d / LF %d)" % (crlf, bare_lf)
    elif crlf:
        result.line_ending = "CRLF"
    else:
        result.line_ending = "LF"

    # 签名行
    for idx, line in enumerate(cipher_text.splitlines(), 1):
        stripped = line.strip()
        if not stripped.startswith(";"):
            continue
        body = stripped[1:].strip()
        if len(body) < 64:
            continue
        if not all(c in "0123456789ABCDEFabcdef" for c in body):
            continue
        if body.startswith("OemSignType1="):
            result.signatures.append(SignatureInfo("OemSignType1", stripped, idx))
        elif len(body) >= 480:
            result.signatures.append(SignatureInfo("VendorAes", stripped, idx))
        else:
            result.signatures.append(SignatureInfo("Unknown", stripped, idx))

    try:
        doc = IniDocument.parse(cipher_text)
    except Exception as exc:
        result.warnings.append("INI 解析失败: %s" % exc)
        return result

    result.sections = [s.name for s in doc.sections]
    result.entry_count = sum(len(s.entries) for s in doc.sections)
    for s in doc.sections:
        if s.name.lower() == "feature":
            result.feature_entry_count = len(s.entries)

    if plain_text is None:
        if looks_like_plaintext(cipher_text):
            plain_text = cipher_text
            result.encrypted = False
        else:
            try:
                plain_text = ProfileConverter().decrypt_document(cipher_text)
                result.encrypted = True
            except Exception as exc:
                result.warnings.append("无法解密，跳过字段分析: %s" % exc)
                return result

    low = plain_text.lower()
    result.license_keys = [k for k in LICENSE_KEYS if k.lower() in low]
    result.feature_keys = [k for k in FEATURE_KEYS if k.lower() in low]

    if result.feature_entry_count:
        result.notes.append("[feature] 段共 %d 条开关，修改后重新加密即可"
                            % result.feature_entry_count)
    return result


# ----------------------------------------------------------------------------
# 自检
# ----------------------------------------------------------------------------

def _selftest() -> None:
    print("=== IDEA 标准向量 ===")
    key = bytes.fromhex("00010002000300040005000600070008")
    pt = bytes.fromhex("0000000100020003")
    subs = _idea_expand_key(key)
    ct = _idea_crypt_block(pt, subs)
    assert ct.hex().upper() == "11FBED2B01986DE5", ct.hex()
    assert _idea_decrypt_block(ct, subs) == pt
    print("  OK")

    print("=== Feature 往返 ===")
    fc = FeatureCodec()
    for fid, val in [(0, 0), (-1, -1), (1, 0), (12345, 999),
                     (16777345, 1), (2147483647, 2147483647)]:
        k, v = fc.encrypt_entry(fid, val)
        assert fc.decrypt_entry(k, v) == (fid, val), (fid, val)
    print("  OK")

    print("=== AES-128 FIPS-197 ===")
    rk = _aes_expand_key(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    out = _aes_encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff"), rk)
    assert out.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", out.hex()
    assert _aes_decrypt_block(out, rk).hex() == "00112233445566778899aabbccddeeff"
    print("  OK")

    print("=== AES-256 FIPS-197 ===")
    rk = _aes_expand_key(bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
    out = _aes_encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff"), rk)
    assert out.hex() == "8ea2b7ca516745bfeafc49904b496089", out.hex()
    print("  OK")

    print("=== Profile 往返 ===")
    pc = ProfileValueCipher()
    for s in ["hello", "Support/OpenTrailMode", "中文测试", "a" * 100]:
        assert pc.decrypt(pc.encrypt(s)) == s, s
    print("  OK")

    print("=== 非法密文必须报错 ===")
    for bad in ["abc", "aGVsbG8=", "!!!!"]:
        try:
            pc.decrypt(bad)
        except DecryptError:
            pass
        else:
            raise AssertionError("应当拒绝: %r" % bad)
    print("  OK")

    print("=== 文档往返（含 BOM / 注释 / 签名）===")
    conv = ProfileConverter()
    src = ("\ufeff;/DWPS_SETUP\n\n[default]\n"
           "OfficialMode={\"support\" : true, \"enable\" : true, \"filter\" : false}\n"
           "List[0]=a, b, c\nList[1]=d, e,\n\n"
           ";0E3813033B4345F3474A1EEE9E77C1B4\n")
    enc = conv.encrypt_document(src)
    dec = conv.decrypt_document(enc)
    assert dec == src, "\n期望:%r\n实际:%r" % (src, dec)
    print("  OK")

    print("\n全部自检通过。pycryptodome: %s" % ("已启用" if HAS_PYCRYPTODOME else "未安装，使用内置实现"))


if __name__ == "__main__":
    _selftest()
