# WPS 配置文件加解密工具 v2.0

WPS Office `oem.ini` / `product.dat` 的加解密、签名与可视化配置编辑工具。

**算法核心零第三方依赖**（IDEA 与 AES 均为内置实现）。

算法与 [NixaVulpi/WPSProfileCipher](https://github.com/NixaVulpi/WPSProfileCipher) 一致，
参数说明来自雨糖科技 [WPSOfficeConf](https://github.com/RainCandyTech/WPSOfficeConf)。

---

## 依赖清单

### Python 标准库（无需安装）

`base64` `binascii` `hashlib` `os` `re` `io` `json` `typing` `argparse` `traceback`

### 第三方库

| 库 | 必需性 | 用途 | 缺失时 |
|---|---|---|---|
| **PyQt5** | **必需** | 图形界面 | 无法启动 GUI；`--check`/`--selftest` 仍可用 |
| **pycryptodome** | 可选 | AES 加速约 165× | 自动降级为内置纯 Python AES，功能完全等价 |

```bash
sudo apt install python3-pyqt5           # 必需
sudo apt install python3-pycryptodome    # 可选，强烈建议
```

### 性能参考（麒麟 V10 / aarch64 / 4 核）

| 场景 | 有 pycryptodome | 纯 Python |
|---|---|---|
| oem.ini (5KB) 解密 | **7.3 ms** | ~800 ms |
| oem.ini (5KB) 加密 | 12.6 ms | ~110 ms |
| product.dat (71KB) 解密 | ~150 ms | ~13 s |

---

## 启动

### 图形界面

```bash
./run.sh
```

### 命令行（不依赖 PyQt5）

```bash
./run.sh --cli info oem.ini
# 或
python3 wps_cipher_cli.py info oem.ini
```

**完整命令列表**：

```bash
wps-cipher info <文件>                     # 文件信息与风险分析
wps-cipher decrypt <文件> [-o 输出]         # 解密
wps-cipher encrypt <文件> [-o 输出]         # 加密
wps-cipher dump <文件>                     # 明文输出到 stdout
wps-cipher get <文件> <段> <键>             # 读取单项
wps-cipher set <文件> <段> KEY=VALUE        # 修改单项
wps-cipher verify <文件>                   # 往返校验
wps-cipher selftest                        # 算法自检
wps-cipher batch-verify <目录>              # 批量校验
```

示例：

```bash
# 查看配置
wps-cipher info /opt/kingsoft/wps-office/office6/cfgs/oem.ini

# 改一个开关
wps-cipher decrypt oem.ini -o plain.ini
wps-cipher set plain.ini support EducationVersion=false -o mod.ini
wps-cipher encrypt mod.ini -o new_oem.ini
wps-cipher verify new_oem.ini
```

**详细文档**：[docs/USAGE.md](docs/USAGE.md)

## 功能

### 1. 文件转换

- **解密 → 明文**：输出 `<原名>.decrypted.ini`
- **加密 → 密文**：输出 `<原名>.encrypted.ini`
- **分析当前文件**：跳转到分析页
- 选中文件后自动显示**风险提示条**（绿/黄/红）

### 2. 参数编辑器

359 个参数全部可视化，11 个分组：

| 分组 | 数量 | | 分组 | 数量 |
|---|---|---|---|---|
| 功能开关 | 199 | | 文档与模板 | 14 |
| 界面与外观 | 34 | | 升级与更新 | 10 |
| 版本标识 | 30 | | 登录与账户 | 8 |
| 服务器配置 | 17 | | 授权与签名 | 7 |
| 云服务与在线 | 18 | | 高级特性 | 6 |
| 隐私与数据收集 | 16 | | | |

**控件类型**：勾选框 281 / 输入框 51 / 数字框 22 / 下拉框 5

**三个内层页签**：
- **图形编辑**：勾选/下拉/输入，带中文说明
- **自定义参数**：填写参数库没有的新选项，支持三种值写法
- **Feature 段**：直接编辑 `[feature]` 段的数字 ID

**核心特性**：
- 值存放在独立数据源，切换分组/搜索**不会丢失修改**
- 从 oem.ini 读取时**保留原始 JSON 结构**（`enable`/`filter` 不丢失）
- 导出时**原样保留参数库没有的条目**
- 自定义参数与已知参数同名时**覆盖**而非重复
- 高风险项（授权相关）默认隐藏，可勾选显示

### 3. 配置分析

输出文件结构、签名检测、授权字段、功能开关、风险等级。

**风险分级**：
- **低** — 无签名、无授权字段
- **中** — 有授权字段，或带 `OemSignType1` 签名
- **高** — 带厂商 AES 签名（256 字节）

### 4. 读取流程

说明 WPS 如何读取与校验 oem.ini，内容来自对 `libkrt.so` 的静态分析。

### 5. 文本编解码

- **profile 模式**：任意文本 ↔ AES-256-ECB
- **feature 模式**：`id=value` ↔ IDEA
- **批量解码**

### 6. OEM 签名

为文件追加 `OemSignType1` 签名，需要 MachineGuid + 两处 InstallPartialData。

---

## 算法

### `[feature]` 段 — IDEA

```
密钥 = MD5("wps")                    (16 字节)
明文 → IDEA-ECB（补零到 8 字节）
     → 追加 3 字节 (md5[0], md5[8], 0x01)
     → 首字节与 trailer 首字节交换 bit0 / bit4
     → 自定义 base64  (0123456789A-Za-z-_)
```

条目语义：`<feature_id>=<value>`，均为十进制整数，值内部编码为 `"<id>:<value>"`。

### 普通键值 — AES-256-ECB

```
密钥 = "F9AF610AE6164C73B78B0A99D8B72890"   (32 字节 ASCII)
PKCS#7 填充
输出 = base64 后替换:  '+' → '_'   '/' → '-'   '=' → '.'
```

### OemSignType1 签名

```
digest = MD5(content + ";OemSignType1=") 的大写十六进制
key    = MD5(MachineGuid + salt + setupPartial + registryPartial)
         的大写十六进制前 16 字符，逐字节 XOR KEY_MASK
载荷   = (IV XOR "S3kP06v2Ne04lDeX") + AES-CBC(digest, key, IV)
```

---

## 关于机器绑定

**oem.ini 的加密不绑定机器。** 实测：麒麟 aarch64 的 oem.ini 拿到 Windows 上
可正常解密，重新加密后 MD5 完全一致。密钥是全局固定的。

可能与机器相关的是：

1. **授权字段**（`PresetSerialNumber` 等）—— 加密的序列号，是否绑定取决于
   WPS 授权模块，不在 oem.ini 加密层
2. **厂商 AES 签名**（`;0E38...`）—— 256 字节，由 `KOemAesSignatureBase` 校验。
   改了内容签名就对不上，风险高

---

## 测试

```bash
# 核心测试（不需要图形环境）
python3 tests/run_tests.py --only core

# GUI 测试（需要 DISPLAY）
DISPLAY=:10 python3 tests/run_tests.py --only gui

# 全部
DISPLAY=:10 python3 tests/run_tests.py
```

**当前状态：119 项测试全部通过。**

覆盖：
- IDEA / AES 标准测试向量（FIPS-197）
- 49 个官方配置样本的字节级往返
- 边界条件（BOM / 空值 / 中文 / 列表 / 多级键 / 注释）
- 异常处理（非法密文 / 错误长度 / 损坏数据）
- 属性测试（200 组随机文档）
- GUI 状态机（值持久化 / 分组筛选 / 导出完整性）

---

## 已验证

在 ssh20（麒麟 V10 SP1 / aarch64）实测：

- **49 个官方配置样本全部字节级还原**（12 个版本系列，含内测/外发/PDF 专用）
- 本机 Windows 教育版 oem.ini：2943 字节，MD5 完全一致
- ssh20 麒麟教育版 oem.ini：5188 字节，MD5 完全一致
- product.dat：71014 字节，含 106 个列表项，字节级一致
- 改 1 项参数，导出后仅该 1 项变化，其余 59 项原封不动

---

## 注意

- 解密后的文件**不覆盖原文件**，另存为 `*.decrypted.ini`
- 改带厂商 AES 签名的文件前**务必备份**
- 签名必须使用目标机器自己的三个材料
- 本工具仅用于分析与运维自己的 WPS 部署
