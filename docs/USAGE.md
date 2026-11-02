# WPS 配置文件工具 —— 使用手册

版本 2.0 ｜ 适用于 WPS Office 10 / 11 / 12 系列（含专业版、教育版、定制版）

---

## 目录

1. [安装与依赖](#1-安装与依赖)
2. [图形界面](#2-图形界面)
3. [命令行](#3-命令行)
4. [典型场景](#4-典型场景)
5. [参数说明](#5-参数说明)
6. [算法与格式](#6-算法与格式)
7. [故障排查](#7-故障排查)
8. [常见问题](#8-常见问题)

---

## 1. 安装与依赖

### 1.1 环境要求

| 项目 | 要求 |
|---|---|
| Python | 3.6 及以上 |
| 操作系统 | Linux（x86_64 / aarch64）、Windows、macOS |
| 图形界面 | 需要 PyQt5（仅 GUI 需要） |

已在 **银河麒麟 V10 SP1 / aarch64 / Python 3.8.10** 实测通过。

### 1.2 依赖

**Python 标准库**（无需安装）：

```
base64  binascii  hashlib  os  re  io  json  typing
argparse  traceback  random  string  tempfile
```

**第三方库**：

| 库 | 必需性 | 用途 | 缺失时的影响 |
|---|---|---|---|
| **PyQt5** | GUI 必需 | 图形界面框架 | 图形界面无法启动；**命令行仍可用** |
| **pycryptodome** | 可选 | AES 加速约 165 倍 | 自动降级为内置纯 Python AES，功能完全等价，但慢 |

```bash
# 麒麟 / Ubuntu / Debian
sudo apt install python3-pyqt5           # GUI 必需
sudo apt install python3-pycryptodome    # 可选，强烈建议
```

### 1.3 部署

```bash
# 解压到任意目录
tar -xzf wps-cipher-2.0.tar.gz
cd wps-cipher-2.0

# 可选：安装为系统命令
sudo cp wps_cipher_cli.py /usr/local/bin/wps-cipher
sudo chmod +x /usr/local/bin/wps-cipher
```

### 1.4 验证安装

```bash
python3 wps_cipher_cli.py selftest
```

预期输出：

```
=== IDEA 标准向量 ===
  OK
=== AES-128 FIPS-197 ===
  OK
=== AES-256 FIPS-197 ===
  OK
=== Feature 往返 ===
  OK
=== Profile 往返 ===
  OK
=== 非法密文必须报错 ===
  OK
=== 文档往返（含 BOM / 注释 / 签名）===
  OK

全部自检通过。pycryptodome: 已启用
```

---

## 2. 图形界面

### 2.1 启动

```bash
cd wps-cipher-2.0
./run.sh
```

或：

```bash
python3 wps_cipher_gui.py
```

### 2.2 界面概览

七个页签：

| 页签 | 用途 |
|---|---|
| 文件转换 | 解密 / 加密 / 分析 |
| 参数编辑器 | 359 个参数可视化编辑 |
| 配置分析 | 结构、签名、风险分析 |
| 读取流程 | WPS 加载机制说明 |
| 文本编解码 | 单个值 / 批量解码 |
| OEM 签名 | 追加 OemSignType1 签名 |
| 关于 | 算法说明 + 内置自检 |

### 2.3 文件转换

1. 点「浏览…」选择 `oem.ini` 或 `product.dat`
2. 选择换行符（LF / CRLF）
3. 点「解密 → 明文」或「加密 → 密文」

**选中文件后会显示风险提示条**：

- 🟢 **低风险**：无签名、无授权字段，可安全修改
- 🟡 **中风险**：有授权字段或 OemSignType1 签名
- 🔴 **高风险**：带厂商 AES 签名，改动后签名失效

输出文件不覆盖原文件：
- 解密 → `<原名>.decrypted.ini`
- 加密 → `<原名>.encrypted.ini`

### 2.4 参数编辑器

**三个内层页签**：

#### 图形编辑

左侧分组树，右侧参数列表。每个参数一行：

```
EducationVersion    ☑    指定是否为教育版，会启用部分专有功能
SubPlatform        [1▼]  指定程序的子平台版本 — 1:AK 2:JK 3:ZYJ
TotalTrialDays   [2147483647]  指定程序总共可以试用多少天
KSNUpdateServerUrl [http://...] 指定自定义序列号检查服务器
```

**控件类型**：

| 类型 | 外观 | 说明 |
|---|---|---|
| 布尔 | 勾选框 | 281 项 |
| 整数 | 数字框 | 22 项 |
| 文本 / URL | 输入框 | 51 项 |
| 枚举 | 下拉框 | 5 项 |

**工具条**：

- **搜索**：按参数名或说明实时过滤（250ms 防抖）
- **显示高风险项**：授权相关参数默认隐藏
- **只看改动**：只显示修改过的参数
- **重置**：恢复所有参数为默认值
- **从 oem.ini 读取**：载入现有配置并回填

> **重要**：切换分组或搜索**不会丢失修改**。值保存在独立数据源中。

#### 自定义参数

用于填写参数库里没有的新选项：

```
SomeNewFeature=true
AnotherOption={"support" : true}
CustomApiEndpoint=https://example.com/api
```

- 每行一条 `KEY=VALUE`
- 「写入段」下拉框可编辑，指定写入哪个段
- 与已知参数同名时**覆盖**已知值
- 非法行（无 `=`、键名含空格）会被自动过滤

#### Feature 段

`[feature]` 段是 `<数字ID>=<值>` 形式：

```
ID: [16777345]  值: [1]  [添加/更新]  [删除选中]

16777288=3
16777307=1
16777313=0
...
```

### 2.5 导出

底部三个按钮：

| 按钮 | 输出内容 |
|---|---|
| 导出明文 oem.ini | 原文件已有的 + 用户修改的 |
| 导出加密 oem.ini | 同上，加密后 |
| 导出全部参数 | 参数库全部 359 项（做模板用，**慎用**） |

> 导出**不会**把参数库里的默认值全部写进去，只写原文件已有的和用户改过的。

### 2.6 配置分析

输出示例：

```
风险等级: 中

文件结构
  段数量: 6  (useranalysis, default, support, language, feature, setup)
  条目总数: 60
  [feature] 条目: 17
  BOM: 无
  换行符: LF
  内容: 已加密

签名检测
  未检测到签名行
  → 修改后重新加密即可，WPS 不做签名校验

授权相关字段
  ⚠ PresetSerialNumber
  ⚠ SerialInfo
  ⚠ NormalSerialNumber
  ⚠ ProductIdentifier
  ⚠ ProductIdentifierCollect
  ⚠ SubPlatform
  → 与激活状态有关，建议不要修改

功能开关字段
  · OfdComponent
  · forbidEditInForceLogin
  ...
```

---

## 3. 命令行

CLI 版本**不依赖 PyQt5**，可在无图形环境的服务器使用。

### 3.1 命令总览

```
wps-cipher <命令> [参数]

命令:
  info           显示文件信息与风险分析
  decrypt        解密文件
  encrypt        加密文件
  dump           输出明文到标准输出
  get            读取单个配置项
  set            修改单个配置项
  verify         往返校验
  selftest       算法自检
  batch-verify   批量校验目录下的配置
```

### 3.2 info — 文件信息

```bash
wps-cipher info oem.ini
```

输出：

```
文件: oem.ini
大小: 5188 字节
内容: 已加密

风险等级: 中
文件结构
  段数量: 6
  条目总数: 60
  [feature] 条目: 17
...

往返校验: 字节级一致
```

### 3.3 decrypt — 解密

```bash
# 默认输出 <原名>.decrypted.ini
wps-cipher decrypt oem.ini

# 指定输出路径
wps-cipher decrypt oem.ini -o plain.ini

# 指定换行符
wps-cipher decrypt oem.ini --line-ending $'\r\n'
```

### 3.4 encrypt — 加密

```bash
# 默认输出 <原名>.encrypted.ini
wps-cipher encrypt plain.ini

# 指定输出 + 头部注释
wps-cipher encrypt plain.ini -o oem.ini --header-comment "自定义配置"
```

### 3.5 dump — 输出明文

```bash
# 输出到标准输出，可管道处理
wps-cipher dump oem.ini

# 配合 grep 查找
wps-cipher dump oem.ini | grep -i serial

# 配合 diff 比较
wps-cipher dump a.ini > a.txt
wps-cipher dump b.ini > b.txt
diff a.txt b.txt
```

### 3.6 get — 读取配置项

```bash
wps-cipher get <文件> <段名> <键名>

# 示例
wps-cipher get oem.ini support EducationVersion
# 输出: true

wps-cipher get oem.ini default PrintProductName
# 输出: {"value" : "WPS 365 Office for Linux 2024 教育版办公软件V12"}
```

### 3.7 set — 修改配置项

```bash
wps-cipher set <文件> <段名> KEY=VALUE [-o 输出]

# 修改明文文件（就地）
wps-cipher set plain.ini support EducationVersion=false

# 修改后另存
wps-cipher set plain.ini support EducationVersion=false -o mod.ini

# 从密文修改（必须指定 -o）
wps-cipher set oem.ini support EducationVersion=false -o new_oem.ini
```

### 3.8 verify — 往返校验

```bash
wps-cipher verify oem.ini
```

输出：

```
输入是密文（编码 utf-8）
结果: 字节级一致 ✓
```

### 3.9 selftest — 自检

```bash
wps-cipher selftest
```

### 3.10 batch-verify — 批量校验

```bash
wps-cipher batch-verify /opt/kingsoft/wps-office/office6/cfgs
```

输出：

```
完成: 49 成功 / 0 失败
```

---

## 4. 典型场景

### 场景 1：查看当前 WPS 配置

```bash
# 定位配置文件
ls /opt/kingsoft/wps-office/office6/cfgs/oem.ini

# 查看信息
wps-cipher info /opt/kingsoft/wps-office/office6/cfgs/oem.ini

# 导出明文查看
wps-cipher dump /opt/kingsoft/wps-office/office6/cfgs/oem.ini
```

### 场景 2：修改一个功能开关

```bash
# 1. 备份
sudo cp /opt/kingsoft/wps-office/office6/cfgs/oem.ini ~/oem.ini.bak

# 2. 解密
wps-cipher decrypt ~/oem.ini.bak -o ~/oem.plain.ini

# 3. 修改
wps-cipher set ~/oem.plain.ini support EducationVersion=false -o ~/oem.mod.ini

# 4. 加密
wps-cipher encrypt ~/oem.mod.ini -o ~/oem.new.ini

# 5. 校验
wps-cipher verify ~/oem.new.ini

# 6. 部署
sudo cp ~/oem.new.ini /opt/kingsoft/wps-office/office6/cfgs/oem.ini

# 7. 重启 WPS 验证
```

### 场景 3：对比两台机器的配置

```bash
wps-cipher dump /opt/kingsoft/wps-office/office6/cfgs/oem.ini > /tmp/a.txt
ssh otherhost "wps-cipher dump /opt/kingsoft/wps-office/office6/cfgs/oem.ini" > /tmp/b.txt
diff /tmp/a.txt /tmp/b.txt
```

### 场景 4：图形界面配置

```bash
./run.sh
```

1. 「参数编辑器」→「从 oem.ini 读取」→ 选文件
2. 搜索参数名，如 `Education`
3. 勾选/取消勾选
4. 底部「导出加密 oem.ini」

### 场景 5：批量检查配置完整性

```bash
wps-cipher batch-verify /opt/kingsoft/wps-office/office6/cfgs
```

---

## 5. 参数说明

### 5.1 常用参数

| 参数 | 段 | 说明 |
|---|---|---|
| `EducationVersion` | Support | 教育版标志，启用专有功能 |
| `OfdComponent` | Support | OFD 组件支持 |
| `forbidEditInForceLogin` | Support | 强制登录时禁止编辑 |
| `WPS365ForceLogin` | Support | 是否强制登录 WPS365 |
| `EnableOemFileAesSignatureVerification` | Support | OEM 文件 AES 签名校验开关 |
| `DisableMainResourceVerification` | Support | 关闭主资源校验 |
| `Update` | Support | 是否启用升级功能 |
| `EnableCloudDocs` | Support | 是否启用云文档 |
| `Prometheus` | Support | 窗口管理模式 |
| `SubPlatform` | Auth | 子平台：1=AK 2=JK 3=ZYJ |
| `PresetSerialNumber` | default | 预置序列号（⚠ 勿改） |

完整列表见 GUI「读取流程 → 支持选项清单」，或：

```bash
python3 -c "import json; d=json.load(open('param_schema.json'));
[print(f\"{p['group']:12s} {p['key']:40s} {p['desc']}\") for p in d]"
```

### 5.2 值的三种写法

```ini
; 1. 裸值
EducationVersion=true
TotalTrialDays=2147483647
KSNUpdateServerUrl=http://snauth.wps.cn

; 2. JSON 包装（WPS 常见）
OfdComponent={"support" : true, "createLink" : false, "install" : false}
SubPlatform={"value" : 1}

; 3. 列表
List[0]=a, b, c
List[1]=d, e,
```

### 5.3 风险等级

| 等级 | 触发条件 | 建议 |
|---|---|---|
| 低 | 无签名、无授权字段 | 可安全修改 |
| 中 | 有授权字段，或有 `OemSignType1` 签名 | 只改功能开关 |
| 高 | 有厂商 AES 签名（256 字节 hex） | **改前务必备份** |

---

## 6. 算法与格式

### 6.1 `[feature]` 段 — IDEA

```
密钥 = MD5("wps")                    (16 字节)
明文 → IDEA-ECB（补零到 8 字节对齐）
     → 追加 3 字节 (md5[0], md5[8], 0x01)
     → 首字节与 trailer 首字节交换 bit0 / bit4
     → 自定义 base64  (0123456789A-Za-z-_)
```

条目语义：`<feature_id>=<value>`，均为十进制整数，值内部编码为 `"<id>:<value>"`。

### 6.2 普通键值 — AES-256-ECB

```
密钥 = "F9AF610AE6164C73B78B0A99D8B72890"   (32 字节 ASCII)
PKCS#7 填充
输出 = base64 后替换:  '+' → '_'   '/' → '-'   '=' → '.'
```

### 6.3 OemSignType1 签名

```
digest = MD5(content + ";OemSignType1=") 的大写十六进制

key_seed = MachineGuid + "9B0p3z7GcKf2XtR5L6Y8Q1W4E7R3T6Y8"
         + setupPartial + registryPartial
key      = MD5(key_seed) 的大写十六进制前 16 字符
           逐字节 XOR "k8Se2hXt6ZDKrkWTQNrZGs3w4TBT10Jt"

载荷 = (IV XOR "S3kP06v2Ne04lDeX") + AES-CBC(digest, key, IV)
输出 = content + ";OemSignType1=" + 载荷的大写十六进制
```

### 6.4 WPS 加载流程

```
1. krt::configs::oemConfigFilePath()     定位 cfgs/oem.ini
2. 逐行解析 [Section] / KEY=VALUE
3. 逐项解密
     [feature] 段 → FeatureCodec (IDEA)
     其他段      → ProfileValueCipher (AES-256-ECB)
4. krt::configs::getOemIniValid()        校验
   krt::configs::getProductDatValid()
5. krt::KProductConfigsReader 装载
6. 业务查询：isSupported("Support/XXX") / getConfigValue(...)
```

### 6.5 关于机器绑定

**oem.ini 的加密不绑定机器。** 实测：麒麟 aarch64 的 oem.ini 拿到 Windows
上可正常解密，重新加密后 MD5 完全一致。密钥是全局固定的。

可能与机器相关的是：

1. **授权字段**（`PresetSerialNumber` 等）—— 是否绑定取决于 WPS 授权模块
2. **厂商 AES 签名**（`;0E38...`）—— 256 字节，由 `KOemAesSignatureBase` 校验

---

## 7. 故障排查

### 7.1 图形界面无法启动

**症状**：`qt.qpa.xcb: could not connect to display`

**原因**：没有图形环境或 `DISPLAY` 未设置。

**解决**：

```bash
# 检查 DISPLAY
echo $DISPLAY

# 有图形界面时
export DISPLAY=:0

# 无图形环境时改用 CLI
python3 wps_cipher_cli.py info oem.ini
```

### 7.2 解密失败：不是合法的 base64

**原因**：文件本身已是明文，或不是 WPS 配置文件。

**解决**：

```bash
# 先判断类型
wps-cipher info 文件
```

### 7.3 加密后 WPS 不识别

**排查步骤**：

1. 确认输出是完整文件，不是片段
2. 用 `wps-cipher verify` 检查往返一致性
3. 检查是否破坏了厂商签名（`info` 命令会显示）

### 7.4 中文乱码

**原因**：文件是 GBK 编码，用 UTF-8 打开。

**解决**：工具已自动识别编码。如需手动处理：

```bash
iconv -f GBK -t UTF-8 oem.ini > oem.utf8.ini
```

### 7.5 参数改了但 WPS 行为没变

可能原因：

1. 该参数在当前版本无效
2. 参数值格式不对（应为 `{"value":...}` 但写成了裸值）
3. 有厂商签名，改动被拒绝加载

---

## 8. 常见问题

**Q: 修改 oem.ini 会不会导致 WPS 无法启动？**

A: 一般不会。WPS 对无法解析的配置项会忽略。但如果文件带厂商 AES 签名，
改动后可能被拒绝加载。**改前务必备份**。

**Q: 能跨机器复制 oem.ini 吗？**

A: 加密层面可以（密钥全局固定）。但授权字段（`PresetSerialNumber`）可能
与机器绑定，复制后授权可能失效。

**Q: 为什么参数库有 359 项，但实际文件只有 60 项？**

A: 参数库是**全集**（所有可能的配置项），实际文件只用了其中一部分。
导出时只写原文件已有的 + 你改过的，不会把默认值全写进去。

**Q: `[feature]` 段的数字 ID 是什么意思？**

A: 是 WPS 内部的加密特性编号，没有公开的对照表。只能通过实测确定含义。

**Q: 没有 pycryptodome 能用吗？**

A: 能。会自动降级为内置纯 Python AES，功能完全等价。oem.ini（5KB）
约 1.2 秒，product.dat（71KB）约 13 秒。

**Q: 支持哪些 WPS 版本？**

A: 已测试 10 / 11 / 12 系列的 12 个版本分支（49 个官方样本），全部字节级还原。

**Q: 工具会联网吗？**

A: 不会。完全离线运行。

---

## 附录：文件清单

```
wps-cipher-2.0/
  wps_profile_cipher.py   核心算法库（零第三方依赖）
  wps_cipher_cli.py       命令行工具
  wps_cipher_gui.py       图形界面
  param_editor.py         参数编辑器组件
  flow_view.py            流程说明组件
  param_schema.json       359 个参数定义
  tests/run_tests.py      120 项自动化测试
  run.sh                  启动脚本
  README.md               简要说明
  CHANGELOG.md            变更日志
  docs/USAGE.md           本文件
```

---

*本工具仅用于分析与运维自己的 WPS 部署。*
