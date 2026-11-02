#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WPS 配置读取流程说明页 + 支持选项清单。

内容来自对 WPS Office 12.1.2 的 libkrt.so 静态分析
（导出符号 + 字符串引用 + 反汇编）以及雨糖科技 WPSOfficeConf 的实测资料。
"""

import io
import json
import os

from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QComboBox, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit,
    QPushButton, QVBoxLayout, QWidget,
)

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, "param_schema.json")

FLOW_TEXT = """\
WPS 配置读取与校验流程
================================================================

一、涉及的文件
----------------------------------------------------------------
  <安装目录>/office6/cfgs/oem.ini        主配置（OEM 定制参数）
  <安装目录>/office6/cfgs/product.dat    产品配置（语言资源 / 产品定义）
  <安装目录>/office6/cfgs/setup.cfg      安装信息（InstallPartialData）
  ~/.config/Kingsoft/Office.conf         用户级配置（运行时写入）

二、加载顺序（从二进制符号还原）
----------------------------------------------------------------
  1. 程序启动 → krt::configs::oemConfigFilePath()
                 返回 cfgs/oem.ini 的绝对路径
  2. 读取文件 → 按行解析 [Section] / KEY=VALUE
  3. 逐项解密
       · [feature] 段        → FeatureCodec（IDEA + MD5("wps")）
       · 其他段              → ProfileValueCipher（AES-256-ECB 固定密钥）
       · 值形如 {"value":..}  → 取 value 字段
         {"support":..}       → 取 support 字段
         {"filter":..}        → 取 filter 字段
  4. 校验      → krt::configs::getOemIniValid(valid, signed, map)
                 同时校验 product.dat：getProductDatValid()
  5. 装载      → krt::KProductConfigsReader / KConfigsReader
  6. 查询      → 业务代码调用：
                   krt::product::isSupported("Support/XXX")
                   krt::product::getConfigValue("Support/XXX")
                   krt::configs::getBool/getInt/getString/getArray(...)
                 查询时会自动拼上 "Support/" 前缀再查表

三、校验机制（关键）
----------------------------------------------------------------
  文件名末尾若存在 `;` + 512 位十六进制 → 视为「整个配置文件的签名」
  由 krt::configs::getOemIniValid 校验，校验失败的处理取决于：
      [Support] EnableOemFileAesSignatureVerification
        = true  → 严格校验，签名不符则拒绝加载 / 删除 oem.ini
        = false → 跳过签名校验（WPS 365 商业版建议在 product.dat 中关闭）
      [Support] DisableMainResourceVerification
        = true  → 关闭主资源校验

  注意：不同版本行为不同
      · 2019 专业版 11.8.2.12344 起加入总校验
      · 2023 专业版 12.8.2.17838 起加入总校验
      · 教育版 / 定制版通常不带签名

四、参数值的三种写法
----------------------------------------------------------------
  1) 裸值           Key=true            Key=123        Key=http://...
  2) JSON 包装      Key={"value" : 1}
                    Key={"support" : true, "enable" : true, "filter" : false}
  3) 列表           Key=a, b, c
     （键名带 [0] [1] 后缀时，值按逗号分隔逐项加密）

五、新增未列出选项的方法
----------------------------------------------------------------
  在「自定义参数」页按 KEY=VALUE 填写即可，值支持上面三种写法。
  参数名不区分大小写地查表，但建议与官方写法一致。
  未知参数不会导致加载失败，WPS 只是忽略它。

六、已验证的查询 API
----------------------------------------------------------------
  krt::product::isSupported(QString)          → bool
  krt::product::getConfigValue(QString)       → QVariant
  krt::product::getStringList(QString, int)   → QStringList
  krt::configs::getValue(QString, int)        → QVariant
  krt::configs::getBool(QString, int)         → bool
  krt::configs::getInt(QString, int)          → int
  krt::configs::getString(QString, int)       → QString
  krt::configs::getArray(QString, int)        → QVariantList
  krt::configs::getRawConfig(QString)         → 原始字符串
  krt::configs::getOemIniValid(bool&, bool&, QMap&)   → 校验结果
  krt::configs::getProductDatValid()          → 校验结果
  krt::configs::refreshCustomConfigReader()   → 热重载
"""


class FlowView(QWidget):
    """读取流程说明 + 支持选项清单。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.schema = []
        try:
            with io.open(SCHEMA_PATH, encoding="utf-8") as fh:
                self.schema = json.load(fh)
        except Exception as exc:
            print("加载参数库失败: %s" % exc)
        self._build()

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(4, 4, 4, 4)

        bar = QHBoxLayout()
        self.mode = QComboBox()
        self.mode.addItems(["读取流程说明", "支持选项清单"])
        self.mode.currentIndexChanged.connect(self._refresh)
        bar.addWidget(QLabel("查看:"))
        bar.addWidget(self.mode)

        btn_copy = QPushButton("复制到剪贴板")
        btn_copy.clicked.connect(self._copy)
        bar.addWidget(btn_copy)

        btn_save = QPushButton("导出为文本")
        btn_save.clicked.connect(self._save)
        bar.addWidget(btn_save)

        bar.addStretch(1)
        outer.addLayout(bar)

        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setFont(QFont("Monospace", 9))
        outer.addWidget(self.view, 1)

        self._refresh()

    def _option_list(self) -> str:
        lines = ["WPS oem.ini 支持的选项清单",
                 "=" * 60,
                 "共 %d 项（来自雨糖科技 WPSOfficeConf + 实测补充）" % len(self.schema),
                 ""]
        from collections import OrderedDict
        groups = OrderedDict()
        for p in self.schema:
            groups.setdefault(p["group"], []).append(p)

        for g, items in groups.items():
            lines.append("[%s]  %d 项" % (g, len(items)))
            lines.append("-" * 60)
            for p in items:
                flag = "⚠" if p["risk"] == "high" else " "
                lines.append("%s %-40s %s" % (flag, p["key"], p["desc"]))
                if p.get("notes"):
                    for n in p["notes"]:
                        lines.append("    " + n)
            lines.append("")
        return "\n".join(lines)

    def _refresh(self):
        if self.mode.currentIndex() == 0:
            self.view.setPlainText(FLOW_TEXT)
        else:
            self.view.setPlainText(self._option_list())

    def _copy(self):
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(self.view.toPlainText())
        QMessageBox.information(self, "已复制", "内容已复制到剪贴板。")

    def _save(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "保存", os.path.expanduser("~/wps_config_info.txt"),
            "文本 (*.txt);;所有文件 (*)")
        if not path:
            return
        with io.open(path, "w", encoding="utf-8") as fh:
            fh.write(self.view.toPlainText())
        QMessageBox.information(self, "已保存", path)
