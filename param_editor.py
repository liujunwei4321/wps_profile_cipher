#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""参数编辑器：把 oem.ini 的每一项配置都做成 GUI 控件。

设计要点
--------
* **值存放在 self.values**（唯一数据源），控件只是它的视图。
  切换分组 / 搜索 / 重建界面都不会丢值。
* 值的**原始字符串**（含 {"support":true} 这类 JSON 包装）被完整保留，
  unwrap 只用于显示，写回时用原值，避免丢失 enable/filter 语义。
* 搜索有 250ms 防抖，避免每敲一个字符重建 348 个控件。
* 与已知参数同名的自定义参数会**覆盖**已知值，而不是产生重复键。
"""
import io
import json
import os
import re
from typing import Dict, List, Optional, Tuple

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QGroupBox, QHBoxLayout, QLabel,
    QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea,
    QSpinBox, QSplitter, QTabWidget, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(HERE, "param_schema.json")

from wps_profile_cipher import (          # noqa: E402
    ListInfo, ProfileConverter, looks_like_plaintext, unwrap_value,
)

# 段输出顺序
SECTION_ORDER = ["default", "setup", "Support", "Auth", "Server", "Account",
                 "Product", "Useranalysis", "UserAnalysis", "Category",
                 "Language", "L10N", "Patent", "HomepagePlugin",
                 "moduleenabledoverseas", "Feature", "feature"]

_VALID_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_./\[\]\-]*$")


def load_schema() -> List[dict]:
    with io.open(SCHEMA_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


class ParamEditor(QWidget):
    """按分组展示所有参数，每项一个控件。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.schema = load_schema()
        self.by_key: Dict[str, dict] = {p["key"]: p for p in self.schema}

        # ---- 唯一数据源 ----
        self.values: Dict[str, str] = {p["key"]: p["default"] for p in self.schema}
        self.raw_values: Dict[str, str] = {}   # 从文件读到的原始字符串（含 JSON）
        self.baseline: Dict[str, str] = {}     # 读取文件时的值，用于计算「改动」
        self.feature_values: Dict[int, int] = {}   # [feature] 段的数字 ID
        self.feature_baseline: Dict[int, int] = {}
        self.list_info: Optional[ListInfo] = None
        self.source_path: str = ""
        # 原文件中存在、但参数库里没有的条目：段 -> [(key, value)]
        self.extra_entries: Dict[str, List[Tuple[str, str]]] = {}
        # 原文件使用的段名（小写 -> 原始大小写），导出时保持原样
        self.section_names: Dict[str, str] = {}
        # 每个键在**原文件**中的实际段名（key -> section），导出时优先使用
        self.key_sections: Dict[str, str] = {}

        self.widgets: Dict[str, QWidget] = {}
        self._loading = False          # 防止程序改控件时触发信号
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(250)
        self._search_timer.timeout.connect(self._rebuild)

        self._build_ui()

    # ------------------------------------------------------------------ UI

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(4, 4, 4, 4)

        self.inner_tabs = QTabWidget()

        # ---- 图形编辑 ----
        graphic = QWidget()
        gv = QVBoxLayout(graphic)
        gv.setContentsMargins(2, 2, 2, 2)

        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索参数名或说明…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(lambda _: self._search_timer.start())
        bar.addWidget(QLabel("搜索:"))
        bar.addWidget(self.search, 1)

        self.chk_show_high = QCheckBox("显示高风险项")
        self.chk_show_high.stateChanged.connect(lambda _: self._rebuild())
        bar.addWidget(self.chk_show_high)

        self.chk_changed_only = QCheckBox("只看改动")
        self.chk_changed_only.stateChanged.connect(lambda _: self._rebuild())
        bar.addWidget(self.chk_changed_only)

        btn_reset = QPushButton("重置")
        btn_reset.clicked.connect(self._reset_all)
        bar.addWidget(btn_reset)

        btn_load = QPushButton("从 oem.ini 读取")
        btn_load.clicked.connect(self.load_from_file)
        bar.addWidget(btn_load)

        gv.addLayout(bar)

        split = QSplitter(Qt.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["分组", "数量"])
        self.tree.setMaximumWidth(230)
        self.tree.itemSelectionChanged.connect(self._rebuild)
        split.addWidget(self.tree)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.form_host = QWidget()
        self.form_layout = QVBoxLayout(self.form_host)
        self.form_layout.setAlignment(Qt.AlignTop)
        self.scroll.setWidget(self.form_host)
        split.addWidget(self.scroll)
        split.setSizes([210, 700])
        gv.addWidget(split, 1)

        self.inner_tabs.addTab(graphic, "图形编辑")

        # ---- 自定义参数 ----
        custom = QWidget()
        cv = QVBoxLayout(custom)
        cv.setContentsMargins(2, 2, 2, 2)
        hint = QLabel(
            "填写参数库里还没有的选项（新版本可能新增）。\n"
            "每行一条 KEY=VALUE，写入下面指定的段。\n"
            "值支持：true / false、数字、{\"support\":true} 这样的 JSON、任意字符串。\n"
            "与已知参数同名时会覆盖已知值。")
        hint.setStyleSheet("color:#666;")
        hint.setWordWrap(True)
        cv.addWidget(hint)

        sec_row = QHBoxLayout()
        sec_row.addWidget(QLabel("写入段:"))
        self.custom_section = QComboBox()
        self.custom_section.setEditable(True)
        for s in ["default", "Support", "Auth", "Server", "Account", "Product",
                  "UserAnalysis", "Category", "Language", "L10N", "Patent",
                  "HomepagePlugin", "moduleenabledoverseas", "Feature", "setup"]:
            self.custom_section.addItem(s)
        sec_row.addWidget(self.custom_section, 1)
        sec_row.addStretch(2)
        cv.addLayout(sec_row)

        self.custom_edit = QPlainTextEdit()
        self.custom_edit.setFont(QFont("Monospace", 9))
        self.custom_edit.setPlaceholderText(
            "SomeNewFeature=true\n"
            "AnotherOption={\"support\" : true}\n"
            "CustomServerUrl=http://example.com/api")
        cv.addWidget(self.custom_edit, 1)
        self.inner_tabs.addTab(custom, "自定义参数")

        # ---- Feature 段 ----
        feat = QWidget()
        fv = QVBoxLayout(feat)
        fv.setContentsMargins(2, 2, 2, 2)
        fh = QLabel(
            "[feature] 段是 <数字ID>=<值> 的形式，WPS 内部用整数查表。\n"
            "这里直接编辑数字，保存时会自动加密。")
        fh.setStyleSheet("color:#666;")
        fh.setWordWrap(True)
        fv.addWidget(fh)

        frow = QHBoxLayout()
        self.feat_id = QSpinBox()
        self.feat_id.setRange(-2147483648, 2147483647)
        self.feat_id.setMinimumWidth(160)
        self.feat_val = QSpinBox()
        self.feat_val.setRange(-2147483648, 2147483647)
        self.feat_val.setMinimumWidth(160)
        btn_add = QPushButton("添加 / 更新")
        btn_add.clicked.connect(self._add_feature)
        btn_del = QPushButton("删除选中")
        btn_del.clicked.connect(self._del_feature)
        frow.addWidget(QLabel("ID:")); frow.addWidget(self.feat_id)
        frow.addWidget(QLabel("值:")); frow.addWidget(self.feat_val)
        frow.addWidget(btn_add); frow.addWidget(btn_del)
        frow.addStretch(1)
        fv.addLayout(frow)

        self.feat_view = QPlainTextEdit()
        self.feat_view.setFont(QFont("Monospace", 9))
        self.feat_view.setReadOnly(True)
        self.feat_view.setPlaceholderText("（空）")
        fv.addWidget(self.feat_view, 1)
        self.inner_tabs.addTab(feat, "Feature 段")

        outer.addWidget(self.inner_tabs, 1)

        self._build_tree()
        self._rebuild()

    # -------------------------------------------------------------- 树

    def _build_tree(self, keep_group: Optional[str] = None):
        if keep_group is None:
            keep_group = self._current_group()
        self.tree.blockSignals(True)
        self.tree.clear()

        groups: Dict[str, int] = {}
        for p in self.schema:
            if p["risk"] == "high" and not self.chk_show_high.isChecked():
                continue
            if self.chk_changed_only.isChecked() and not self._is_changed(p["key"]):
                continue
            groups[p["group"]] = groups.get(p["group"], 0) + 1

        total = sum(groups.values())
        all_item = QTreeWidgetItem(["全部", str(total)])
        all_item.setData(0, Qt.UserRole, None)
        self.tree.addTopLevelItem(all_item)

        target = all_item
        for g, n in groups.items():
            it = QTreeWidgetItem([g, str(n)])
            it.setData(0, Qt.UserRole, g)
            self.tree.addTopLevelItem(it)
            if keep_group == g:
                target = it
        self.tree.expandAll()
        self.tree.setCurrentItem(target)
        self.tree.blockSignals(False)

    def _current_group(self) -> Optional[str]:
        it = self.tree.currentItem()
        return it.data(0, Qt.UserRole) if it else None

    # ---------------------------------------------------------- 表单

    def _clear_form(self):
        while self.form_layout.count():
            item = self.form_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
            elif item.layout() is not None:
                self._clear_layout(item.layout())
        self.widgets.clear()

    def _clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
            elif item.layout() is not None:
                self._clear_layout(item.layout())

    def _is_changed(self, key: str) -> bool:
        """相对「基线」是否有改动。

        基线：读取文件时的值；未读取过文件则为 schema 默认值。
        """
        p = self.by_key.get(key)
        if p is None:
            return False
        base = self.baseline.get(key, p["default"])
        return self.values.get(key, p["default"]) != base

    def _rebuild(self):
        group = self._current_group()
        self._build_tree(keep_group=group)
        self._clear_form()

        group = self._current_group()
        needle = self.search.text().strip().lower()

        buckets: Dict[str, List[dict]] = {}
        for p in self.schema:
            if p["risk"] == "high" and not self.chk_show_high.isChecked():
                continue
            if self.chk_changed_only.isChecked() and not self._is_changed(p["key"]):
                continue
            if group and p["group"] != group:
                continue
            if needle:
                hay = (p["key"] + " " + p["desc"] + " " +
                       " ".join(p.get("notes") or [])).lower()
                if needle not in hay:
                    continue
            buckets.setdefault(p["group"], []).append(p)

        if not buckets:
            self.form_layout.addWidget(QLabel("没有匹配的参数。"))
            self.form_layout.addStretch(1)
            return

        for g, items in buckets.items():
            box = QGroupBox("%s  (%d 项)" % (g, len(items)))
            vbox = QVBoxLayout(box)
            vbox.setSpacing(2)
            for p in items:
                vbox.addLayout(self._make_row(p))
            self.form_layout.addWidget(box)

        self.form_layout.addStretch(1)

    def _make_row(self, p: dict) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(6)

        key_lbl = QLabel(p["key"])
        key_lbl.setFont(QFont("Monospace", 8))
        key_lbl.setMinimumWidth(200)
        key_lbl.setMaximumWidth(250)
        key_lbl.setToolTip(p["key"])
        if p["risk"] == "high":
            key_lbl.setStyleSheet("color:#c0392b;")
        elif p["risk"] == "medium":
            key_lbl.setStyleSheet("color:#b9770e;")
        row.addWidget(key_lbl)

        w = self._make_widget(p)
        self.widgets[p["key"]] = w
        if isinstance(w, QLineEdit):
            w.setMinimumWidth(280)
        row.addWidget(w, 2)

        desc = QLabel(p["desc"])
        desc.setWordWrap(True)
        desc.setStyleSheet("color:#666;")
        desc.setMinimumWidth(260)
        row.addWidget(desc, 3)
        return row

    def _make_widget(self, p: dict) -> QWidget:
        key = p["key"]
        cur = self.values.get(key, p["default"])
        display = unwrap_value(cur)
        widget = p["widget"]

        # 原值是 JSON 包装时，用「原始字符串」作为 tooltip，提醒用户不会被压扁
        wrapped = cur.strip().startswith("{") and cur.strip().endswith("}")

        if widget == "bool":
            cb = QCheckBox()
            cb.setChecked(str(display).lower() == "true")
            tip = "%s\n默认: %s" % (p["desc"], p["default"])
            if wrapped:
                tip += "\n当前原始值: %s" % cur
            cb.setToolTip(tip)
            cb.stateChanged.connect(lambda _s, k=key: self._on_widget_changed(k))
            return cb

        if widget == "enum":
            combo = QComboBox()
            for opt in p["options"]:
                combo.addItem(opt["label"], opt["value"])
            idx = combo.findData(display)
            if idx >= 0:
                combo.setCurrentIndex(idx)
            combo.currentIndexChanged.connect(lambda _i, k=key: self._on_widget_changed(k))
            return combo

        if widget == "int":
            sp = QSpinBox()
            sp.setRange(-2147483648, 2147483647)
            try:
                sp.setValue(int(display))
            except (TypeError, ValueError):
                sp.setValue(0)
            sp.valueChanged.connect(lambda _v, k=key: self._on_widget_changed(k))
            return sp

        le = QLineEdit(str(display))
        if widget == "url":
            le.setPlaceholderText("http://…")
        le.textEdited.connect(lambda _t, k=key: self._on_widget_changed(k))
        return le

    def _on_widget_changed(self, key: str):
        """控件变化 → 立即写回 self.values（唯一数据源）。"""
        if self._loading:
            return
        w = self.widgets.get(key)
        p = self.by_key.get(key)
        if w is None or p is None:
            return

        if isinstance(w, QCheckBox):
            new_display = "true" if w.isChecked() else "false"
        elif isinstance(w, QComboBox):
            new_display = w.currentData() or ""
        elif isinstance(w, QSpinBox):
            new_display = str(w.value())
        elif isinstance(w, QLineEdit):
            new_display = w.text()
        else:
            return

        # 若原值是 JSON 包装，尝试只替换对应字段，保留其它字段
        self.values[key] = _merge_display_into_raw(
            self.raw_values.get(key, p["default"]), new_display)

    # -------------------------------------------------------- 值读取

    def get_values(self) -> Dict[str, str]:
        """当前所有参数值（不受界面可见性影响）。"""
        return dict(self.values)

    def changed_values(self) -> Dict[str, str]:
        return {k: v for k, v in self.values.items()
                if k in self.by_key and v != self.by_key[k]["default"]}

    def _reset_all(self):
        if QMessageBox.question(self, "确认", "把所有参数恢复为默认值？") \
                != QMessageBox.Yes:
            return
        self.values = {p["key"]: p["default"] for p in self.schema}
        self.raw_values.clear()
        self._rebuild()

    # -------------------------------------------------- 从 oem.ini 读取

    def load_from_file(self, path: str = "", silent: bool = False):
        if not path:
            path, _ = QFileDialog.getOpenFileName(
                self, "选择 oem.ini", os.path.expanduser("~"),
                "WPS 配置 (*.ini *.dat);;所有文件 (*)")
        if not path:
            return None
        try:
            raw_bytes = open(path, "rb").read()
            text = raw_bytes.decode("utf-8-sig", errors="replace")
            conv = ProfileConverter()
            if looks_like_plaintext(text):
                plain, info = text, None
            else:
                plain, info = conv.decrypt_with_meta(text)
        except Exception as exc:
            if not silent:
                QMessageBox.critical(self, "读取失败", str(exc))
            return None

        self.source_path = path
        self.list_info = info
        self.raw_values.clear()
        self.feature_values.clear()

        parsed: Dict[str, str] = {}
        parsed_section: Dict[str, str] = {}    # key -> section（原文件中的段名）
        in_feature = False
        cur_section = ""
        for line in plain.splitlines():
            s = line.strip()
            if not s or s.startswith(("#", ";")):
                continue
            # 先判断 section（[xxx] 不含 '='，必须先处理）
            if s.startswith("[") and s.endswith("]"):
                cur_section = s[1:-1].strip()
                self.section_names[cur_section.lower()] = cur_section
                in_feature = cur_section.lower() == "feature"
                continue
            if "=" not in s:
                continue
            k, _, v = s.partition("=")
            k, v = k.strip(), v
            if in_feature and k.lstrip("-").isdigit():
                try:
                    self.feature_values[int(k)] = int(v.strip())
                    continue
                except ValueError:
                    pass
            # 同名键可能出现在多个段中（如 ProductIdentifierCollect 同时在
            # [default] 和 [support]），用 "段名\0键名" 作为唯一标识
            uid = cur_section + "\0" + k
            parsed[uid] = v
            parsed_section[uid] = cur_section

        matched = 0
        # 先按「同段同名」精确匹配；每个 schema key 只接受一次，避免被别的段覆盖
        used: set = set()
        filled: set = set()
        for uid, v in parsed.items():
            k = uid.split("\0", 1)[1]
            sec = parsed_section.get(uid, "")
            p = self.by_key.get(k)
            if p is None or k in filled:
                continue
            if p["section"].lower() == sec.lower():
                self.values[k] = v
                self.raw_values[k] = v
                self.key_sections[k] = sec      # 记住实际段名
                used.add(uid)
                filled.add(k)
                matched += 1
        # 再按名字兜底匹配（仍未填过的）
        for uid, v in parsed.items():
            if uid in used:
                continue
            k = uid.split("\0", 1)[1]
            if k in self.by_key and k not in filled:
                self.values[k] = v
                self.raw_values[k] = v
                self.key_sections[k] = parsed_section.get(uid, "")
                filled.add(k)
                matched += 1

        # 记录参数库没有的条目，导出时原样保留，避免丢数据
        self.extra_entries = {}
        for uid, v in parsed.items():
            k = uid.split("\0", 1)[1]
            if k not in self.by_key:
                sec = parsed_section.get(uid, "default") or "default"
                self.extra_entries.setdefault(sec, []).append((k, v))
        # 跨段同名但 schema 只登记了一个段的，把另一份也作为额外条目保留
        for uid, v in parsed.items():
            k = uid.split("\0", 1)[1]
            p = self.by_key.get(k)
            if p is not None and p["section"].lower() != parsed_section.get(uid, "").lower():
                sec = parsed_section.get(uid, "default") or "default"
                self.extra_entries.setdefault(sec, []).append((k, v))

        # 记录基线：只有相对它变化的项才算「改动」
        self.baseline = {k: self.values.get(k, p["default"])
                         for k, p in self.by_key.items()}
        self.feature_baseline = dict(self.feature_values)

        self._refresh_feature_view()
        self._rebuild()

        msg = ("共解析 %d 项，匹配参数库 %d 项，[feature] %d 条。\n\n%s"
               % (len(parsed), matched, len(self.feature_values), path))
        self._log(msg)
        if not silent:
            QMessageBox.information(self, "读取完成", msg)
        return {"total": len(parsed), "matched": matched,
                "feature": len(self.feature_values)}

    # ---------------------------------------------------- Feature 段

    def _refresh_feature_view(self):
        lines = ["%d=%d" % (k, v) for k, v in sorted(self.feature_values.items())]
        self.feat_view.setPlainText("\n".join(lines))

    def _add_feature(self):
        self.feature_values[self.feat_id.value()] = self.feat_val.value()
        self._refresh_feature_view()
        self._log("已设置 feature %d=%d"
                  % (self.feat_id.value(), self.feat_val.value()))

    def _del_feature(self):
        fid = self.feat_id.value()
        if fid in self.feature_values:
            del self.feature_values[fid]
            self._refresh_feature_view()
            self._log("已删除 feature %d" % fid)
        else:
            QMessageBox.information(self, "提示", "该 ID 不存在。")

    # -------------------------------------------------------- 导出

    def build_plain_ini(self, only_changed: bool = True,
                        include_features: bool = True,
                        all_schema: bool = False) -> str:
        """生成明文 oem.ini。

        only_changed=True  → 只输出相对基线有变化的项（最小改动）
        only_changed=False → 输出「原文件已有的 + 用户修改/新增的」，
                             不会把参数库里的默认值全部写进去
        all_schema=True    → 输出参数库全部 359 项（做完整模板用，慎用）
        """
        sections: Dict[str, List[Tuple[str, str]]] = {}
        for p in self.schema:
            key = p["key"]
            if all_schema:
                include = True
            elif only_changed:
                include = self._is_changed(key)
            else:
                # 原文件里有这个键，或用户改过它
                include = key in self.raw_values or self._is_changed(key)
            if not include:
                continue
            # 优先用原文件里的实际段名，其次用 schema 的段名
            actual = self.key_sections.get(key)
            if actual:
                sec = actual
            else:
                sec = self.section_names.get(p["section"].lower(), p["section"])
            sections.setdefault(sec, []).append((key, self.values[key]))

        # 参数库没有的原始条目：原样保留，避免导出时丢配置
        for sec, items in self.extra_entries.items():
            for k, v in items:
                sections.setdefault(sec, []).append((k, v))

        # 自定义参数（可覆盖已知值）
        custom_section = (self.custom_section.currentText() or "default").strip() or "default"
        custom_items: List[Tuple[str, str]] = []
        for line in self.custom_edit.toPlainText().splitlines():
            s = line.strip()
            if not s or s.startswith(("#", ";")):
                continue
            if "=" not in s:
                continue
            k, _, v = s.partition("=")
            k = k.strip()
            if not _VALID_KEY_RE.match(k):
                continue
            custom_items.append((k, v.strip()))

        # 自定义参数覆盖已知同名项
        overridden = {k for k, _ in custom_items}
        for sec in sections:
            sections[sec] = [(k, v) for k, v in sections[sec] if k not in overridden]
        for k, v in custom_items:
            sections.setdefault(custom_section, []).append((k, v))

        # 输出
        lines: List[str] = [";/DWPS_SETUP", ""]
        def _order(name):
            low = name.lower()
            for i, s in enumerate(SECTION_ORDER):
                if s.lower() == low:
                    return i
            return 99
        for sec in sorted(sections, key=_order):
            items = sections[sec]
            if not items:
                continue
            lines.append("[%s]" % sec)
            for k, v in items:
                lines.append("%s=%s" % (k, v))
            lines.append("")

        if include_features and self.feature_values:
            changed_feats = {k: v for k, v in self.feature_values.items()
                             if self.feature_baseline.get(k) != v}
            feats = changed_feats if only_changed else self.feature_values
            if feats:
                lines.append("[feature]")
                for k in sorted(feats):
                    lines.append("%d=%d" % (k, feats[k]))
                lines.append("")

        # 去掉末尾多余空行，保留单个换行
        while lines and not lines[-1].strip():
            lines.pop()
        return "\n".join(lines) + "\n"

    # -------------------------------------------------------- 日志

    def _log(self, text: str):
        parent = self.parent()
        while parent is not None:
            if hasattr(parent, "_log"):
                parent._log(text.replace("\n", " "))
                return
            parent = parent.parent()
        print(text)


def _merge_display_into_raw(raw: str, new_display: str) -> str:
    """把界面上的新值合并回原始字符串。

    原值是 {"support":true,"enable":true,"filter":false} 时，
    只替换 support 字段，保留 enable/filter。
    """
    raw = (raw or "").strip()
    if not raw.startswith("{"):
        return new_display

    import json as _json
    try:
        obj = _json.loads(raw)
    except Exception:
        return new_display
    if not isinstance(obj, dict):
        return new_display

    for field in ("value", "support", "enable"):
        if field in obj:
            old = obj[field]
            if isinstance(old, bool):
                obj[field] = (new_display.strip().lower() == "true")
            elif isinstance(old, int):
                try:
                    obj[field] = int(new_display)
                except ValueError:
                    obj[field] = new_display
            else:
                obj[field] = new_display
            break
    else:
        return new_display

    return _json.dumps(obj, ensure_ascii=False)
