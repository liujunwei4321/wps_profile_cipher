#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WPS 配置文件加解密工具 (GUI)
============================
WPS oem.ini / product.dat 的加解密与签名图形工具。

算法与 https://github.com/NixaVulpi/WPSProfileCipher 一致：
  - [feature] 段   : IDEA + MD5("wps") 密钥 + 自定义 base64
  - 普通键值       : AES-256-ECB + base64 变体
  - 签名           : OemSignType1 (AES-CBC 派生密钥)

依赖: PyQt5, pycryptodome (可选，缺失时用内置纯 Python 实现)
运行: python3 wps_cipher_gui.py
"""

import os
import sys
import traceback
from typing import List, Optional

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QFont, QTextCursor
from PyQt5.QtWidgets import (
    QAction, QApplication, QComboBox, QDialog, QFileDialog, QFormLayout,
    QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QPushButton, QTabWidget, QVBoxLayout, QWidget,
)

from wps_profile_cipher import (
    FeatureCodec, OemSignature, ProfileConverter,
    ProfileValueCipher, analyze_config, looks_like_plaintext, _selftest,
)

APP_TITLE = "WPS 配置文件加解密工具"
APP_VERSION = "2.0"


# ----------------------------------------------------------------------------
# 后台任务
# ----------------------------------------------------------------------------

class Worker(QThread):
    """在后台线程执行耗时任务，避免界面卡死。"""

    finished_ok = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self):
        try:
            result = self._fn(*self._args, **self._kwargs)
            self.finished_ok.emit(result if isinstance(result, str) else str(result))
        except Exception:
            self.failed.emit(traceback.format_exc())


# ----------------------------------------------------------------------------
# 主窗口
# ----------------------------------------------------------------------------

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.converter = ProfileConverter()
        self.value_cipher = ProfileValueCipher()
        self.feature_codec = FeatureCodec()
        self._worker: Optional[Worker] = None
        self._log_lines: List[str] = []
        self._last_list_info = None      # 上次解密得到的 ListInfo，供加密还原列表结构

        self.setWindowTitle("%s v%s" % (APP_TITLE, APP_VERSION))
        # 按屏幕可用高度自适应，避免在小屏上底部被裁掉
        screen = QApplication.primaryScreen()
        avail = screen.availableGeometry() if screen else None
        if avail is not None:
            w = min(1080, max(880, avail.width() - 60))
            h = min(760, max(560, avail.height() - 70))
        else:
            w, h = 1080, 720
        self.resize(w, h)

        tabs = QTabWidget()
        tabs.addTab(self._build_file_tab(), "文件转换")
        tabs.addTab(self._build_param_tab(), "参数编辑器")
        tabs.addTab(self._build_analyze_tab(), "配置分析")
        tabs.addTab(self._build_flow_tab(), "读取流程")
        tabs.addTab(self._build_text_tab(), "文本编解码")
        tabs.addTab(self._build_sign_tab(), "OEM 签名")
        tabs.addTab(self._build_about_tab(), "关于")

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)
        layout.addWidget(tabs, 1)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(5000)
        self.log_view.setFont(QFont("Monospace", 9))
        self.log_view.setPlaceholderText("运行日志…")

        self.log_box = QGroupBox("运行日志")
        log_layout = QVBoxLayout(self.log_box)
        log_layout.setContentsMargins(4, 2, 4, 2)
        log_layout.addWidget(self.log_view)
        self.log_box.setVisible(False)

        layout.addWidget(self.log_box, 0)

        self.setCentralWidget(central)
        self.statusBar().showMessage("就绪")

        # 菜单栏
        menubar = self.menuBar()
        view_menu = menubar.addMenu("视图(&V)")
        self.act_toggle_log = QAction("查看运行日志…", self)
        self.act_toggle_log.setShortcut("Ctrl+L")
        self.act_toggle_log.triggered.connect(self._toggle_log)
        view_menu.addAction(self.act_toggle_log)

        help_menu = menubar.addMenu("帮助(&H)")
        act_about = QAction("关于", self)
        act_about.triggered.connect(lambda: self._log(
            "%s v%s — 算法参考 github.com/NixaVulpi/WPSProfileCipher" % (APP_TITLE, APP_VERSION)))
        help_menu.addAction(act_about)

        self._log("工具已启动。算法: IDEA(feature) + AES-256-ECB(profile) + OemSignType1(签名)")

    # -- 工具方法 ----------------------------------------------------------

    def _log(self, text: str) -> None:
        """日志同时写入内存缓冲与状态栏；详细日志可通过「视图」菜单查看。"""
        self._log_lines.append(text)
        if len(self._log_lines) > 2000:
            del self._log_lines[:1000]
        self.statusBar().showMessage(text.replace("\n", " ")[:160], 8000)

    def _show_log_dialog(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("运行日志")
        dlg.resize(820, 480)
        lay = QVBoxLayout(dlg)
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setFont(QFont("Monospace", 9))
        view.setPlainText("\n".join(self._log_lines))
        view.moveCursor(QTextCursor.End)
        lay.addWidget(view)
        btn = QPushButton("关闭")
        btn.clicked.connect(dlg.accept)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(btn)
        lay.addLayout(row)
        dlg.exec_()

    def _toggle_log(self, checked: bool) -> None:
        self._show_log_dialog()

    def _set_busy(self, busy: bool, message: str = "") -> None:
        self.statusBar().showMessage(message or ("处理中…" if busy else "就绪"))
        QApplication.processEvents()

    def _run_async(self, fn, on_done, *args, **kwargs) -> None:
        if self._worker is not None and self._worker.isRunning():
            QMessageBox.warning(self, "提示", "已有任务在运行，请稍候。")
            return
        self._set_busy(True)
        worker = Worker(fn, *args, **kwargs)
        self._worker = worker

        def _ok(text: str) -> None:
            self._set_busy(False)
            on_done(text)

        def _err(text: str) -> None:
            self._set_busy(False)
            self._log("!! 失败:\n" + text)
            QMessageBox.critical(self, "失败", text.splitlines()[-1] if text else "未知错误")

        worker.finished_ok.connect(_ok)
        worker.failed.connect(_err)
        worker.start()

    @staticmethod
    def _read_text(path: str) -> str:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            return fh.read()

    @staticmethod
    def _write_text(path: str, text: str) -> None:
        """原子写入：先写临时文件再改名，避免中途失败损坏原文件。"""
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except Exception:
            try:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            except OSError:
                pass
            raise

    def _decrypt_file_task(self, path: str):
        text = self._read_text(path)
        result, info = self.converter.decrypt_with_meta(
            text, self._current_line_ending())
        base, _ = os.path.splitext(path)
        out_path = base + ".decrypted.ini"
        self._write_text(out_path, result)
        # 记住 ListInfo，供后续加密时精确还原列表结构
        self._last_list_info = info
        return result

    def _on_decrypted(self, text: str) -> None:
        self.preview.setPlainText(text)
        self._log("解密完成，共 %d 行。已保存为 *.decrypted.ini" % len(text.splitlines()))

    def _do_encrypt_file(self) -> None:
        path = self.input_edit.text().strip()
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "提示", "请先选择有效的输入文件。")
            return
        self._log("正在加密: " + path)
        header = self.header_edit.text().strip() or None
        self._run_async(self._encrypt_file_task, self._on_encrypted,
                        path, header)

    def _encrypt_file_task(self, path: str, header: Optional[str]) -> str:
        text = self._read_text(path)
        result = self.converter.encrypt_document(
            text, self._current_line_ending(), header,
            list_info=getattr(self, "_last_list_info", None))
        base, _ = os.path.splitext(path)
        out_path = base + ".encrypted.ini"
        self._write_text(out_path, result)
        return result

    def _on_encrypted(self, text: str) -> None:
        self.preview.setPlainText(text)
        self._log("加密完成，共 %d 行。已保存为 *.encrypted.ini" % len(text.splitlines()))

    # -- 文件转换 ----------------------------------------------------------

    def _build_file_tab(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)

        # 输入
        in_box = QGroupBox("输入文件")
        in_layout = QHBoxLayout(in_box)
        self.input_edit = QLineEdit()
        self.input_edit.setPlaceholderText("选择 oem.ini / product.dat 等 WPS 配置文件…")
        self.input_edit.editingFinished.connect(self._on_input_path_changed)
        self.input_edit.returnPressed.connect(self._on_input_path_changed)
        btn_in = QPushButton("浏览…")
        btn_in.clicked.connect(self._pick_input)
        in_layout.addWidget(self.input_edit, 1)
        in_layout.addWidget(btn_in)
        outer.addWidget(in_box)

        # 选项
        opt_box = QGroupBox("选项")
        opt_layout = QHBoxLayout(opt_box)

        self.le_combo = QComboBox()
        self.le_combo.addItems(["LF (\\n)", "CRLF (\\r\\n)"])
        opt_layout.addWidget(QLabel("换行符:"))
        opt_layout.addWidget(self.le_combo)

        self.header_edit = QLineEdit()
        self.header_edit.setPlaceholderText("可选：加密时在文件头插入的注释")
        opt_layout.addWidget(QLabel("头部注释:"))
        opt_layout.addWidget(self.header_edit, 1)

        opt_layout.addStretch(1)
        outer.addWidget(opt_box)

        # 操作按钮
        btn_row = QHBoxLayout()
        self.btn_decrypt = QPushButton("解密 → 明文")
        self.btn_decrypt.setMinimumHeight(38)
        self.btn_decrypt.clicked.connect(self._do_decrypt_file)

        self.btn_encrypt = QPushButton("加密 → 密文")
        self.btn_encrypt.setMinimumHeight(38)
        self.btn_encrypt.clicked.connect(self._do_encrypt_file)

        btn_row.addWidget(self.btn_decrypt)
        btn_row.addWidget(self.btn_encrypt)

        self.btn_analyze = QPushButton("分析当前文件")
        self.btn_analyze.setMinimumHeight(38)
        self.btn_analyze.clicked.connect(self._analyze_current)
        btn_row.addWidget(self.btn_analyze)

        outer.addLayout(btn_row)

        # 风险提示条
        self.risk_label = QLabel()
        self.risk_label.setWordWrap(True)
        self.risk_label.setVisible(False)
        outer.addWidget(self.risk_label)

        # 预览
        self.preview = QPlainTextEdit()
        self.preview.setFont(QFont("Monospace", 9))
        self.preview.setPlaceholderText("转换结果预览（解密后的明文 / 加密后的密文）…")
        outer.addWidget(self.preview, 1)

        return page

    def _on_input_path_changed(self) -> None:
        """输入框路径变化后，自动刷新风险提示。"""
        path = self.input_edit.text().strip()
        if path and os.path.isfile(path):
            self._update_risk_hint(path)
        else:
            self.risk_label.setVisible(False)

    def _pick_input(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择 WPS 配置文件", os.path.expanduser("~"),
            "WPS 配置 (*.ini *.dat *.cfg);;所有文件 (*)")
        if path:
            self.input_edit.setText(path)
            self._log("已选择: " + path)
            self._update_risk_hint(path)

    def _current_line_ending(self) -> str:
        return "\r\n" if self.le_combo.currentIndex() == 1 else "\n"

    def _do_decrypt_file(self) -> None:
        path = self.input_edit.text().strip()
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "提示", "请先选择有效的输入文件。")
            return
        self._log("正在解密: " + path)
        self._run_async(self._decrypt_file_task, self._on_decrypted, path)

    def _decrypt_file_task(self, path: str) -> str:
        text = self._read_text(path)
        result = self.converter.decrypt_document(text, self._current_line_ending())
        base, _ = os.path.splitext(path)
        out_path = base + ".decrypted.ini"
        self._write_text(out_path, result)
        return result

    def _on_decrypted(self, text: str) -> None:
        self.preview.setPlainText(text)
        self._log("解密完成，共 %d 行。已保存为 *.decrypted.ini" % len(text.splitlines()))

    def _do_encrypt_file(self) -> None:
        path = self.input_edit.text().strip()
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "提示", "请先选择有效的输入文件。")
            return
        self._log("正在加密: " + path)
        header = self.header_edit.text().strip() or None
        self._run_async(self._encrypt_file_task, self._on_encrypted,
                        path, header)

    def _encrypt_file_task(self, path: str, header: Optional[str]) -> str:
        text = self._read_text(path)
        result = self.converter.encrypt_document(
            text, self._current_line_ending(), header)
        base, _ = os.path.splitext(path)
        out_path = base + ".encrypted.ini"
        self._write_text(out_path, result)
        return result

    def _on_encrypted(self, text: str) -> None:
        self.preview.setPlainText(text)
        self._log("加密完成，共 %d 行。已保存为 *.encrypted.ini" % len(text.splitlines()))

    # -- 参数编辑器 --------------------------------------------------------

    def _build_param_tab(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(2, 2, 2, 2)

        from param_editor import ParamEditor
        self.param_editor = ParamEditor()
        outer.addWidget(self.param_editor, 1)

        bar = QHBoxLayout()

        btn_plain = QPushButton("导出明文 oem.ini")
        btn_plain.clicked.connect(lambda: self._export_params(False))
        bar.addWidget(btn_plain)

        btn_cipher = QPushButton("导出加密 oem.ini")
        btn_cipher.clicked.connect(lambda: self._export_params(True))
        bar.addWidget(btn_cipher)

        btn_all = QPushButton("导出全部参数")
        btn_all.setToolTip("包含所有参数（不只是改动过的）")
        btn_all.clicked.connect(lambda: self._export_params(False, True))
        bar.addWidget(btn_all)

        bar.addStretch(1)
        self.param_hint = QLabel("提示：勾选框=开关，下拉框=枚举，输入框=文本/URL/数字")
        self.param_hint.setStyleSheet("color:#666;")
        bar.addWidget(self.param_hint)

        outer.addLayout(bar)
        return page

    def _export_params(self, encrypt: bool, all_params: bool = False) -> None:
        try:
            plain = self.param_editor.build_plain_ini(only_changed=not all_params)
        except Exception as exc:
            QMessageBox.critical(self, "生成失败", str(exc))
            return

        body = [l for l in plain.splitlines()
                if l.strip() and not l.strip().startswith(";")]
        if not body:
            QMessageBox.information(
                self, "提示",
                "没有可导出的内容。\n\n"
                "请先修改参数，或点击「导出全部参数」。")
            return

        suffix = ".encrypted.ini" if encrypt else ".plain.ini"
        path, _ = QFileDialog.getSaveFileName(
            self, "保存 oem.ini", os.path.expanduser("~/oem" + suffix),
            "INI 文件 (*.ini);;所有文件 (*)")
        if not path:
            return

        try:
            if encrypt:
                content = self.converter.encrypt_document(
                    plain, list_info=getattr(self.param_editor, "list_info", None))
            else:
                content = plain
            self._write_text(path, content)
        except Exception as exc:
            QMessageBox.critical(self, "保存失败", str(exc))
            self._log("!! 导出失败: %s" % exc)
            return

        self._log("已导出%s: %s" % ("加密" if encrypt else "明文", path))
        QMessageBox.information(
            self, "导出完成",
            "%s 已保存：\n%s\n\n行数: %d"
            % ("加密配置" if encrypt else "明文配置", path, len(plain.splitlines())))

    # -- 读取流程 ----------------------------------------------------------

    def _build_flow_tab(self) -> QWidget:
        from flow_view import FlowView
        self.flow_view = FlowView()
        return self.flow_view

    # -- 配置分析 ----------------------------------------------------------

    def _build_analyze_tab(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)

        in_row = QHBoxLayout()
        self.analyze_path = QLineEdit()
        self.analyze_path.setPlaceholderText("选择要分析的 oem.ini / product.dat …")
        btn_pick = QPushButton("浏览…")
        btn_pick.clicked.connect(self._pick_analyze_file)
        btn_run = QPushButton("开始分析")
        btn_run.setMinimumHeight(32)
        btn_run.clicked.connect(self._run_analyze)
        in_row.addWidget(self.analyze_path, 1)
        in_row.addWidget(btn_pick)
        in_row.addWidget(btn_run)
        outer.addLayout(in_row)

        self.analyze_out = QPlainTextEdit()
        self.analyze_out.setReadOnly(True)
        self.analyze_out.setFont(QFont("Monospace", 9))
        self.analyze_out.setPlaceholderText(
            "分析结果会显示在这里：\n"
            "  · 文件结构（段 / 条目 / 换行符 / BOM）\n"
            "  · 签名检测（OemSignType1 / 厂商 AES 签名）\n"
            "  · 授权相关字段（建议不要修改）\n"
            "  · 功能开关字段（可安全修改）\n"
            "  · 改动风险等级")
        outer.addWidget(self.analyze_out, 1)

        return page

    def _pick_analyze_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择要分析的配置文件", os.path.expanduser("~"),
            "WPS 配置 (*.ini *.dat *.cfg);;所有文件 (*)")
        if path:
            self.analyze_path.setText(path)

    def _run_analyze(self) -> None:
        path = self.analyze_path.text().strip()
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "提示", "请先选择有效的文件。")
            return
        try:
            with open(path, "rb") as fh:
                raw_bytes = fh.read()
            text = raw_bytes.decode("utf-8-sig", errors="replace")
            analysis = analyze_config(text, raw_bytes=raw_bytes)
        except Exception as exc:
            QMessageBox.critical(self, "分析失败", str(exc))
            return

        self.analyze_out.setPlainText("\n".join(analysis.summary_lines()))
        self._log("分析完成: %s  风险=%s" % (path, analysis.risk_level))

    def _analyze_current(self) -> None:
        """从文件转换页跳转到分析页并立即分析。"""
        path = self.input_edit.text().strip()
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "提示", "请先选择有效的输入文件。")
            return
        self.analyze_path.setText(path)
        self._run_analyze()
        # 切到分析页
        tabs = self.findChild(QTabWidget)
        if tabs is not None:
            tabs.setCurrentIndex(1)

    def _update_risk_hint(self, path: str) -> None:
        """在文件转换页顶部显示风险提示。"""
        try:
            with open(path, "rb") as fh:
                raw_bytes = fh.read()
            text = raw_bytes.decode("utf-8-sig", errors="replace")
            analysis = analyze_config(text, raw_bytes=raw_bytes)
        except Exception:
            self.risk_label.setVisible(False)
            return

        level = analysis.risk_level
        if level == "高":
            color, msg = "#c0392b", ("⚠ 高风险：此文件带厂商 AES 签名，"
                                     "修改内容后签名将失效，WPS 可能拒绝加载。请先备份。")
        elif level == "中":
            color, msg = "#d68910", ("⚠ 中风险：检测到授权字段或签名，"
                                     "建议只改功能开关，勿动授权项。")
        else:
            color, msg = "#1e8449", "✓ 低风险：无签名、无授权字段，可安全修改后重新加密。"

        self.risk_label.setText(
            '<span style="color:%s;font-weight:bold">%s</span>' % (color, msg))
        self.risk_label.setVisible(True)

    # -- 文本编解码 --------------------------------------------------------

    def _build_text_tab(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)

        ctrl = QGroupBox("单条编解码")
        form = QFormLayout(ctrl)

        self.codec_combo = QComboBox()
        self.codec_combo.addItems([
            "profile  — AES-256-ECB（普通键值）",
            "feature  — IDEA（[feature] 段的 id=value）",
        ])
        form.addRow("编码器:", self.codec_combo)

        self.text_in = QPlainTextEdit()
        self.text_in.setFont(QFont("Monospace", 9))
        self.text_in.setPlaceholderText(
            "profile 模式：输入任意文本，例如 Support/OpenTrailMode\n"
            "feature 模式：输入 id=value，例如 16777345=1")
        self.text_in.setFixedHeight(110)
        form.addRow("输入:", self.text_in)

        btn_row = QHBoxLayout()
        btn_enc = QPushButton("加密 / 编码")
        btn_enc.clicked.connect(lambda: self._do_text_codec(True))
        btn_dec = QPushButton("解密 / 解码")
        btn_dec.clicked.connect(lambda: self._do_text_codec(False))
        btn_row.addWidget(btn_enc)
        btn_row.addWidget(btn_dec)
        btn_row.addStretch(1)
        form.addRow("", btn_row)

        self.text_out = QPlainTextEdit()
        self.text_out.setFont(QFont("Monospace", 9))
        self.text_out.setReadOnly(True)
        self.text_out.setPlaceholderText("结果…")
        self.text_out.setFixedHeight(110)
        form.addRow("结果:", self.text_out)

        outer.addWidget(ctrl)

        # 批量
        batch = QGroupBox("批量解码（每行一条密文）")
        bl = QVBoxLayout(batch)
        self.batch_in = QPlainTextEdit()
        self.batch_in.setFont(QFont("Monospace", 9))
        self.batch_in.setPlaceholderText("每行粘贴一条密文…")
        self.batch_in.setFixedHeight(120)
        btn_batch = QPushButton("批量解码")
        btn_batch.clicked.connect(self._do_batch_decode)
        self.batch_out = QPlainTextEdit()
        self.batch_out.setFont(QFont("Monospace", 9))
        self.batch_out.setReadOnly(True)
        self.batch_out.setFixedHeight(120)
        bl.addWidget(self.batch_in)
        bl.addWidget(btn_batch)
        bl.addWidget(self.batch_out)
        outer.addWidget(batch)

        return page

    def _do_text_codec(self, encrypt: bool) -> None:
        text = self.text_in.toPlainText()
        if not text:
            QMessageBox.warning(self, "提示", "请输入内容。")
            return
        use_feature = self.codec_combo.currentIndex() == 1
        try:
            if use_feature:
                if encrypt:
                    if "=" not in text:
                        raise ValueError("feature 模式需输入 id=value")
                    k, v = text.split("=", 1)
                    rk, rv = self.feature_codec.encrypt_entry(int(k.strip()), int(v.strip()))
                    result = "%s=%s" % (rk, rv)
                else:
                    if "=" not in text:
                        raise ValueError("feature 模式需输入 key=value")
                    k, v = text.split("=", 1)
                    fid, val = self.feature_codec.decrypt_entry(k.strip(), v.strip())
                    result = "%d=%d" % (fid, val)
            else:
                result = (self.value_cipher.encrypt(text) if encrypt
                          else self.value_cipher.decrypt(text))
        except Exception as exc:
            QMessageBox.critical(self, "失败", str(exc))
            self._log("!! 文本编解码失败: %s" % exc)
            return
        self.text_out.setPlainText(result)
        self._log("%s 完成（%s 模式）" % ("加密" if encrypt else "解密",
                                       "feature" if use_feature else "profile"))

    def _do_batch_decode(self) -> None:
        lines = [l.strip() for l in self.batch_in.toPlainText().splitlines() if l.strip()]
        if not lines:
            return
        out: List[str] = []
        for i, line in enumerate(lines, 1):
            try:
                out.append("%3d. %s" % (i, self.value_cipher.decrypt(line)))
            except Exception as exc:
                out.append("%3d. <失败: %s>" % (i, exc))
        self.batch_out.setPlainText("\n".join(out))
        self._log("批量解码完成，共 %d 条" % len(lines))

    # -- OEM 签名 ----------------------------------------------------------

    def _build_sign_tab(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)

        info = QLabel(
            "OemSignType1 签名会在加密内容末尾追加 <b>;OemSignType1=</b> 与签名载荷。<br>"
            "签名密钥由 <b>MachineGuid + InstallPartialData</b> 派生，必须与本机安装信息一致，"
            "否则 WPS 校验失败。")
        info.setWordWrap(True)
        outer.addWidget(info)

        box = QGroupBox("签名材料")
        form = QFormLayout(box)

        self.guid_edit = QLineEdit()
        self.guid_edit.setPlaceholderText("例如 3f2504e0-4f89-11d3-9a0c-0305e82c3301")
        form.addRow("MachineGuid:", self.guid_edit)

        self.setup_edit = QLineEdit()
        self.setup_edit.setPlaceholderText("office6/cfgs/setup.cfg 中的 InstallPartialData")
        form.addRow("Setup InstallPartialData:", self.setup_edit)

        self.registry_edit = QLineEdit()
        self.registry_edit.setPlaceholderText("WPS 注册表项中的 InstallPartialData")
        form.addRow("Registry InstallPartialData:", self.registry_edit)

        outer.addWidget(box)

        row = QHBoxLayout()
        self.btn_sign = QPushButton("为当前文件追加签名")
        self.btn_sign.setMinimumHeight(36)
        self.btn_sign.clicked.connect(self._do_sign)
        row.addWidget(self.btn_sign)
        row.addStretch(1)
        outer.addLayout(row)

        self.sign_out = QPlainTextEdit()
        self.sign_out.setReadOnly(True)
        self.sign_out.setFont(QFont("Monospace", 9))
        self.sign_out.setPlaceholderText("签名结果预览…")
        outer.addWidget(self.sign_out, 1)

        return page

    def _do_sign(self) -> None:
        path = self.input_edit.text().strip()
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "提示", "请先在「文件转换」页选择要签名的文件。")
            return
        guid = self.guid_edit.text().strip()
        setup = self.setup_edit.text().strip()
        reg = self.registry_edit.text().strip()
        if not (guid and setup and reg):
            QMessageBox.warning(self, "提示", "三个签名材料都必须填写。")
            return
        self._log("正在签名: " + path)
        self._run_async(self._sign_task, self._on_signed, path, guid, setup, reg)

    def _sign_task(self, path: str, guid: str, setup: str, reg: str) -> str:
        with open(path, "rb") as fh:
            content = fh.read()
        signed = OemSignature.append(content, guid, setup, reg)
        out_path = os.path.splitext(path)[0] + ".signed.ini"
        with open(out_path, "wb") as fh:
            fh.write(signed)
        return signed.decode("latin-1")

    def _on_signed(self, text: str) -> None:
        tail = text[-400:] if len(text) > 400 else text
        self.sign_out.setPlainText("…（末尾片段）…\n" + tail)
        self._log("签名完成，已保存为 *.signed.ini")

    # -- 关于 --------------------------------------------------------------

    def _build_about_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setFont(QFont("Monospace", 9))
        text.setPlainText(
            "%s v%s\n"
            "=============================================\n\n"
            "WPS Office 配置文件 (oem.ini / product.dat) 加解密工具。\n\n"
            "支持的算法\n"
            "-----------\n"
            "1. [feature] 段\n"
            "   IDEA 分组密码，密钥 = MD5(\"wps\") (16 字节)\n"
            "   明文 -> IDEA-ECB -> 追加 3 字节 (md5[0], md5[8], 0x01)\n"
            "        -> 首字节与 trailer 首字节做 bit0/bit4 交换\n"
            "        -> 自定义 base64 (0123456789A-Za-z-_)\n"
            "   条目语义: <feature_id>=<value>，两者都是十进制整数，\n"
            "   且值内部编码为 \"<id>:<value>\"。\n\n"
            "2. 普通键值\n"
            "   AES-256-ECB，固定密钥 \"F9AF610AE6164C73B78B0A99D8B72890\"\n"
            "   PKCS#7 填充，输出标准 base64 后替换:\n"
            "     '+' -> '_'   '/' -> '-'   '=' -> '.'\n\n"
            "3. OemSignType1 签名\n"
            "   digest = MD5(content + \";OemSignType1=\") 的大写十六进制\n"
            "   key    = MD5(MachineGuid + salt + setupPartial + registryPartial)\n"
            "            的大写十六进制前 16 字符，逐字节 XOR KEY_MASK\n"
            "   签名载荷 = (IV XOR IV_MASK) + AES-CBC(digest, key, IV)\n"
            "   追加形式 = content + \";OemSignType1=\" + 载荷大写十六进制\n\n"
            "算法参考\n"
            "---------\n"
            "https://github.com/NixaVulpi/WPSProfileCipher\n\n"
            "说明\n"
            "----\n"
            "• 纯 Python 实现，IDEA 与 AES 均内置，不依赖 Java / C++ 运行时。\n"
            "• 有 pycryptodome 时自动使用（更快）；没有则走纯 Python 兜底。\n"
            "• 解密后的明文默认保存为 <原名>.decrypted.ini，不覆盖原文件。\n" % (APP_TITLE, APP_VERSION)
        )
        layout.addWidget(text)

        btn = QPushButton("运行内置自检")
        btn.clicked.connect(self._run_selftest)
        layout.addWidget(btn)
        return page

    def _run_selftest(self) -> None:
        try:
            _selftest()
            self._log("内置自检通过：IDEA 向量 / Feature 往返 / AES 向量 / Profile 往返")
            QMessageBox.information(self, "自检", "全部通过。")
        except Exception as exc:
            self._log("!! 自检失败: %s" % exc)
            QMessageBox.critical(self, "自检失败", str(exc))


def _cli_check(path: str) -> int:
    """命令行检查单个配置文件：解密、校验、报告结构。"""
    try:
        raw = open(path, "rb").read()
    except OSError as exc:
        print("无法读取文件: %s" % exc)
        return 2

    text = raw.decode("utf-8-sig", errors="replace")
    conv = ProfileConverter()
    encrypted = not looks_like_plaintext(text)
    try:
        if encrypted:
            plain, info = conv.decrypt_with_meta(text)
        else:
            plain, info = text, None
    except Exception as exc:
        print("解密失败: %s" % exc)
        return 1

    analysis = analyze_config(text, plain_text=plain, raw_bytes=raw)
    print("文件: %s (%d 字节)" % (path, len(raw)))
    print("内容: %s" % ("已加密" if encrypted else "明文"))
    print()
    for line in analysis.summary_lines():
        print(line)

    if encrypted and info is not None:
        back = conv.encrypt_document(plain, list_info=info).encode()
        print()
        print("往返校验: %s"
              % ("字节级一致" if back == raw else "不一致（有信息损失）"))
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if "--version" in argv:
        print("%s v%s" % (APP_TITLE, APP_VERSION))
        return 0
    if "--selftest" in argv:
        try:
            _selftest()
        except Exception as exc:
            print("自检失败: %s" % exc)
            return 1
        return 0
    if "--check" in argv:
        idx = argv.index("--check")
        if idx + 1 >= len(argv):
            print("用法: --check <文件路径>")
            return 2
        return _cli_check(argv[idx + 1])

    app = QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    window = MainWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
