#!/bin/bash
# WPS 配置文件加解密工具 — 启动脚本
# 用法: ./run.sh            启动图形界面
#       ./run.sh --cli ...  使用命令行（不依赖 PyQt5）

cd "$(dirname "$0")" || exit 1

# 命令行模式直接转交，不需要 PyQt5
case "$1" in
    --cli)
        shift
        exec python3 wps_cipher_cli.py "$@"
        ;;
esac

# 检查 PyQt5
if ! python3 -c "import PyQt5" 2>/dev/null; then
    echo "错误: 未安装 PyQt5，无法启动图形界面"
    echo ""
    echo "安装方法:"
    echo "  sudo apt install python3-pyqt5"
    echo ""
    echo "或使用命令行模式（不需要 PyQt5）:"
    echo "  ./run.sh --cli --help"
    exit 1
fi

# 提示加速库
if python3 -c "from Crypto.Cipher import AES" 2>/dev/null; then
    echo "使用 pycryptodome 加速"
else
    echo "未检测到 pycryptodome，使用内置纯 Python 实现（速度较慢但功能完整）"
fi

exec python3 wps_cipher_gui.py "$@"
