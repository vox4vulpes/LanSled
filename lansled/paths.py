"""Where to find this package's own files -- handles both a normal install
and a PyInstaller-frozen portable executable, where everything lives under
sys._MEIPASS instead of next to this file."""
import os
import sys


def package_dir():
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, "lansled")
    return os.path.dirname(os.path.abspath(__file__))


def static_dir():
    return os.path.join(package_dir(), "static")
