"""MAC address vendor lookup, from a local IEEE OUI database -- no network
calls, nothing about your devices ever leaves the machine."""
import json
import os

_OUI_PATH = os.path.join(os.path.dirname(__file__), "static", "oui.json")
_oui = None


def _load():
    global _oui
    if _oui is None:
        try:
            with open(_OUI_PATH, "r", encoding="utf-8") as f:
                _oui = json.load(f)
        except OSError:
            _oui = {}
    return _oui


def normalize_mac(mac):
    """'aa:bb:cc:dd:ee:ff' / 'AA-BB-CC-DD-EE-FF' -> 'AABBCCDDEEFF', or None."""
    if not mac:
        return None
    cleaned = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    if len(cleaned) != 12 or any(c not in "0123456789ABCDEF" for c in cleaned):
        return None
    return cleaned


def lookup(mac):
    """Return the vendor name for a MAC address, or None if unknown."""
    cleaned = normalize_mac(mac)
    if not cleaned:
        return None
    return _load().get(cleaned[:6])
