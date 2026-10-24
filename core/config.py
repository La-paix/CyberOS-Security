"""
CORE CONFIG - Global configuration, themes, languages, preferences
Central settings manager for CyberOS_Security
"""
import json, os
from pathlib import Path

ROOT = Path(__file__).parent.parent
CONFIG_FILE = ROOT / "data" / "config.json"
I18N_FILE = ROOT / "data" / "i18n.json"

# ─── THEMES ─────────────────────────────────────────────────────────────────
THEMES = {
    "dark": {
        "name": "dark",
        "bg_dark":   "#0a0f1a",
        "bg_medium": "#111827",
        "bg_light":  "#1f2937",
        "bg_card":   "#162032",
        "accent":    "#00d4ff",
        "accent2":   "#7c3aed",
        "accent3":   "#00ff88",
        "danger":    "#ff3b3b",
        "warning":   "#ff8c00",
        "success":   "#00ff88",
        "text":      "#f1f5f9",
        "text_sub":  "#94a3b8",
        "text_muted":"#475569",
        "border":    "#374151",
        "scrollbar": "#374151",
    },
    "light": {
        "name": "light",
        "bg_dark":   "#f8fafc",
        "bg_medium": "#ffffff",
        "bg_light":  "#f1f5f9",
        "bg_card":   "#e2e8f0",
        "accent":    "#0369a1",
        "accent2":   "#7c3aed",
        "accent3":   "#059669",
        "danger":    "#dc2626",
        "warning":   "#d97706",
        "success":   "#059669",
        "text":      "#0f172a",
        "text_sub":  "#475569",
        "text_muted":"#94a3b8",
        "border":    "#cbd5e1",
        "scrollbar": "#94a3b8",
    },
    "high_contrast": {
        "name": "high_contrast",
        "bg_dark":   "#000000",
        "bg_medium": "#0a0a0a",
        "bg_light":  "#111111",
        "bg_card":   "#1a1a1a",
        "accent":    "#ffff00",
        "accent2":   "#ff00ff",
        "accent3":   "#00ff00",
        "danger":    "#ff0000",
        "warning":   "#ffaa00",
        "success":   "#00ff00",
        "text":      "#ffffff",
        "text_sub":  "#eeeeee",
        "text_muted":"#cccccc",
        "border":    "#ffffff",
        "scrollbar": "#888888",
    },
    "blue_dark": {
        "name": "blue_dark",
        "bg_dark":   "#030712",
        "bg_medium": "#0c1631",
        "bg_light":  "#1e3a5f",
        "bg_card":   "#112244",
        "accent":    "#60a5fa",
        "accent2":   "#818cf8",
        "accent3":   "#34d399",
        "danger":    "#f87171",
        "warning":   "#fbbf24",
        "success":   "#34d399",
        "text":      "#e0f2fe",
        "text_sub":  "#93c5fd",
        "text_muted":"#64748b",
        "border":    "#1e40af",
        "scrollbar": "#1e40af",
    },
    "matrix": {
        "name": "matrix",
        "bg_dark":   "#000300",
        "bg_medium": "#001200",
        "bg_light":  "#002200",
        "bg_card":   "#001a00",
        "accent":    "#00ff41",
        "accent2":   "#008f11",
        "accent3":   "#00ff41",
        "danger":    "#ff0000",
        "warning":   "#ffff00",
        "success":   "#00ff41",
        "text":      "#00ff41",
        "text_sub":  "#008f11",
        "text_muted":"#005500",
        "border":    "#003300",
        "scrollbar": "#003300",
    },
}

# ─── FONT SIZES ──────────────────────────────────────────────────────────────
FONT_SIZES = {
    "small":   {"title": 14, "body": 8,  "nav": 8,  "btn": 9,  "mono": 8},
    "medium":  {"title": 18, "body": 10, "nav": 10, "btn": 10, "mono": 9},
    "large":   {"title": 22, "body": 12, "nav": 11, "btn": 12, "mono": 11},
    "xlarge":  {"title": 28, "body": 15, "nav": 14, "btn": 14, "mono": 14},
}

DEFAULT_CONFIG = {
    "theme": "dark",
    "font_size": "medium",
    "language": "fr",
    "api_key": "",
    "ai_enabled": False,
    "auto_protect": True,
    "auto_quarantine": False,
    "threat_score_kill": 80,
    "threat_score_isolate": 60,
    "threat_score_alert": 40,
    "scan_on_startup": False,
    "show_notifications": True,
    "log_level": "INFO",
    "version": "2026.2.0",
}

class Config:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded = False
        return cls._instance

    def __init__(self):
        if self._loaded:
            return
        self._loaded = True
        self._data = dict(DEFAULT_CONFIG)
        self._i18n = {}
        self._load()
        self._load_i18n()

    def _load(self):
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        if CONFIG_FILE.exists():
            try:
                saved = json.loads(CONFIG_FILE.read_text())
                self._data.update(saved)
            except:
                pass

    def _load_i18n(self):
        if I18N_FILE.exists():
            try:
                self._i18n = json.loads(I18N_FILE.read_text())
            except:
                pass

    def save(self):
        safe = dict(self._data)
        # Don't save API key in plain text - it's stored encrypted
        safe["api_key"] = ""
        CONFIG_FILE.write_text(json.dumps(safe, indent=2))

    def get(self, key, default=None):
        return self._data.get(key, default)

    def set(self, key, value):
        self._data[key] = value
        self.save()

    def t(self, key: str) -> str:
        """Translate key to current language."""
        lang = self._data.get("language", "fr")
        lang_data = self._i18n.get(lang, self._i18n.get("fr", {}))
        return lang_data.get(key, self._i18n.get("en", {}).get(key, key))

    def theme(self) -> dict:
        return THEMES.get(self._data.get("theme", "dark"), THEMES["dark"])

    def fonts(self) -> dict:
        return FONT_SIZES.get(self._data.get("font_size", "medium"), FONT_SIZES["medium"])

    def available_themes(self) -> list:
        return list(THEMES.keys())

    def available_languages(self) -> list:
        return list(self._i18n.keys())

    def available_font_sizes(self) -> list:
        return list(FONT_SIZES.keys())
