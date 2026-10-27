"""Real Tkinter integration tests. Requires a display; no paid/external API."""
import contextlib
import io
from pathlib import Path
import queue
import threading
import time
import unittest
from unittest.mock import patch
from __main__ import IsolatedCase, ROOT, PASSWORD


class GUICase(unittest.TestCase):
    fixture = IsolatedCase.fixture
    license = IsolatedCase.license
    def setUp(self):
        IsolatedCase.setUp(self)
        self.errors = []
        self.dialogs = []
        self.dialog_patch = []
        for method in ("showerror", "showwarning", "showinfo", "askyesno"):
            def receive(*args, _method=method, **kwargs):
                self.dialogs.append((_method, args))
                if _method == "showerror":
                    self.errors.append(args)
                return False
            mock = patch("tkinter.messagebox."+method, side_effect=receive)
            mock.start()
            self.dialog_patch.append(mock)
        from gui.dashboard import CyberOSApp
        from core.controller import CentralController
        self.app = CyberOSApp()
        self.app.root.report_callback_exception = lambda kind, value, tb: self.errors.append(str(value))
        self.controller = CentralController()
        self.controller.auth.set_password(PASSWORD)
        self.controller.initialize_all_modules()
        self.app._controller = self.controller
        self.app._build_main_dashboard()
        self.pump(0.05)

    def pump(self, seconds=0.1, condition=None):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.app.root.update()
            if condition and condition():
                return True
            time.sleep(0.01)
        return bool(condition and condition())

    def tearDown(self):
        try:
            self.app._close()
        finally:
            for mock in self.dialog_patch:
                mock.stop()
            IsolatedCase.tearDown(self)

    def test_gui_login_password_and_dashboard(self):
        self.app._controller = None
        self.app._build_login()
        self.app._pw_var.set(PASSWORD)
        self.app._do_login()
        self.assertTrue(self.pump(3, lambda: self.app._controller is not None and hasattr(self.app, "_content")))
        self.pump(0.3)
        self.assertEqual([], self.errors)

    def test_gui_appearance_themes_languages_fonts(self):
        for theme in ("dark", "light", "high_contrast", "blue_dark", "matrix"):
            self.app._apply_theme(theme)
            self.pump(0.03)
        for language in ("fr", "en", "es", "pt"):
            self.app._apply_lang(language)
            self.pump(0.03)
        for size in ("small", "medium", "large", "xlarge"):
            self.app._apply_font(size)
            self.pump(0.03)
        self.assertEqual([], self.errors)

    def test_gui_full_scan_action_and_pdf(self):
        file = self.fixture("scan/clean.txt")
        self.app._show_full_scan()
        with patch("tkinter.filedialog.askdirectory", return_value=str(file.parent)):
            self.app._start_scan("full")
            self.assertTrue(self.pump(5, lambda: not self.app._scan_running))
        self.assertEqual(1, self.app._last_scan_result["files_scanned"])
        self.app._show_forensic()
        self.app._gen_pdf_report("SCAN")
        self.assertTrue(self.pump(5, lambda: any((ROOT/"reports/pdf").glob("*.pdf"))))
        self.pump(0.2)
        self.assertEqual([], self.errors)

    def test_gui_scan_stop_action(self):
        engine = self.controller._modules["engine"]
        for i in range(50):
            self.fixture(f"scan/{i}.txt")
        original = engine._scan_file
        def slow(path):
            time.sleep(0.02)
            return original(path)
        self.app._show_full_scan()
        with patch.object(engine, "_scan_file", side_effect=slow), \
             patch("tkinter.filedialog.askdirectory", return_value=str(self.root/"scan")):
            self.app._start_scan("full")
            self.pump(0.05)
            self.app._stop_scan()
            self.assertTrue(self.pump(4, lambda: not self.app._scan_running))
        self.assertTrue(self.app._last_scan_result["cancelled"])
        self.assertEqual([], self.errors)

    def test_gui_scan_failure_recovers_controls(self):
        self.app._show_full_scan()
        with patch.object(self.controller, "run_full_scan", side_effect=OSError("fixture failure")), \
             patch("tkinter.filedialog.askdirectory", return_value=str(self.root)):
            self.app._start_scan("full")
            self.assertTrue(self.pump(2, lambda: not self.app._scan_running))
        self.assertEqual("normal", str(self.app._scan_btn.cget("state")))
        self.assertTrue(any("fixture failure" in str(x) for x in self.errors))

    def test_gui_forensic_action_generates_json(self):
        engine = self.controller._modules["forensic"]
        self.app._show_forensic()
        with patch.object(engine, "collect_system_snapshot", return_value={"fixture": True}):
            self.app._do_forensic()
            self.assertTrue(self.pump(4, lambda: bool(engine.get_report_list())))
        self.pump(0.1)
        self.assertEqual([], self.errors)

    def test_gui_pdf_empty_results_prompt(self):
        self.app._show_forensic()
        self.app._gen_pdf_report("SCAN")
        self.app._gen_pdf_report("URL")
        self.assertEqual(2, sum(name == "showinfo" for name, _ in self.dialogs))
        self.assertEqual([], self.errors)

    def test_gui_general_pdf_action(self):
        self.app._show_forensic()
        self.app._gen_pdf_report("GENERAL")
        self.assertTrue(self.pump(5, lambda: any((ROOT/"reports/pdf").glob("*.pdf"))))
        self.pump(0.1)
        self.assertEqual([], self.errors)

    def test_gui_worker_result_after_navigation(self):
        self.app._show_full_scan()
        events = []
        self.app._run_job(lambda: (time.sleep(0.1), self.app._dispatch(lambda: events.append("stale"))))
        self.app._show_settings()
        self.pump(0.3)
        self.assertEqual([], events)
        self.assertEqual([], self.errors)

    def test_gui_assistant_send(self):
        self.app._show_assistant()
        self.app._chat_input.insert("1.0", "Bonjour")
        self.app._send_chat()
        self.assertTrue(self.pump(3, lambda: str(self.app._send_btn.cget("state")) == "normal"))
        self.assertEqual([], self.errors)

    def test_gui_shutdown_stops_background_modules(self):
        self.controller.start_protection()
        self.app._close()
        self.assertFalse(self.controller._modules["scheduler"]._active)
        self.assertFalse(self.controller._modules["integrity"]._active)
        # tearDown can be called after a user has already closed the window.
        self.app._close = lambda: None


    def test_gui_closing_cancels_timers(self):
        self.app._close()
        self.assertFalse(self.app.root.tk.call("after", "info"))

    def test_gui_scan_navigation_does_not_lock_future_scans(self):
        engine = self.controller._modules["engine"]
        self.fixture("scan/one.txt")
        original = engine._scan_file
        def slow(path):
            time.sleep(0.1)
            return original(path)
        self.app._show_full_scan()
        with patch.object(engine, "_scan_file", side_effect=slow), \
             patch("tkinter.filedialog.askdirectory", return_value=str(self.root/"scan")):
            self.app._start_scan("full")
            self.app._show_settings()
            self.assertTrue(self.pump(3, lambda: not self.app._scan_running))
        self.assertEqual(1, self.app._last_scan_result["files_scanned"])

    def test_gui_fresh_install_password_setup(self):
        from elpati.elpati_auth_voice import AUTH_DIR
        from elpati.elpati_crypto import KEYS_DIR
        for file in AUTH_DIR.glob("*"):
            file.unlink()
        (KEYS_DIR / "auth.initialized").unlink(missing_ok=True)
        self.app._controller = None
        self.app._build_login()
        self.app._pw_var.set(PASSWORD)
        self.app._pw_confirm.set("different")
        self.app._do_login()
        self.assertIn("12", self.app._login_msg.cget("text"))
        self.app._pw_confirm.set(PASSWORD)
        self.app._do_login()
        self.assertTrue(self.pump(3, lambda: self.app._controller is not None))
        self.pump(0.2)
        self.assertEqual([], self.errors)

    def test_gui_url_action_and_pdf(self):
        from elpati.elpati_url_scanner import ElpatiURLScanner
        self.app._show_url_scanner()
        result = {"url":"https://example.invalid/", "domain":"example.invalid", "checks":{},
                  "score":0, "verdict":"INCONCLUSIF", "verdict_color":"warning", "details":{},
                  "summary":[], "incomplete":True, "scan_duration_ms":1}
        # Find the URL StringVar created by the page, then exercise the button handler.
        self.app._url_var.set("https://example.invalid")
        with patch.object(ElpatiURLScanner, "scan_url", return_value=result):
            self.app._run_url_scan()
            self.assertTrue(self.pump(3, lambda: self.app._last_url_result is not None))
        self.app._show_forensic()
        self.app._gen_pdf_report("URL")
        self.assertTrue(self.pump(4, lambda: any((ROOT/"reports/pdf").glob("*.pdf"))))
        self.pump(0.1)
        self.assertEqual([], self.errors)

    def test_gui_quarantine_restore_button(self):
        from tkinter import ttk
        file = self.fixture()
        saved = self.controller._modules["quarantine"].quarantine_file(str(file), {})
        self.app._show_quarantine()
        def descendants(widget):
            for child in widget.winfo_children():
                yield child
                yield from descendants(child)
        children = list(descendants(self.app._content))
        tree = next(widget for widget in children if isinstance(widget, ttk.Treeview))
        tree.selection_set(saved["quarantine_id"])
        button = next(widget for widget in children if widget.winfo_class() == "Button" and widget.cget("text") == "RESTAURER")
        with patch("tkinter.messagebox.askyesno", return_value=True):
            button.invoke()
        self.assertTrue(file.exists())
        self.assertEqual([], self.errors)

    def test_gui_scheduler_pause_and_delete(self):
        from tkinter import ttk
        scheduler = self.controller._modules["scheduler"]
        identifier = scheduler.add_task("fixture", "quick_scan", 10)
        self.app._show_scheduler()
        def descendants(widget):
            for child in widget.winfo_children():
                yield child
                yield from descendants(child)
        children = list(descendants(self.app._content))
        self.app._sched_tree.selection_set(identifier)
        button = next(w for w in children if w.winfo_class() == "Button" and w.cget("text") == "PAUSE / REPRENDRE")
        button.invoke()
        self.assertFalse(scheduler.get_tasks()[0]["enabled"])
        self.app._sched_tree.selection_set(identifier)
        button = next(w for w in children if w.winfo_class() == "Button" and w.cget("text") == "SUPPRIMER")
        with patch("tkinter.messagebox.askyesno", return_value=True):
            button.invoke()
        self.assertEqual([], scheduler.get_tasks())
        self.assertEqual([], self.errors)

    def test_gui_full_pdf_action(self):
        self.app._last_scan_result = {"files_scanned": 5, "errors": 0, "threats_found": 0}
        self.app._show_forensic()
        self.app._gen_pdf_report("FULL")
        self.assertTrue(self.pump(5, lambda: any((ROOT/"reports/pdf").glob("*.pdf"))))
        self.pump(0.1)
        self.assertEqual([], self.errors)

    def test_gui_scan_distinguishes_static_review_and_signature_matches(self):
        self.app._show_full_scan()
        self.app._show_scan_results({"files_scanned": 2, "errors": 0, "skipped": 0,
            "duration_sec": 1, "threats_found": 1, "confirmed_threats": 0, "review_count": 1,
            "threats": [{"path": "review.ps1", "type": "HEURISTIC_ALERT", "score": 60,
                         "confirmed": False, "review_required": True}]})
        text = self.app._scan_results.get("1.0", "end")
        self.assertIn("Signatures identifiées: 0", text)
        self.assertIn("Indices à examiner: 1", text)
        self.assertIn("INDICE NON CONFIRMÉ", text)
        self.assertNotIn("MENACES DÉTECTÉES", text)
        self.assertEqual([], self.errors)

def page_test(method):
    def test(self):
        getattr(self.app, method)()
        self.pump(0.08)
        self.assertEqual([], self.errors)
    return test


for method in ("_show_overview", "_show_quick_scan", "_show_full_scan",
               "_show_processes", "_show_memory", "_show_network", "_show_threats",
               "_show_quarantine", "_show_sandbox", "_show_forensic", "_show_ai_analyst",
               "_show_logs", "_show_settings", "_show_url_scanner", "_show_vuln_scan",
               "_show_scheduler", "_show_auto_response", "_show_assistant"):
    setattr(GUICase, "test_gui_page" + method, page_test(method))

for method in ("_settings_appearance", "_settings_language", "_settings_security",
               "_settings_api", "_settings_license", "_settings_general"):
    def settings_test(self, method=method):
        self.app._show_settings()
        getattr(self.app, method)()
        self.pump(0.05)
        self.assertEqual([], self.errors)
    setattr(GUICase, "test_gui_page" + method, settings_test)
