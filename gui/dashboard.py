"""
GUI DASHBOARD v2 - CyberOS_Security
Features: Multi-theme, Multi-language, Font size, Password change, API key, License generator
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading, time, json, os
import queue
import traceback
from datetime import datetime
from pathlib import Path

def launch_gui():
    CyberOSApp().run()

class CyberOSApp:
    def __init__(self):
        from core.config import Config
        self.cfg = Config()
        self._T = self.cfg.theme()
        self._F = self.cfg.fonts()
        self._controller = None
        self._closed = False
        self._page_generation = 0
        self._ui_queue = queue.Queue()
        self._job_local = threading.local()
        self._clock_started = False
        self._scan_running = False
        self._scan_stop_requested = False
        self._last_scan_result = None
        self._last_url_result = None
        self._scan_start = 0
        self._stop_btn = None
        self._alerts = []
        self._assistant = None  # Lazy load
        self.root = tk.Tk()
        self.root.title(self.cfg.t("app_title"))
        self.root.geometry("1360x820")
        self.root.minsize(1024, 720)
        self.root.configure(bg=self._T["bg_dark"])
        self.root.resizable(True, True)
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.report_callback_exception = self._callback_error
        self.root.after(30, self._drain_ui)
        self._setup_styles()
        self._build_login()

    # ═══════════════════════════════════════════════════════════════════
    #  STYLE HELPERS
    # ═══════════════════════════════════════════════════════════════════
    def _setup_styles(self):
        T, F = self._T, self._F
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("Dark.TFrame", background=T["bg_dark"])
        s.configure("Card.TFrame",  background=T["bg_light"])
        s.configure("TScrollbar", background=T["scrollbar"], troughcolor=T["bg_dark"])
        s.configure("Treeview", background=T["bg_light"], foreground=T["text"],
                    fieldbackground=T["bg_light"], rowheight=24, font=("Consolas", F["body"]))
        s.configure("Treeview.Heading", background=T["bg_dark"], foreground=T["accent"],
                    font=("Consolas", F["body"], "bold"))
        s.map("Treeview", background=[("selected", T["accent2"])])
        s.configure("TProgressbar", background=T["accent"], troughcolor=T["bg_dark"])

    def _lbl(self, parent, text, size_key="body", color=None, bold=False, **kw):
        T, F = self._T, self._F
        return tk.Label(parent, text=text,
                        font=("Consolas", F[size_key], "bold" if bold else "normal"),
                        bg=kw.pop("bg", T["bg_medium"]),
                        fg=color or T["text"], **kw)

    def _btn(self, parent, text, cmd, color=None, fg=None, size_key="btn", **kw):
        T, F = self._T, self._F
        return tk.Button(parent, text=text,
                         font=("Consolas", F[size_key], "bold"),
                         bg=color or T["accent"], fg=fg or T["bg_dark"],
                         relief="flat", cursor="hand2",
                         activebackground=T["accent2"], activeforeground=T["text"],
                         command=cmd, **kw)

    def _entry(self, parent, var=None, show=None, width=30, **kw):
        T, F = self._T, self._F
        bg = kw.pop("bg", T["bg_dark"])
        fg = kw.pop("fg", T["accent"])
        return tk.Entry(parent, textvariable=var, show=show,
                        font=("Consolas", F["body"]),
                        bg=bg, fg=fg,
                        insertbackground=T["accent"],
                        relief="flat", width=width, **kw)

    def _frame(self, parent, bg_key="bg_medium", **kw):
        return tk.Frame(parent, bg=self._T[bg_key], **kw)

    def _sep(self, parent):
        return tk.Frame(parent, bg=self._T["border"], height=1)

    def _scrolltext(self, parent, h=10):
        T, F = self._T, self._F
        return scrolledtext.ScrolledText(parent,
            font=("Consolas", F["mono"]), bg=T["bg_dark"],
            fg=T["accent3"], insertbackground=T["accent"],
            relief="flat", height=h)

    def _rebuild_ui(self):
        """Rebuild entire UI — theme, font or language change."""
        # Force fresh config read (singleton already updated by set())
        from core.config import Config
        self.cfg = Config()
        self._T = self.cfg.theme()
        self._F = self.cfg.fonts()
        self.root.configure(bg=self._T["bg_dark"])
        # Destroy ALL existing widgets before rebuild
        for widget in self.root.winfo_children():
            try:
                widget.destroy()
            except:
                pass
        self._setup_styles()
        self.root.update_idletasks()
        if self._controller:
            self._build_main_dashboard()
        else:
            self._build_login()

    # ═══════════════════════════════════════════════════════════════════
    #  LOGIN
    # ═══════════════════════════════════════════════════════════════════
    def _build_login(self):
        from elpati.elpati_auth_voice import ElpatiAuthVoice
        self._auth = ElpatiAuthVoice()
        self._clear_root()
        T, F = self._T, self._F
        wrap = self._frame(self.root, "bg_dark")
        wrap.place(relx=0.5, rely=0.5, anchor="center")

        # Logo
        tk.Label(wrap, text="⬢", font=("Consolas", 64),
                 bg=T["bg_dark"], fg=T["accent"]).pack()
        tk.Label(wrap, text="CyberOS_Security",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_dark"], fg=T["text"]).pack()
        tk.Label(wrap, text="ELPATI System v2026.2.1",
                 font=("Consolas", F["body"]),
                 bg=T["bg_dark"], fg=T["accent"]).pack(pady=2)
        tk.Label(wrap, text="Outils locaux de sécurité — version de validation",
                 font=("Consolas", F["body"]),
                 bg=T["bg_dark"], fg=T["text_muted"]).pack(pady=(0,25))

        card = self._frame(wrap, "bg_light")
        card.pack(padx=10, pady=5, ipadx=25, ipady=20)

        tk.Label(card, text=self.cfg.t("login_title"),
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_light"], fg=T["accent"]).pack()
        tk.Label(card, text=self.cfg.t("login_subtitle"),
                 font=("Consolas", F["body"]),
                 bg=T["bg_light"], fg=T["text_sub"]).pack(pady=(4,14))

        self._pw_var = tk.StringVar()
        e = self._entry(card, self._pw_var, show="●", width=28, bg=T["bg_dark"])
        e.pack(pady=4)
        e.focus(); e.bind("<Return>", lambda _: self._do_login())

        self._pw_confirm = tk.StringVar()
        if self._auth.needs_setup:
            tk.Label(card, text="Créer votre mot de passe (12 caractères minimum)",
                     bg=T["bg_light"], fg=T["text"]).pack(pady=4)
            self._entry(card, self._pw_confirm, show="●", width=28).pack(pady=4)
            tk.Label(card, text="Répéter le mot de passe", bg=T["bg_light"], fg=T["text_sub"]).pack()
        self._login_msg = tk.Label(card, text="",
                                   font=("Consolas", F["body"]),
                                   bg=T["bg_light"], fg=T["danger"])
        self._login_msg.pack()

        self._btn(card, self.cfg.t("login_btn"), self._do_login,
                  padx=25, pady=10).pack(pady=10)
        tk.Label(card, text="Première connexion : créer un mot de passe" if self._auth.needs_setup else "",
                 font=("Consolas", F["body"]),
                 bg=T["bg_light"], fg=T["text_muted"]).pack()

        # Language quick-select at login
        lang_f = self._frame(wrap, "bg_dark")
        lang_f.pack(pady=(15,0))
        tk.Label(lang_f, text="🌐",
                 font=("Consolas", 11),
                 bg=T["bg_dark"], fg=T["text_muted"]).pack(side="left")
        for lang, lbl in [("fr","FR"),("en","EN"),("es","ES"),("pt","PT")]:
            c = T["accent"] if self.cfg.get("language") == lang else T["text_muted"]
            tk.Button(lang_f, text=lbl,
                      font=("Consolas", F["body"]),
                      bg=T["bg_dark"], fg=c, relief="flat", padx=6,
                      cursor="hand2",
                      command=lambda l=lang: self._quick_lang(l)).pack(side="left", padx=2)

    def _quick_lang(self, lang):
        self.cfg.set("language", lang)
        self._build_login()

    def _do_login(self):
        auth = self._auth
        pw = self._pw_var.get()
        if auth.needs_setup:
            if pw != self._pw_confirm.get() or not auth.set_password(pw):
                self._login_msg.config(text="Confirmation identique et 12 caractères minimum requis.")
                return
        if auth.verify_password(pw):
            self._login_msg.config(text="✓ OK", fg=self._T["success"])
            self.root.after(100, self._init_dashboard)
        else:
            error = auth.get_status().get("error")
            self._login_msg.config(text=error or ("Compte bloqué 5 min" if auth.is_locked() else "Mot de passe incorrect"))
            self._pw_var.set("")

    def _init_dashboard(self):
        lbl = tk.Label(self.root, text="Initialisation ELPATI...",
                       font=("Consolas", 12), bg=self._T["bg_dark"], fg=self._T["accent"])
        lbl.place(relx=0.5, rely=0.6, anchor="center")
        self.root.update()
        def _go():
            from core.controller import CentralController
            self._controller = CentralController()
            self._controller.initialize_all_modules()
            if self._closed:
                self._controller.stop_protection()
                return
            self._controller.register_alert_callback(self._on_alert_cb)
            self._controller.start_protection()
            self._dispatch(self._build_main_dashboard)
        self._run_job(_go)

    def _on_alert_cb(self, alert):
        self._alerts.insert(0, alert)
        self._alerts = self._alerts[:100]

    # ═══════════════════════════════════════════════════════════════════
    #  MAIN DASHBOARD
    # ═══════════════════════════════════════════════════════════════════
    def _build_main_dashboard(self):
        self._setup_styles()
        self._clear_root()
        T = self._T
        self.root.configure(bg=T["bg_dark"])
        mf = self._frame(self.root, "bg_dark")
        mf.pack(fill="both", expand=True)
        self._build_topbar(mf)
        body = self._frame(mf, "bg_dark")
        body.pack(fill="both", expand=True)
        self._build_sidebar(body)
        self._content = self._frame(body, "bg_medium")
        self._content.pack(side="left", fill="both", expand=True)
        self._show_overview()
        self._start_live_updates()

    def _build_topbar(self, parent):
        T, F = self._T, self._F
        bar = self._frame(parent, "bg_light")
        bar.pack(fill="x")
        tk.Label(bar, text="⬢  CyberOS_Security",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_light"], fg=T["accent"]).pack(side="left", padx=16, pady=10)
        tk.Label(bar, text="ELPATI v2026.2.1",
                 font=("Consolas", F["body"]),
                 bg=T["bg_light"], fg=T["text_muted"]).pack(side="left")
        self._ai_badge = tk.Label(bar, text="",
                                   font=("Consolas", F["body"]),
                                   bg=T["bg_light"], fg=T["warning"])
        self._ai_badge.pack(side="left", padx=10)
        self._topbar_status = tk.Label(bar, text="● Surveillance locale" if self._controller and self._controller._protection_active else "● Outils locaux",
                                        font=("Consolas", F["body"], "bold"),
                                        bg=T["bg_light"], fg=T["success"])
        self._topbar_status.pack(side="right", padx=16)
        self._clock = tk.Label(bar, text="",
                                font=("Consolas", F["body"]),
                                bg=T["bg_light"], fg=T["text_muted"])
        self._clock.pack(side="right", padx=10)

    def _build_sidebar(self, parent):
        T, F = self._T, self._F

        # Outer container fixed width
        sb_outer = self._frame(parent, "bg_light")
        sb_outer.pack(side="left", fill="y")
        sb_outer.config(width=210)
        sb_outer.pack_propagate(False)

        # Title (fixed, not scrollable)
        tk.Label(sb_outer, text="NAVIGATION", font=("Consolas", F["body"], "bold"),
                 bg=T["bg_light"], fg=T["text_muted"]).pack(pady=(12,2), padx=15, anchor="w")

        # Canvas + scrollbar for scrollable nav
        canvas = tk.Canvas(sb_outer, bg=T["bg_light"], highlightthickness=0,
                           borderwidth=0)
        scrollbar = tk.Scrollbar(sb_outer, orient="vertical",
                                 command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        # Scrollbar on right, canvas fills rest
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        # Inner frame inside canvas
        inner = tk.Frame(canvas, bg=T["bg_light"])
        canvas_window = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_inner_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(canvas_window, width=canvas.winfo_width())

        def _on_canvas_configure(event):
            canvas.itemconfig(canvas_window, width=event.width)

        inner.bind("<Configure>", _on_inner_configure)
        canvas.bind("<Configure>", _on_canvas_configure)

        # Mouse wheel scroll — bind to canvas and inner frame
        def _on_mousewheel(event):
            try:
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            except:
                pass

        def _on_mousewheel_linux(event):
            try:
                if event.num == 4:
                    canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    canvas.yview_scroll(1, "units")
            except:
                pass

        canvas.bind("<MouseWheel>", _on_mousewheel)
        inner.bind("<MouseWheel>", _on_mousewheel)
        canvas.bind("<Button-4>", _on_mousewheel_linux)
        canvas.bind("<Button-5>", _on_mousewheel_linux)
        inner.bind("<Button-4>", _on_mousewheel_linux)
        inner.bind("<Button-5>", _on_mousewheel_linux)

        # Navigation items
        nav = [
            ("⬡", "nav_overview",   self._show_overview),
            ("⚡", "nav_quickscan", self._show_quick_scan),
            ("🔍","nav_fullscan",   self._show_full_scan),
            ("⚙", "nav_processes", self._show_processes),
            ("💾","nav_memory",    self._show_memory),
            ("🌐","nav_network",   self._show_network),
            ("🚨","nav_threats",   self._show_threats),
            ("🔒","nav_quarantine",self._show_quarantine),
            ("🧪","nav_sandbox",   self._show_sandbox),
            ("📋","nav_forensic",  self._show_forensic),
            ("🧠","nav_ai",        self._show_ai_analyst),
            ("📊","nav_logs",      self._show_logs),
            ("⚙", "nav_settings",   self._show_settings),
            ("🌍", "nav_urlscan",    self._show_url_scanner),
            ("🔎", "nav_vulnscan",   self._show_vuln_scan),
            ("⏰", "nav_scheduler",  self._show_scheduler),
            ("🤖", "nav_autorespond",self._show_auto_response),
            ("💬", "nav_assistant",  self._show_assistant),
        ]

        for icon, key, cmd in nav:
            btn = tk.Button(inner, text=f"{icon}  {self.cfg.t(key)}",
                            font=("Consolas", F["nav"]),
                            bg=T["bg_light"], fg=T["text_sub"],
                            relief="flat", anchor="w", padx=16, pady=8,
                            cursor="hand2",
                            activebackground=T["bg_medium"],
                            activeforeground=T["accent"],
                            command=cmd)
            btn.pack(fill="x")
            # Also bind scroll on each button
            btn.bind("<MouseWheel>", _on_mousewheel)
            btn.bind("<Button-4>", _on_mousewheel_linux)
            btn.bind("<Button-5>", _on_mousewheel_linux)

        # Version label at bottom of inner frame
        tk.Label(inner, text="v2026.2.1 | Outils locaux",
                 font=("Consolas", F["body"]),
                 bg=T["bg_light"], fg=T["text_muted"]).pack(pady=10)

    # ═══════════════════════════════════════════════════════════════════
    #  OVERVIEW
    # ═══════════════════════════════════════════════════════════════════
    def _show_overview(self):
        self._clear_content()
        T, F = self._T, self._F
        f = self._frame(self._content, "bg_medium")
        f.pack(fill="both", expand=True, padx=20, pady=20)
        tk.Label(f, text="VUE D'ENSEMBLE / OVERVIEW",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tk.Label(f, text=ts, font=("Consolas", F["body"]),
                 bg=T["bg_medium"], fg=T["text_muted"]).pack(anchor="w", pady=(2,16))

        # Stat cards
        row = self._frame(f, "bg_medium")
        row.pack(fill="x", pady=(0,16))
        try:
            st = self._controller.get_system_status()
            state = st.get("state", {})
            sys_i = st.get("system", {})
            mem = sys_i.get("memory", {})
            ai_mode = st.get("ai_mode", "LOCAL")
            self._ai_badge.config(
                text=f"🧠 {'Claude AI' if ai_mode == 'CLAUDE' else 'IA Locale'}")
            cards = [
                (self.cfg.t("threats_found"), str(state.get("threats_found", 0)), T["danger"]),
                (self.cfg.t("scans_run"),     str(state.get("scan_count", 0)),    T["accent"]),
                (self.cfg.t("quarantined"),   str(state.get("quarantined", 0)),   T["warning"]),
                ("CPU",  f"{sys_i.get('cpu_percent', 0):.0f}%",   T["success"]),
                ("RAM",  f"{mem.get('percent', 0):.0f}%",          T["accent2"]),
                ("PROCS",str(sys_i.get("process_count", 0)),        T["text_sub"]),
            ]
        except:
            cards = [("THREATS","?",T["danger"]),("SCANS","?",T["accent"]),
                     ("STATUS","OK",T["success"]),("CPU","?",T["success"]),
                     ("RAM","?",T["accent2"]),("PROCS","?",T["text_sub"])]

        for title, val, col in cards:
            c = self._frame(row, "bg_light")
            c.pack(side="left", padx=5, ipadx=14, ipady=10)
            tk.Label(c, text=val, font=("Consolas", F["title"], "bold"),
                     bg=T["bg_light"], fg=col).pack()
            tk.Label(c, text=title, font=("Consolas", F["body"]),
                     bg=T["bg_light"], fg=T["text_muted"]).pack()

        # Quick actions
        tk.Label(f, text="ACTIONS RAPIDES",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(8,6))
        ar = self._frame(f, "bg_medium")
        ar.pack(fill="x")
        for lbl, col, cmd in [
            ("⚡ SCAN RAPIDE",      T["accent"],   self._show_quick_scan),
            ("🔍 SCAN COMPLET",    T["success"],  self._show_full_scan),
            ("📄 RAPPORT PDF",     T["danger"],   self._do_pdf_evening_report),
            ("🧠 ANALYSE IA",      T["warning"],  self._show_ai_analyst),
        ]:
            self._btn(ar, lbl, cmd, color=col, padx=14, pady=9).pack(side="left", padx=4)

        # Alerts
        tk.Label(f, text="ALERTES RÉCENTES",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(18,6))
        box = self._scrolltext(f, h=8)
        box.pack(fill="x")
        from elpati.elpati_log import ElpatiLog
        for e in ElpatiLog().get_recent(30):
            icon = {"THREAT":"⚠","CRITICAL":"🔴","WARNING":"🟡","AUDIT":"🔒"}.get(e.get("level"),"●")
            box.insert("end", f"{icon} [{e.get('ts','')[:19]}] [{e.get('level','?'):8}] {e.get('msg','')}\n")
        box.see("end"); box.config(state="disabled")

    # ═══════════════════════════════════════════════════════════════════
    #  SCAN PAGES
    # ═══════════════════════════════════════════════════════════════════
    def _show_quick_scan(self): self._show_scan_page("SCAN RAPIDE", "quick")
    def _show_full_scan(self):  self._show_scan_page("SCAN COMPLET", "full")

    def _show_scan_page(self, title, mode):
        self._clear_content()
        T, F = self._T, self._F
        f = self._frame(self._content, "bg_medium")
        f.pack(fill="both", expand=True, padx=20, pady=20)
        tk.Label(f, text=title, font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")

        prog_f = self._frame(f, "bg_light")
        prog_f.pack(fill="x", pady=(12,10))
        self._scan_status = tk.Label(prog_f, text="Prêt", font=("Consolas", F["nav"]),
                                      bg=T["bg_light"], fg=T["text"])
        self._scan_status.pack(anchor="w", padx=15, pady=(10,4))
        self._prog_var = tk.DoubleVar()
        ttk.Progressbar(prog_f, variable=self._prog_var, maximum=100,
                        length=500, mode="determinate").pack(fill="x", padx=15, pady=6)
        stat_r = self._frame(prog_f, "bg_light")
        stat_r.pack(fill="x", padx=15, pady=(0,10))
        self._s_files = tk.Label(stat_r, text="Fichiers: 0", font=("Consolas", F["body"]),
                                  bg=T["bg_light"], fg=T["text_sub"])
        self._s_files.pack(side="left", padx=8)
        self._s_threats = tk.Label(stat_r, text="Menaces: 0", font=("Consolas", F["body"], "bold"),
                                    bg=T["bg_light"], fg=T["danger"])
        self._s_threats.pack(side="left", padx=8)
        self._s_time = tk.Label(stat_r, text="Durée: 0s", font=("Consolas", F["body"]),
                                 bg=T["bg_light"], fg=T["text_muted"])
        self._s_time.pack(side="left", padx=8)

        # Boutons LANCER + STOP côte à côte
        btn_row = self._frame(f, "bg_medium")
        btn_row.pack(pady=8, anchor="w")

        self._scan_btn = self._btn(btn_row, f"▶  {self.cfg.t('btn_scan')}",
                                    lambda: self._start_scan(mode), padx=20, pady=10)
        self._scan_btn.pack(side="left", padx=(0, 8))

        self._stop_btn = self._btn(btn_row, "⏹  STOP",
                                    self._stop_scan,
                                    color=self._T["danger"], fg=self._T["text"],
                                    padx=18, pady=10)
        self._stop_btn.pack(side="left")
        self._stop_btn.config(state="disabled")  # Désactivé au départ

        tk.Label(f, text="RÉSULTATS", font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(8,4))
        self._scan_results = self._scrolltext(f, h=16)
        self._scan_results.pack(fill="both", expand=True)
        self._scan_results.insert("end", "Cliquez 'LANCER LE SCAN' pour démarrer...\n")
        self._scan_results.config(state="disabled")

    def _start_scan(self, mode):
        if self._scan_running:
            messagebox.showwarning("Scan", "Un scan est déjà en cours"); return
        if mode == "full":
            path = filedialog.askdirectory(title="Dossier à scanner", initialdir=str(Path.home()))
            if not path: return
        else:
            path = None
        self._scan_running = True
        self._scan_stop_requested = False
        self._scan_start = time.time()
        # Bouton LANCER → grisé, STOP → actif rouge
        self._scan_btn.config(state="disabled", text="⏳  EN COURS...")
        self._stop_btn.config(state="normal")
        self._scan_status.config(text=f"Scan {'rapide' if mode=='quick' else 'complet'} en cours...",
                                  fg=self._T["warning"])
        self._run_job(lambda: self._do_scan(mode, path))

    def _stop_scan(self):
        """Demande l'arrêt propre du scan en cours."""
        self._scan_stop_requested = True
        self._controller._modules["engine"].stop_scan()
        try:
            self._stop_btn.config(state="disabled", text="⏹  ARRÊT...")
            self._scan_status.config(text="⏹ Arrêt demandé — attente de la fin du fichier en cours...",
                                      fg=self._T["warning"])
        except: pass

    def _do_scan(self, mode, path):
        def cb(p):
            # Si stop demandé, on signale au moteur
            if getattr(self, "_scan_stop_requested", False):
                # Inject stop flag into engine
                engine = self._controller._modules.get("engine")
                if engine:
                    engine.stop_scan()
            tot = p.get("total", 1) or 1
            pct = p["scanned"] / tot * 100
            elapsed = time.time() - self._scan_start
            self._dispatch(lambda: self._upd_scan(pct, p["scanned"], p["threats"], elapsed))

        result = (self._controller.run_quick_scan(callback=cb) if mode == "quick"
                  else self._controller.run_full_scan(path=path, callback=cb))

        self._last_scan_result = result
        self._scan_running = False
        # Si arrêté manuellement, ajouter la mention dans les résultats
        if getattr(self, "_scan_stop_requested", False):
            result["_stopped_by_user"] = True
        self._dispatch(lambda: self._show_scan_results(result))

    def _upd_scan(self, pct, f, t, elapsed):
        try:
            self._prog_var.set(pct)
            self._s_files.config(text=f"Fichiers: {f:,}")
            self._s_threats.config(text=f"Alertes: {t}")
            self._s_time.config(text=f"Durée: {elapsed:.0f}s")
        except: pass

    def _show_scan_results(self, r):
        self._scan_running = False
        self._scan_stop_requested = False
        self._last_scan_result = r
        T = self._T
        try:
            self._scan_btn.config(state="normal", text=f"▶  {self.cfg.t('btn_scan')}")
            self._stop_btn.config(state="disabled", text="⏹  STOP")
            stopped = r.get("_stopped_by_user", False) or r.get("cancelled", False)
            self._prog_var.set(r.get("_pct", 100) if stopped else 100)
            n = r.get("threats_found", 0)
            if stopped:
                self._scan_status.config(
                    text=f"⏹ Scan arrêté — {r.get('files_scanned',0):,} fichiers examinés | {n} alertes",
                    fg=T["warning"])
            elif r.get("errors") or r.get("skipped"):
                self._scan_status.config(text=f"Analyse partielle : {r.get('errors', 0)} erreurs, {r.get('skipped', 0)} fichiers ignorés",
                                         fg=T["warning"])
            else:
                self._scan_status.config(
                    text=f"{'✓ ' + self.cfg.t('scan_complete') if n==0 else '⚠ ' + self.cfg.t('threats_detected')} — {r['files_scanned']:,} fichiers | {n} alertes",
                    fg=T["success"] if n == 0 else T["danger"])
            self._scan_results.config(state="normal")
            self._scan_results.delete("1.0","end")
            statut_ligne = "⏹ ARRÊTÉ PAR L'UTILISATEUR" if stopped else "✓ TERMINÉ"
            txt = (f"{'='*60}\nRAPPORT DE SCAN — {statut_ligne}\n{'='*60}\n"
                   f"Terminé:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                   f"Durée:    {r.get('duration_sec',0):.2f}s\n"
                   f"Fichiers: {r.get('files_scanned',0):,}\n"
                   f"Alertes:  {r.get('threats_found',0)}\n"
                   f"Signatures identifiées: {r.get('confirmed_threats', 0)}\n"
                   f"Indices à examiner: {r.get('review_count', 0)}\n"
                   f"Erreurs:  {r.get('errors',0)}\n"
                   f"Fichiers ignorés: {r.get('skipped', 0)}\n"
                   + ("Portée rapide: 2 niveaux de sous-dossiers; utiliser le scan complet pour approfondir.\n"
                      if r.get('max_directory_depth') is not None else "")
                   + (f"STATUT:   Scan interrompu manuellement\n" if stopped else "")
                   + f"{'='*60}\n\n")
            self._scan_results.insert("end", txt)
            if r.get("threats"):
                self._scan_results.insert("end", "RÉSULTATS À EXAMINER (indices distincts des signatures):\n\n")
                preview = sorted(r["threats"], key=lambda item: (bool(item.get("confirmed")), item.get("score", 0)), reverse=True)
                for t in preview[:200]:
                    evidence = "SIGNATURE" if t.get("confirmed") else "INDICE NON CONFIRMÉ"
                    self._scan_results.insert("end",
                        f"[{evidence}] [{t.get('type','?')}] Score:{t.get('score',0):3d} | {t.get('path','')}\n")
                    if t.get("ai_verdict"):
                        self._scan_results.insert("end", f"   └─ IA: {t['ai_verdict']}\n")
                if len(preview) > 200:
                    self._scan_results.insert("end", f"\nAperçu limité à 200 sur {len(preview)} alertes. Exporter le rapport et son JSON pour tous les détails.\n")
            else:
                self._scan_results.insert("end", f"✓ {self.cfg.t('no_threats')}\n")
            self._scan_results.config(state="disabled")
        except: pass

    # ═══════════════════════════════════════════════════════════════════
    #  PROCESSES / MEMORY / NETWORK
    # ═══════════════════════════════════════════════════════════════════
    def _show_processes(self):
        self._clear_content()
        T, F = self._T, self._F
        f = self._frame(self._content, "bg_medium")
        f.pack(fill="both", expand=True, padx=20, pady=20)
        tk.Label(f, text=self.cfg.t("nav_processes").upper(),
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")
        self._btn(f, f"🔄 {self.cfg.t('btn_refresh')}",
                  self._refresh_procs, padx=12, pady=6).pack(pady=8, anchor="w")
        cols = ("PID","Nom","Score","Risque","Indicateurs")
        self._proc_tree = ttk.Treeview(f, columns=cols, show="headings", height=22)
        widths = (65, 200, 65, 95, 400)
        for col, w in zip(cols, widths):
            self._proc_tree.heading(col, text=col)
            self._proc_tree.column(col, width=w)
        sb = ttk.Scrollbar(f, orient="vertical", command=self._proc_tree.yview)
        self._proc_tree.configure(yscrollcommand=sb.set)
        self._proc_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self._proc_tree.tag_configure("critical", background="#4a0000")
        self._proc_tree.tag_configure("high",     background="#3d1a00")
        self._proc_tree.tag_configure("medium",   background="#3d3000")
        self._refresh_procs()

    def _refresh_procs(self):
        try:
            results = self._controller._modules["engine"].scan_processes()
            for i in self._proc_tree.get_children(): self._proc_tree.delete(i)
            for r in results:
                tag = ("critical" if r["score"]>75 else "high" if r["score"]>50
                       else "medium" if r["score"]>25 else "")
                risk = ("CRITIQUE" if r["score"]>75 else "ÉLEVÉ" if r["score"]>50
                        else "MOYEN" if r["score"]>25 else "BAS")
                self._proc_tree.insert("","end",
                    values=(r["pid"],r["name"][:28],r["score"],risk,
                            ", ".join(r.get("flags",[]))[:80]), tags=(tag,))
        except: pass

    def _show_memory(self):
        self._clear_content()
        T, F = self._T, self._F
        f = self._frame(self._content, "bg_medium")
        f.pack(fill="both", expand=True, padx=20, pady=20)
        tk.Label(f, text="ANALYSE MÉMOIRE RAM",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")
        try:
            stats = self._controller._modules["memory_scan"].get_memory_stats()
            sf = self._frame(f, "bg_light")
            sf.pack(fill="x", pady=10)
            for lbl, val in [("Total RAM", f"{stats.get('total_gb','?')} GB"),
                              ("Utilisée",  f"{stats.get('used_gb','?')} GB ({stats.get('percent','?')}%)"),
                              ("Disponible",f"{stats.get('available_gb','?')} GB")]:
                tk.Label(sf, text=f"  {lbl}: {val}",
                         font=("Consolas", F["nav"]),
                         bg=T["bg_light"], fg=T["text"]).pack(anchor="w", padx=15, pady=2)
        except: pass
        self._btn(f, "▶ LANCER SCAN MÉMOIRE",
                  self._run_memory_scan, padx=15, pady=9).pack(pady=10, anchor="w")
        self._mem_box = self._scrolltext(f, h=20)
        self._mem_box.pack(fill="both", expand=True)
        self._mem_box.insert("end","Cliquez pour lancer l'analyse mémoire...\n")
        self._mem_box.config(state="disabled")

    def _run_memory_scan(self):
        def _go():
            self._dispatch(lambda: self._mem_box.config(state="normal"))
            self._dispatch(lambda: self._mem_box.delete("1.0","end"))
            self._dispatch(lambda: self._mem_box.insert("end","[*] Analyse mémoire en cours...\n"))
            results = self._controller._modules["memory_scan"].scan_all_processes(top_risk_only=True)
            txt = f"\n[MÉMOIRE SCAN COMPLET]\n{'='*50}\nProcessus flagués: {len(results)}\n\n"
            for r in results[:20]:
                txt += f"PID:{r['pid']:6}  Score:{r['score']:3}  Risque:{r.get('risk','?'):8}  [{r.get('name','?')}]\n"
                for fi in r.get("findings",[])[:3]:
                    txt += f"         └─ {fi.get('type','')} {fi.get('pattern','')[:40]}\n"
            self._dispatch(lambda: self._mem_box.insert("end", txt))
            self._dispatch(lambda: self._mem_box.see("end"))
            self._dispatch(lambda: self._mem_box.config(state="disabled"))
        self._run_job(_go)

    def _show_network(self):
        self._clear_content()
        T, F = self._T, self._F
        f = self._frame(self._content, "bg_medium")
        f.pack(fill="both", expand=True, padx=20, pady=20)
        tk.Label(f, text="RÉSEAU / NETWORK GUARD",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")
        hdr = self._frame(f, "bg_medium")
        hdr.pack(fill="x", pady=8)
        self._btn(hdr, f"🔄 {self.cfg.t('btn_refresh')}",
                  self._refresh_net, padx=12, pady=6).pack(side="left", padx=4)
        try:
            stats = self._controller._modules["network_guard"].get_network_stats()
            tk.Label(hdr,
                     text=f"  ↑{stats.get('bytes_sent',0)//1024:,}KB  ↓{stats.get('bytes_recv',0)//1024:,}KB  |  {stats.get('active_connections',0)} connexions",
                     font=("Consolas", F["body"]),
                     bg=T["bg_medium"], fg=T["text_sub"]).pack(side="left", padx=10)
        except: pass
        cols = ("Local","Remote","Statut","PID","Processus")
        self._net_tree = ttk.Treeview(f, columns=cols, show="headings", height=22)
        widths = (230, 230, 110, 65, 160)
        for col, w in zip(cols, widths):
            self._net_tree.heading(col, text=col)
            self._net_tree.column(col, width=w)
        sb = ttk.Scrollbar(f, orient="vertical", command=self._net_tree.yview)
        self._net_tree.configure(yscrollcommand=sb.set)
        self._net_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self._refresh_net()

    def _refresh_net(self):
        try:
            conns = self._controller._modules["network_guard"].get_active_connections()
            for i in self._net_tree.get_children(): self._net_tree.delete(i)
            for c in conns:
                self._net_tree.insert("","end",
                    values=(c.get("local",""), c.get("remote",""),
                            c.get("status",""), c.get("pid",""), c.get("process","")))
        except: pass

    # ═══════════════════════════════════════════════════════════════════
    #  THREATS / QUARANTINE / SANDBOX / FORENSIC
    # ═══════════════════════════════════════════════════════════════════
    def _show_threats(self):
        self._clear_content()
        T, F = self._T, self._F
        f = self._frame(self._content, "bg_medium")
        f.pack(fill="both", expand=True, padx=20, pady=20)
        tk.Label(f, text="THREAT INTELLIGENCE",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")
        tk.Label(f, text="Base de signatures locale | Détection hors-ligne",
                 font=("Consolas", F["body"]),
                 bg=T["bg_medium"], fg=T["text_muted"]).pack(anchor="w", pady=(2,14))
        try:
            stats = self._controller._modules["threat_intel"].get_stats()
            sf = self._frame(f, "bg_light")
            sf.pack(fill="x", pady=6)
            for k, v in stats.items():
                tk.Label(sf, text=f"  {k.upper()}: {v}",
                         font=("Consolas", F["nav"]),
                         bg=T["bg_light"], fg=T["text"]).pack(anchor="w", padx=15, pady=2)
        except: pass

    def _show_quarantine(self):
        self._clear_content()
        T, F = self._T, self._F
        f = self._frame(self._content, "bg_medium")
        f.pack(fill="both", expand=True, padx=20, pady=20)
        tk.Label(f, text="QUARANTAINE",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")
        try:
            qm = self._controller._modules["quarantine"]
            stats = qm.get_stats()
            tk.Label(f, text=f"Actifs: {stats['active']} | Restaurés: {stats['restored']} | Total: {stats['total']}",
                     font=("Consolas", F["body"]),
                     bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(4,12))
            cols = ("Date","Fichier","Type de menace","Hash")
            tree = ttk.Treeview(f, columns=cols, show="headings", height=20)
            widths = (120, 220, 160, 220)
            for col, w in zip(cols, widths):
                tree.heading(col, text=col); tree.column(col, width=w)
            for it in qm.list_quarantined():
                tree.insert("","end", iid=it["id"], values=(
                    it.get("quarantined_at","")[:10],
                    it.get("original_name","")[:35],
                    it.get("threat_info",{}).get("type","?"),
                    (it.get("hash") or "?")[:20]+"..."))
            tree.pack(fill="both", expand=True)
            actions = self._frame(f, "bg_medium")
            actions.pack(fill="x", pady=8)
            def restore():
                selected = tree.selection()
                if not selected or not messagebox.askyesno("Restaurer", "Restaurer le fichier sélectionné ? Il peut être dangereux."):
                    return
                result = qm.restore_file(selected[0])
                if not result.get("success") and "existe déjà" in result.get("error", ""):
                    target = filedialog.asksaveasfilename(title="Restaurer vers un nouveau fichier")
                    if target:
                        result = qm.restore_file(selected[0], target)
                if result.get("success"):
                    self._show_quarantine()
                else:
                    messagebox.showerror("Restauration", result.get("error", "Échec"))
            def delete():
                selected = tree.selection()
                if not selected or not messagebox.askyesno("Supprimer", "Supprimer définitivement le fichier chiffré sélectionné ?"):
                    return
                result = qm.delete_quarantined(selected[0])
                if result.get("success"):
                    self._show_quarantine()
                else:
                    messagebox.showerror("Suppression", result.get("error", "Échec"))
            self._btn(actions, "RESTAURER", restore, padx=10, pady=6).pack(side="left", padx=4)
            self._btn(actions, "SUPPRIMER", delete, color=T["danger"], padx=10, pady=6).pack(side="left", padx=4)
        except Exception as e:
            tk.Label(f, text=str(e), bg=T["bg_medium"], fg=T["danger"]).pack()

    def _show_sandbox(self):
        self._clear_content()
        T, F = self._T, self._F
        f = self._frame(self._content, "bg_medium")
        f.pack(fill="both", expand=True, padx=20, pady=20)
        tk.Label(f, text="SANDBOX — ANALYSE STATIQUE",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")
        tk.Label(f, text="Analyse approfondie sans exécution",
                 font=("Consolas", F["body"]),
                 bg=T["bg_medium"], fg=T["text_muted"]).pack(anchor="w", pady=(2,12))
        row = self._frame(f, "bg_medium")
        row.pack(fill="x", pady=4)
        self._sb_path = tk.StringVar()
        self._entry(row, self._sb_path, width=48).pack(side="left", padx=4)
        self._btn(row, "📂",
                  lambda: self._sb_path.set(filedialog.askopenfilename()),
                  padx=8, pady=5).pack(side="left", padx=3)
        self._btn(row, "🧪 ANALYSER", self._run_sandbox,
                  color=T["warning"], padx=14, pady=5).pack(side="left", padx=5)
        self._sb_box = self._scrolltext(f, h=20)
        self._sb_box.pack(fill="both", expand=True, pady=8)
        self._sb_box.insert("end","Sélectionnez un fichier et cliquez ANALYSER...\n")
        self._sb_box.config(state="disabled")

    def _run_sandbox(self):
        fp = self._sb_path.get().strip()
        if not fp or not os.path.exists(fp):
            messagebox.showerror("Erreur","Fichier introuvable"); return
        def _go():
            self._dispatch(lambda: self._sb_box.config(state="normal"))
            self._dispatch(lambda: self._sb_box.delete("1.0","end"))
            self._dispatch(lambda: self._sb_box.insert("end",f"[*] Analyse de {fp}...\n"))
            r = self._controller._modules["sandbox"].analyze_file(fp)
            txt = json.dumps(r, indent=2, default=str)
            self._dispatch(lambda: self._sb_box.insert("end","\n"+txt))
            self._dispatch(lambda: self._sb_box.config(state="disabled"))
        self._run_job(_go)

    def _show_forensic(self):
        self._clear_content()
        T, F = self._T, self._F
        f = self._frame(self._content, "bg_medium")
        f.pack(fill="both", expand=True, padx=20, pady=20)
        tk.Label(f, text="MOTEUR FORENSIQUE & RAPPORTS",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")
        tk.Label(f, text="Générez des rapports PDF professionnels lisibles par tous",
                 font=("Consolas", F["body"]),
                 bg=T["bg_medium"], fg=T["text_muted"]).pack(anchor="w", pady=(2,14))

        # Boutons de rapport
        btn_f = self._frame(f, "bg_light")
        btn_f.pack(fill="x", pady=(0,12))
        tk.Label(btn_f, text="  GÉNÉRER UN RAPPORT PDF",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_light"], fg=T["text_sub"]).pack(anchor="w", padx=15, pady=(10,6))
        btns = self._frame(btn_f, "bg_light")
        btns.pack(fill="x", padx=15, pady=(0,12))
        self._btn(btns, "📄 RAPPORT GÉNÉRAL (PDF)",
                  lambda: self._gen_pdf_report("GENERAL"),
                  color=T["accent"], padx=14, pady=9).pack(side="left", padx=4)
        self._btn(btns, "🔍 APRÈS UN SCAN (PDF)",
                  lambda: self._gen_pdf_report("SCAN"),
                  color=T["success"], fg=T["bg_dark"], padx=14, pady=9).pack(side="left", padx=4)
        self._btn(btns, "🌍 APRÈS UN SCAN URL (PDF)",
                  lambda: self._gen_pdf_report("URL"),
                  color=T["accent2"], padx=14, pady=9).pack(side="left", padx=4)
        self._btn(btns, "📦 RAPPORT COMPLET (PDF)",
                  lambda: self._gen_pdf_report("FULL"),
                  color=T["warning"], fg=T["bg_dark"], padx=14, pady=9).pack(side="left", padx=4)

        self._pdf_status = tk.Label(btn_f, text="",
                                     font=("Consolas", F["body"]),
                                     bg=T["bg_light"], fg=T["success"])
        self._pdf_status.pack(anchor="w", padx=15, pady=(0,8))

        self._btn(f, "📋 RAPPORT FORENSIC TECHNIQUE (JSON)",
                  self._do_forensic, color=T["bg_light"], fg=T["text_sub"],
                  padx=16, pady=8).pack(pady=4, anchor="w")
        try:
            reports = self._controller._modules["forensic"].get_report_list()
            tk.Label(f, text=f"Rapports enregistrés: {len(reports)}",
                     font=("Consolas", F["body"]),
                     bg=T["bg_medium"], fg=T["text_muted"]).pack(anchor="w")
            for r in reports[:20]:
                tk.Label(f, text=f"  📄 {r['name']}  ({r.get('size',0):,} octets)",
                         font=("Consolas", F["body"]),
                         bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w")
        except: pass

    def _do_forensic(self):
        def _go():
            path = self._controller._modules["forensic"].generate_report()
            self._dispatch(lambda p=path: messagebox.showinfo("Rapport", f"Rapport sauvegardé : {p}"))
        self._run_job(_go)

    # ═══════════════════════════════════════════════════════════════════
    #  AI ANALYST PAGE
    # ═══════════════════════════════════════════════════════════════════
    def _show_ai_analyst(self):
        self._clear_content()
        T, F = self._T, self._F
        f = self._frame(self._content, "bg_medium")
        f.pack(fill="both", expand=True, padx=20, pady=20)
        tk.Label(f, text="🧠 IA ANALYSTE",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")
        ai = self._controller.ai
        mode = "Claude AI (avancé)" if ai.is_claude_available() else "IA Locale (heuristiques embarquées)"
        mode_col = T["success"] if ai.is_claude_available() else T["warning"]
        tk.Label(f, text=f"Mode actif: {mode}",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=mode_col).pack(anchor="w", pady=(4,14))

        # Manual analysis
        tk.Label(f, text="ANALYSE MANUELLE D'UN FICHIER",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(8,6))
        row = self._frame(f, "bg_medium")
        row.pack(fill="x", pady=4)
        self._ai_path = tk.StringVar()
        self._entry(row, self._ai_path, width=48).pack(side="left", padx=4)
        self._btn(row, "📂", lambda: self._ai_path.set(filedialog.askopenfilename()),
                  padx=8, pady=5).pack(side="left", padx=3)
        self._btn(row, "🧠 ANALYSER AVEC IA",
                  self._run_ai_analysis, color=T["accent2"], padx=14, pady=5).pack(side="left", padx=5)
        self._ai_box = self._scrolltext(f, h=18)
        self._ai_box.pack(fill="both", expand=True, pady=8)
        stats = ai.get_stats()
        self._ai_box.insert("end",
            f"Statistiques IA:\n"
            f"  Analyses locales: {stats['local_analyses']}\n"
            f"  Analyses Claude:  {stats['claude_analyses']}\n"
            f"  Total:            {stats['total']}\n\n"
            f"[IA {mode}]\n"
            f"Sélectionnez un fichier pour l'analyse IA...\n")
        self._ai_box.config(state="disabled")

    def _run_ai_analysis(self):
        fp = self._ai_path.get().strip()
        if not fp or not os.path.exists(fp):
            messagebox.showerror("Erreur","Fichier introuvable"); return
        def _go():
            self._dispatch(lambda: self._ai_box.config(state="normal"))
            self._dispatch(lambda: self._ai_box.delete("1.0","end"))
            self._dispatch(lambda: self._ai_box.insert("end",f"[IA] Analyse de {fp}...\n"))
            # First do local heuristic analysis
            file_result = self._controller._modules["ai_analyzer"].analyze_file_heuristic(fp)
            # Then run through AI core
            ai_result = self._controller.ai.analyze_threat({
                "type": "file_analysis", "file_path": fp,
                "unconfirmed_file": True,
                "local_score": file_result.get("score", 0),
                "indicators": {n: True for n in file_result.get("notes", [])[:5]},
                "behavior": {}
            })
            txt = (f"\n{'='*55}\nRÉSULTAT ANALYSE IA\n{'='*55}\n"
                   f"Source IA: {ai_result.get('source','?')}\n"
                   f"Score:     {ai_result.get('score',0)}/100\n"
                   f"Risque:    {ai_result.get('risk_level','?')}\n"
                   f"Verdict:   {ai_result.get('verdict','?')}\n\n"
                   f"Explication:\n{ai_result.get('explanation','')}\n\n"
                   f"Actions recommandées:\n{chr(10).join('  • '+a for a in ai_result.get('actions',[]))}\n\n"
                   f"Analyse locale:\n  Score: {file_result.get('score',0)}\n"
                   f"  Notes: {', '.join(file_result.get('notes',[]))}\n")
            self._dispatch(lambda: self._ai_box.insert("end", txt))
            self._dispatch(lambda: self._ai_box.config(state="disabled"))
        self._run_job(_go)

    # ═══════════════════════════════════════════════════════════════════
    #  LOGS
    # ═══════════════════════════════════════════════════════════════════
    def _show_logs(self):
        self._clear_content()
        T, F = self._T, self._F
        f = self._frame(self._content, "bg_medium")
        f.pack(fill="both", expand=True, padx=20, pady=20)
        tk.Label(f, text="JOURNAUX SÉCURISÉS",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")
        from elpati.elpati_log import ElpatiLog
        log = ElpatiLog()
        ok, n = log.verify_chain()
        chain_txt = f"✓ Intégrité chaîne: OK ({n} entrées)" if ok else f"⚠ INTÉGRITÉ COMPROMISE!"
        chain_col = T["success"] if ok else T["danger"]
        tk.Label(f, text=chain_txt, font=("Consolas", F["body"]),
                 bg=T["bg_medium"], fg=chain_col).pack(anchor="w", pady=(4,12))
        box = self._scrolltext(f, h=30)
        box.pack(fill="both", expand=True)
        for e in log.get_recent(150):
            icon = {"THREAT":"⚠","CRITICAL":"🔴","WARNING":"🟡","AUDIT":"🔒","ERROR":"❌"}.get(e.get("level"),"●")
            box.insert("end",
                f"{icon} [{e.get('ts','')[:19]}] [{e.get('level','?'):8}] {e.get('msg','')}\n")
        box.see("end"); box.config(state="disabled")

    # ═══════════════════════════════════════════════════════════════════
    #  SETTINGS — Full settings page
    # ═══════════════════════════════════════════════════════════════════
    def _show_settings(self):
        self._clear_content()
        T, F = self._T, self._F
        outer = self._frame(self._content, "bg_medium")
        outer.pack(fill="both", expand=True)

        # Left nav
        # Settings left nav — scrollable
        nav_outer = self._frame(outer, "bg_light")
        nav_outer.pack(side="left", fill="y")
        nav_outer.config(width=170)
        nav_outer.pack_propagate(False)

        tk.Label(nav_outer, text="PARAMÈTRES",
                 font=("Consolas", F["body"], "bold"),
                 bg=T["bg_light"], fg=T["text_muted"]).pack(pady=(14,4), padx=12, anchor="w")

        # Scrollable canvas for settings nav
        s_canvas = tk.Canvas(nav_outer, bg=T["bg_light"], highlightthickness=0, borderwidth=0)
        s_scroll = tk.Scrollbar(nav_outer, orient="vertical", command=s_canvas.yview)
        s_canvas.configure(yscrollcommand=s_scroll.set)
        s_scroll.pack(side="right", fill="y")
        s_canvas.pack(side="left", fill="both", expand=True)

        s_inner = tk.Frame(s_canvas, bg=T["bg_light"])
        s_win = s_canvas.create_window((0, 0), window=s_inner, anchor="nw")

        def _s_inner_cfg(e):
            s_canvas.configure(scrollregion=s_canvas.bbox("all"))
            s_canvas.itemconfig(s_win, width=s_canvas.winfo_width())
        def _s_canvas_cfg(e):
            s_canvas.itemconfig(s_win, width=e.width)

        s_inner.bind("<Configure>", _s_inner_cfg)
        s_canvas.bind("<Configure>", _s_canvas_cfg)

        def _s_mwheel(event):
            try: s_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            except: pass
        def _s_mwheel_lx(event):
            try:
                if event.num == 4: s_canvas.yview_scroll(-1, "units")
                elif event.num == 5: s_canvas.yview_scroll(1, "units")
            except: pass

        s_canvas.bind("<MouseWheel>", _s_mwheel)
        s_inner.bind("<MouseWheel>", _s_mwheel)
        s_canvas.bind("<Button-4>", _s_mwheel_lx)
        s_canvas.bind("<Button-5>", _s_mwheel_lx)

        self._settings_content = self._frame(outer, "bg_medium")
        self._settings_content.pack(side="left", fill="both", expand=True, padx=20, pady=20)

        sections = [
            ("🎨 Apparence",    self._settings_appearance),
            ("🌐 Langue",       self._settings_language),
            ("🔒 Sécurité",     self._settings_security),
            ("🧠 Clé API IA",   self._settings_api),
            ("💳 Licences",     self._settings_license),
            ("⚙  Général",     self._settings_general),
        ]
        for lbl, fn in sections:
            b = tk.Button(s_inner, text=lbl,
                          font=("Consolas", F["body"]),
                          bg=T["bg_light"], fg=T["text_sub"],
                          relief="flat", anchor="w", padx=12, pady=9,
                          cursor="hand2",
                          command=fn)
            b.pack(fill="x")
            b.bind("<MouseWheel>", _s_mwheel)
            b.bind("<Button-4>", _s_mwheel_lx)
            b.bind("<Button-5>", _s_mwheel_lx)

        self._settings_appearance()

    def _clr_sc(self):
        for w in self._settings_content.winfo_children(): w.destroy()

    def _settings_appearance(self):
        self._clr_sc()
        T, F = self._T, self._F
        sc = self._settings_content
        tk.Label(sc, text="🎨 APPARENCE",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")

        # Theme selector
        tk.Label(sc, text="Thème visuel:",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(16,6))
        theme_f = self._frame(sc, "bg_medium")
        theme_f.pack(fill="x")
        theme_names = {
            "dark":          ("🌑 Sombre (défaut)", T["text_muted"]),
            "light":         ("☀️ Clair",           "#000000"),
            "high_contrast": ("⚡ Contraste élevé (accessibilité)", "#ffff00"),
            "blue_dark":     ("🌊 Bleu nuit",       "#60a5fa"),
            "matrix":        ("💚 Matrix Vert",     "#00ff41"),
        }
        current_theme = self.cfg.get("theme", "dark")
        for theme_key, (lbl_txt, col) in theme_names.items():
            is_cur = theme_key == current_theme
            btn = tk.Button(theme_f, text=("✓ " if is_cur else "  ") + lbl_txt,
                            font=("Consolas", F["body"]),
                            bg=T["bg_light"] if is_cur else T["bg_dark"],
                            fg=T["accent"] if is_cur else T["text_sub"],
                            relief="flat", anchor="w", padx=14, pady=7,
                            cursor="hand2",
                            command=lambda k=theme_key: self._apply_theme(k))
            btn.pack(fill="x", pady=1)

        # Font size
        tk.Label(sc, text="Taille de police (accessibilité):",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(20,6))
        font_f = self._frame(sc, "bg_medium")
        font_f.pack(fill="x")
        font_labels = {
            "small":  "🔡 Petite (8pt)",
            "medium": "🔤 Moyenne (10pt) — défaut",
            "large":  "🔠 Grande (12pt)",
            "xlarge": "🅰️ Très grande (15pt) — malvoyants",
        }
        current_font = self.cfg.get("font_size", "medium")
        for fk, fl in font_labels.items():
            is_cur = fk == current_font
            tk.Button(font_f, text=("✓ " if is_cur else "  ") + fl,
                      font=("Consolas", F["body"]),
                      bg=T["bg_light"] if is_cur else T["bg_dark"],
                      fg=T["accent"] if is_cur else T["text_sub"],
                      relief="flat", anchor="w", padx=14, pady=7,
                      cursor="hand2",
                      command=lambda k=fk: self._apply_font(k)).pack(fill="x", pady=1)

    def _apply_theme(self, theme_key):
        self.cfg.set("theme", theme_key)
        self._rebuild_ui()

    def _apply_font(self, font_key):
        self.cfg.set("font_size", font_key)
        self._rebuild_ui()

    def _settings_language(self):
        self._clr_sc()
        T, F = self._T, self._F
        sc = self._settings_content
        tk.Label(sc, text="🌐 LANGUE / LANGUAGE",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")
        langs = {
            "fr": "🇫🇷 Français (défaut)",
            "en": "🇬🇧 English",
            "es": "🇪🇸 Español",
            "pt": "🇧🇷 Português (Brasil)",
        }
        current = self.cfg.get("language", "fr")
        tk.Label(sc, text="Sélectionnez la langue de l'interface:",
                 font=("Consolas", F["body"]),
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(14,8))
        for code, name in langs.items():
            is_cur = code == current
            tk.Button(sc, text=("✓ " if is_cur else "  ") + name,
                      font=("Consolas", F["nav"]),
                      bg=T["bg_light"] if is_cur else T["bg_dark"],
                      fg=T["accent"] if is_cur else T["text_sub"],
                      relief="flat", anchor="w", padx=16, pady=10,
                      cursor="hand2",
                      command=lambda c=code: self._apply_lang(c)).pack(fill="x", pady=2)
        tk.Label(sc,
                 text="ℹ️ Le changement de langue s'applique immédiatement.\nD'autres langues seront ajoutées.",
                 font=("Consolas", F["body"]),
                 bg=T["bg_medium"], fg=T["text_muted"]).pack(anchor="w", pady=(16,0))

    def _apply_lang(self, lang):
        self.cfg.set("language", lang)
        self._rebuild_ui()

    def _settings_security(self):
        self._clr_sc()
        T, F = self._T, self._F
        sc = self._settings_content
        tk.Label(sc, text="🔒 SÉCURITÉ — CHANGER LE MOT DE PASSE",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")

        from elpati.elpati_auth_voice import ElpatiAuthVoice
        auth = ElpatiAuthVoice()
        status = auth.get_status()
        info_f = self._frame(sc, "bg_light")
        info_f.pack(fill="x", pady=(12,16))
        for lbl, val in [
            ("Dernière connexion", status.get("last_login","Inconnue")[:19]),
            ("Nombre de connexions", str(status.get("login_count",0))),
            ("Mot de passe modifié", "Oui" if status.get("password_changed") else "Non (défaut utilisé)")
        ]:
            tk.Label(info_f, text=f"  {lbl}: {val}",
                     font=("Consolas", F["body"]),
                     bg=T["bg_light"], fg=T["text"]).pack(anchor="w", padx=15, pady=3)

        tk.Label(sc, text="Modifier le mot de passe:",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(8,6))

        fields_f = self._frame(sc, "bg_light")
        fields_f.pack(fill="x")
        self._pw_cur = tk.StringVar()
        self._pw_new = tk.StringVar()
        self._pw_cfm = tk.StringVar()
        for lbl, var in [
            ("Mot de passe actuel:", self._pw_cur),
            ("Nouveau mot de passe (min. 12 car.):", self._pw_new),
            ("Confirmer nouveau:", self._pw_cfm),
        ]:
            row = self._frame(fields_f, "bg_light")
            row.pack(fill="x", padx=15, pady=5)
            tk.Label(row, text=lbl, font=("Consolas", F["body"]),
                     bg=T["bg_light"], fg=T["text_sub"], width=35, anchor="w").pack(side="left")
            self._entry(row, var, show="●", width=25,
                        bg=T["bg_dark"]).pack(side="left", padx=8)

        self._pw_msg = tk.Label(fields_f, text="",
                                 font=("Consolas", F["body"]),
                                 bg=T["bg_light"], fg=T["danger"])
        self._pw_msg.pack(pady=5)
        self._btn(fields_f, "🔒 CHANGER LE MOT DE PASSE",
                  self._do_change_pw, padx=16, pady=9).pack(pady=10)

    def _do_change_pw(self):
        from elpati.elpati_auth_voice import ElpatiAuthVoice
        r = ElpatiAuthVoice().change_password(
            self._pw_cur.get(), self._pw_new.get(), self._pw_cfm.get())
        if r["success"]:
            self._pw_msg.config(text="✓ " + self.cfg.t("password_changed"), fg=self._T["success"])
            for v in (self._pw_cur, self._pw_new, self._pw_cfm): v.set("")
        else:
            self._pw_msg.config(text="✗ " + r["error"], fg=self._T["danger"])

    def _settings_api(self):
        """Statut IA — la clé est dans config.env, jamais dans l'UI."""
        self._clr_sc()
        T, F = self._T, self._F
        sc = self._settings_content
        tk.Label(sc, text="🧠 INTELLIGENCE ARTIFICIELLE",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")

        ai = self._controller.ai
        mode_col = T["success"] if ai.is_claude_available() else T["warning"]
        tk.Label(sc, text=f"Mode actif : {ai.get_mode_label()}",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=mode_col).pack(anchor="w", pady=(10,16))

        # Carte de statut
        sf = self._frame(sc, "bg_light")
        sf.pack(fill="x", pady=(0,18))
        rows = [
            ("Clé API dans config.env",
             "✓ Oui" if ai.has_api_key() else "✗ Non",
             T["success"] if ai.has_api_key() else T["text_muted"]),
            ("Claude API en ligne",
             "✓ Connectée" if ai.is_claude_available() else "✗ Non disponible",
             T["success"] if ai.is_claude_available() else T["warning"]),
            ("IA Locale (fallback)",  "✓ Toujours active",  T["success"]),
            ("Total analyses",        str(ai.get_stats().get("total", 0)),          T["text"]),
            ("Via Claude AI",         str(ai.get_stats().get("claude_analyses", 0)),T["accent"]),
            ("Via IA Locale",         str(ai.get_stats().get("local_analyses", 0)), T["text_sub"]),
        ]
        for lbl, val, col in rows:
            r = self._frame(sf, "bg_light")
            r.pack(fill="x", padx=15, pady=3)
            tk.Label(r, text=lbl, font=("Consolas", F["body"]),
                     bg=T["bg_light"], fg=T["text_sub"],
                     width=30, anchor="w").pack(side="left")
            tk.Label(r, text=val, font=("Consolas", F["body"], "bold"),
                     bg=T["bg_light"], fg=col).pack(side="left", padx=8)

        # Instructions admin
        tk.Label(sc, text="CONFIGURATION — RÉSERVÉ À L'ADMINISTRATEUR",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(8,8))

        inf = self._frame(sc, "bg_light")
        inf.pack(fill="x")
        for line, col_key in [
            ("La clé API ne se configure PAS dans cette interface.",        "text_sub"),
            ("Elle est définie dans le fichier  config.env  (racine).",     "text_sub"),
            ("",                                                             "text_sub"),
            ("Procédure pour activer Claude AI :",                          "text"),
            ("  1. Ouvrez config.env avec un éditeur de texte",             "text_sub"),
            ("  2. Modifiez la ligne :",                                    "text_sub"),
            ("       ANTHROPIC_API_KEY=",                                   "accent2"),
            ("     Remplacez par :",                                        "text_sub"),
            ("       ANTHROPIC_API_KEY=sk-ant-votre-cle-ici",               "accent"),
            ("  3. Sauvegardez config.env",                                 "text_sub"),
            ("  4. Relancez CyberOS_Security",                              "text_sub"),
            ("",                                                             "text_sub"),
            ("Obtenir une clé : https://console.anthropic.com",             "accent"),
            ("",                                                             "text_sub"),
            ("⚠  Ne partagez JAMAIS config.env avec vos utilisateurs.",    "danger"),
            ("⚠  Ne publiez JAMAIS config.env sur GitHub ou autre.",       "danger"),
        ]:
            tk.Label(inf, text=f"  {line}",
                     font=("Consolas", F["body"]),
                     bg=T["bg_light"], fg=T[col_key],
                     anchor="w").pack(anchor="w", padx=10, pady=1)
        tk.Frame(inf, bg=T["bg_light"], height=8).pack()

        # Bouton recharger (utile après édition de config.env)
        def _reload():
            self._controller.ai.reload_config()
            self._settings_api()
        self._btn(sc, "🔄 RECHARGER config.env",
                  _reload, color=T["accent2"], padx=14, pady=9).pack(pady=14, anchor="w")

    def _settings_license(self):
        self._clr_sc()
        T, F = self._T, self._F
        sc = self._settings_content
        tk.Label(sc, text="💳 GESTION DES LICENCES",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")

        pay = self._controller.payment
        info = pay.get_info()
        tier = info.get("tier","FREE")
        valid = info.get("valid", True)

        # Current license status
        sf = self._frame(sc, "bg_light")
        sf.pack(fill="x", pady=(12,16))
        col = T["success"] if valid else T["danger"]
        tier_colors = {"FREE": T["text_muted"], "PRO": T["accent"], "ENTERPRISE": T["warning"]}
        tk.Label(sf, text=f"  Licence actuelle: {tier}",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_light"], fg=tier_colors.get(tier, T["accent"])).pack(anchor="w", padx=15, pady=6)
        tk.Label(sf, text=f"  Statut: {'✓ Valide' if valid else '✗ Expirée'}",
                 font=("Consolas", F["body"]),
                 bg=T["bg_light"], fg=col).pack(anchor="w", padx=15, pady=2)
        days = info.get("days_remaining", 9999)
        days_txt = f"  Jours restants: {days}" if days < 9000 else "  Durée: Perpétuelle"
        tk.Label(sf, text=days_txt, font=("Consolas", F["body"]),
                 bg=T["bg_light"], fg=T["text"]).pack(anchor="w", padx=15, pady=(2,8))

        # Feature comparison table
        tk.Label(sc, text="COMPARAISON DES NIVEAUX",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(8,6))
        matrix = pay.get_matrix()
        features_to_show = [
            ("quick_scan",       "Scan rapide"),
            ("full_scan",        "Scan complet"),
            ("realtime_monitor", "Protection temps réel"),
            ("memory_scan",      "Scan mémoire RAM"),
            ("network_guard",    "Surveillance réseau"),
            ("ai_analyzer",      "Analyse IA locale"),
            ("api_ai",           "Analyse Claude AI"),
            ("forensic",         "Rapports forensic"),
            ("ransomguard",      "Anti-ransomware"),
            ("sandbox",          "Sandbox"),
        ]
        tbl = self._frame(sc, "bg_light")
        tbl.pack(fill="x", pady=4)
        hdr_r = self._frame(tbl, "bg_dark")
        hdr_r.pack(fill="x")
        for lbl, w in [("Fonctionnalité", 220), ("GRATUIT", 90), ("PRO", 90), ("ENTERPRISE", 100)]:
            tk.Label(hdr_r, text=lbl, font=("Consolas", F["body"], "bold"),
                     bg=T["bg_dark"], fg=T["accent"], width=w//8).pack(side="left", padx=4, pady=4)
        for feat_key, feat_lbl in features_to_show:
            row = self._frame(tbl, "bg_light")
            row.pack(fill="x")
            tk.Label(row, text=feat_lbl, font=("Consolas", F["body"]),
                     bg=T["bg_light"], fg=T["text"], width=26, anchor="w").pack(side="left", padx=8, pady=2)
            for tier_k in ("FREE", "PRO", "ENTERPRISE"):
                has = matrix.get(tier_k, {}).get(feat_key, False)
                sym, col = ("✓", T["success"]) if has else ("✗", T["text_muted"])
                tk.Label(row, text=sym, font=("Consolas", F["nav"], "bold"),
                         bg=T["bg_light"], fg=col, width=8).pack(side="left", padx=4)

        tk.Label(sc, text="Les licences sont signées par le propriétaire du logiciel.",
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=12)

        # Key Activation
        tk.Label(sc, text="ACTIVER UNE LICENCE",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(14,6))
        act_f = self._frame(sc, "bg_light")
        act_f.pack(fill="x")
        act_inner = self._frame(act_f, "bg_light")
        act_inner.pack(padx=15, pady=12)
        tk.Label(act_inner, text="Clé:", font=("Consolas", F["body"]),
                 bg=T["bg_light"], fg=T["text_sub"]).pack(side="left")
        self._act_key = tk.StringVar()
        self._entry(act_inner, self._act_key, width=46,
                    bg=T["bg_dark"]).pack(side="left", padx=8)
        self._act_msg = tk.Label(act_f, text="",
                                  font=("Consolas", F["body"]),
                                  bg=T["bg_light"], fg=T["success"])
        self._act_msg.pack(pady=(0,6))
        self._btn(act_f, f"✓ {self.cfg.t('btn_activate')} LA LICENCE",
                  self._activate_key, color=T["accent"], padx=14, pady=9).pack(padx=15, pady=(0,12), anchor="w")

    def _activate_key(self):
        key = self._act_key.get().strip()
        if not key: return
        r = self._controller.payment.activate(key)
        if r["success"]:
            self._act_msg.config(
                text=f"✓ Activé: {r['tier']} | Expire: {r.get('expires','N/A')[:10]}",
                fg=self._T["success"])
        else:
            self._act_msg.config(text=f"✗ {r['error']}", fg=self._T["danger"])

    def _settings_general(self):
        self._clr_sc()
        T, F = self._T, self._F
        sc = self._settings_content
        tk.Label(sc, text="⚙ PARAMÈTRES GÉNÉRAUX",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w", pady=(0,16))
        opts = [
            ("auto_protect",    "Protection automatique active"),
            ("auto_quarantine", "Quarantaine automatique (score > 80)"),
            ("scan_on_startup", "Scan au démarrage"),
            ("show_notifications","Afficher les notifications"),
        ]
        for key, lbl in opts:
            v = tk.BooleanVar(value=self.cfg.get(key, False))
            def make_cmd(k, var): return lambda: self.cfg.set(k, var.get())
            tk.Checkbutton(sc, text=lbl, variable=v,
                           font=("Consolas", F["body"]),
                           bg=T["bg_medium"], fg=T["text"],
                           selectcolor=T["bg_dark"],
                           activebackground=T["bg_medium"],
                           command=make_cmd(key, v)).pack(anchor="w", pady=4)

        tk.Label(sc, text="\nA propos:",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(12,4))
        for line in [
            "CyberOS_Security v2026.2.1",
            "Système ELPATI — outils locaux de sécurité",
            "Heuristiques locales et rapports; API facultative",
            "Version corrigée 2026.2.1 — limites dans le README",
            "Développé pour la cybersécurité africaine et mondiale",
        ]:
            tk.Label(sc, text=f"  {line}",
                     font=("Consolas", F["body"]),
                     bg=T["bg_medium"], fg=T["text_muted"]).pack(anchor="w")

    # ═══════════════════════════════════════════════════════════════════
    #  URL SCANNER — Style VirusTotal
    # ═══════════════════════════════════════════════════════════════════
    def _show_url_scanner(self):
        self._clear_content()
        T, F = self._T, self._F
        f = self._frame(self._content, "bg_medium")
        f.pack(fill="both", expand=True, padx=20, pady=20)

        # ── Titre ──
        tk.Label(f, text="🌍 SCANNER D'URL / SITES WEB",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")
        tk.Label(f, text="Analyse complète de sites web — Phishing · Malware · Réputation · SSL · Contenu",
                 font=("Consolas", F["body"]),
                 bg=T["bg_medium"], fg=T["text_muted"]).pack(anchor="w", pady=(2,16))

        # ── Barre de saisie URL ──
        input_f = self._frame(f, "bg_light")
        input_f.pack(fill="x", pady=(0,12))

        tk.Label(input_f, text="  URL à analyser:",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_light"], fg=T["text_sub"]).pack(anchor="w", padx=15, pady=(10,4))

        url_row = self._frame(input_f, "bg_light")
        url_row.pack(fill="x", padx=15, pady=(0,10))

        self._url_var = tk.StringVar()
        url_entry = tk.Entry(url_row, textvariable=self._url_var,
                             font=("Consolas", F["nav"]),
                             bg=T["bg_dark"], fg=T["accent"],
                             insertbackground=T["accent"],
                             relief="flat", width=55)
        url_entry.pack(side="left", padx=(0,8), ipady=6)
        url_entry.insert(0, "https://")
        url_entry.bind("<Return>", lambda e: self._run_url_scan())
        url_entry.bind("<FocusIn>", lambda e: (
            url_entry.delete(0, "end") if self._url_var.get() == "https://" else None))

        self._url_scan_btn = self._btn(url_row, "🔍 ANALYSER",
                                        self._run_url_scan,
                                        color=T["accent"], padx=16, pady=6)
        self._url_scan_btn.pack(side="left", padx=4)

        self._url_clear_btn = self._btn(url_row, "🗑",
                                         lambda: (self._url_var.set("https://"), url_entry.focus()),
                                         color=T["bg_dark"], fg=T["text_muted"], padx=10, pady=6)
        self._url_clear_btn.pack(side="left", padx=2)

        # URLs rapides de test
        quick_row = self._frame(input_f, "bg_light")
        quick_row.pack(fill="x", padx=15, pady=(0,10))
        tk.Label(quick_row, text="Tester:", font=("Consolas", F["body"]),
                 bg=T["bg_light"], fg=T["text_muted"]).pack(side="left")
        for lbl, test_url in [
            ("Google", "https://google.com"),
            ("GitHub", "https://github.com"),
            ("Test phishing", "http://paypa1-secure-verify.xyz"),
        ]:
            tk.Button(quick_row, text=lbl,
                      font=("Consolas", F["body"]),
                      bg=T["bg_dark"], fg=T["text_sub"],
                      relief="flat", padx=8, pady=3,
                      cursor="hand2",
                      command=lambda u=test_url: (
                          self._url_var.set(u),
                          self._run_url_scan()
                      )).pack(side="left", padx=4)

        # ── Zone de résultats (2 colonnes) ──
        results_outer = self._frame(f, "bg_medium")
        results_outer.pack(fill="both", expand=True)

        # Colonne gauche : verdict + détails
        self._url_left = self._frame(results_outer, "bg_medium")
        self._url_left.pack(side="left", fill="both", expand=True, padx=(0,8))

        # Colonne droite : historique
        right_f = self._frame(results_outer, "bg_light")
        right_f.pack(side="right", fill="y", ipadx=5)
        right_f.config(width=220)
        right_f.pack_propagate(False)

        tk.Label(right_f, text="HISTORIQUE",
                 font=("Consolas", F["body"], "bold"),
                 bg=T["bg_light"], fg=T["text_muted"]).pack(pady=(10,4), padx=10, anchor="w")

        self._url_history_frame = self._frame(right_f, "bg_light")
        self._url_history_frame.pack(fill="both", expand=True, padx=6)
        self._refresh_url_history()

        # Afficher l'écran d'attente
        self._url_show_waiting()

    def _url_show_waiting(self):
        """Écran d'attente avant premier scan."""
        for w in self._url_left.winfo_children():
            w.destroy()
        T, F = self._T, self._F
        wait_f = self._frame(self._url_left, "bg_light")
        wait_f.pack(fill="both", expand=True)
        tk.Label(wait_f, text="🌍",
                 font=("Consolas", 48),
                 bg=T["bg_light"], fg=T["text_muted"]).pack(pady=(40,10))
        tk.Label(wait_f, text="Entrez une URL et cliquez ANALYSER",
                 font=("Consolas", F["nav"]),
                 bg=T["bg_light"], fg=T["text_muted"]).pack()
        tk.Label(wait_f,
                 text="9 vérifications: Blacklist · SSL · DNS · Contenu\nRedirections · Réputation · Headers · IP · IA",
                 font=("Consolas", F["body"]),
                 bg=T["bg_light"], fg=T["text_muted"],
                 justify="center").pack(pady=8)

    def _run_url_scan(self):
        """Lance le scan URL dans un thread."""
        url = self._url_var.get().strip()
        if not url or url == "https://":
            return
        # Afficher loading
        for w in self._url_left.winfo_children():
            w.destroy()
        T, F = self._T, self._F
        loading_f = self._frame(self._url_left, "bg_light")
        loading_f.pack(fill="both", expand=True)
        self._url_loading_lbl = tk.Label(loading_f,
                                          text=f"🔍 Analyse en cours...\n{url}",
                                          font=("Consolas", F["nav"]),
                                          bg=T["bg_light"], fg=T["warning"],
                                          justify="center")
        self._url_loading_lbl.pack(pady=(40,10))

        checks_lbl = tk.Label(loading_f, text="",
                               font=("Consolas", F["body"]),
                               bg=T["bg_light"], fg=T["text_sub"])
        checks_lbl.pack()
        self._url_checks_lbl = checks_lbl

        # Mise à jour animée des étapes
        steps = ["Blacklist...", "SSL...", "DNS...", "Redirections...",
                 "Contenu...", "Réputation...", "Headers...", "IA..."]
        self._url_step_idx = 0

        def animate():
            if self._url_step_idx < len(steps):
                try:
                    self._url_checks_lbl.config(
                        text="→ " + steps[self._url_step_idx])
                    self._url_step_idx += 1
                    self.root.after(600, animate)
                except:
                    pass
        animate()

        self._url_scan_btn.config(state="disabled", text="⏳ Analyse...")

        def _go():
            from elpati.elpati_url_scanner import ElpatiURLScanner
            scanner = ElpatiURLScanner()
            result = scanner.scan_url(url)
            self._dispatch(lambda: self._display_url_results(result))

        self._run_job(_go)

    def _display_url_results(self, r: dict):
        """Affiche les résultats du scan URL."""
        self._url_scan_btn.config(state="normal", text="🔍 ANALYSER")
        self._last_url_result = r  # Save for PDF report
        for w in self._url_left.winfo_children():
            w.destroy()
        T, F = self._T, self._F

        # Scrollable results
        canvas = tk.Canvas(self._url_left, bg=T["bg_medium"], highlightthickness=0)
        sb = tk.Scrollbar(self._url_left, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(canvas, bg=T["bg_medium"])
        win = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: (
            canvas.configure(scrollregion=canvas.bbox("all")),
            canvas.itemconfig(win, width=canvas.winfo_width())))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(win, width=e.width))
        canvas.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
        inner.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        score = r.get("score", 0)
        verdict = r.get("verdict", "INCONNU")
        v_color_key = r.get("verdict_color", "warning")
        v_color = {"success": T["success"], "warning": T["warning"], "danger": T["danger"]}.get(v_color_key, T["warning"])

        # ── Bandeau Verdict ──
        verdict_f = tk.Frame(inner, bg=v_color if score > 40 else T["bg_light"])
        verdict_f.pack(fill="x", pady=(0,10))
        tk.Label(verdict_f,
                 text=f"  {verdict}",
                 font=("Consolas", F["title"], "bold"),
                 bg=verdict_f["bg"],
                 fg=T["bg_dark"] if score > 40 else v_color).pack(side="left", padx=15, pady=12)
        tk.Label(verdict_f,
                 text=f"Score: {score}/100  |  {r.get('scan_duration_ms',0)}ms",
                 font=("Consolas", F["body"]),
                 bg=verdict_f["bg"],
                 fg=T["bg_dark"] if score > 40 else T["text_muted"]).pack(side="right", padx=15)

        # ── URL analysée ──
        url_f = self._frame(inner, "bg_light")
        url_f.pack(fill="x", pady=(0,8))
        tk.Label(url_f, text=f"  🔗 {r.get('url','')[:80]}",
                 font=("Consolas", F["body"]),
                 bg=T["bg_light"], fg=T["accent"]).pack(anchor="w", padx=10, pady=6)

        # ── Grille des 9 contrôles ──
        tk.Label(inner, text="RÉSULTATS DES VÉRIFICATIONS",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(8,6))

        checks_grid = tk.Frame(inner, bg=T["bg_medium"])
        checks_grid.pack(fill="x", pady=(0,10))

        check_display = [
            ("blacklist",       "🚫 Blacklist"),
            ("domain_age",      "🏷️ Domaine"),
            ("ssl",             "🔒 SSL/TLS"),
            ("dns",             "📡 DNS"),
            ("redirects",       "🔀 Redirections"),
            ("content",         "📄 Contenu"),
            ("reputation",      "⭐ Réputation"),
            ("ip_geolocation",  "🌐 IP/Géo"),
            ("tech_stack",      "⚙️ Headers"),
        ]

        col = 0
        row_f = None
        for i, (key, label) in enumerate(check_display):
            if i % 3 == 0:
                row_f = tk.Frame(checks_grid, bg=T["bg_medium"])
                row_f.pack(fill="x", pady=2)
            check = r.get("checks", {}).get(key, {})
            s = check.get("score", 0)
            icon = "✅" if s == 0 else ("⚠️" if s <= 40 else "🔴")
            bg = T["bg_light"]
            fg = T["success"] if s == 0 else (T["warning"] if s <= 40 else T["danger"])
            card = tk.Frame(row_f, bg=bg, relief="flat")
            card.pack(side="left", fill="x", expand=True, padx=3, pady=2, ipadx=6, ipady=6)
            tk.Label(card, text=f"{icon} {label}",
                     font=("Consolas", F["body"], "bold"),
                     bg=bg, fg=fg).pack(anchor="w", padx=6)
            first_finding = check.get("findings", [""])[0][:45]
            tk.Label(card, text=first_finding,
                     font=("Consolas", max(F["body"]-1, 7)),
                     bg=bg, fg=T["text_muted"],
                     wraplength=160).pack(anchor="w", padx=6)
            col += 1

        # ── Détails techniques ──
        details = r.get("details", {})
        tk.Label(inner, text="DÉTAILS TECHNIQUES",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(12,6))

        det_f = self._frame(inner, "bg_light")
        det_f.pack(fill="x", pady=(0,8))
        detail_rows = [
            ("Domaine",         details.get("domain", "?")),
            ("IP",              details.get("ip", "?")),
            ("SSL valide",      "✓ Oui" if details.get("has_ssl") else "✗ Non"),
            ("Émetteur SSL",    details.get("ssl_issuer", "?")),
            ("Statut HTTP",     str(details.get("http_status", "?"))),
            ("Titre de la page",details.get("page_title", "?")[:60]),
            ("Formulaires",     str(details.get("forms_count", 0))),
            ("Catégorie",       details.get("category", "?")),
            ("Redirections",    str(details.get("redirect_count", 0))),
        ]
        for lbl, val in detail_rows:
            dr = self._frame(det_f, "bg_light")
            dr.pack(fill="x", padx=12, pady=2)
            tk.Label(dr, text=f"{lbl}:", font=("Consolas", F["body"]),
                     bg=T["bg_light"], fg=T["text_muted"], width=20, anchor="w").pack(side="left")
            tk.Label(dr, text=val, font=("Consolas", F["body"]),
                     bg=T["bg_light"], fg=T["text"]).pack(side="left", padx=6)

        # Headers manquants
        missing = details.get("missing_headers", [])
        if missing:
            tk.Label(det_f, text=f"  En-têtes manquants ({len(missing)}):",
                     font=("Consolas", F["body"]),
                     bg=T["bg_light"], fg=T["warning"]).pack(anchor="w", padx=12, pady=(4,2))
            for h in missing[:4]:
                tk.Label(det_f, text=f"    • {h}",
                         font=("Consolas", max(F["body"]-1,7)),
                         bg=T["bg_light"], fg=T["text_muted"]).pack(anchor="w", padx=12)

        # ── Résumé des flags ──
        flags = r.get("summary", [])
        if flags:
            tk.Label(inner, text="FLAGS DÉTECTÉS",
                     font=("Consolas", F["nav"], "bold"),
                     bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(12,6))
            flag_f = self._frame(inner, "bg_light")
            flag_f.pack(fill="x", pady=(0,8))
            for flag in flags[:10]:
                tk.Label(flag_f, text=f"  ⚑ {flag}",
                         font=("Consolas", F["body"]),
                         bg=T["bg_light"], fg=T["warning"]).pack(anchor="w", padx=12, pady=2)

        # ── Analyse IA ──
        ai = r.get("ai_analysis", {})
        if ai:
            tk.Label(inner, text=f"🧠 ANALYSE IA ({ai.get('source','LOCAL_AI')})",
                     font=("Consolas", F["nav"], "bold"),
                     bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w", pady=(12,6))
            ai_f = self._frame(inner, "bg_light")
            ai_f.pack(fill="x", pady=(0,8))
            ai_col = {"CRITICAL":T["danger"],"HIGH":T["danger"],"MEDIUM":T["warning"],
                      "LOW":T["success"],"CLEAN":T["success"]}.get(ai.get("risk_level","?"), T["text"])
            tk.Label(ai_f,
                     text=f"  Risque: {ai.get('risk_level','?')}  |  Score IA: {ai.get('score',0)}/100",
                     font=("Consolas", F["nav"], "bold"),
                     bg=T["bg_light"], fg=ai_col).pack(anchor="w", padx=12, pady=6)
            tk.Label(ai_f,
                     text=f"  {ai.get('explanation', ai.get('verdict',''))}",
                     font=("Consolas", F["body"]),
                     bg=T["bg_light"], fg=T["text_sub"],
                     wraplength=500, justify="left").pack(anchor="w", padx=12, pady=(0,6))
            actions = ai.get("actions", [])
            if actions:
                tk.Label(ai_f, text=f"  Actions: {' · '.join(actions)}",
                         font=("Consolas", F["body"]),
                         bg=T["bg_light"], fg=T["warning"]).pack(anchor="w", padx=12, pady=(0,8))

        # Bouton export PDF
        export_row = self._frame(inner, "bg_medium")
        export_row.pack(fill="x", pady=(8,0))
        self._btn(export_row, "📄 EXPORTER EN PDF",
                  lambda res=r: self._do_url_pdf_report(res),
                  color=T["danger"], padx=14, pady=8).pack(side="left")
        tk.Label(export_row, text="  Rapport professionnel lisible par tous",
                 font=("Consolas", F["body"]),
                 bg=T["bg_medium"], fg=T["text_muted"]).pack(side="left", padx=8)

        # Mise à jour historique
        self._refresh_url_history()

    def _refresh_url_history(self):
        """Rafraîchit la liste historique."""
        for w in self._url_history_frame.winfo_children():
            w.destroy()
        T, F = self._T, self._F
        try:
            from elpati.elpati_url_scanner import ElpatiURLScanner
            history = ElpatiURLScanner().get_history(15)
        except:
            history = []

        if not history:
            tk.Label(self._url_history_frame,
                     text="Aucun scan\neffectué",
                     font=("Consolas", F["body"]),
                     bg=T["bg_light"], fg=T["text_muted"],
                     justify="center").pack(pady=20)
            return

        for item in history:
            score = item.get("score", 0)
            col = T["success"] if score <= 20 else (T["warning"] if score <= 60 else T["danger"])
            h_f = tk.Frame(self._url_history_frame, bg=T["bg_light"],
                           relief="flat", cursor="hand2")
            h_f.pack(fill="x", pady=1)
            domain = item.get("url","")
            if "://" in domain:
                domain = domain.split("://")[1]
            domain = domain[:22]
            tk.Label(h_f, text=f"● {domain}",
                     font=("Consolas", max(F["body"]-1,7)),
                     bg=T["bg_light"], fg=col).pack(anchor="w", padx=6, pady=2)
            tk.Label(h_f, text=f"  {item.get('verdict','?')[:18]}",
                     font=("Consolas", max(F["body"]-2,6)),
                     bg=T["bg_light"], fg=T["text_muted"]).pack(anchor="w", padx=6)

    # ═══════════════════════════════════════════════════════════════════
    #  PDF REPORT METHODS
    # ═══════════════════════════════════════════════════════════════════
    def _do_pdf_evening_report(self):
        """Lance la génération du rapport PDF du soir."""
        self._show_pdf_progress("Rapport de sécurité du soir",
                                 self._generate_evening_pdf)

    def _show_pdf_progress(self, title: str, generate_fn):
        """Affiche une fenêtre de progression pendant la génération PDF."""
        T, F = self._T, self._F
        win = tk.Toplevel(self.root)
        win.title("Génération du rapport PDF")
        win.geometry("480x200")
        win.resizable(False, False)
        win.configure(bg=T["bg_dark"])
        win.grab_set()
        win.focus()

        tk.Label(win, text="📄 Génération du rapport PDF",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_dark"], fg=T["accent"]).pack(pady=(20,8))
        tk.Label(win, text=title,
                 font=("Consolas", F["body"]),
                 bg=T["bg_dark"], fg=T["text_sub"]).pack()

        pvar = tk.DoubleVar()
        pb = ttk.Progressbar(win, variable=pvar, maximum=100,
                              mode="indeterminate", length=380)
        pb.pack(pady=14)
        pb.start(12)

        status_lbl = tk.Label(win, text="Collecte des données...",
                               font=("Consolas", F["body"]),
                               bg=T["bg_dark"], fg=T["text_muted"])
        status_lbl.pack()

        def _go():
            try:
                self._dispatch(lambda: status_lbl.config(text="Analyse IA en cours..."))
                path = generate_fn()
                self._dispatch(lambda: self._pdf_done(win, pb, path))
            except Exception as e:
                self._dispatch(lambda error=str(e): self._pdf_error(win, pb, error))

        self._run_job(_go)

    def _pdf_done(self, win, pb, path: str):
        pb.stop()
        win.destroy()
        from tkinter import messagebox
        msg = ("Rapport PDF sauvegarde :\n" + str(path) +
               "\n\nLes donnees detaillees sont conservees dans le fichier JSON du meme nom." +
               "\n\nOuvrir le dossier contenant les fichiers ?")
        if messagebox.askyesno("Succes", msg):
            import subprocess, os
            folder = str(Path(path).parent)
            if os.name == 'nt':
                subprocess.Popen(["explorer", folder])
            else:
                subprocess.Popen(["xdg-open", folder])

    def _pdf_error(self, win, pb, error: str):
        pb.stop()
        win.destroy()
        from tkinter import messagebox
        msg = "Impossible de generer le rapport.\n" + str(error) + "\n\nInstallez reportlab: pip install reportlab"
        messagebox.showerror("Erreur PDF", msg)

    def _gen_pdf_report(self, report_type):
        from reports.pdf_generator import PDFReportGenerator
        gen = PDFReportGenerator()
        if report_type == "SCAN":
            if not self._last_scan_result:
                messagebox.showinfo("Rapport", "Lancer d'abord un scan de fichiers.")
                return
            result = dict(self._last_scan_result)
            job = lambda: gen.generate_scan_report(result)
        elif report_type == "URL":
            if not self._last_url_result:
                messagebox.showinfo("Rapport", "Lancer d'abord une analyse URL.")
                return
            result = dict(self._last_url_result)
            job = lambda: gen.generate_url_report(result)
        elif report_type == "FULL":
            scan = dict(self._last_scan_result) if self._last_scan_result else None
            url = dict(self._last_url_result) if self._last_url_result else None
            job = lambda: gen.generate_full_report(self._controller, scan, url)
        else:
            job = lambda: gen.generate_evening_report(self._controller, report_type)
        self._show_pdf_progress("Rapport PDF", job)

    def _generate_evening_pdf(self) -> str:
        from reports.pdf_generator import PDFReportGenerator
        gen = PDFReportGenerator()
        return gen.generate_evening_report(controller=self._controller)

    def _do_url_pdf_report(self, url_result: dict):
        def _gen():
            from reports.pdf_generator import PDFReportGenerator
            gen = PDFReportGenerator()
            return gen.generate_url_report(url_result)
        self._show_pdf_progress(
            f"Analyse URL : {url_result.get('domain','?')}", _gen)

    # ═══════════════════════════════════════════════════════════════════
    #  UTILITIES
    # ═══════════════════════════════════════════════════════════════════
    def _clear_root(self):
        self._page_generation += 1
        for w in self.root.winfo_children(): w.destroy()

    # ═══════════════════════════════════════════════════════════════════
    #  VULN SCAN — Scanner de vulnérabilités CVE
    # ═══════════════════════════════════════════════════════════════════



    # ═══════════════════════════════════════════════════════════════════
    #  SCHEDULER — Planificateur de scans automatiques
    # ═══════════════════════════════════════════════════════════════════



    # ═══════════════════════════════════════════════════════════════════
    #  AUTO RESPONSE — Réponse automatique aux incidents
    # ═══════════════════════════════════════════════════════════════════


    # ═══════════════════════════════════════════════════════════════
    #  VULN SCAN
    # ═══════════════════════════════════════════════════════════════
    def _show_vuln_scan(self):
        self._clear_content()
        T, F = self._T, self._F
        f = self._frame(self._content, "bg_medium")
        f.pack(fill="both", expand=True, padx=20, pady=20)
        tk.Label(f, text="CONTROLES DE CONFIGURATION LOCALE",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")
        tk.Label(f, text="Vérifications partielles des réglages et ports locaux; aucune détection exhaustive des CVE.",
                 font=("Consolas", F["body"]),
                 bg=T["bg_medium"], fg=T["text_muted"]).pack(anchor="w", pady=(2,14))
        btn_row = self._frame(f, "bg_medium")
        btn_row.pack(fill="x", pady=(0,10))
        self._vuln_btn = self._btn(btn_row, "LANCER LES CONTROLES",
                                    self._run_vuln_scan, padx=18, pady=10)
        self._vuln_btn.pack(side="left")
        self._vuln_status = tk.Label(btn_row, text="",
                                      font=("Consolas", F["body"]),
                                      bg=T["bg_medium"], fg=T["warning"])
        self._vuln_status.pack(side="left", padx=12)
        self._vuln_box = self._scrolltext(f, h=28)
        self._vuln_box.pack(fill="both", expand=True)
        self._vuln_box.insert("end", "Cliquez LANCER pour analyser les vulnerabilites...\n")
        self._vuln_box.config(state="disabled")

    def _run_vuln_scan(self):
        self._vuln_btn.config(state="disabled", text="Analyse...")
        self._vuln_status.config(text="Scan en cours...", fg=self._T["warning"])
        def _go():
            try:
                r = self._controller._modules["vuln_scan"].run_full_scan()
                self._dispatch(lambda: self._show_vuln_results(r))
            except Exception as e:
                self._dispatch(lambda error=str(e): self._vuln_status.config(
                    text="Erreur: " + error[:60], fg=self._T["danger"]))
                self._dispatch(lambda: self._vuln_btn.config(
                    state="normal", text="LANCER LES CONTROLES"))
        self._run_job(_go)

    def _show_vuln_results(self, r):
        T, F = self._T, self._F
        self._vuln_btn.config(state="normal", text="LANCER LES CONTROLES")
        score = r.get("score", 0)
        col = T["success"] if score <= 20 else (T["warning"] if score <= 60 else T["danger"])
        self._vuln_status.config(
            text="Score: " + str(score) + "/100 | Critique: " + str(r.get("critical_count",0)),
            fg=col)
        self._vuln_box.config(state="normal")
        self._vuln_box.delete("1.0","end")
        lines = []
        lines.append("=" * 60)
        lines.append("RAPPORT SCAN DE VULNERABILITES")
        lines.append("=" * 60)
        lines.append("Systeme   : " + r.get("os","?"))
        lines.append("Score     : " + str(score) + "/100")
        lines.append("Critique  : " + str(r.get("critical_count",0)))
        lines.append("Eleve     : " + str(r.get("high_count",0)))
        lines.append("Duree     : " + str(round(r.get("duration_sec",0),2)) + "s")
        lines.append("=" * 60)
        lines.append("")
        weak = r.get("weak_configs", [])
        if weak:
            lines.append("CONFIGURATIONS FAIBLES (" + str(len(weak)) + ") :")
            for w in weak:
                lines.append("  [" + str(w.get("score",0)) + "] " + w.get("name","?") + " -- " + w.get("desc","?"))
            lines.append("")
        ports = r.get("open_ports", [])
        if ports:
            lines.append("PORTS OUVERTS (" + str(len(ports)) + ") :")
            for p in ports:
                lines.append("  Port " + str(p["port"]) + " [" + p["service"] + "] Risque: " + p["risk"])
            lines.append("")
        os_sec = r.get("os_security", [])
        if os_sec:
            lines.append("SECURITE OS :")
            for o in os_sec:
                lines.append("  [" + str(o.get("score",0)) + "] " + o.get("name","?"))
            lines.append("")
        if not weak and not ports and not os_sec:
            lines.append("Aucun indicateur trouvé dans les contrôles effectués; ce résultat n'est pas un certificat de sécurité.")
        self._vuln_box.insert("end", "\n".join(lines))
        self._vuln_box.config(state="disabled")

    # ═══════════════════════════════════════════════════════════════
    #  SCHEDULER
    # ═══════════════════════════════════════════════════════════════
    def _show_scheduler(self):
        self._clear_content()
        T, F = self._T, self._F
        f = self._frame(self._content, "bg_medium")
        f.pack(fill="both", expand=True, padx=20, pady=20)
        tk.Label(f, text="PLANIFICATEUR DE SCANS AUTOMATIQUES",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")
        tk.Label(f, text="Automatisez vos scans — Protection 24h/24 sans intervention manuelle",
                 font=("Consolas", F["body"]),
                 bg=T["bg_medium"], fg=T["text_muted"]).pack(anchor="w", pady=(2,14))
        form_f = self._frame(f, "bg_light")
        form_f.pack(fill="x", pady=(0,10))
        tk.Label(form_f, text="  Ajouter une tache planifiee :",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_light"], fg=T["text_sub"]).pack(anchor="w", padx=15, pady=(10,6))
        row1 = self._frame(form_f, "bg_light")
        row1.pack(fill="x", padx=15, pady=(0,4))
        tk.Label(row1, text="Nom:", font=("Consolas", F["body"]),
                 bg=T["bg_light"], fg=T["text_sub"]).pack(side="left")
        self._sched_name = tk.StringVar(value="Scan quotidien")
        self._entry(row1, self._sched_name, width=16).pack(side="left", padx=6)
        tk.Label(row1, text="Type:", font=("Consolas", F["body"]),
                 bg=T["bg_light"], fg=T["text_sub"]).pack(side="left", padx=(8,0))
        self._sched_type = tk.StringVar(value="quick_scan")
        ttk.Combobox(row1, textvariable=self._sched_type, width=14,
                     values=["quick_scan","full_scan","memory_scan","report"],
                     state="readonly").pack(side="left", padx=6)
        tk.Label(row1, text="Heure:", font=("Consolas", F["body"]),
                 bg=T["bg_light"], fg=T["text_sub"]).pack(side="left", padx=(8,0))
        self._sched_hour = tk.StringVar(value="02")
        ttk.Combobox(row1, textvariable=self._sched_hour, width=4,
                     values=["%02d" % h for h in range(24)],
                     state="readonly").pack(side="left", padx=2)
        tk.Label(row1, text="h", font=("Consolas", F["body"]),
                 bg=T["bg_light"], fg=T["text_sub"]).pack(side="left")
        self._sched_min = tk.StringVar(value="00")
        ttk.Combobox(row1, textvariable=self._sched_min, width=4,
                     values=["%02d" % m for m in range(0,60,5)],
                     state="readonly").pack(side="left", padx=2)
        btn_f = self._frame(form_f, "bg_light")
        btn_f.pack(fill="x", padx=15, pady=(6,12))
        self._btn(btn_f, "AJOUTER", self._add_schedule,
                  color=T["success"], fg=T["bg_dark"], padx=12, pady=6).pack(side="left")
        self._sched_msg = tk.Label(btn_f, text="",
                                    font=("Consolas", F["body"]),
                                    bg=T["bg_light"], fg=T["success"])
        self._sched_msg.pack(side="left", padx=10)
        tk.Label(f, text="TACHES PLANIFIEES",
                 font=("Consolas", F["nav"], "bold"),
                 bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(8,4))
        cols = ("Nom","Type","Heure","Prochaine execution","Statut")
        self._sched_tree = ttk.Treeview(f, columns=cols, show="headings", height=14)
        for col, w in zip(cols, [160,120,60,180,80]):
            self._sched_tree.heading(col, text=col)
            self._sched_tree.column(col, width=w)
        self._sched_tree.pack(fill="both", expand=True)
        self._refresh_scheduler()
        controls = self._frame(f, "bg_medium")
        controls.pack(fill="x", pady=6)
        def selected_task():
            selection = self._sched_tree.selection()
            if not selection:
                return None
            return next((task for task in self._controller._modules["scheduler"].get_tasks()
                         if task["id"] == selection[0]), None)
        def toggle():
            task = selected_task()
            if task:
                self._controller._modules["scheduler"].toggle_task(task["id"], not task["enabled"])
                self._refresh_scheduler()
        def remove():
            task = selected_task()
            if task and messagebox.askyesno("Planification", "Supprimer cette tâche ?"):
                self._controller._modules["scheduler"].remove_task(task["id"])
                self._refresh_scheduler()
        self._btn(controls, "PAUSE / REPRENDRE", toggle, padx=10, pady=5).pack(side="left", padx=4)
        self._btn(controls, "SUPPRIMER", remove, color=T["danger"], padx=10, pady=5).pack(side="left", padx=4)

    def _add_schedule(self):
        try:
            sched = self._controller._modules["scheduler"]
            sched.add_task(
                name=self._sched_name.get(),
                task_type=self._sched_type.get(),
                hour=int(self._sched_hour.get()),
                minute=int(self._sched_min.get()))
            self._sched_msg.config(text="Tache ajoutee avec succes", fg=self._T["success"])
            self._refresh_scheduler()
        except Exception as e:
            self._sched_msg.config(text="Erreur: " + str(e)[:50], fg=self._T["danger"])

    def _refresh_scheduler(self):
        try:
            for i in self._sched_tree.get_children():
                self._sched_tree.delete(i)
            tasks = self._controller._modules["scheduler"].get_tasks()
            for t in tasks:
                status = "Actif" if t.get("enabled") else "Pause"
                nr = t.get("next_run","?")
                if nr and "T" in nr:
                    nr = nr[:16].replace("T"," ")
                self._sched_tree.insert("","end", iid=t["id"], values=(
                    t.get("name","?"), t.get("type","?"),
                    "%02d:%02d" % (t.get("hour",0), t.get("minute",0)),
                    nr, status))
        except:
            pass

    # ═══════════════════════════════════════════════════════════════
    #  AUTO RESPONSE
    # ═══════════════════════════════════════════════════════════════
    def _show_auto_response(self):
        self._clear_content()
        T, F = self._T, self._F
        f = self._frame(self._content, "bg_medium")
        f.pack(fill="both", expand=True, padx=20, pady=20)
        tk.Label(f, text="REPONSE AUTOMATIQUE AUX INCIDENTS (SOAR)",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_medium"], fg=T["accent"]).pack(anchor="w")
        tk.Label(f,
                 text="Playbooks automatiques — Kill, Quarantaine, Blocage IP sans intervention",
                 font=("Consolas", F["body"]),
                 bg=T["bg_medium"], fg=T["text_muted"]).pack(anchor="w", pady=(2,14))
        try:
            ar = self._controller._modules["auto_response"]
            status = ar.get_status()
            sf = self._frame(f, "bg_light")
            sf.pack(fill="x", pady=(0,12))
            col_s = T["success"] if status["enabled"] else T["danger"]
            txt_s = "ACTIF" if status["enabled"] else "INACTIF"
            tk.Label(sf, text="  Statut : " + txt_s,
                     font=("Consolas", F["nav"], "bold"),
                     bg=T["bg_light"], fg=col_s).pack(side="left", padx=15, pady=10)
            toggle_lbl = "DESACTIVER" if status["enabled"] else "ACTIVER"
            toggle_col = T["warning"] if status["enabled"] else T["success"]
            def toggle_ar():
                if ar.get_status()["enabled"]:
                    ar.disable()
                else:
                    ar.enable()
                self._show_auto_response()
            self._btn(sf, toggle_lbl, toggle_ar,
                      color=toggle_col, fg=T["bg_dark"],
                      padx=12, pady=6).pack(side="right", padx=15)
            tk.Label(f, text="PLAYBOOKS ACTIFS",
                     font=("Consolas", F["nav"], "bold"),
                     bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(8,4))
            for pb in ar.get_playbooks():
                pb_f = self._frame(f, "bg_light")
                pb_f.pack(fill="x", pady=2)
                trigger = pb.get("trigger", {})
                acts = " - ".join(pb.get("actions",[])[:4])
                tk.Label(pb_f,
                         text="  " + pb["name"] + "  |  " + pb.get("description",""),
                         font=("Consolas", F["body"], "bold"),
                         bg=T["bg_light"], fg=T["accent"]).pack(anchor="w", padx=12, pady=(4,0))
                tk.Label(pb_f,
                         text="  Declenchement: score >= " + str(trigger.get("min_score",0)) +
                              "  |  Actions: " + acts,
                         font=("Consolas", max(F["body"]-1,7)),
                         bg=T["bg_light"], fg=T["text_muted"]).pack(anchor="w", padx=12, pady=(0,4))
            tk.Label(f,
                     text="HISTORIQUE (" + str(len(ar.get_history())) + " actions executees)",
                     font=("Consolas", F["nav"], "bold"),
                     bg=T["bg_medium"], fg=T["text_sub"]).pack(anchor="w", pady=(12,4))
            hist_box = self._scrolltext(f, h=8)
            hist_box.pack(fill="x")
            for action in ar.get_history(20):
                ts = action.get("ts","")[:19]
                pb_name = action.get("playbook","?")
                n_a = len(action.get("actions",[]))
                hist_box.insert("end", "[" + ts + "] " + pb_name + " -- " + str(n_a) + " actions\n")
            hist_box.config(state="disabled")
        except Exception as e:
            tk.Label(f, text="Module indisponible: " + str(e),
                     bg=T["bg_medium"], fg=T["danger"]).pack()


    # ===============================================================
    #  ASSISTANT ELPATI — Robot IA conversationnel
    # ===============================================================
    def _show_assistant(self):
        self._clear_content()
        T, F = self._T, self._F

        # Init assistant si pas encore fait
        if self._assistant is None:
            try:
                from elpati.elpati_assistant import ElpatiAssistant
                self._assistant = ElpatiAssistant()
            except Exception as e:
                tk.Label(self._content, text="Erreur assistant: " + str(e),
                         bg=T["bg_medium"], fg=T["danger"]).pack(pady=20)
                return

        # Layout principal
        main = self._frame(self._content, "bg_medium")
        main.pack(fill="both", expand=True)

        # ── HEADER ──
        header = self._frame(main, "bg_dark")
        header.pack(fill="x")
        tk.Label(header, text="  ASSISTANT ELPATI",
                 font=("Consolas", F["title"], "bold"),
                 bg=T["bg_dark"], fg=T["accent"]).pack(side="left", padx=16, pady=12)
        # Badge mode
        mode = self._assistant.get_status().get("mode","local")
        mode_txt = "Claude AI" if mode == "claude" else "IA Locale"
        mode_col = T["success"] if mode == "claude" else T["warning"]
        tk.Label(header, text="Mode : " + mode_txt,
                 font=("Consolas", F["body"], "bold"),
                 bg=T["bg_dark"], fg=mode_col).pack(side="left", padx=8)
        self._btn(header, "Effacer", self._clear_chat,
                  color=T["bg_light"], fg=T["text_muted"],
                  padx=10, pady=5).pack(side="right", padx=12, pady=8)

        # ── CORPS : conversation + suggestions ──
        body = self._frame(main, "bg_medium")
        body.pack(fill="both", expand=True, padx=0, pady=0)

        # Zone de chat (scrollable)
        chat_outer = self._frame(body, "bg_dark")
        chat_outer.pack(fill="both", expand=True, padx=12, pady=(8,0))

        self._chat_canvas = tk.Canvas(chat_outer, bg=T["bg_dark"],
                                       highlightthickness=0, borderwidth=0)
        chat_sb = tk.Scrollbar(chat_outer, orient="vertical",
                               command=self._chat_canvas.yview)
        self._chat_canvas.configure(yscrollcommand=chat_sb.set)
        chat_sb.pack(side="right", fill="y")
        self._chat_canvas.pack(side="left", fill="both", expand=True)

        self._chat_inner = tk.Frame(self._chat_canvas, bg=T["bg_dark"])
        self._chat_win = self._chat_canvas.create_window(
            (0,0), window=self._chat_inner, anchor="nw")

        def _cfg(e):
            self._chat_canvas.configure(scrollregion=self._chat_canvas.bbox("all"))
            self._chat_canvas.itemconfig(self._chat_win, width=self._chat_canvas.winfo_width())
        def _cfg2(e):
            self._chat_canvas.itemconfig(self._chat_win, width=e.width)
        def _mw(e):
            self._chat_canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        self._chat_inner.bind("<Configure>", _cfg)
        self._chat_canvas.bind("<Configure>", _cfg2)
        self._chat_canvas.bind("<MouseWheel>", _mw)
        self._chat_inner.bind("<MouseWheel>", _mw)

        # ── SUGGESTIONS ──
        self._sugg_frame = self._frame(body, "bg_medium")
        self._sugg_frame.pack(fill="x", padx=12, pady=4)

        # ── BARRE DE SAISIE ──
        input_bar = self._frame(body, "bg_light")
        input_bar.pack(fill="x", padx=12, pady=(4,12))

        self._chat_input = tk.Text(input_bar,
                                    font=("Consolas", F["nav"]),
                                    bg=T["bg_dark"], fg=T["text"],
                                    insertbackground=T["accent"],
                                    relief="flat", height=2, wrap="word")
        self._chat_input.pack(side="left", fill="x", expand=True, padx=10, pady=8)
        self._chat_input.bind("<Return>", self._on_chat_enter)
        self._chat_input.bind("<Shift-Return>", lambda e: None)
        self._chat_input.focus()

        self._send_btn = self._btn(input_bar, "ENVOYER",
                                    self._send_chat,
                                    color=T["accent"], fg=T["bg_dark"],
                                    padx=14, pady=10)
        self._send_btn.pack(side="right", padx=10, pady=8)

        # Message de bienvenue
        welcome_text = (
            "Bonjour ! Je suis l'Assistant ELPATI.\n\n"
            "Je suis ici pour vous aider avec :\n"
            "  - CyberOS_Security et ses fonctionnalites\n"
            "  - Le depannage informatique\n"
            "  - La cybersecurite\n"
            "  - Toute question technique\n\n"
            "Comment puis-je vous aider aujourd'hui ?"
        )
        self._add_bot_bubble(
            welcome_text,
            show_suggestions=[
                "Comment lancer un scan ?",
                "Mon ordinateur est lent, que faire ?",
                "Comment analyser un site suspect ?",
            ]
        )

    def _on_chat_enter(self, event):
        if not event.state & 1:  # Shift non enfonce
            self._send_chat()
            return "break"

    def _send_chat(self):
        if not hasattr(self,'_chat_input'):
            return
        msg = self._chat_input.get("1.0","end").strip()
        if not msg:
            return
        self._chat_input.delete("1.0","end")
        self._send_btn.config(state="disabled", text="...")
        # Afficher le message utilisateur
        self._add_user_bubble(msg)
        # Indicateur de frappe
        typing_lbl = self._add_typing_indicator()
        # Appel IA en thread
        def _go():
            try:
                result = self._assistant.chat(msg)
                self._dispatch(lambda: self._on_chat_response(result, typing_lbl))
            except Exception as e:
                self._dispatch(lambda error=str(e): self._on_chat_response(
                    {"response": "Desolee, une erreur s'est produite: " + error[:80],
                     "source":"local","suggestions":[],"ask_satisfaction":False,
                     "satisfaction_question":"","mode":"local"},
                    typing_lbl))
        self._run_job(_go)

    def _on_chat_response(self, result, typing_lbl):
        # Supprimer l'indicateur de frappe
        try:
            typing_lbl.destroy()
        except:
            pass
        # Afficher la reponse
        response = result.get("response","")
        suggestions = result.get("suggestions",[])
        # Si question de satisfaction, l'ajouter aux suggestions
        if result.get("ask_satisfaction") and result.get("satisfaction_question"):
            self._add_bot_bubble(
                result["satisfaction_question"],
                is_satisfaction=True,
                show_suggestions=suggestions
            )
        else:
            self._add_bot_bubble(response, show_suggestions=suggestions)
        # Reactivate send button
        try:
            self._send_btn.config(state="normal", text="ENVOYER")
        except:
            pass

    def _add_user_bubble(self, text: str):
        T, F = self._T, self._F
        row = tk.Frame(self._chat_inner, bg=T["bg_dark"])
        row.pack(fill="x", padx=10, pady=4, anchor="e")
        # Aligne a droite
        spacer = tk.Frame(row, bg=T["bg_dark"])
        spacer.pack(side="left", fill="x", expand=True)
        bubble = tk.Frame(row, bg=T["accent2"])
        bubble.pack(side="right")
        tk.Label(bubble, text=text,
                 font=("Consolas", F["body"]),
                 bg=T["accent2"], fg=T["text"],
                 wraplength=420, justify="left",
                 padx=12, pady=8).pack()
        self._scroll_chat_bottom()

    def _add_bot_bubble(self, text: str, show_suggestions=None,
                         is_satisfaction=False):
        T, F = self._T, self._F
        row = tk.Frame(self._chat_inner, bg=T["bg_dark"])
        row.pack(fill="x", padx=10, pady=4, anchor="w")
        # Avatar
        av = tk.Label(row, text="AI",
                      font=("Consolas", F["body"], "bold"),
                      bg=T["accent"], fg=T["bg_dark"],
                      width=3, padx=4, pady=4)
        av.pack(side="left", anchor="n", padx=(0,8))
        # Bulle
        col = T["accent"] if is_satisfaction else T["bg_light"]
        bubble = tk.Frame(row, bg=col)
        bubble.pack(side="left", fill="x", expand=True)
        tk.Label(bubble, text=text,
                 font=("Consolas", F["body"]),
                 bg=col, fg=T["text"],
                 wraplength=520, justify="left",
                 padx=12, pady=8).pack(anchor="w")
        # Suggestions sous la bulle
        if show_suggestions:
            self._show_suggestions_buttons(show_suggestions)
        self._scroll_chat_bottom()

    def _add_typing_indicator(self):
        T, F = self._T, self._F
        row = tk.Frame(self._chat_inner, bg=T["bg_dark"])
        row.pack(fill="x", padx=10, pady=4, anchor="w")
        tk.Label(row, text="AI",
                 font=("Consolas", F["body"], "bold"),
                 bg=T["accent"], fg=T["bg_dark"],
                 width=3, padx=4, pady=4).pack(side="left", padx=(0,8))
        lbl = tk.Label(row, text="...",
                       font=("Consolas", F["body"]),
                       bg=T["bg_light"], fg=T["text_muted"],
                       padx=12, pady=8)
        lbl.pack(side="left")
        self._scroll_chat_bottom()
        return row

    def _show_suggestions_buttons(self, suggestions: list):
        T, F = self._T, self._F
        # Nettoyer les suggestions precedentes
        for w in self._sugg_frame.winfo_children():
            w.destroy()
        for suggestion in suggestions:
            def make_cmd(s):
                def cmd():
                    try:
                        self._chat_input.delete("1.0","end")
                        self._chat_input.insert("1.0", s)
                        self._send_chat()
                    except:
                        pass
                return cmd
            btn = tk.Button(self._sugg_frame,
                            text=suggestion,
                            font=("Consolas", max(F["body"]-1,7)),
                            bg=T["bg_dark"], fg=T["accent"],
                            relief="flat", padx=8, pady=4,
                            cursor="hand2",
                            command=make_cmd(suggestion),
                            wraplength=200)
            btn.pack(side="left", padx=3, pady=2)

    def _scroll_chat_bottom(self):
        try:
            self._chat_canvas.update_idletasks()
            self._chat_canvas.yview_moveto(1.0)
        except:
            pass

    def _clear_chat(self):
        if self._assistant:
            self._assistant.clear_history()
        self._show_assistant()

    def _clear_content(self):
        self._page_generation += 1
        for w in self._content.winfo_children(): w.destroy()

    def _start_live_updates(self):
        if self._clock_started:
            return
        self._clock_started = True
        def tick():
            if self._closed:
                return
            if hasattr(self, "_clock") and self._clock.winfo_exists():
                self._clock.config(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            self.root.after(1000, tick)
        tick()

    def _dispatch(self, callback):
        if not self._closed:
            generation = getattr(self._job_local, "generation", None)
            self._ui_queue.put((generation, callback))

    def _drain_ui(self):
        if self._closed:
            return
        for _ in range(100):
            try:
                generation, callback = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            if generation is not None and generation != self._page_generation:
                continue
            try:
                callback()
            except Exception as exc:
                self._callback_error(type(exc), exc, exc.__traceback__)
        self.root.after(30, self._drain_ui)

    def _run_job(self, callback):
        generation = self._page_generation
        def worker():
            self._job_local.generation = generation
            try:
                callback()
            except Exception as exc:
                error = str(exc)
                self._dispatch(lambda error=error: self._job_failed(error))
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        return thread

    def _job_failed(self, error):
        self._scan_running = False
        for name in ("_scan_btn", "_vuln_btn", "_send_btn"):
            widget = getattr(self, name, None)
            if widget is not None and widget.winfo_exists():
                widget.config(state="normal")
        messagebox.showerror("Opération interrompue", error)

    def _callback_error(self, kind, error, tb):
        if self._controller:
            self._controller.log.error("GUI: " + "".join(traceback.format_exception(kind, error, tb)))
        if not self._closed:
            messagebox.showerror("Erreur", str(error))

    def _close(self):
        if self._closed:
            return
        self._closed = True
        for identifier in self.root.tk.call("after", "info"):
            self.root.after_cancel(identifier)
        if self._controller:
            self._controller.stop_protection()
            self._controller.auth.logout()
            self._controller.log.flush_chain()
        if hasattr(self, "_auth"):
            self._auth.logout()
        self.root.destroy()

    def run(self): self.root.mainloop()
