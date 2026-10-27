"""
CORE ENGINE - CyberOS_Security Scan Engine
Orchestrates file scanning, process analysis, registry analysis
"""
import os, hashlib, time, json, psutil
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import threading

class CyberEngine:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        from elpati.elpati_threat_intel import ElpatiThreatIntel
        from elpati.elpati_ai_analyzer import ElpatiAIAnalyzer
        from elpati.elpati_crypto import ElpatiCrypto
        self.log = ElpatiLog()
        self.ti = ElpatiThreatIntel()
        self.ai = ElpatiAIAnalyzer(threat_intel=self.ti)
        self.crypto = ElpatiCrypto()
        self._scan_running = False
        self._scan_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._scan_progress = {"total": 0, "scanned": 0, "threats": 0, "errors": 0}
        self._results = []

    def quick_scan(self, callback=None) -> dict:
        """Fast scan of critical system locations."""
        critical_paths = self._get_critical_paths()
        return self._run_scan(critical_paths, "QUICK", callback=callback)

    def full_scan(self, root_path: str = None, callback=None) -> dict:
        """Deep scan of entire filesystem."""
        if root_path is None:
            if os.name == 'nt':
                root_path = "C:\\"
            else:
                root_path = "/"
        return self._run_scan([root_path], "FULL", callback=callback)

    def _get_critical_paths(self) -> list:
        paths = []
        home = str(Path.home())
        if os.name == 'nt':
            paths = [
                os.environ.get("TEMP", "C:\\Windows\\Temp"),
                os.environ.get("APPDATA", ""),
                "C:\\Windows\\System32",
                "C:\\Windows\\SysWOW64",
                home + "\\Downloads",
                home + "\\Desktop",
            ]
        else:
            paths = [
                "/tmp", "/var/tmp", "/dev/shm",
                home, home + "/Downloads",
                "/usr/bin", "/usr/local/bin",
                "/etc/cron.d", "/etc/cron.daily",
            ]
        return [p for p in paths if p and os.path.exists(p)]

    def stop_scan(self):
        self._stop_event.set()

    def _run_scan(self, paths: list, scan_type: str, callback=None) -> dict:
        if not self._scan_lock.acquire(blocking=False):
            raise RuntimeError("Un scan est déjà en cours")
        self._stop_event.clear()
        self._scan_running = True
        self._scan_progress = {"total": 0, "scanned": 0, "threats": 0, "errors": 0, "skipped": 0,
                               "directories_excluded": 0}
        started = time.monotonic()
        threats, errors = [], []
        file_errors = 0
        max_depth = 2 if scan_type == "QUICK" else None
        try:
            self.log.info(f"Engine: Starting {scan_type} scan")
            files, seen = [], set()
            for path in paths:
                for filename in self._walk_files(path, max_depth=max_depth):
                    if self._stop_event.is_set():
                        break
                    normalized = os.path.normcase(os.path.abspath(filename))
                    if normalized not in seen:
                        seen.add(normalized)
                        files.append(filename)
            self._scan_progress["total"] = len(files)
            iterator = iter(files)
            pending = {}
            with ThreadPoolExecutor(max_workers=4) as executor:
                def submit():
                    if self._stop_event.is_set():
                        return False
                    filename = next(iterator, None)
                    if filename is None:
                        return False
                    pending[executor.submit(self._scan_file, filename)] = filename
                    return True
                for _ in range(8):
                    if not submit():
                        break
                while pending:
                    completed, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for future in completed:
                        filename = pending.pop(future)
                        if future.cancelled():
                            continue
                        self._scan_progress["scanned"] += 1
                        try:
                            result = future.result()
                            if result and (result.get("threat") or result.get("review_required")):
                                threats.append(result)
                                self._scan_progress["threats"] += 1
                        except Exception as exc:
                            file_errors += 1
                            self._scan_progress["errors"] += 1
                            if len(errors) < 20:
                                errors.append({"path": filename, "error": str(exc)})
                            self.log.warning(f"Scan unreadable: {filename}: {exc}")
                        if callback:
                            try:
                                callback(dict(self._scan_progress))
                            except Exception as exc:
                                self.log.warning(f"Scan callback: {exc}")
                        submit()
                    if self._stop_event.is_set():
                        for future in pending:
                            future.cancel()
            summary = {"type": scan_type, "duration_sec": round(time.monotonic() - started, 2),
                       "files_scanned": self._scan_progress["scanned"], "total_files": len(files),
                       "threats_found": len(threats), "errors": self._scan_progress["errors"],
                       "skipped": self._scan_progress["skipped"], "error_details": errors,
                       "files_read": self._scan_progress["scanned"] - file_errors,
                       "confirmed_threats": sum(1 for item in threats if item.get("confirmed")),
                       "review_count": sum(1 for item in threats if not item.get("confirmed")),
                       "max_directory_depth": max_depth,
                       "directories_excluded": self._scan_progress["directories_excluded"],
                       "cancelled": self._stop_event.is_set(), "threats": threats,
                       "ts": datetime.utcnow().isoformat()}
            self._results = threats
            self.log.info(f"Engine: {scan_type} ended: {len(threats)} findings, {summary['errors']} errors")
            return summary
        finally:
            self._scan_running = False
            self._scan_lock.release()

    def _walk_files(self, path: str, max_depth=None):
        root = Path(path)
        internal = Path(__file__).resolve().parent.parent
        excluded = [internal / rel for rel in ("security", "logs", "quarantine/vault",
                                                "reports/forensic", "reports/pdf", ".git", ".venv", "venv")]
        def allowed(file):
            return not any(file.resolve().is_relative_to(p) for p in excluded)
        if root.is_symlink():
            self._scan_progress["skipped"] += 1
            return
        if root.is_file():
            if allowed(root):
                if root.stat().st_size <= 100 * 1024 * 1024:
                    yield str(root)
                else:
                    self._scan_progress["skipped"] += 1
            return
        if not root.is_dir():
            self._scan_progress["errors"] += 1
            return
        def onerror(exc):
            self._scan_progress["errors"] += 1
            self.log.warning(f"Scan traversal: {exc}")
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
            if self._stop_event.is_set():
                return
            base = Path(directory)
            dirs[:] = [name for name in dirs if not (base / name).is_symlink() and allowed(base / name)
                       and name not in {"__pycache__", ".git", ".venv", "venv"}]
            if max_depth is not None and len(base.relative_to(root).parts) >= max_depth:
                self._scan_progress["directories_excluded"] += len(dirs)
                dirs[:] = []
            for name in files:
                file = base / name
                try:
                    if file.is_symlink() or not file.is_file() or not allowed(file):
                        self._scan_progress["skipped"] += 1
                    elif file.stat().st_size > 100 * 1024 * 1024:
                        self._scan_progress["skipped"] += 1
                    else:
                        yield str(file)
                except OSError as exc:
                    onerror(exc)

    def _scan_file(self, filepath: str):
        # Do not hide failures as clean results: the coordinator reports them.
        digests = self.crypto.file_hashes(filepath)
        file_hash = digests["sha256"]
        for digest in digests.values():
            if self.ti.check_hash(digest)["detected"]:
                return {"path": filepath, "threat": True, "type": "KNOWN_MALWARE",
                        "score": 100, "hash": file_hash, "hash_algorithm": "sha256", "confirmed": True}
        ext_result = self.ti.check_extension(filepath)
        if ext_result["detected"]:
            return {"path": filepath, "threat": False, "type": "EXTENSION_ALERT",
                    "review_required": True, "confirmed": False,
                    "score": ext_result["score"], "hash": file_hash,
                    "notes": ["Extension associee au chiffrement; cause et infection non confirmees."]}
        scannable = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js",
                     ".py", ".sh", ".php", ".jar", ".msi", ".scr", ".hta"}
        if Path(filepath).suffix.lower() in scannable:
            ai_result = self.ai.analyze_file_heuristic(filepath)
            if ai_result.get("error"):
                raise OSError(ai_result["error"])
            if ai_result.get("review_required"):
                return {"path": filepath, "threat": False, "confirmed": False, "review_required": True,
                        "type": "HEURISTIC_ALERT", "risk_level": ai_result.get("risk_level", "MEDIUM"),
                        "score": ai_result["score"], "hash": file_hash,
                        "notes": ai_result.get("notes", [])}
        return None

    def scan_processes(self) -> list:
        """Scan all running processes."""
        results = []
        self.log.info("Engine: Scanning processes")
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'status']):
            try:
                info = proc.info
                result = {"pid": info['pid'], "name": info['name'],
                          "exe": info.get('exe') or "", "threat": False, "score": 0, "flags": []}

                # Check process name
                ti_result = self.ti.check_process_name(info['name'])
                if ti_result['detected']:
                    result["threat"] = True
                    result["score"] = ti_result['score']
                    result["flags"].append("KNOWN_MALICIOUS_PROCESS")

                # Check cmdline
                cmdline = ' '.join(info.get('cmdline') or [])
                if cmdline:
                    str_results = self.ti.scan_strings(cmdline)
                    for r in str_results:
                        result["score"] = max(result["score"], r.get("score", 0))
                        result["flags"].append(r.get("name", r.get("match", "")))
                        if result["score"] > 50:
                            result["threat"] = True

                if result["score"] > 0:
                    results.append(result)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        results.sort(key=lambda x: x["score"], reverse=True)
        self.log.info(f"Engine: Process scan complete - {len(results)} flagged")
        return results

    def scan_registry(self) -> list:
        """Scan Windows registry for persistence mechanisms."""
        if os.name != 'nt':
            return [{"info": "Registry scan is Windows-only"}]
        results = []
        try:
            import winreg
            run_keys = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            ]
            for hive, key_path in run_keys:
                try:
                    with winreg.OpenKey(hive, key_path) as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                result = {"key": key_path, "name": name, "value": value,
                                          "threat": False, "score": 0, "flags": []}
                                # Check value against threat intel
                                str_results = self.ti.scan_strings(value)
                                for r in str_results:
                                    result["score"] = max(result["score"], r.get("score", 0))
                                    result["flags"].append(r.get("name", r.get("match", "")))
                                    if result["score"] > 40:
                                        result["threat"] = True
                                results.append(result)
                                i += 1
                            except OSError:
                                break
                except (PermissionError, OSError):
                    continue
        except ImportError:
            results.append({"info": "Registry scan requires Windows"})
        return results

    def get_progress(self) -> dict:
        return dict(self._scan_progress)

    def is_running(self) -> bool:
        return self._scan_running
