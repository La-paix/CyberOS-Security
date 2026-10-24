"""
CORE ENGINE - CyberOS_Security Scan Engine
Orchestrates file scanning, process analysis, registry analysis
"""
import os, hashlib, time, json, psutil
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class CyberEngine:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        from elpati.elpati_threat_intel import ElpatiThreatIntel
        from elpati.elpati_ai_analyzer import ElpatiAIAnalyzer
        from elpati.elpati_crypto import ElpatiCrypto
        self.log = ElpatiLog()
        self.ti = ElpatiThreatIntel()
        self.ai = ElpatiAIAnalyzer()
        self.crypto = ElpatiCrypto()
        self._scan_running = False
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

    def _run_scan(self, paths: list, scan_type: str, callback=None) -> dict:
        self._scan_running = True
        self._scan_progress = {"total": 0, "scanned": 0, "threats": 0, "errors": 0}
        self._results = []
        start_time = time.time()
        self.log.info(f"Engine: Starting {scan_type} scan on {len(paths)} paths")

        # Collect all files
        all_files = []
        for path in paths:
            for f in self._walk_files(path):
                all_files.append(f)

        self._scan_progress["total"] = len(all_files)
        self.log.info(f"Engine: {len(all_files)} files to scan")

        # Scan with thread pool
        threats = []
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(self._scan_file, f): f for f in all_files}
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=10)
                    self._scan_progress["scanned"] += 1
                    if result and result.get("threat"):
                        threats.append(result)
                        self._scan_progress["threats"] += 1
                        self.log.threat(f"THREAT: {result['path']} score={result['score']}")
                    if callback:
                        try:
                            callback(self._scan_progress.copy())
                        except:
                            pass
                except Exception as e:
                    self._scan_progress["errors"] += 1

        self._scan_running = False
        duration = time.time() - start_time
        summary = {
            "type": scan_type, "duration_sec": round(duration, 2),
            "files_scanned": self._scan_progress["scanned"],
            "threats_found": self._scan_progress["threats"],
            "errors": self._scan_progress["errors"],
            "threats": threats, "ts": datetime.utcnow().isoformat()
        }
        self.log.info(f"Engine: {scan_type} scan complete. {len(threats)} threats in {duration:.1f}s")
        return summary

    def _walk_files(self, path: str, max_depth: int = 5):
        """Walk directory yielding files, with depth limit."""
        try:
            p = Path(path)
            if p.is_file():
                yield str(p)
                return
            for item in p.rglob("*"):
                try:
                    if item.is_file() and not item.is_symlink():
                        # Skip very large files and system files
                        if item.stat().st_size < 100 * 1024 * 1024:  # < 100MB
                            yield str(item)
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            pass

    def _scan_file(self, filepath: str) -> dict:
        try:
            # Hash check
            file_hash = self.crypto.hash_file(filepath)
            if not file_hash:
                return None

            # Check against threat intel
            hash_result = self.ti.check_hash(file_hash)
            if hash_result["detected"]:
                return {"path": filepath, "threat": True, "type": "KNOWN_MALWARE",
                        "score": 100, "hash": file_hash}

            # Check extension
            ext_result = self.ti.check_extension(filepath)
            if ext_result["detected"]:
                return {"path": filepath, "threat": True, "type": "RANSOMWARE_EXTENSION",
                        "score": ext_result["score"], "hash": file_hash}

            # AI heuristic for executables and scripts
            p = Path(filepath)
            scannable_exts = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js",
                              ".py", ".sh", ".php", ".jar", ".msi", ".scr", ".hta"}
            if p.suffix.lower() in scannable_exts:
                ai_result = self.ai.analyze_file_heuristic(filepath)
                if ai_result.get("score", 0) > 50:
                    return {"path": filepath, "threat": True,
                            "type": ai_result.get("risk_level", "SUSPICIOUS"),
                            "score": ai_result["score"], "hash": file_hash,
                            "notes": ai_result.get("notes", [])}
            return None
        except Exception:
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
