"""
ELPATI MEMORY SCAN - RAM Analysis & Process Memory Inspection
Detects in-memory malware, injected code, and anomalies
"""
import os, re, psutil, struct
from datetime import datetime
from pathlib import Path

class ElpatiMemoryScan:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        from elpati.elpati_threat_intel import ElpatiThreatIntel
        self.log = ElpatiLog()
        self.ti = ElpatiThreatIntel()
        self._suspicious_patterns = [
            rb"MZ\x90\x00",           # PE header (injected DLL/EXE)
            rb"This program cannot",   # PE string
            rb"TVqQ",                  # Base64 encoded PE
            rb"4d5a90",               # Hex PE header
            b"cmd.exe", b"powershell", b"mshta.exe",
            b"CreateRemoteThread", b"VirtualAlloc",
            b"mimikatz", b"sekurlsa", b"lsadump",
            b"metasploit", b"meterpreter", b"cobalt strike",
        ]

    def scan_process_memory(self, pid: int) -> dict:
        """Scan process memory for suspicious patterns."""
        findings = []
        score = 0
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()

            # Check memory maps
            try:
                maps = proc.memory_maps(grouped=False)
                for mmap in maps:
                    # Check for executable regions not backed by files
                    if hasattr(mmap, 'perms') and 'x' in mmap.perms:
                        if not mmap.path or mmap.path == '':
                            findings.append({
                                "type": "ANONYMOUS_EXEC_REGION",
                                "addr": hex(mmap.addr) if hasattr(mmap, 'addr') else "unknown",
                                "size": mmap.size if hasattr(mmap, 'size') else 0,
                                "score": 70
                            })
                            score += 70
            except (psutil.AccessDenied, AttributeError):
                pass

            # Read process memory on Linux
            if os.name == 'posix':
                result = self._scan_linux_process_memory(pid)
                findings.extend(result["findings"])
                score += result["score"]

            # Check for known bad modules
            try:
                for mod in proc.memory_maps(grouped=True):
                    mod_path = mod.path.lower() if hasattr(mod, 'path') else ""
                    suspicious_dlls = ["hooklib", "injector", "payload", "shellcode"]
                    for s in suspicious_dlls:
                        if s in mod_path:
                            findings.append({"type": "SUSPICIOUS_MODULE", "path": mod.path, "score": 80})
                            score += 80
            except:
                pass

            return {
                "pid": pid, "name": proc_name, "score": min(score, 100),
                "findings": findings, "ts": datetime.utcnow().isoformat(),
                "risk": "CRITICAL" if score > 75 else "HIGH" if score > 50 else "MEDIUM" if score > 25 else "LOW"
            }
        except psutil.NoSuchProcess:
            return {"pid": pid, "score": 0, "findings": [], "risk": "NONE", "error": "Process not found"}
        except psutil.AccessDenied:
            return {"pid": pid, "score": 0, "findings": [], "risk": "UNKNOWN", "error": "Access denied"}

    def _scan_linux_process_memory(self, pid: int) -> dict:
        """Linux-specific memory scan via /proc."""
        findings = []
        score = 0
        maps_file = Path(f"/proc/{pid}/maps")
        mem_file = Path(f"/proc/{pid}/mem")

        if not maps_file.exists():
            return {"findings": [], "score": 0}

        try:
            regions = []
            with open(maps_file) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        addrs = parts[0].split("-")
                        perms = parts[1]
                        if 'r' in perms and len(addrs) == 2:
                            start = int(addrs[0], 16)
                            end = int(addrs[1], 16)
                            size = end - start
                            if size < 10 * 1024 * 1024:  # < 10MB regions
                                regions.append((start, end, perms))

            if mem_file.exists():
                with open(mem_file, "rb") as mem:
                    for start, end, perms in regions[:20]:  # Limit regions scanned
                        try:
                            mem.seek(start)
                            data = mem.read(min(end - start, 65536))
                            for pat in self._suspicious_patterns:
                                if pat in data:
                                    findings.append({
                                        "type": "SUSPICIOUS_MEMORY_PATTERN",
                                        "pattern": pat.decode("utf-8", errors="replace")[:30],
                                        "region_start": hex(start),
                                        "perms": perms,
                                        "score": 65
                                    })
                                    score = max(score, 65)
                                    break
                        except:
                            continue
        except Exception as e:
            pass

        return {"findings": findings, "score": score}

    def scan_all_processes(self, top_risk_only=True) -> list:
        results = []
        pids = psutil.pids()
        self.log.info(f"Memory scan: scanning {len(pids)} processes")
        for pid in pids:
            result = self.scan_process_memory(pid)
            if not top_risk_only or result.get("score", 0) > 20:
                results.append(result)
        results.sort(key=lambda x: x.get("score", 0), reverse=True)
        self.log.info(f"Memory scan complete: {len(results)} flagged processes")
        return results

    def get_memory_stats(self) -> dict:
        try:
            vm = psutil.virtual_memory()
            return {
                "total_gb": round(vm.total / (1024**3), 2),
                "used_gb": round(vm.used / (1024**3), 2),
                "available_gb": round(vm.available / (1024**3), 2),
                "percent": vm.percent,
                "swap": dict(psutil.swap_memory()._asdict())
            }
        except:
            return {}
