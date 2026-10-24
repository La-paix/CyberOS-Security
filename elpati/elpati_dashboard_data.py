"""
ELPATI DASHBOARD DATA - Métriques temps réel pour le dashboard
Collecte toutes les stats en un seul appel optimisé
"""
import psutil, time
from datetime import datetime
from collections import deque

class ElpatiDashboardData:
    """Collecteur de métriques optimisé pour le dashboard."""
    def __init__(self):
        self._history_cpu = deque(maxlen=60)
        self._history_mem = deque(maxlen=60)
        self._history_net_sent = deque(maxlen=60)
        self._history_net_recv = deque(maxlen=60)
        self._last_net = psutil.net_io_counters()
        self._last_time = time.time()

    def snapshot(self) -> dict:
        """Snapshot complet en un seul appel."""
        now = time.time()
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        net = psutil.net_io_counters()

        dt = max(now - self._last_time, 0.1)
        net_sent_s = (net.bytes_sent - self._last_net.bytes_sent) / dt
        net_recv_s = (net.bytes_recv - self._last_net.bytes_recv) / dt
        self._last_net = net
        self._last_time = now

        self._history_cpu.append(cpu)
        self._history_mem.append(mem.percent)
        self._history_net_sent.append(net_sent_s)
        self._history_net_recv.append(net_recv_s)

        # Top 5 processus par CPU
        top_procs = []
        try:
            procs = [(p.pid, p.info) for p in psutil.process_iter(
                ['pid','name','cpu_percent','memory_percent','status'])
                if p.info.get('cpu_percent', 0) is not None]
            top_procs = sorted(procs, key=lambda x: x[1].get('cpu_percent',0) or 0,
                               reverse=True)[:5]
            top_procs = [{"pid":p,"name":i.get('name','?')[:20],
                          "cpu":round(i.get('cpu_percent',0) or 0,1),
                          "mem":round(i.get('memory_percent',0) or 0,1)}
                         for p,i in top_procs]
        except: pass

        return {
            "ts":             datetime.utcnow().isoformat(),
            "cpu":            cpu,
            "cpu_history":    list(self._history_cpu),
            "cpu_count":      psutil.cpu_count(),
            "mem_percent":    mem.percent,
            "mem_used_gb":    round(mem.used / 1024**3, 2),
            "mem_total_gb":   round(mem.total / 1024**3, 2),
            "mem_history":    list(self._history_mem),
            "net_sent_s":     round(net_sent_s / 1024, 1),
            "net_recv_s":     round(net_recv_s / 1024, 1),
            "net_total_sent": net.bytes_sent,
            "net_total_recv": net.bytes_recv,
            "process_count":  len(psutil.pids()),
            "top_processes":  top_procs,
        }

    def format_bytes(self, n: int) -> str:
        for u in ['B','KB','MB','GB','TB']:
            if n < 1024: return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} PB"
