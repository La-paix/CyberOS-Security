"""
ELPATI SCHEDULER - Planification automatique des scans
Scans automatiques jour/nuit, alertes programmées, maintenance auto
"""
import threading, time, json
from datetime import datetime, timedelta
from pathlib import Path

SCHED_FILE = Path(__file__).parent.parent / "data" / "schedules.json"

class ElpatiScheduler:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        self.log = ElpatiLog()
        self._schedules = self._load()
        self._active = False
        self._thread = None
        self._callbacks = []

    def _load(self):
        if SCHED_FILE.exists():
            try: return json.loads(SCHED_FILE.read_text(encoding='utf-8'))
            except: pass
        return {"tasks": []}

    def _save(self):
        SCHED_FILE.parent.mkdir(exist_ok=True)
        SCHED_FILE.write_text(json.dumps(self._schedules, indent=2), encoding='utf-8')

    def add_task(self, name, task_type, hour, minute=0, days="daily", enabled=True):
        """Ajouter une tâche planifiée."""
        task = {
            "id": f"task_{int(time.time())}",
            "name": name,
            "type": task_type,  # quick_scan, full_scan, memory_scan, report
            "hour": hour, "minute": minute,
            "days": days,  # daily, weekdays, weekends, monday...sunday
            "enabled": enabled,
            "last_run": None, "next_run": self._calc_next(hour, minute, days)
        }
        self._schedules["tasks"].append(task)
        self._save()
        self.log.audit(f"Scheduler: Tâche ajoutée: {name} à {hour:02d}:{minute:02d}")
        return task["id"]

    def _calc_next(self, hour, minute, days):
        now = datetime.now()
        next_dt = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if next_dt <= now:
            next_dt += timedelta(days=1)
        return next_dt.isoformat()

    def remove_task(self, task_id):
        self._schedules["tasks"] = [t for t in self._schedules["tasks"] if t["id"] != task_id]
        self._save()

    def toggle_task(self, task_id, enabled):
        for t in self._schedules["tasks"]:
            if t["id"] == task_id:
                t["enabled"] = enabled
                self._save()
                return True
        return False

    def start(self):
        self._active = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ELPATI-Scheduler")
        self._thread.start()
        self.log.info("Scheduler démarré")

    def stop(self):
        self._active = False

    def _loop(self):
        while self._active:
            now = datetime.now()
            for task in self._schedules.get("tasks", []):
                if not task.get("enabled"):
                    continue
                try:
                    next_run = datetime.fromisoformat(task["next_run"])
                    if now >= next_run:
                        self._run_task(task)
                        task["last_run"] = now.isoformat()
                        task["next_run"] = self._calc_next(task["hour"], task["minute"], task["days"])
                        self._save()
                except Exception as e:
                    self.log.error(f"Scheduler task error: {e}")
            time.sleep(30)  # Vérifie toutes les 30 secondes

    def _run_task(self, task):
        self.log.audit(f"Scheduler: Exécution tâche '{task['name']}' type={task['type']}")
        for cb in self._callbacks:
            try: cb(task)
            except: pass

    def register_callback(self, cb): self._callbacks.append(cb)
    def get_tasks(self): return self._schedules.get("tasks", [])
    def get_next_task(self):
        tasks = [t for t in self.get_tasks() if t.get("enabled") and t.get("next_run")]
        if not tasks: return None
        return min(tasks, key=lambda t: t["next_run"])
