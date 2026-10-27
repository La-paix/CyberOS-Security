"""Local daily/weekday scheduler. Times use the operating system timezone."""
import json
import threading
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4
from utils.storage import write_json

SCHED_FILE = Path(__file__).resolve().parent.parent / "data" / "schedules.json"
DAY_NAMES = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")


class ElpatiScheduler:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        self.log = ElpatiLog()
        self._lock = threading.RLock()
        self._schedules = self._load()
        self._active = False
        self._thread = None
        self._stop = threading.Event()
        self._callbacks = []

    def _load(self):
        if not SCHED_FILE.exists():
            return {"tasks": []}
        value = json.loads(SCHED_FILE.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or not isinstance(value.get("tasks"), list):
            raise ValueError("Fichier de planification corrompu")
        return value

    def _save(self):
        write_json(SCHED_FILE, self._schedules)

    def add_task(self, name, task_type, hour, minute=0, days="daily", enabled=True):
        if task_type not in {"quick_scan", "full_scan", "memory_scan", "report"}:
            raise ValueError("Type de tâche inconnu")
        if not name.strip():
            raise ValueError("Nom de tâche requis")
        next_run = self._calc_next(hour, minute, days)
        with self._lock:
            task = {"id": "task_" + uuid4().hex, "name": name, "type": task_type,
                    "hour": hour, "minute": minute, "days": days, "enabled": enabled,
                    "last_run": None, "next_run": next_run}
            self._schedules["tasks"].append(task)
            self._save()
        return task["id"]

    def _calc_next(self, hour, minute, days, now=None):
        if (not isinstance(hour, int) or not isinstance(minute, int) or
            not 0 <= hour <= 23 or not 0 <= minute <= 59 or
            days not in {"daily", "weekdays", "weekends", *DAY_NAMES}):
            raise ValueError("Horaire ou jours invalides")
        now = now or datetime.now()
        for offset in range(8):
            candidate = (now + timedelta(days=offset)).replace(
                hour=hour, minute=minute, second=0, microsecond=0)
            weekday = candidate.weekday()
            allowed = (days == "daily" or days == "weekdays" and weekday < 5 or
                       days == "weekends" and weekday >= 5 or days == DAY_NAMES[weekday])
            if candidate > now and allowed:
                return candidate.isoformat()
        raise ValueError("Horaire introuvable")

    def remove_task(self, task_id):
        with self._lock:
            self._schedules["tasks"] = [t for t in self._schedules["tasks"] if t["id"] != task_id]
            self._save()

    def toggle_task(self, task_id, enabled):
        with self._lock:
            for task in self._schedules["tasks"]:
                if task["id"] == task_id:
                    task["enabled"] = bool(enabled)
                    task["next_run"] = self._calc_next(task["hour"], task["minute"], task["days"])
                    self._save()
                    return True
        return False

    def start(self):
        if self._active:
            return
        self._active = True
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ELPATI-Scheduler")
        self._thread.start()

    def stop(self):
        self._active = False
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)

    def _run_due(self, now=None):
        now = now or datetime.now()
        due = []
        with self._lock:
            for task in self._schedules["tasks"]:
                if task.get("enabled") and now >= datetime.fromisoformat(task["next_run"]):
                    # Persist the next occurrence before dispatch to avoid immediate re-execution.
                    task["last_run"] = now.isoformat()
                    task["next_run"] = self._calc_next(task["hour"], task["minute"], task["days"], now)
                    due.append(dict(task))
            if due:
                self._save()
        for task in due:
            self._run_task(task)

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._run_due()
            except Exception as exc:
                self.log.error(f"Scheduler: {exc}")
            self._stop.wait(30)

    def _run_task(self, task):
        for callback in self._callbacks:
            try:
                callback(dict(task))
            except Exception as exc:
                self.log.error(f"Scheduled task {task['name']}: {exc}")

    def register_callback(self, callback):
        if callback not in self._callbacks:
            self._callbacks.append(callback)

    def get_tasks(self):
        with self._lock:
            return [dict(task) for task in self._schedules["tasks"]]

    def get_next_task(self):
        tasks = [t for t in self.get_tasks() if t.get("enabled")]
        return min(tasks, key=lambda t: t["next_run"]) if tasks else None
