"""Run the suite in a disposable source copy, never in your installation data."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIRS = ("core", "elpati", "gui", "cli", "scanner", "forensic", "sandbox",
               "quarantine", "reports", "utils", "tools", "vendor_tools", "tests")


def copy_source(target):
    target.mkdir(parents=True, exist_ok=True)
    for directory in SOURCE_DIRS:
        for file in (ROOT / directory).glob("*.py"):
            out = target / directory / file.name
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file, out)
    for name in ("main.py", ".gitignore", "requirements.txt", "config.env.example",
                 "data/i18n.json", "security/integrity/manifest.json", "threat_db/signatures.json"):
        out = target / name
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gui", action="store_true", help="Inclure les tests Tkinter avec un vrai affichage")
    parser.add_argument("--json", type=Path, help="Enregistrer le résultat au chemin choisi")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="cyberos-test-") as temp:
        target = Path(temp) / "app"
        copy_source(target)
        env = dict(os.environ, CYBEROS_TEST_COPY=str(target),
                   CYBEROS_TEST_GUI="1" if args.gui else "0", PYTHONDONTWRITEBYTECODE="1",
                   AI_REMOTE_ENABLED="false")
        env.pop("ANTHROPIC_API_KEY", None)
        env.pop("ANTHROPIC_MODEL", None)
        command = [sys.executable, str(target / "tests/suite.py")]
        if args.json:
            command += ["--json", str(args.json.resolve())]
        return subprocess.call(command, cwd=target, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
