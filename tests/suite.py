"""Regression and integration tests. Launch with python tests/run_tests.py."""
import base64
import contextlib
import copy
import errno
from datetime import datetime, timedelta, timezone
import hashlib
import http.server
import importlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
PASSWORD = "FixturePassword!2026"


def eicar_fixture_unavailable(error, expected_path, *, windows=None):
    """Classify fixture I/O, without treating an unknown error as an AV verdict."""
    if windows is None:
        windows = sys.platform == "win32"
    if not windows or not isinstance(error, OSError):
        return False
    filename = getattr(error, "filename", None)
    if filename is None or os.path.normcase(os.path.abspath(filename)) != os.path.normcase(os.path.abspath(expected_path)):
        return False
    return (getattr(error, "winerror", None) in {225, 226} or
            error.errno in {errno.ENOENT, errno.EACCES, errno.EPERM, errno.EINVAL})


class IsolatedCase(unittest.TestCase):
    def setUp(self):
        if os.environ.get("CYBEROS_TEST_COPY") != str(ROOT) or not ROOT.parent.name.startswith("cyberos-test-"):
            raise RuntimeError("Exécuter python tests/run_tests.py pour protéger les données locales.")
        for directory in ("security/keys", "security/auth", "security/vault", "logs", "quarantine/vault",
                          "reports/pdf", "reports/forensic", "sandbox/analysis", ".test-fixtures",
                          ".local-backups"):
            shutil.rmtree(ROOT / directory, ignore_errors=True)
        for name in ("security/fim_baseline.json", "security/state.json", "data/config.json",
                     "data/schedules.json", "threat_db/custom_signatures.json", "config.env",
                     "security/license_public_key.pub", "security/migration_in_progress.json"):
            (ROOT / name).unlink(missing_ok=True)
        from elpati.elpati_crypto import KEYS_DIR
        from elpati.elpati_auth_voice import AUTH_DIR
        KEYS_DIR.mkdir(parents=True, exist_ok=True)
        AUTH_DIR.mkdir(parents=True, exist_ok=True)
        from elpati.elpati_log import ElpatiLog, LOGS_DIR
        LOGS_DIR.mkdir(exist_ok=True)
        ElpatiLog._instance = None
        from core.controller import CentralController
        from core.config import Config
        CentralController._instance = None
        Config._instance = None
        self.root = ROOT / ".test-fixtures"
        self.root.mkdir()

    def tearDown(self):
        from core.controller import CentralController
        if CentralController._instance and hasattr(CentralController._instance, "_modules"):
            CentralController._instance.stop_protection()

    def fixture(self, name="clean.txt", content=b"Harmless fixture.\n"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def auth(self):
        from elpati.elpati_auth_voice import ElpatiAuthVoice
        value = ElpatiAuthVoice()
        self.assertTrue(value.set_password(PASSWORD))
        return value

    def engine(self):
        from core.engine import CyberEngine
        return CyberEngine()

    def license(self, tier="PRO", days=2, machine_id="GLOBAL", now=None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        from vendor_tools.license_issuer import issue
        from elpati.elpati_payment import PUBLIC_KEY_FILE, ElpatiPayment
        private = Ed25519PrivateKey.generate()
        PUBLIC_KEY_FILE.write_bytes(private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        return ElpatiPayment(), issue(private, tier, days, machine_id, now)

    def test_01_first_setup_has_no_default_password(self):
        from elpati.elpati_auth_voice import ElpatiAuthVoice, DEFAULT_PASSWORD
        auth = ElpatiAuthVoice()
        self.assertTrue(auth.needs_setup)
        self.assertFalse(auth.verify_password(DEFAULT_PASSWORD))
        self.assertFalse(auth.set_password("short"))
        self.assertTrue(auth.set_password(PASSWORD))
        self.assertTrue(auth.verify_password(PASSWORD))

    def test_02_password_change(self):
        auth = self.auth()
        self.assertTrue(auth.change_password(PASSWORD, "UpdatedPassword2026!", "UpdatedPassword2026!")["success"])
        self.assertFalse(auth.verify_password(PASSWORD))
        self.assertTrue(auth.verify_password("UpdatedPassword2026!"))

    def test_03_password_confirmation_and_length(self):
        auth = self.auth()
        self.assertFalse(auth.change_password(PASSWORD, "UpdatedPassword2026!", "different")["success"])
        self.assertFalse(auth.change_password(PASSWORD, "short", "short")["success"])

    def test_04_lockout_survives_new_auth_instance(self):
        from elpati.elpati_auth_voice import ElpatiAuthVoice
        auth = self.auth()
        for _ in range(5):
            self.assertFalse(ElpatiAuthVoice().verify_password("incorrect"))
        self.assertTrue(ElpatiAuthVoice().is_locked())
        self.assertFalse(ElpatiAuthVoice().verify_password(PASSWORD))

    def test_05_corrupt_password_fails_closed(self):
        from elpati.elpati_auth_voice import ElpatiAuthVoice, DEFAULT_PASSWORD
        auth = self.auth()
        auth._pw_file.write_bytes(b"corrupt")
        before = auth._pw_file.read_bytes()
        restarted = ElpatiAuthVoice()
        self.assertFalse(restarted.verify_password(DEFAULT_PASSWORD))
        self.assertFalse(restarted.verify_password(PASSWORD))
        self.assertEqual(before, auth._pw_file.read_bytes())

    def test_06_missing_password_does_not_reset(self):
        from elpati.elpati_auth_voice import ElpatiAuthVoice
        auth = self.auth()
        auth._pw_file.unlink()
        self.assertFalse(ElpatiAuthVoice().needs_setup)
        self.assertFalse(ElpatiAuthVoice().set_password("AttackPassword2026!"))

    def test_07_authenticated_password_set_required(self):
        from elpati.elpati_auth_voice import ElpatiAuthVoice
        self.auth()
        self.assertFalse(ElpatiAuthVoice().set_password("AttackPassword2026!"))

    def test_08_encryption_roundtrip(self):
        from elpati.elpati_crypto import ElpatiCrypto
        crypto = ElpatiCrypto()
        for data in (b"", b"secret", bytes(range(256))):
            encrypted = crypto.encrypt(data)
            self.assertEqual(data, ElpatiCrypto().decrypt(encrypted))
            self.assertNotEqual(encrypted, crypto.encrypt(data))

    def test_09_ciphertext_tamper(self):
        from elpati.elpati_crypto import ElpatiCrypto
        crypto = ElpatiCrypto()
        ciphertext = crypto.encrypt(b"secret")
        raw = bytearray(base64.b64decode(ciphertext.split(b":", 1)[1]))
        raw[-1] ^= 1
        with self.assertRaises(Exception):
            crypto.decrypt(b"CYBEROS2:" + base64.b64encode(raw))

    def test_10_copied_salt_cannot_reconstruct_key(self):
        import elpati.elpati_crypto as mod
        first = mod.ElpatiCrypto()
        ciphertext = first.encrypt(b"private")
        second_dir = self.root / "second/keys"
        second_dir.mkdir(parents=True)
        (second_dir / "master.salt").write_bytes(os.urandom(32))
        with patch.object(mod, "KEYS_DIR", second_dir):
            with self.assertRaises(mod.KeyRecoveryRequired):
                mod.ElpatiCrypto()
            (second_dir / "master.salt").unlink()
            second = mod.ElpatiCrypto()
            with self.assertRaises(Exception):
                second.decrypt(ciphertext)

    def test_11_lost_key_fails_closed(self):
        from elpati.elpati_crypto import ElpatiCrypto, KEYS_DIR, KeyRecoveryRequired
        ElpatiCrypto()
        (KEYS_DIR / "master.key").unlink()
        with self.assertRaises(KeyRecoveryRequired):
            ElpatiCrypto()

    def test_12_corrupt_key_fails_closed(self):
        from elpati.elpati_crypto import ElpatiCrypto, KEYS_DIR, KeyRecoveryRequired
        ElpatiCrypto()
        (KEYS_DIR / "master.key").write_bytes(b"bad")
        with self.assertRaises(KeyRecoveryRequired):
            ElpatiCrypto()

    def test_13_rsa_sign_verify_restart(self):
        from elpati.elpati_crypto import ElpatiCrypto
        crypto = ElpatiCrypto()
        signature = crypto.sign(b"payload")
        self.assertTrue(ElpatiCrypto().verify(b"payload", signature))
        self.assertFalse(crypto.verify(b"changed", signature))

    def test_14_sha256_md5_and_sha3(self):
        crypto = self.engine().crypto
        payload = b"fixture"
        hashes = crypto.file_hashes(self.fixture(content=payload))
        self.assertEqual(hashlib.md5(payload).hexdigest(), hashes["md5"])
        self.assertEqual(hashlib.sha256(payload).hexdigest(), hashes["sha256"])
        self.assertEqual(hashlib.sha3_256(payload).hexdigest(), hashes["sha3_256"])

    def test_15_manifest_accepts_current_release(self):
        from core.security_vault import SecurityVault
        self.assertTrue(SecurityVault().verify_integrity())

    def test_16_manifest_detects_modified_source(self):
        from core.security_vault import SecurityVault
        path = ROOT / "core/config.py"
        original = path.read_bytes()
        try:
            vault = SecurityVault()
            path.write_bytes(original + b"\n# altered\n")
            self.assertFalse(vault.verify_integrity())
        finally:
            path.write_bytes(original)

    def test_17_manifest_detects_deleted_source(self):
        from core.security_vault import SecurityVault
        path = ROOT / "cli/__init__.py"
        original = path.read_bytes()
        try:
            path.unlink()
            self.assertFalse(SecurityVault().verify_integrity())
        finally:
            path.write_bytes(original)

    def test_18_manifest_detects_unlisted_source(self):
        from core.security_vault import SecurityVault
        path = ROOT / "core/extra_fixture.py"
        try:
            path.write_text("# fixture\n", encoding="utf-8")
            self.assertFalse(SecurityVault().verify_integrity())
        finally:
            path.unlink(missing_ok=True)

    def test_19_windows_manifest_paths(self):
        from core.security_vault import SecurityVault, INTEGRITY_DIR
        path = INTEGRITY_DIR / "manifest.json"
        original = path.read_bytes()
        try:
            content = json.loads(original)
            path.write_text(json.dumps({k.replace("/", "\\"): v for k, v in content.items()}), encoding="utf-8")
            self.assertTrue(SecurityVault().verify_integrity())
        finally:
            path.write_bytes(original)

    def test_20_corrupt_manifest_fails_closed(self):
        from core.security_vault import SecurityVault, INTEGRITY_DIR
        path = INTEGRITY_DIR / "manifest.json"
        original = path.read_bytes()
        try:
            path.write_text("{invalid", encoding="utf-8")
            self.assertFalse(SecurityVault().verify_integrity())
        finally:
            path.write_bytes(original)

    def test_21_missing_manifest_fails_closed(self):
        from core.security_vault import SecurityVault, INTEGRITY_DIR
        path = INTEGRITY_DIR / "manifest.json"
        original = path.read_bytes()
        try:
            path.unlink()
            self.assertFalse(SecurityVault().verify_integrity())
        finally:
            path.write_bytes(original)

    def test_22_evidence_roundtrip_hash(self):
        from core.security_vault import SecurityVault
        vault = SecurityVault()
        path = Path(vault.store_evidence("fixture", b"evidence"))
        self.assertEqual(b"evidence", vault.retrieve_evidence(path.name))
        self.assertTrue(vault.verify_integrity())

    def test_23_evidence_path_traversal_rejected(self):
        from core.security_vault import SecurityVault
        vault = SecurityVault()
        for name in ("../../main.py", "../secret", "sub\\secret"):
            with self.assertRaises(ValueError):
                vault.retrieve_evidence(name)

    def test_24_evidence_unique_ids(self):
        from core.security_vault import SecurityVault
        vault = SecurityVault()
        one = vault.store_evidence("../../same", b"first")
        two = vault.store_evidence("../../same", b"second")
        self.assertNotEqual(one, two)
        self.assertEqual(b"first", vault.retrieve_evidence(Path(one).name))

    def test_25_quarantine_roundtrip(self):
        from quarantine.quarantine_manager import QuarantineManager
        manager = QuarantineManager()
        file = self.fixture()
        original = file.read_bytes()
        stored = manager.quarantine_file(str(file), {})
        self.assertTrue(stored["success"], stored)
        self.assertFalse(file.exists())
        self.assertTrue(manager.restore_file(stored["quarantine_id"])["success"])
        self.assertEqual(original, file.read_bytes())

    def test_26_quarantine_same_filename_collision(self):
        from quarantine.quarantine_manager import QuarantineManager
        manager = QuarantineManager()
        one = manager.quarantine_file(str(self.fixture("left/same.txt", b"first")), {})
        two = manager.quarantine_file(str(self.fixture("right/same.txt", b"second")), {})
        self.assertNotEqual(one["quarantine_id"], two["quarantine_id"])
        dest = self.root / "restore.txt"
        self.assertTrue(manager.restore_file(one["quarantine_id"], dest)["success"])
        self.assertEqual(b"first", dest.read_bytes())

    def test_27_quarantine_restore_no_overwrite(self):
        from quarantine.quarantine_manager import QuarantineManager
        manager = QuarantineManager()
        file = self.fixture()
        stored = manager.quarantine_file(str(file), {})
        file.write_bytes(b"keep new data")
        self.assertFalse(manager.restore_file(stored["quarantine_id"])["success"])
        self.assertEqual(b"keep new data", file.read_bytes())

    def test_28_quarantine_corrupt_payload_preserved(self):
        from quarantine.quarantine_manager import QuarantineManager, QUARANTINE_DIR
        manager = QuarantineManager()
        file = self.fixture()
        stored = manager.quarantine_file(str(file), {})
        (QUARANTINE_DIR / stored["quarantine_id"]).write_bytes(b"corrupt")
        self.assertFalse(manager.restore_file(stored["quarantine_id"])["success"])
        self.assertFalse(file.exists())

    def test_29_quarantine_corrupt_index_fails_closed(self):
        from quarantine.quarantine_manager import QuarantineManager, QUARANTINE_INDEX
        QUARANTINE_INDEX.parent.mkdir(parents=True, exist_ok=True)
        QUARANTINE_INDEX.write_text("{invalid", encoding="utf-8")
        file = self.fixture()
        with self.assertRaises(ValueError):
            QuarantineManager()
        self.assertTrue(file.exists())

    def test_30_quarantine_delete_and_missing_file(self):
        from quarantine.quarantine_manager import QuarantineManager
        manager = QuarantineManager()
        self.assertFalse(manager.quarantine_file(str(self.root / "missing"), {})["success"])
        stored = manager.quarantine_file(str(self.fixture()), {})
        self.assertTrue(manager.delete_quarantined(stored["quarantine_id"])["success"])
        self.assertEqual(0, manager.get_stats()["total"])

    def test_31_quarantine_two_instances(self):
        from quarantine.quarantine_manager import QuarantineManager
        one, two = QuarantineManager(), QuarantineManager()
        self.assertTrue(one.quarantine_file(str(self.fixture("a.txt")), {})["success"])
        self.assertTrue(two.quarantine_file(str(self.fixture("b.txt")), {})["success"])
        self.assertEqual(2, one.get_stats()["active"])

    def test_32_clean_file_scan(self):
        self.assertIsNone(self.engine()._scan_file(str(self.fixture())))

    def test_33_eicar_real_file_signature(self):
        payload = b"X5O!P%@AP[4" + b"\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        engine = self.engine()
        expected_path = self.root / "standard-test.com"
        try:
            file = self.fixture("standard-test.com", payload)
            result = engine._scan_file(str(file))
        except OSError as error:
            if not eicar_fixture_unavailable(error, expected_path):
                raise
            # A generic filesystem problem must remain an error, not a skip.
            benign = b"Harmless Windows fixture I/O control.\n"
            control = self.fixture("standard-control.com", benign)
            self.assertEqual(benign, control.read_bytes())
            self.skipTest(
                "EICAR disque inaccessible sous Windows "
                f"(errno={error.errno}, winerror={getattr(error, 'winerror', None)}); "
                "controle de lecture ordinaire reussi. Interception antivirus possible, non confirmee. "
                "Detection disque non validee; detection du flux testee separement. "
                "Ne pas desactiver l'antivirus."
            )
        self.assertIsNotNone(result)
        self.assertEqual("KNOWN_MALWARE", result["type"])

    def test_33b_eicar_signature_stream_without_disk_payload(self):
        """Exercise the real hashing/scanning code with a controlled byte stream."""
        payload = b"X5O!P%@AP[4" + b"\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        engine = self.engine()
        file = self.fixture("memory-signature-control.com", b"Harmless on-disk control\n")
        real_open = open
        expected = os.path.normcase(os.path.abspath(file))

        def read_fixture(path, mode="r", *args, **kwargs):
            if not isinstance(path, int) and os.path.normcase(os.path.abspath(path)) == expected:
                self.assertEqual("rb", mode)
                return io.BytesIO(payload)
            return real_open(path, mode, *args, **kwargs)

        with patch("builtins.open", side_effect=read_fixture):
            result = engine._scan_file(str(file))
        self.assertIsNotNone(result)
        self.assertEqual("KNOWN_MALWARE", result["type"])
        self.assertEqual(hashlib.sha256(payload).hexdigest(), result["hash"])
        self.assertEqual(b"Harmless on-disk control\n", file.read_bytes())

    def test_34_custom_hash_all_algorithms(self):
        from elpati.elpati_threat_intel import ElpatiThreatIntel
        engine = self.engine()
        file = self.fixture()
        hashes = engine.crypto.file_hashes(file)
        for algorithm in hashes:
            engine.ti._custom = {"hashes": [{"hash": hashes[algorithm]}], "strings": [], "rules": []}
            self.assertEqual("KNOWN_MALWARE", engine._scan_file(str(file))["type"])

    def test_35_custom_signature_persists(self):
        from elpati.elpati_threat_intel import ElpatiThreatIntel
        file = self.fixture()
        engine = self.engine()
        digest = engine.crypto.hash_file(file)
        engine.ti.add_custom_hash(digest, "fixture")
        self.assertTrue(ElpatiThreatIntel().check_hash(digest)["detected"])
        self.assertEqual("KNOWN_MALWARE", engine._scan_file(str(file))["type"])

    def test_36_ransomware_extension_and_custom_signature(self):
        engine = self.engine()
        self.fixture("locked.locked")
        clean = self.fixture("clean.txt")
        engine.ti.add_custom_hash(engine.crypto.hash_file(clean), "fixture")
        result = engine.full_scan(str(self.root))
        self.assertEqual(2, result["threats_found"])
        self.assertEqual(0, result["errors"])

    def test_37_scan_progress_and_duplicates(self):
        engine = self.engine()
        self.fixture("a.txt")
        self.fixture("b.txt")
        updates = []
        result = engine._run_scan([str(self.root), str(self.root)], "TEST", updates.append)
        self.assertEqual(2, result["files_scanned"])
        self.assertTrue(updates)
        self.assertFalse(engine.is_running())

    def test_38_scan_failure_counted(self):
        engine = self.engine()
        self.fixture()
        with patch.object(engine, "_scan_file", side_effect=PermissionError("denied")):
            result = engine.full_scan(str(self.root))
        self.assertEqual(1, result["errors"])
        self.assertEqual(1, result["files_scanned"])
        self.assertFalse(engine.is_running())

    def test_39_scan_stop_cancels_pending_work(self):
        engine = self.engine()
        for i in range(100):
            self.fixture(str(i)+".txt")
        result = engine.full_scan(str(self.root), callback=lambda _: engine.stop_scan())
        self.assertTrue(result["cancelled"])
        self.assertLess(result["files_scanned"], result["total_files"])
        self.assertFalse(engine.is_running())

    def test_40_scan_recovers_after_exception(self):
        engine = self.engine()
        with patch.object(engine, "_walk_files", side_effect=RuntimeError("fixture")):
            with self.assertRaises(RuntimeError):
                engine.full_scan(str(self.root))
        self.assertFalse(engine.is_running())
        self.assertEqual(0, engine.full_scan(str(self.root))["files_scanned"])

    def test_41_empty_process_name_not_malicious(self):
        from elpati.elpati_threat_intel import ElpatiThreatIntel
        ti = ElpatiThreatIntel()
        for name in ("", "a", "python", None):
            self.assertFalse(ti.check_process_name(name)["detected"])

    def test_42_ai_boolean_indicators_have_full_weight(self):
        from elpati.elpati_ai_analyzer import ElpatiAIAnalyzer
        ai = ElpatiAIAnalyzer()
        self.assertEqual(100, ai.calculate_threat_score({"known_malware_hash": True})["score"])
        self.assertEqual(0, ai.calculate_threat_score({"known_malware_hash": False})["score"])

    def test_43_local_ai_preserves_module_score(self):
        from core.ai_core import AICore
        ai = AICore()
        self.assertEqual(85, ai.analyze_threat({"local_score": 85})["score"])
        self.assertEqual(100, ai.analyze_threat({"indicators": {"known_malware": True}})["score"])

    def test_44_remote_api_disabled_by_default(self):
        from core.ai_core import AICore
        (ROOT / "config.env").write_text("ANTHROPIC_API_KEY=fixture-not-real\n", encoding="utf-8")
        with patch("urllib.request.urlopen", side_effect=AssertionError("No requests permitted")) as call:
            ai = AICore()
            self.assertEqual("LOCAL_AI", ai.analyze_threat({"local_score": 10})["source"])
            call.assert_not_called()

    def test_45_remote_failure_falls_back(self):
        from core.ai_core import AICore
        (ROOT / "config.env").write_text("ANTHROPIC_API_KEY=fixture-not-real\nAI_REMOTE_ENABLED=true\nANTHROPIC_MODEL=fixture-model\n", encoding="utf-8")
        with patch("urllib.request.urlopen", side_effect=OSError("offline")):
            result = AICore().analyze_threat({"local_score": 90})
        self.assertEqual(90, result["score"])
        self.assertEqual("LOCAL_AI", result["source"])

    def test_46_log_genesis_and_later_tamper(self):
        from elpati.elpati_log import ElpatiLog
        log = ElpatiLog()
        log.info("first")
        log.info("second")
        self.assertTrue(log.verify_chain()[0])
        log._chain[0]["msg"] = "modified"
        self.assertFalse(log.verify_chain()[0])

    def test_47_log_restart_keeps_entries(self):
        from elpati.elpati_log import ElpatiLog
        log = ElpatiLog()
        log.info("durable")
        ElpatiLog._instance = None
        new = ElpatiLog()
        self.assertTrue(new.verify_chain()[0])
        self.assertEqual("durable", new.get_recent(1)[0]["msg"])

    def test_48_log_corruption_not_reset(self):
        from elpati.elpati_log import ElpatiLog, LOGS_DIR
        (LOGS_DIR / "chain.json").write_text("{invalid", encoding="utf-8")
        log = ElpatiLog()
        self.assertFalse(log.verify_chain()[0])
        log.info("must not erase damaged history")
        self.assertEqual("{invalid", log.chain_file.read_text(encoding="utf-8"))

    def test_49_license_sign_verify(self):
        pay, key = self.license()
        self.assertTrue(pay.validate_key(key)["valid"])
        parts = key.split(".")
        raw = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        raw["tier"] = "ENTERPRISE"
        parts[1] = base64.urlsafe_b64encode(json.dumps(raw).encode()).rstrip(b"=").decode()
        self.assertFalse(pay.validate_key(".".join(parts))["valid"])

    def test_50_license_expired_rejected(self):
        pay, key = self.license(now=datetime.now(timezone.utc)-timedelta(days=5))
        self.assertFalse(pay.validate_key(key)["valid"])

    def test_51_license_activation_restart(self):
        from elpati.elpati_payment import ElpatiPayment
        pay, key = self.license("ENTERPRISE")
        self.assertTrue(pay.activate(key)["success"])
        self.assertEqual("ENTERPRISE", ElpatiPayment().get_tier())

    def test_52_license_renewal_does_not_extend_expiry(self):
        pay, key = self.license()
        first = pay.activate(key)
        second = pay.activate(key)
        self.assertEqual(first["expires"], second["expires"])

    def test_53_license_machine_binding(self):
        pay, key = self.license(machine_id="another-machine")
        self.assertFalse(pay.validate_key(key)["valid"])

    def test_54_license_client_cannot_issue(self):
        from elpati.elpati_payment import ElpatiPayment
        with self.assertRaises(PermissionError):
            ElpatiPayment().generate_key("ENTERPRISE")

    def test_55_license_tampered_local_state_rejected(self):
        pay, key = self.license()
        pay.activate(key)
        pay._current["expires"] = "2999-01-01T00:00:00+00:00"
        self.assertFalse(pay.is_valid())
        self.assertEqual("FREE", pay.get_tier())

    def test_56_license_missing_public_key(self):
        from elpati.elpati_payment import PUBLIC_KEY_FILE
        pay, key = self.license()
        PUBLIC_KEY_FILE.unlink()
        self.assertFalse(pay.validate_key(key)["valid"])

    def test_57_forensic_json_vault_and_canonical_hash(self):
        from forensic.forensic_engine import ForensicEngine
        engine = ForensicEngine()
        with patch.object(engine, "collect_system_snapshot", return_value={"fixture": True}):
            path = Path(engine.generate_report("../../test"))
        self.assertEqual((ROOT / "reports/forensic").resolve(), path.parent.resolve())
        data = json.loads(path.read_text(encoding="utf-8"))
        expected = data["chain_of_custody"].pop("report_hash")
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
        self.assertEqual(expected, hashlib.sha256(canonical.encode()).hexdigest())
        evidence = engine.vault.retrieve_evidence(engine.vault.list_evidence()[-1])
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), json.loads(evidence))

    def test_58_pdf_url_and_scan_reports(self):
        from reports.pdf_generator import PDFReportGenerator
        generator = PDFReportGenerator()
        paths = [generator.generate_url_report({"url": "https://example.invalid/?a=<x>&b=é",
                                                "checks": {"payload": "<b>fixture</b>"}}),
                 generator.generate_scan_report({"files_scanned": 3, "threats": [], "errors": 0})]
        for path in paths:
            raw = Path(path).read_bytes()
            self.assertTrue(raw.startswith(b"%PDF-"))
            self.assertGreater(len(raw), 1000)

    def test_59_pdf_general_report(self):
        from reports.pdf_generator import PDFReportGenerator
        from elpati.elpati_log import ElpatiLog
        controller = SimpleNamespace(get_system_status=lambda: {"status": "fixture"},
                                     _modules={}, log=ElpatiLog())
        path = PDFReportGenerator().generate_evening_report(controller)
        self.assertTrue(Path(path).read_bytes().startswith(b"%PDF-"))

    def test_60_scheduler_day_filter_and_unique_ids(self):
        from elpati.elpati_scheduler import ElpatiScheduler
        scheduler = ElpatiScheduler()
        friday = datetime(2026, 10, 23, 23, 0)
        self.assertEqual(0, datetime.fromisoformat(scheduler._calc_next(9, 0, "weekdays", friday)).weekday())
        self.assertEqual(5, datetime.fromisoformat(scheduler._calc_next(9, 0, "weekends", friday)).weekday())
        self.assertNotEqual(scheduler.add_task("a", "quick_scan", 10),
                            scheduler.add_task("b", "quick_scan", 10))

    def test_61_scheduler_due_once(self):
        from elpati.elpati_scheduler import ElpatiScheduler
        scheduler = ElpatiScheduler()
        scheduler.add_task("test", "quick_scan", 10)
        scheduler._schedules["tasks"][0]["next_run"] = "2000-01-01T00:00:00"
        events = []
        scheduler.register_callback(events.append)
        scheduler._run_due()
        scheduler._run_due()
        self.assertEqual(1, len(events))

    def test_62_scheduler_validation(self):
        from elpati.elpati_scheduler import ElpatiScheduler
        scheduler = ElpatiScheduler()
        for hour, minute, days in [(24, 0, "daily"), (10, 60, "daily"), (10, 0, "invalid")]:
            with self.assertRaises(ValueError):
                scheduler.add_task("bad", "quick_scan", hour, minute, days)

    def test_63_fim_detects_modification_and_deletion(self):
        from elpati.elpati_integrity import ElpatiIntegrity
        file = self.fixture()
        fim = ElpatiIntegrity()
        fim.create_baseline([str(file)])
        file.write_bytes(b"changed")
        self.assertEqual("MODIFIED", fim.check_integrity()[0]["type"])
        fim.create_baseline([str(file)])  # A restart must not bless the changed bytes.
        self.assertEqual("MODIFIED", fim.check_integrity()[0]["type"])
        file.unlink()
        self.assertEqual("DELETED", fim.check_integrity()[0]["type"])

    def test_64_ransomguard_honeypot_entropy(self):
        from elpati.elpati_ransom_guard import ElpatiRansomGuard
        guard = ElpatiRansomGuard()
        guard.deploy_honeypots(1)
        alerts = []
        guard.register_alert_callback(alerts.append)
        Path(guard._honeypot_files[0]).write_bytes(b"changed")
        guard._check_honeypots()
        self.assertEqual(1, len(alerts))
        self.assertEqual(8.0, guard.calculate_entropy(bytes(range(256))))
        self.assertEqual(0.0, guard.calculate_entropy(b"AAAA"))

    def test_65_auto_response_disabled_and_unsupported_truthful(self):
        from elpati.elpati_autoresponse import ElpatiAutoResponse
        response = ElpatiAutoResponse()
        self.assertFalse(response.process_alert({"score": 100})["processed"])
        response.enable()
        self.assertTrue(response.process_alert({"score": 70, "message": "fixture"})["processed"])
        self.assertIn("non effectuée", response._execute_action("not-implemented", {}, None))

    def test_66_shield_passive_and_protected_pid(self):
        from elpati.elpati_shield import ElpatiShield
        shield = ElpatiShield()
        with patch("psutil.Process", side_effect=AssertionError("no process mutation")):
            self.assertEqual("skipped", shield.kill_process(9999)["action"])
            self.assertEqual("skipped", shield.isolate_process(9999)["action"])
            shield.set_protection_level("ACTIVE")
            self.assertEqual("denied", shield.kill_process(os.getpid())["action"])
            self.assertEqual("denied", shield.isolate_process(1)["action"])

    def test_67_firewall_invalid_input_and_failure(self):
        from elpati.elpati_shield import ElpatiShield
        shield = ElpatiShield()
        shield.set_protection_level("ACTIVE")
        self.assertEqual("failed", shield.block_network_ip("1.2.3.4;bad")["action"])
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=1)):
            self.assertEqual("failed", shield.block_network_ip("192.0.2.1")["action"])

    def test_68_network_guard_alert_callback(self):
        from elpati.elpati_network_guard import ElpatiNetworkGuard
        guard = ElpatiNetworkGuard()
        events = []
        guard.register_alert_callback(events.append)
        guard._fire_alert("HIGH", "fixture", 80)
        self.assertEqual(1, len(events))

    def test_69_url_parser_rejects_unsafe_schemes(self):
        from elpati.elpati_url_scanner import ElpatiURLScanner
        scanner = ElpatiURLScanner()
        for url in ("", "file:///etc/passwd", "javascript:alert(1)", "https://user:pass@example.com/",
                    "https://example.com:99999", "https://bad host/"):
            self.assertEqual("", scanner._normalize_url(url), url)
        self.assertEqual("example.com", scanner._extract_domain("https://www.example.com:8443/path"))
        self.assertEqual("::1", scanner._extract_domain("http://[::1]:1234/"))

    def test_70_url_blacklist_not_diluted(self):
        from elpati.elpati_url_scanner import ElpatiURLScanner
        score, _ = ElpatiURLScanner()._calculate_score(
            {"blacklist": {"score": 100, "findings": ["known malicious"]}}, "example.com", "https://example.com/")
        self.assertEqual(100, score)

    def test_71_url_offline_is_inconclusive(self):
        from elpati.elpati_url_scanner import ElpatiURLScanner
        scanner = ElpatiURLScanner()
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("offline")), \
             patch("socket.gethostbyname", side_effect=socket.gaierror("offline")), \
             patch("socket.create_connection", side_effect=OSError("offline")), \
             patch("urllib.request.urlopen", side_effect=OSError("offline")), \
             patch("urllib.request.OpenerDirector.open", side_effect=OSError("offline")):
            result = scanner.scan_url("https://example.invalid", use_ai=False)
        self.assertTrue(result["incomplete"])
        self.assertIn("INCONCLUSIF", result["verdict"])

    def test_72_url_local_http_redirect_and_content(self):
        from elpati.elpati_url_scanner import ElpatiURLScanner
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                if self.path == "/start":
                    self.send_response(302)
                    self.send_header("Location", "/final")
                else:
                    self.send_response(200)
                self.end_headers()
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"<html><title>Fixture</title><p>Hello</p></html>")
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            scanner = ElpatiURLScanner()
            url = f"http://127.0.0.1:{server.server_port}/start"
            result = scanner._check_redirects(url)
            self.assertEqual(1, result["redirect_count"])
            self.assertTrue(result["chain"][-1].endswith("/final"))
            content = scanner._check_content(url)
            self.assertTrue(content["reachable"])
            self.assertEqual("Fixture", content["page_title"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_73_assistant_local_respects_remote_opt_in(self):
        from elpati.elpati_assistant import ElpatiAssistant
        (ROOT / "config.env").write_text("ANTHROPIC_API_KEY=fixture-not-real\n", encoding="utf-8")
        with patch("urllib.request.urlopen", side_effect=AssertionError("No requests")):
            result = ElpatiAssistant().chat("Bonjour")
        self.assertTrue(result["response"])
        self.assertEqual("local", result["mode"])

    def test_74_module_initialization_and_shutdown(self):
        from core.controller import CentralController
        controller = CentralController()
        controller.initialize_all_modules()
        first = controller._modules["engine"]
        controller.initialize_all_modules()
        self.assertIs(first, controller._modules["engine"])
        self.assertEqual(18, len(controller._modules))
        controller.start_protection()
        controller.stop_protection()
        self.assertFalse(controller._protection_active)
        self.assertFalse(controller._modules["scheduler"]._active)
        self.assertFalse(controller._modules["integrity"]._active)

    def test_75_cli_all_menu_routes(self):
        from core.controller import CentralController
        from elpati.elpati_auth_voice import ElpatiAuthVoice
        controller = CentralController()
        controller.auth.set_password(PASSWORD)
        controller.initialize_all_modules()
        calls = []
        summary = {"files_scanned": 0, "threats_found": 0, "duration_sec": 0}
        routes = ["1", "2", str(self.root), "3", "4", "5", "6", "7", "8", "l",
                  "9", str(self.fixture()), "10", str(self.fixture()), "11", "12", "invalid",
                  "14", "invalid url", "15", "0"]
        with patch("getpass.getpass", return_value=PASSWORD), patch("builtins.input", side_effect=routes), \
             patch.object(controller, "run_quick_scan", side_effect=lambda **k: calls.append("quick") or summary), \
             patch.object(controller, "run_full_scan", side_effect=lambda **k: calls.append("full") or summary), \
             patch.object(controller._modules["engine"], "scan_processes", return_value=[]), \
             patch.object(controller._modules["memory_scan"], "scan_all_processes", return_value=[]), \
             patch.object(controller._modules["network_guard"], "get_active_connections", return_value=[]), \
             patch.object(controller._modules["forensic"], "generate_report", return_value="fixture.json"), \
             patch.object(controller._modules["vuln_scan"], "run_full_scan", return_value={}), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            controller.run_cli()
        self.assertEqual(["quick", "full"], calls)
        self.assertNotIn("[ERREUR]", output.getvalue().replace('"error"', ""))

    def test_76_main_check_and_source_unchanged(self):
        result = subprocess.run([sys.executable, str(ROOT/"main.py"), "--check"],
                                cwd=self.root, capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("[OK]", result.stdout)

    def test_77_instance_lock_exclusive(self):
        from utils.instance_lock import InstanceLock
        path = self.root / "lock"
        with InstanceLock(path):
            with self.assertRaises(RuntimeError):
                with InstanceLock(path):
                    pass

    def test_78_legacy_migration_preserves_data(self):
        from tools.migrate_legacy import migrate, LEGACY_PASSWORD
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from elpati.elpati_crypto import KEYS_DIR, ElpatiCrypto
        salt = os.urandom(32)
        (KEYS_DIR / "master.salt").write_bytes(salt)
        key = hashlib.pbkdf2_hmac("sha256", LEGACY_PASSWORD, salt, 600000)
        auth = ROOT / "security/auth/password.enc"
        nonce = os.urandom(12)
        old = base64.b64encode(nonce + AESGCM(key).encrypt(nonce, b"legacy fixture", None))
        auth.write_bytes(old)
        result = migrate(ROOT)
        self.assertEqual(1, result["converted"])
        self.assertEqual(b"legacy fixture", ElpatiCrypto().decrypt(auth.read_bytes()))
        self.assertEqual(old, (Path(result["backup"])/"security/auth/password.enc").read_bytes())

    def test_79_legacy_corruption_aborts_without_key(self):
        from tools.migrate_legacy import migrate
        from elpati.elpati_crypto import KEYS_DIR
        (KEYS_DIR / "master.salt").write_bytes(os.urandom(32))
        path = ROOT / "security/auth/password.enc"
        path.write_bytes(b"broken data")
        with self.assertRaises(ValueError):
            migrate(ROOT)
        self.assertEqual(b"broken data", path.read_bytes())
        self.assertFalse((KEYS_DIR / "master.key").exists())

    def test_80_migration_rollback_after_interrupted_commit(self):
        from tools.migrate_legacy import migrate, rollback, LEGACY_PASSWORD
        from elpati.elpati_crypto import KEYS_DIR, ElpatiCrypto, KeyRecoveryRequired
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from utils.storage import atomic_write
        salt = os.urandom(32)
        (KEYS_DIR / "master.salt").write_bytes(salt)
        old_key = hashlib.pbkdf2_hmac("sha256", LEGACY_PASSWORD, salt, 600000)
        nonce = os.urandom(12)
        old = base64.b64encode(nonce + AESGCM(old_key).encrypt(nonce, b"fixture", None))
        path = ROOT / "security/auth/password.enc"
        path.write_bytes(old)
        def fail_new_key(target, value, **kwargs):
            if Path(target) == KEYS_DIR / "master.key":
                raise OSError("simulated disk failure")
            return atomic_write(target, value, **kwargs)
        with patch("tools.migrate_legacy.atomic_write", side_effect=fail_new_key):
            with self.assertRaises(OSError):
                migrate(ROOT)
        self.assertEqual(old, path.read_bytes())
        self.assertFalse((KEYS_DIR / "master.key").exists())
        self.assertFalse((ROOT / "security/migration_in_progress.json").exists())

    def test_81_sandbox_is_static_and_benign_signature(self):
        from sandbox.malware_lab import MalwareLab
        file = self.fixture("fixture.py", b"print('hello')\n")
        with patch("subprocess.Popen", side_effect=AssertionError("Never execute analyzed file")):
            result = MalwareLab().analyze_file(str(file))
        self.assertIn("overall_score", result)

    def test_82_memory_metadata_with_string_address(self):
        from elpati.elpati_memory_scan import ElpatiMemoryScan
        process = SimpleNamespace(name=lambda: "fixture",
            memory_maps=lambda grouped=False: [SimpleNamespace(path="", perms="rwxp", addr="1000-2000", size=4096)])
        with patch("psutil.Process", return_value=process), \
             patch.object(ElpatiMemoryScan, "_scan_linux_process_memory", return_value={"score":0,"findings":[]}):
            result = ElpatiMemoryScan().scan_process_memory(1234)
        self.assertNotIn("error", result)
        self.assertEqual("1000-2000", result["findings"][0]["addr"])

    def test_83_cli_startup_in_separate_process(self):
        from elpati.elpati_auth_voice import ElpatiAuthVoice
        self.auth()
        code = ("import sys,builtins,getpass;sys.path.insert(0," + repr(str(ROOT)) + ");"
                "getpass.getpass=lambda *a,**k:" + repr(PASSWORD) + ";"
                "builtins.input=lambda *a,**k:'0';"
                "sys.argv=['main.py','--cli'];import main;raise SystemExit(main.main())")
        result = subprocess.run([sys.executable, "-c", code], cwd=self.root,
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("Scan complet", result.stdout)

    def test_84_quarantine_metadata_write_failure_keeps_original(self):
        from quarantine.quarantine_manager import QuarantineManager
        manager = QuarantineManager()
        file = self.fixture()
        original = file.read_bytes()
        with patch.object(manager, "_save_index", side_effect=OSError("disk full")):
            result = manager.quarantine_file(str(file), {})
        self.assertFalse(result["success"])
        self.assertEqual(original, file.read_bytes())

    def test_85_quarantine_parallel_operations(self):
        from concurrent.futures import ThreadPoolExecutor
        from quarantine.quarantine_manager import QuarantineManager
        manager = QuarantineManager()
        files = [self.fixture(f"parallel/{i}/same.txt", str(i).encode()) for i in range(8)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda file: manager.quarantine_file(str(file), {}), files))
        self.assertTrue(all(r["success"] for r in results), results)
        self.assertEqual(8, manager.get_stats()["active"])
        self.assertEqual(8, len({r["quarantine_id"] for r in results}))

    def test_86_native_shield_command_results_are_reported(self):
        from elpati.elpati_shield import ElpatiShield
        shield = ElpatiShield()
        shield.set_protection_level("ACTIVE")
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=0)) as call:
            self.assertEqual("blocked", shield.block_network_ip("192.0.2.1")["action"])
            args = call.call_args.args[0]
            self.assertEqual("netsh" if os.name == "nt" else "iptables", args[0])
            self.assertEqual("unblocked", shield.block_network_ip("192.0.2.1", unblock=True)["action"])

    def test_87_url_cache_returns_independent_snapshot(self):
        from elpati.elpati_url_scanner import ElpatiURLScanner
        scanner = ElpatiURLScanner()
        url = scanner._normalize_url("https://example.invalid")
        key = hashlib.md5(url.encode()).hexdigest()
        scanner._cache[key] = {"url": url, "score": 10, "_cached_at": time.time(), "checks": {}}
        result = scanner.scan_url(url, use_ai=False)
        result["score"] = 100
        self.assertEqual(10, scanner._cache[key]["score"])

    def test_88_python_310_grammar(self):
        import ast
        from core.security_vault import source_files
        for name, file in source_files().items():
            with self.subTest(file=name):
                ast.parse(file.read_text(encoding="utf-8"), feature_version=(3, 10))

    def test_89_lost_rsa_private_key_requires_recovery(self):
        from elpati.elpati_crypto import ElpatiCrypto, KEYS_DIR, KeyRecoveryRequired
        crypto = ElpatiCrypto()
        crypto.sign(b"fixture")
        (KEYS_DIR / "rsa_private.enc").unlink()
        with self.assertRaises(KeyRecoveryRequired):
            ElpatiCrypto().sign(b"fixture")

    def test_90_current_auto_protect_setting_applied(self):
        from core.controller import CentralController
        controller = CentralController()
        controller.initialize_all_modules()
        self.assertEqual("PASSIVE", controller._modules["shield"].get_status()["protection_level"])
        controller.config.set("auto_protect", True)
        controller._on_alert({"score": 90, "severity": "HIGH", "message": "fixture", "pid": None})
        self.assertEqual("ACTIVE", controller._modules["shield"].get_status()["protection_level"])
        controller.config.set("auto_protect", False)
        controller._on_alert({"score": 90, "severity": "HIGH", "message": "fixture", "pid": None})
        self.assertEqual("PASSIVE", controller._modules["shield"].get_status()["protection_level"])


    def test_91_eicar_fixture_io_classification_is_conservative(self):
        path = self.root / "standard-test.com"
        for code in (errno.EINVAL, errno.ENOENT, errno.EACCES, errno.EPERM):
            error = OSError(code, "fixture I/O", str(path))
            self.assertTrue(eicar_fixture_unavailable(error, path, windows=True))
            self.assertFalse(eicar_fixture_unavailable(error, path, windows=False))
        self.assertFalse(eicar_fixture_unavailable(OSError(errno.EIO, "disk error", str(path)), path, windows=True))
        self.assertFalse(eicar_fixture_unavailable(OSError(errno.EINVAL, "other file", str(self.root / "other.com")), path, windows=True))
        self.assertFalse(eicar_fixture_unavailable(OSError(errno.EINVAL, "missing filename"), path, windows=True))
        self.assertFalse(eicar_fixture_unavailable(ValueError("not an I/O error"), path, windows=True))

    def test_92_eicar_fixture_interruption_is_not_a_detection_success(self):
        """Reproduce the supplied Windows errno 22 without relying on an AV."""
        path = self.root / "standard-test.com"
        error = OSError(errno.EINVAL, "Invalid argument", str(path))
        engine = self.engine()
        original_fixture = self.fixture
        original_classifier = eicar_fixture_unavailable

        def benign_fixture(name, content=b"Harmless control\n"):
            return original_fixture(name, b"Harmless simulated fixture\n" if name == "standard-test.com" else content)

        with patch.object(self, "engine", return_value=engine), \
             patch.object(self, "fixture", side_effect=benign_fixture), \
             patch.object(engine, "_scan_file", side_effect=error), \
             patch(__name__ + ".eicar_fixture_unavailable",
                   side_effect=lambda exc, target: original_classifier(exc, target, windows=True)):
            with self.assertRaises(unittest.SkipTest) as observed:
                self.test_33_eicar_real_file_signature()
            self.assertIn("Detection disque non validee", str(observed.exception))

    def test_93_common_windows_imports_do_not_identify_malware(self):
        engine = self.engine()
        sample = b"MZ harmless import-name fixture\0GetProcAddress\0LoadLibraryA\0IsDebuggerPresent\0WSAStartup"
        self.assertIsNone(engine._scan_file(str(self.fixture("AppData/ordinary.dll", sample))))

    def test_94_security_source_literals_are_not_executed_commands(self):
        sample = (b'RULES = ["VirtualAllocEx WriteProcessMemory CreateRemoteThread", '
                  b'"lsass.exe", "vssadmin delete shadows", "GetProcAddress"]\n')
        self.assertIsNone(self.engine()._scan_file(str(self.fixture("security_rules.py", sample))))

    def test_95_hash_matches_survive_ordinary_names_and_encrypted_extensions(self):
        engine = self.engine()
        sample = b"Harmless owner-provided signature control\n"
        engine.ti.add_custom_hash(hashlib.sha256(sample).hexdigest(), "control")
        for name in ("AppData/library.dll", "password.enc", "elpati_rules.py"):
            result = engine._scan_file(str(self.fixture(name, sample)))
            self.assertEqual("KNOWN_MALWARE", result["type"])
            self.assertTrue(result["confirmed"])

    def test_96_generic_encrypted_extension_is_not_a_ransomware_verdict(self):
        engine = self.engine()
        for ext in ("enc", "crypt", "encrypted", "vault"):
            self.assertIsNone(engine._scan_file(str(self.fixture("ordinary." + ext))))
        result = engine._scan_file(str(self.fixture("document.locky")))
        self.assertTrue(result["review_required"])
        self.assertFalse(result["confirmed"])
        self.assertFalse(result["threat"])

    def test_97_high_entropy_alone_is_not_malware(self):
        sample = b"MZ" + bytes(range(256)) * 300
        engine = self.engine()
        file = self.fixture("AppData/compressed-resource.dll", sample)
        observed = engine.ai.analyze_file_heuristic(str(file))
        self.assertGreater(observed["sample_entropy"], 7.2)
        self.assertFalse(observed["review_required"])
        self.assertIsNone(engine._scan_file(str(file)))

    def test_98_static_command_requires_review_without_confirmed_infection(self):
        engine = self.engine()
        file = self.fixture("review.ps1", b"vssadmin delete shadows /all /quiet\n")
        result = engine.full_scan(str(self.root))
        self.assertEqual(1, result["threats_found"])
        self.assertEqual(0, result["confirmed_threats"])
        self.assertEqual(1, result["review_count"])
        finding = result["threats"][0]
        self.assertEqual(str(file), finding["path"])
        self.assertFalse(finding["threat"])
        self.assertTrue(finding["review_required"])

    def test_99_auto_quarantine_rejects_unconfirmed_static_alerts(self):
        from core.controller import CentralController
        controller = CentralController()
        controller.initialize_all_modules()
        controller.config.set("auto_quarantine", True)
        file = self.fixture()
        review = {"path": str(file), "type": "HEURISTIC_ALERT", "score": 95,
                  "confirmed": False, "review_required": True}
        known = {"path": str(file), "type": "KNOWN_MALWARE", "score": 100, "confirmed": True}
        manager = controller._modules["quarantine"]
        with patch.object(manager, "quarantine_file", return_value={"success": True}) as action:
            controller._post_process_scan({"threats": [review]})
            action.assert_not_called()
            self.assertEqual(["INVESTIGATE"], review["ai_actions"])
            controller._post_process_scan({"threats": [known]})
            action.assert_called_once()

    def test_100_quick_scan_scope_is_bounded_and_full_scan_keeps_deep_files(self):
        engine = self.engine()
        self.fixture("scope/top.txt")
        self.fixture("scope/a/b/c/deep.txt")
        with patch.object(engine, "_get_critical_paths", return_value=[str(self.root / "scope")]):
            quick = engine.quick_scan()
        full = engine.full_scan(str(self.root / "scope"))
        self.assertEqual(1, quick["files_scanned"])
        self.assertEqual(2, full["files_scanned"])
        self.assertEqual(2, quick["max_directory_depth"])
        self.assertIsNone(full["max_directory_depth"])
        self.assertGreater(quick["directories_excluded"], 0)

    def test_101_large_pdf_keeps_all_results_in_json_and_limits_pages(self):
        import re
        from reports.pdf_generator import PDFReportGenerator
        findings = [{"path": "C:\\AppData\\ordinary-" + str(i) + ".dll", "type": "HIGH",
                     "score": 60, "notes": ["GetProcAddress"]} for i in range(5981)]
        scan = {"type": "QUICK", "files_scanned": 128588, "total_files": 128588,
                "duration_sec": 1768.9, "errors": 62, "skipped": 36,
                "threats_found": len(findings), "threats": findings, "cancelled": False}
        generator = PDFReportGenerator()
        path = Path(generator.generate_scan_report(scan))
        stored = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
        self.assertEqual(scan, stored["scan"])
        pages = len(re.findall(rb"/Type\s*/Page\b", path.read_bytes()))
        self.assertGreater(pages, 0)
        self.assertLessEqual(pages, 15)
        self.assertEqual(5981, generator.scan_summary(scan)["Alertes totalisees"])
        self.assertEqual(0, generator.scan_summary(scan)["Correspondances de signatures"])

    def test_102_python_shell_call_is_reviewed_but_never_executed(self):
        source = b'import subprocess\nsubprocess.run(["vssadmin", "delete", "shadows", "/all"])\n'
        file = self.fixture("command_review.py", source)
        finding = self.engine()._scan_file(str(file))
        self.assertTrue(finding["review_required"])
        self.assertFalse(finding["confirmed"])
        self.assertIn("SHADOW_COPY_DELETION_COMMAND", finding["notes"])
        self.assertEqual(source, file.read_bytes())

    def test_103_ransomguard_does_not_escalate_generic_encrypted_files(self):
        from elpati.elpati_ransom_guard import ElpatiRansomGuard
        guard = ElpatiRansomGuard()
        self.fixture("home/Documents/backup.enc")
        self.fixture("home/Documents/document.locky")
        # .locky is not required in the live module's list; use its known .ryuk indicator.
        self.fixture("home/Documents/document.ryuk")
        alerts = []
        guard.register_alert_callback(alerts.append)
        with patch("pathlib.Path.home", return_value=self.root / "home"):
            guard._scan_recent_extensions()
        self.assertTrue(alerts)
        self.assertFalse(any("backup.enc" in item["message"] for item in alerts))
        self.assertTrue(all(item["score"] < 60 for item in alerts))

    def test_104_file_ai_never_recommends_destructive_action_for_static_evidence(self):
        from core.ai_core import AICore
        result = AICore().analyze_threat({"unconfirmed_file": True, "local_score": 95,
                                        "indicators": {"known_malware": True}})
        self.assertEqual(["INVESTIGATE"], result["actions"])
        self.assertEqual("REVIEW", result["risk_level"])

    def test_105_live_extension_review_cannot_trigger_automatic_response(self):
        from core.controller import CentralController
        controller = CentralController()
        controller.initialize_all_modules()
        controller.config.set("auto_protect", True)
        shield = controller._modules["shield"]
        response = controller._modules["auto_response"]
        with patch.object(shield, "kill_process") as kill, \
             patch.object(shield, "isolate_process") as isolate, \
             patch.object(response, "process_alert") as action:
            controller._on_alert({"score": 95, "review_required": True, "severity": "MEDIUM",
                                  "message": "Extension only", "pid": 123456})
            kill.assert_not_called()
            isolate.assert_not_called()
            action.assert_not_called()


if __name__ == "__main__":
    class RecordingResult(unittest.TextTestResult):
        rows = []
        def addSuccess(self, test):
            super().addSuccess(test)
            self.rows.append({"test": test.id(), "status": "PASS"})
        def addFailure(self, test, err):
            super().addFailure(test, err)
            self.rows.append({"test": test.id(), "status": "FAIL", "detail": self._exc_info_to_string(err, test)})
        def addError(self, test, err):
            super().addError(test, err)
            self.rows.append({"test": test.id(), "status": "ERROR", "detail": self._exc_info_to_string(err, test)})
        def addSkip(self, test, reason):
            super().addSkip(test, reason)
            self.rows.append({"test": test.id(), "status": "SKIP", "detail": reason})
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(IsolatedCase)
    if os.environ.get("CYBEROS_TEST_GUI") == "1":
        from gui_suite import GUICase
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(GUICase))
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult).run(suite)
    if "--json" in sys.argv:
        target = Path(sys.argv[sys.argv.index("--json")+1])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"python": sys.version, "platform": sys.platform,
            "duration_sec": round(time.monotonic()-started, 3), "tests": result.rows,
            "total": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "skipped": len(result.skipped)}, ensure_ascii=False, indent=2),
            encoding="utf-8")
    raise SystemExit(0 if result.wasSuccessful() else 1)
