"""Offline contract + fault tests. No DNS, ACME or cloud writes are performed."""
import contextlib
import copy
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import time
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src/esa-certbot"))
import cloud as adapter
import config
import dns01
import engine
import index
from state import Failure, Lock, read, write
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import dns.flags
import dns.message
import dns.rrset

REAL_SLEEP = time.sleep


def material(days=90, domain="api.example.com"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()).decode())


class FakeCloud:
    def __init__(self):
        self.txt = []
        self.certs = {}
        self.current = {"protocol": "HTTPS", "name": "manual", "cert": None}
        self.creates = self.deletes = self.uploads = self.installs = 0
        self.create_mode = self.upload_mode = self.install_mode = "ok"
        self.route = {"path": "/original"}

    def validate_site(self):
        pass

    def records(self, name):
        return copy.deepcopy([r for r in self.txt if r["name"] == name])

    def create_txt(self, name, value, comment):
        self.creates += 1
        if self.create_mode != "absent":
            self.txt.append(dict(id=self.creates, name=name, value=value, comment=comment,
                                 type="TXT", site_id=123456789))
        if self.create_mode != "ok":
            raise TimeoutError("SECRET API BODY")
        return self.creates

    def delete_txt(self, record_id):
        self.deletes += 1
        self.txt = [r for r in self.txt if r["id"] != record_id]

    def find_cert(self, name):
        return self.certs.get(name)

    def upload(self, name, cert, key, token):
        self.uploads += 1
        if self.upload_mode != "absent":
            self.certs[name] = {"id": self.uploads, "cert": cert, "key": key}
        if self.upload_mode != "ok":
            raise TimeoutError("SECRET API BODY")
        return self.uploads

    def domain(self):
        return copy.deepcopy(self.current)

    def install(self, name, cert, key):
        self.installs += 1
        self.route = {"path": "/concurrently-changed"}
        if self.install_mode != "absent":
            self.current.update(name=name, cert=cert)
        if self.install_mode != "ok":
            raise TimeoutError("SECRET API BODY")


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert, cls.key = material()
        cls.old_cert, cls.old_key = material(days=20)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cfg = json.loads((Path(__file__).parents[1] / "src/esa-certbot/config.example.json").read_text())
        self.cfg.update(agree_tos=True, acme_directory=config.PRODUCTION)
        self.target = self.cfg["targets"]["api"]
        self.cloud = FakeCloud()
        self.verify = Mock()
        self.issues = 0
        self.issued_material = (self.cert, self.key)
        self.pause = patch("time.sleep", return_value=None)
        self.pause.start()
        self.addCleanup(self.pause.stop)

    def issuer(self, cfg, target, run, credentials, account, lock):
        self.issues += 1
        cert, key = self.issued_material
        (run / "fullchain.pem").write_text(cert)
        (run / "key.pem").write_text(key)
        return cert, key

    def run_event(self, action="issue", issuer=None):
        return engine.run(self.cfg, {"action": action, "target": "api"}, self.root, self.cloud,
                          {}, "123456789", issuer=issuer or self.issuer, verifier=self.verify)

    def state(self):
        return read(self.root / "api/state.json")

    def load_cfg(self, cfg):
        path = self.root / "config.json"
        write(path, cfg)
        return config.load(path)

    def bind(self):
        result = self.run_event()
        self.cloud.current.update(cert=self.cert, name=result["cert_name"])
        self.run_event("renew")
        return result

    def test_config_exact_domain_zone_site_region(self):
        self.assertEqual(self.load_cfg(self.cfg), self.cfg)
        for field, value in [("domain", "api.example.com.evil.com"), ("domain", "*.example.com"),
                             ("domain", "https://api.example.com"), ("region", "cn-beijing"),
                             ("esa_region", "cn-shanghai"), ("site_id", "123"),
                             ("domain", "-bad.example.com"), ("domain", "bad/example.com")]:
            cfg = copy.deepcopy(self.cfg)
            cfg["targets"]["api"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(Failure):
                self.load_cfg(cfg)

    def test_event_cannot_override_domain_site_or_region(self):
        for event in [{"domainName": "other.example.com"}, {"action": "renew", "target": "other"},
                      {"action": "issue", "target": "api", "site_id": 999}]:
            with self.assertRaises(Failure):
                config.select(self.cfg, event)

    def test_email_tos_and_staging_install_gate(self):
        self.cfg["agree_tos"] = False
        with self.assertRaisesRegex(Failure, "EMAIL_TOS"):
            self.load_cfg(self.cfg)
        self.cfg.update(agree_tos=True, acme_directory=config.STAGING)
        self.load_cfg(self.cfg)
        with self.assertRaisesRegex(Failure, "STAGING_INSTALL"):
            config.select(self.cfg, {"action": "renew", "target": "api"})

    def test_same_name_txt_and_parallel_run_cleanup(self):
        name = "_acme-challenge.api.example.com"
        self.cloud.txt = [dict(id=900, name=name, value="other", comment="human", type="TXT", site_id=123456789)]
        a = dns01.create(self.cloud, self.target, self.root / "a", "one", lambda: None)
        b = dns01.create(self.cloud, self.target, self.root / "b", "two", lambda: None)
        self.assertEqual(a["name"], name)
        self.assertNotEqual(a["id"], b["id"])
        dns01.cleanup(self.cloud, self.target, self.root / "a", lambda: None)
        self.assertEqual({r["id"] for r in self.cloud.txt}, {900, b["id"]})
        dns01.cleanup(self.cloud, self.target, self.root / "a", lambda: None)
        self.assertEqual(self.cloud.deletes, 1)

    def test_create_timeout_readback_no_second_create(self):
        self.cloud.create_mode = "committed"
        a = dns01.create(self.cloud, self.target, self.root, "token", lambda: None)
        b = dns01.create(self.cloud, self.target, self.root, "token", lambda: None)
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(self.cloud.creates, 1)

    def test_create_unknown_absent_not_retried_or_forgotten(self):
        self.cloud.create_mode = "absent"
        for _ in range(2):
            with self.assertRaisesRegex(Failure, "DNS_CREATE_UNKNOWN"):
                dns01.create(self.cloud, self.target, self.root, "token", lambda: None)
        with self.assertRaisesRegex(Failure, "DNS_CREATE_UNKNOWN"):
            dns01.cleanup(self.cloud, self.target, self.root, lambda: None)
        self.assertEqual(self.cloud.creates, 1)

    def test_cleanup_refuses_changed_owner(self):
        dns01.create(self.cloud, self.target, self.root, "token", lambda: None)
        self.cloud.txt[0]["comment"] = "someone-else"
        with self.assertRaisesRegex(Failure, "OWNERSHIP_CHANGED"):
            dns01.cleanup(self.cloud, self.target, self.root, lambda: None)
        self.assertEqual(self.cloud.deletes, 0)

    def test_cleanup_delete_timeout_readback(self):
        dns01.create(self.cloud, self.target, self.root, "token", lambda: None)
        real = self.cloud.delete_txt
        def uncertain(record_id):
            real(record_id)
            raise TimeoutError()
        self.cloud.delete_txt = uncertain
        dns01.cleanup(self.cloud, self.target, self.root, lambda: None)
        self.assertEqual(self.cloud.deletes, 1)
        self.assertEqual(self.cloud.txt, [])

    def test_cleanup_unknown_create_uses_newly_visible_recovered_record(self):
        item = dns01.create(self.cloud, self.target, self.root, "token", lambda: None)
        path = next((self.root / "challenges").glob("*.json"))
        item["id"] = None  # Create committed, but the RecordId was never journaled.
        write(path, item)
        actual_records = self.cloud.records
        snapshots = []
        def delayed_visibility(name):
            records = [] if not snapshots else actual_records(name)
            snapshots.append(records)
            return records
        self.cloud.records = Mock(side_effect=delayed_visibility)
        dns01.cleanup(self.cloud, self.target, self.root, lambda: None)
        self.assertEqual(len(snapshots), 3)  # empty -> recovered record -> deleted
        self.assertEqual(self.cloud.deletes, 1)
        self.assertEqual(self.cloud.txt, [])
        self.assertTrue(read(path)["deleted"])
        self.assertEqual(self.cloud.creates, 1)

    def test_cleanup_empty_list_without_delete_intent_is_unconfirmed(self):
        dns01.create(self.cloud, self.target, self.root, "token", lambda: None)
        path = next((self.root / "challenges").glob("*.json"))
        self.cloud.records = Mock(return_value=[])
        with self.assertRaisesRegex(Failure, "DNS_CLEANUP_UNCONFIRMED"):
            dns01.cleanup(self.cloud, self.target, self.root, lambda: None)
        self.assertFalse(read(path).get("deleted", False))
        self.assertEqual(self.cloud.deletes, 0)

    def test_cleanup_crash_after_delete_recovers_without_second_delete(self):
        item = dns01.create(self.cloud, self.target, self.root, "token", lambda: None)
        path = next((self.root / "challenges").glob("*.json"))
        item["delete_attempted"] = True
        write(path, item)
        self.cloud.delete_txt(item["id"])
        dns01.cleanup(self.cloud, self.target, self.root, lambda: None)
        self.assertTrue(read(path)["deleted"])
        self.assertEqual(self.cloud.deletes, 1)

    def test_propagation_bounded_timeout_and_retry(self):
        clock = [0]
        def sleep(seconds):
            clock[0] += seconds
        probe = Mock(return_value=False)
        with self.assertRaisesRegex(Failure, "PROPAGATION_TIMEOUT"):
            dns01.wait(self.target, {"name": "n", "value": "v"}, 12, lambda: None,
                       probe=probe, sleep=sleep, clock=lambda: clock[0])
        self.assertEqual(clock[0], 12)
        self.assertEqual(probe.call_count, 3)
        probe = Mock(side_effect=[False, True])
        dns01.wait(self.target, {"name": "n", "value": "v"}, 12, lambda: None,
                   probe=probe, sleep=sleep, clock=lambda: clock[0])
        self.assertEqual(probe.call_count, 2)

    def test_real_dns_packet_logic_requires_all_ns_aa_and_no_cname(self):
        def resolve(name, kind, **kwargs):
            if kind == "NS":
                return [NS(target=dns.name.from_text(n)) for n in self.target["nameservers"]]
            if kind == "A":
                return [NS(address="192.0.2.1")]
            return []
        name = "_acme-challenge.api.example.com"
        response = dns.message.make_response(dns.message.make_query(name, "TXT"))
        response.flags |= dns.flags.AA
        response.answer = [dns.rrset.from_text(name + ".", 60, "IN", "TXT", '"token"')]
        with patch("dns.resolver.Resolver") as resolver, patch("dns.query.udp", return_value=response) as udp:
            resolver.return_value.resolve.side_effect = resolve
            self.assertTrue(dns01.authoritative(self.target, name, "token", time.monotonic() + 30))
            self.assertEqual(udp.call_count, 2)
            response.flags &= ~dns.flags.AA
            self.assertFalse(dns01.authoritative(self.target, name, "token", time.monotonic() + 30))
            response.flags |= dns.flags.AA
            response.answer = [dns.rrset.from_text(name + ".", 60, "IN", "CNAME", "other.example.com.")]
            with self.assertRaisesRegex(Failure, "CNAME_UNSUPPORTED"):
                dns01.authoritative(self.target, name, "token", time.monotonic() + 30)

    def test_ns_mismatch_stops(self):
        with patch("dns.resolver.Resolver") as resolver:
            resolver.return_value.resolve.return_value = [NS(target=dns.name.from_text("foreign.example.com"))]
            with self.assertRaisesRegex(Failure, "DNS_NS_MISMATCH"):
                dns01.authoritative(self.target, "_acme-challenge.api.example.com", "v", time.monotonic()+5)

    def test_acme_failure_cleans_txt_never_uploads(self):
        def fail(cfg, target, run, *args):
            dns01.create(self.cloud, target, run, "token", lambda: None)
            raise Failure("ACME_FAILED")
        with self.assertRaisesRegex(Failure, "ACME_FAILED"):
            self.run_event(issuer=fail)
        self.assertEqual(self.cloud.txt, [])
        self.assertEqual((self.cloud.uploads, self.cloud.installs), (0, 0))

    def test_issue_idempotent_new_name_remains_discoverable(self):
        a, b = self.run_event(), self.run_event()
        self.assertEqual(a, b)
        self.assertTrue(a["cert_name"].startswith(engine.PREFIX))
        self.assertLessEqual(len(a["cert_name"]), 63)
        self.assertEqual((self.issues, self.cloud.uploads), (1, 1))

    def test_upload_timeout_committed_recovers_by_name_and_material(self):
        self.cloud.upload_mode = "committed"
        self.run_event()
        self.run_event()
        self.assertEqual(self.cloud.uploads, 1)

    def test_upload_absent_unknown_never_repeated_old_certificate_kept(self):
        self.cloud.certs["old"] = {"cert": self.old_cert, "key": self.old_key, "id": 99}
        self.cloud.upload_mode = "absent"
        for _ in range(2):
            with self.assertRaisesRegex(Failure, "CAS_UPLOAD_UNKNOWN"):
                self.run_event()
        self.assertEqual(self.cloud.uploads, 1)
        self.assertIn("old", self.cloud.certs)
        self.assertEqual(self.cloud.installs, 0)

    def test_cas_name_collision_refused(self):
        self.run_event()
        name = self.state()["candidate"]["name"]
        self.cloud.certs[name]["cert"] = self.old_cert
        with self.assertRaisesRegex(Failure, "CAS_NAME_CONFLICT"):
            self.run_event()

    def test_manual_first_binding_required(self):
        self.run_event()
        self.cloud.current["cert"] = self.old_cert
        with self.assertRaisesRegex(Failure, "FC_CERTIFICATE_CONFLICT"):
            self.run_event("renew")
        self.assertEqual(self.cloud.installs, 0)

    def test_manual_binding_then_daily_run_without_reissue(self):
        self.bind()
        self.run_event("renew")
        self.assertTrue(self.state()["candidate"]["installed"])
        self.assertEqual((self.issues, self.cloud.uploads, self.cloud.installs), (1, 1, 0))
        self.assertEqual(self.verify.call_count, 2)

    def prepare_renewal(self):
        self.issued_material = self.old_cert, self.old_key
        self.cfg["renew_before_days"] = 7
        self.run_event()
        self.cloud.current["cert"] = self.old_cert
        self.run_event("renew")
        self.cfg["renew_before_days"] = 30
        self.issued_material = self.cert, self.key

    def test_renew_install_unknown_readback_success_and_next_run(self):
        self.prepare_renewal()
        self.cloud.install_mode = "committed"
        result = self.run_event("renew")
        self.assertEqual(result["status"], "verified")
        self.run_event("renew")
        self.assertEqual((self.issues, self.cloud.uploads, self.cloud.installs), (2, 2, 1))
        self.assertEqual(len(self.cloud.certs), 2)
        self.assertEqual(len(self.state()["history"]), 1)
        self.assertEqual(self.cloud.route["path"], "/concurrently-changed")

    def test_fc_failure_preserves_old_and_retry_reuses_candidate(self):
        self.prepare_renewal()
        self.cloud.install_mode = "absent"
        with self.assertRaisesRegex(Failure, "FC_UPDATE_UNCONFIRMED"):
            self.run_event("renew")
        self.assertEqual(self.cloud.current["cert"], self.old_cert)
        self.assertEqual(len(self.cloud.certs), 2)
        self.cloud.install_mode = "ok"
        self.run_event("renew")
        self.assertEqual((self.issues, self.cloud.uploads), (2, 2))

    def test_tls_failure_retries_verification_without_issuance_or_fc_write(self):
        self.prepare_renewal()
        self.verify.side_effect = Failure("TLS_VERIFY_FAILED")
        with self.assertRaisesRegex(Failure, "TLS_VERIFY_FAILED"):
            self.run_event("renew")
        self.assertEqual(self.state()["active"]["fingerprint"], engine.fingerprint(self.old_cert))
        self.verify.side_effect = None
        self.run_event("renew")
        self.assertEqual((self.issues, self.cloud.uploads, self.cloud.installs), (2, 2, 1))

    def test_concurrent_and_stale_lock_never_stolen(self):
        with Lock(self.root) as first:
            with self.assertRaisesRegex(Failure, "LOCK_BUSY"):
                with Lock(self.root):
                    pass
            write(first.token, {"owner": first.owner, "expires": 0})
            with self.assertRaisesRegex(Failure, "LOCK_STALE"):
                with Lock(self.root):
                    pass
        expired = Lock(self.root, ttl=-1)
        with expired:
            with self.assertRaisesRegex(Failure, "LOCK_LOST"):
                expired.check()

    def test_old_owner_cannot_release_new_lock(self):
        old = Lock(self.root)
        old.__enter__()
        old.path.rename(self.root / "quarantined-lock")
        with Lock(self.root) as new:
            old.__exit__()
            new.check()
            self.assertTrue(new.token.exists())
            with self.assertRaisesRegex(Failure, "LOCK_LOST"):
                old.check()

    def test_deployment_archive_is_readable_by_fc_non_owner_uid(self):
        spec = importlib.util.spec_from_file_location(
            "esa_builder", Path(__file__).parents[1] / "tools/build_esa.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source, build = base / "source", base / "build"
            source.mkdir()
            (source / "index.py").write_text("def handler(event, context): return 'ok'\n")
            (source / "requirements.lock").write_text("locked dependencies")
            configuration = source / "config.example.json"
            configuration.write_text('{"domain":"api.example.com"}')
            (build / "python").mkdir(parents=True)
            (build / "python/dependency.py").write_text("answer = 42\n")
            (build / "dependencies.sha256").write_text(hashlib.sha256(
                (source / "requirements.lock").read_bytes()).hexdigest())
            with patch.object(builder, "SOURCE", source), patch.object(builder, "BUILD", build), \
                    patch.object(builder.subprocess, "check_output", return_value="uv 0.6.16"), \
                    patch.object(sys, "argv", ["build_esa.py", "--reuse-deps", "--config", str(configuration)]), \
                    contextlib.redirect_stdout(io.StringIO()):
                builder.main()
            with zipfile.ZipFile(build / "fc-certbot-esa.zip") as archive:
                self.assertEqual(set(archive.namelist()), {"index.py", "config.json", "python/dependency.py"})
                for item in archive.infolist():
                    mode = item.external_attr >> 16
                    self.assertTrue(mode & 0o004, item.filename + " unreadable by FC runtime UID")
                    self.assertFalse(mode & 0o022, item.filename + " writable by non-owner")

    def test_handler_uses_fc_allowed_environment_names(self):
        context = NS(credentials=NS(access_key_id="test", access_key_secret="test",
                                   security_token="test"), account_id="123456789")
        evt = {"action": "issue", "target": "api"}
        with patch.dict(os.environ, {"ESA_CERTBOT_CONFIG": "deployment.json",
                                     "ESA_CERTBOT_STATE_ROOT": str(self.root)}, clear=True), \
                patch.object(index, "load", return_value=self.cfg) as load_config, \
                patch.object(index, "require_nas", return_value=self.root) as check_nas, \
                patch.object(index, "Cloud", return_value=self.cloud), \
                patch.object(index, "run", return_value={"status": "uploaded"}) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(index.handler(json.dumps(evt), context), {"status": "uploaded"})
        load_config.assert_called_once_with("deployment.json")
        check_nas.assert_called_once_with(str(self.root))
        self.assertEqual(run.call_args.args[2], self.root)
        # FC rejects user-defined variables with its reserved FC_ prefix.
        template = (Path(__file__).parents[1] / "s-esa.example.yaml").read_text()
        for name in ("ESA_CERTBOT_CONFIG", "ESA_CERTBOT_STATE_ROOT"):
            self.assertIn(name + ":", template)
        self.assertNotIn("FC_CERTBOT_", template)

    def test_handler_sanitizes_sdk_errors_and_private_values(self):
        context = NS(credentials=NS(access_key_id="SECRET-AK", access_key_secret="SECRET-KEY", security_token="SECRET-STS"), account_id="123456789")
        captured = io.StringIO()
        with patch.object(index, "load", return_value=self.cfg), patch.dict(os.environ, {
                "ESA_CERTBOT_CONFIG": "config", "ESA_CERTBOT_STATE_ROOT": str(self.root)}), \
                patch.object(index, "require_nas", return_value=self.root), \
                patch.object(index, "Cloud", side_effect=Exception("SECRET-KEY CERTIFICATE BODY")), \
                contextlib.redirect_stdout(captured):
            with self.assertRaisesRegex(RuntimeError, "^OPERATION_FAILED$"):
                index.handler(json.dumps({"action": "issue", "target": "api"}), context)
        self.assertNotIn("SECRET", captured.getvalue())
        self.assertNotIn("api.example.com", captured.getvalue())
        self.assertIn('"phase": "failed"', captured.getvalue())

    def test_sdk_request_contracts_and_no_automatic_retries(self):
        sdk = adapter.Cloud({"access_key_id": "test", "access_key_secret": "test", "security_token": "test"}, "123456789", self.target)
        sdk.esa, sdk.cas, sdk.fc = Mock(), Mock(), Mock()
        sdk.esa.get_site_with_options.return_value.body.site_model = NS(
            site_id=123456789, site_name="example.com", access_type="NS", status="active",
            name_server_list="ns1.example.com,ns2.example.com")
        sdk.esa.create_record_with_options.return_value.body.record_id = 123
        sdk.create_txt("_acme-challenge.api.example.com", "value", "owned")
        req = sdk.esa.create_record_with_options.call_args.args[0].to_map()
        self.assertEqual(req["RecordName"], "_acme-challenge.api.example.com")
        self.assertEqual(req["Data"], {"Value": "value"})
        self.assertEqual(req["Type"], "TXT")
        self.assertFalse(req["Proxied"])
        self.assertFalse(sdk.runtime.autoretry)
        sdk.upload("name", self.cert, self.key, "stable-token")
        self.assertEqual(sdk.cas.upload_user_certificate_with_options.call_args.args[0].client_token, "stable-token")
        sdk.install("name", self.cert, self.key)
        body = sdk.fc.update_custom_domain_with_options.call_args.args[1].to_map()["body"]
        self.assertEqual(set(body), {"certConfig"})
        self.assertEqual(body["certConfig"]["certName"], "name")
        sdk.delete_txt(123)
        self.assertEqual(sdk.esa.delete_record_with_options.call_args.args[0].to_map(), {"RecordId": 123})

    def test_missing_sts_and_local_tmp_state_refused(self):
        with self.assertRaisesRegex(Failure, "FC_ROLE_STS_REQUIRED"):
            adapter.Cloud({"access_key_id": "test", "access_key_secret": "test"}, "123", self.target)
        with patch("state.Path.read_text", return_value="tmpfs /tmp tmpfs rw 0 0\n"):
            with self.assertRaisesRegex(Failure, "SHARED_NAS_REQUIRED"):
                index.require_nas(self.root)

    def test_cert_scope_and_key_mismatch(self):
        with self.assertRaisesRegex(Failure, "CERT_SCOPE_OR_EXPIRY"):
            engine.validate_material(self.cert, self.key, "other.example.com")
        with self.assertRaisesRegex(Failure, "CERT_KEY_MISMATCH"):
            engine.validate_material(self.cert, self.old_key, "api.example.com")

    def test_site_response_scope_is_verified_before_creation(self):
        sdk = adapter.Cloud({"access_key_id": "test", "access_key_secret": "test", "security_token": "test"},
                            "123456789", self.target)
        sdk.esa = Mock()
        site = NS(site_id=123456789, site_name="example.com", access_type="NS", status="active",
                  name_server_list="ns1.example.com,ns2.example.com")
        sdk.esa.get_site_with_options.return_value.body.site_model = site
        for field, value in [("site_id", 999), ("site_name", "other.example.com"), ("access_type", "CNAME"),
                             ("status", "pending"), ("name_server_list", "foreign.example.com")]:
            altered = copy.copy(site)
            setattr(altered, field, value)
            sdk.esa.get_site_with_options.return_value.body.site_model = altered
            with self.subTest(field=field), self.assertRaisesRegex(Failure, "ESA_SITE_SCOPE_MISMATCH"):
                sdk.create_txt("_acme-challenge.api.example.com", "value", "owned")
        sdk.esa.create_record_with_options.assert_not_called()

    def test_staging_and_changed_site_cannot_reuse_production_state(self):
        self.run_event()
        self.cfg["acme_directory"] = config.STAGING
        with self.assertRaisesRegex(Failure, "STATE_SCOPE_CHANGED"):
            self.run_event()
        self.cfg["acme_directory"] = config.PRODUCTION
        self.target["site_id"] = 999
        with self.assertRaisesRegex(Failure, "STATE_SCOPE_CHANGED"):
            self.run_event()
        self.assertEqual(self.issues, 1)

    def test_tls_verifier_checks_origin_sni_chain_and_leaf(self):
        raw = engine.leaf(self.cert).public_bytes(serialization.Encoding.DER)
        sock = MagicMock()
        tls_context = MagicMock()
        tls = tls_context.wrap_socket.return_value.__enter__.return_value
        tls.getpeercert.return_value = raw
        with patch("engine.socket.create_connection", return_value=sock) as connect, \
                patch("engine.ssl.create_default_context", return_value=tls_context):
            engine.verify_tls(self.target, self.cert, lambda: None)
            connect.assert_called_once_with((self.target["tls_connect_host"], 443), timeout=5)
            self.assertEqual(tls_context.wrap_socket.call_args.kwargs["server_hostname"], self.target["domain"])
            tls.getpeercert.return_value = engine.leaf(self.old_cert).public_bytes(serialization.Encoding.DER)
            tick = [0]
            def clock():
                tick[0] += 0.5
                return tick[0]
            with patch("engine.time.monotonic", side_effect=clock), self.assertRaisesRegex(Failure, "TLS_VERIFY_FAILED"):
                engine.verify_tls(self.target, self.cert, lambda: None, timeout=2, sleep=lambda n: None)

    def test_certificate_files_survive_issue_state_commit_crash(self):
        # Certbot may finish writing a lineage before the journal is committed.
        live = self.root / "letsencrypt/live/managed"
        live.mkdir(parents=True)
        (live / "fullchain.pem").write_text(self.cert)
        (live / "privkey.pem").write_text(self.key)
        with Lock(self.root) as lock, patch("engine.run_certbot") as certbot:
            result = engine.issue(self.cfg, self.target, self.root, {}, "123", lock)
        self.assertEqual(result, (self.cert, self.key))
        certbot.assert_not_called()

    def test_certbot_failure_output_suppressed_and_cleanup_hooks_configured(self):
        with Lock(self.root) as lock, patch("engine.subprocess.Popen") as popen, \
                patch("engine.stop_certbot_group", return_value=True):
            popen.return_value.wait.return_value = 1
            with self.assertRaisesRegex(Failure, "ACME_FAILED"):
                engine.issue(self.cfg, self.target, self.root, {"security_token": "PRIVATE"}, "123", lock)
            kwargs = popen.call_args.kwargs
            self.assertEqual(kwargs["stdout"], engine.subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], engine.subprocess.DEVNULL)
            self.assertTrue(kwargs["start_new_session"])
            popen.return_value.wait.assert_called_once_with(timeout=600)
            args = popen.call_args.args[0]
            self.assertIn("--manual-cleanup-hook", args)
            self.assertIn("--manual-auth-hook", args)
            self.assertNotIn("your_mail@mail.com", args)

    def test_real_certbot_descendants_stop_before_cleanup_and_cannot_write_late(self):
        real_run_certbot = engine.run_certbot
        for mode in ("timeout", "parent-error"):
            with self.subTest(mode=mode):
                base = self.root / mode
                ready, started, marker = (base / n for n in ("group", "worker-ready", "late-marker"))
                worker = ("import time; from pathlib import Path; "
                          f"Path({str(started)!r}).write_text('ready'); time.sleep(3); "
                          f"Path({str(marker)!r}).write_text('late')")
                hook = ("import subprocess, sys, time; "
                        f"subprocess.Popen([sys.executable, '-c', {worker!r}]); time.sleep(30)")
                parent = ("import os, subprocess, sys, time; from pathlib import Path\n"
                          f"subprocess.Popen([sys.executable, '-c', {hook!r}])\n"
                          f"while not Path({str(started)!r}).exists(): time.sleep(0.01)\n"
                          f"Path({str(ready)!r}).write_text(str(os.getpgrp()))\n"
                          + ("time.sleep(30)\n" if mode == "timeout" else "sys.exit(1)\n"))
                def fixture_certbot(args, env, lock):
                    return real_run_certbot([sys.executable, "-c", parent], env, lock, timeout=1)
                def cleanup_after_exit(cloud, target, generation, check):
                    check()
                    self.assertTrue((base / "api/lock").exists())
                    self.assertTrue(started.exists())
                    with self.assertRaises(ProcessLookupError):
                        os.killpg(int(ready.read_text()), 0)
                with patch("engine.run_certbot", side_effect=fixture_certbot), \
                        patch("engine.cleanup", side_effect=cleanup_after_exit) as cleanup, \
                        patch("engine.time.sleep", REAL_SLEEP):
                    expected = "ACME_TIMEOUT" if mode == "timeout" else "ACME_FAILED"
                    with self.assertRaisesRegex(Failure, expected):
                        engine.run(self.cfg, {"action": "issue", "target": "api"}, base, self.cloud,
                                   {}, "123456789", issuer=engine.issue)
                cleanup.assert_called_once()
                self.assertFalse((base / "api/lock").exists())
                REAL_SLEEP(3.2)
                self.assertFalse(marker.exists())

    def test_unconfirmed_process_group_quarantines_lock_and_skips_cleanup(self):
        for stop_result in (False, OSError("cannot inspect group")):
            base = self.root / ("stop-error" if isinstance(stop_result, Exception) else "still-alive")
            with self.subTest(result=type(stop_result).__name__), patch("engine.subprocess.Popen") as popen, \
                    patch("engine.stop_certbot_group") as stop, patch("engine.cleanup") as cleanup:
                popen.return_value.wait.side_effect = engine.subprocess.TimeoutExpired("fixture", 600)
                if isinstance(stop_result, Exception):
                    stop.side_effect = stop_result
                else:
                    stop.return_value = stop_result
                with self.assertRaisesRegex(Failure, "ACME_PROCESS_GROUP_UNCONFIRMED"):
                    engine.run(self.cfg, {"action": "issue", "target": "api"}, base, self.cloud,
                               {}, "123456789", issuer=engine.issue)
                cleanup.assert_not_called()
                token = next((base / "api/lock").iterdir())
                self.assertTrue(read(token)["quarantined"])
                self.assertEqual(read(token)["expires"], 0)
                with self.assertRaisesRegex(Failure, "LOCK_QUARANTINED"):
                    with Lock(base / "api"):
                        pass

    def test_legacy_cas_never_deletes_old_on_upload_success_or_failure(self):
        source = Path(__file__).parents[1] / "src/cert-generator/cas/index.py"
        spec = importlib.util.spec_from_file_location("legacy_cas", source)
        legacy = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {"ALIBABA_CLOUD_ACCESS_KEY_ID": "test", "ALIBABA_CLOUD_ACCESS_KEY_SECRET": "test",
                                     "ALIBABA_CLOUD_SECURITY_TOKEN": "test"}):
            spec.loader.exec_module(legacy)
        legacy.client = Mock()
        cert_path, key_path = self.root / "cert.pem", self.root / "key.pem"
        cert_path.write_text(self.cert)
        key_path.write_text(self.key)
        legacy.upload_cert(cert_path, key_path, "api.example.com", "devs-certbot-generated-old", 99)
        name = legacy.client.upload_user_certificate_with_options.call_args.args[0].name
        self.assertNotEqual(name, "devs-certbot-generated-old")
        self.assertTrue(name.startswith(engine.PREFIX))
        legacy.client.upload_user_certificate_with_options.side_effect = TimeoutError()
        with self.assertRaises(TimeoutError):
            legacy.upload_cert(cert_path, key_path, "api.example.com", name, 99)
        legacy.client.delete_user_certificate_with_options.assert_not_called()


if __name__ == "__main__":
    unittest.main()
