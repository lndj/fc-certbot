import hashlib
import json
import os
import shlex
import signal
import socket
import ssl
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from config import select
from dns01 import cleanup
from state import Failure, Lock, read, write

PREFIX = "devs-certbot-generated-"


def leaf(pem):
    return x509.load_pem_x509_certificate(pem.encode())


def fingerprint(pem):
    return leaf(pem).fingerprint(hashes.SHA256()).hex()


def days_left(pem):
    return (leaf(pem).not_valid_after_utc - datetime.now(timezone.utc)).total_seconds() / 86400


def validate_material(cert, key, domain):
    parsed = leaf(cert)
    names = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    if names != [domain] or days_left(cert) <= 1:
        raise Failure("CERT_SCOPE_OR_EXPIRY")
    private = serialization.load_pem_private_key(key.encode(), password=None)
    def public(key):
        return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if public(private.public_key()) != public(parsed.public_key()):
        raise Failure("CERT_KEY_MISMATCH")


def stop_certbot_group(process, grace=2):
    """Reap our child and confirm its entire Unix process group has disappeared."""
    def gone():
        process.poll()  # Reap the direct child; killpg also detects live descendants.
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        return False
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if gone():
            return True
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            return gone()
        except OSError:
            return False
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            if gone():
                return True
            time.sleep(0.05)
    return gone()


def run_certbot(args, env, lock, timeout=600):
    lock.check()
    process = subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    def finish_group():
        try:
            stopped = stop_certbot_group(process)
        except BaseException:
            stopped = False
        if not stopped:
            lock.quarantine()
            raise Failure("ACME_PROCESS_GROUP_UNCONFIRMED") from None
    try:
        code = process.wait(timeout=timeout)
    except BaseException as exc:
        finish_group()
        if isinstance(exc, subprocess.TimeoutExpired):
            raise Failure("ACME_TIMEOUT") from None
        raise
    # A failed or successful parent may leave descendants behind. Neither permits
    # cleanup or lock release until those processes have also stopped.
    finish_group()
    if code != 0:
        raise Failure("ACME_FAILED")


def issue(cfg, target, run, credentials, account, lock):
    # Each generation has its own lineage; account/config/key data stay on private NAS.
    config = run / "letsencrypt"
    cert_path = config / "live" / "managed" / "fullchain.pem"
    key_path = cert_path.with_name("privkey.pem")
    if not (cert_path.exists() and key_path.exists()):
        env = os.environ.copy()
        env.update(FC_CERTBOT_TARGET=json.dumps(target), FC_CERTBOT_STS=json.dumps(credentials),
                   FC_CERTBOT_ACCOUNT=str(account), FC_CERTBOT_RUN=str(run),
                   FC_CERTBOT_LOCK_TOKEN=str(lock.token),
                   FC_CERTBOT_DNS_TIMEOUT=str(cfg.get("dns_timeout", 180)))
        hook = shlex.quote(sys.executable) + " " + shlex.quote(str(Path(__file__).with_name("hook.py")))
        args = [sys.executable, "-c", "from certbot.main import main; import sys; sys.exit(main())",
                "certonly", "--config", "/dev/null", "--config-dir", str(config),
                "--work-dir", str(run / "work"), "--logs-dir", str(run / "logs"),
                "--manual", "--non-interactive", "--agree-tos", "--no-eff-email",
                "--manual-auth-hook", hook + " auth", "--manual-cleanup-hook", hook + " cleanup",
                "--preferred-challenges", "dns", "--key-type", "rsa", "--rsa-key-size", "2048",
                "--cert-name", "managed", "--email", cfg["email"],
                "--server", cfg["acme_directory"], "--domains", target["domain"]]
        run_certbot(args, env, lock)
    if not cert_path.exists() or not key_path.exists():
        raise Failure("ACME_OUTPUT_MISSING")
    cert, key = cert_path.read_text(), key_path.read_text()
    validate_material(cert, key, target["domain"])
    for name, text in (("fullchain.pem", cert), ("key.pem", key)):
        path = run / name
        path.write_text(text)
        path.chmod(0o600)
    return cert, key


def verify_tls(target, cert, check, timeout=60, sleep=time.sleep):
    expected = fingerprint(cert)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        check()
        try:
            # Connect to the reviewed FC origin host but verify the domain as SNI.
            # A proxied ESA edge certificate cannot prove an FC origin update.
            with socket.create_connection((target["tls_connect_host"], 443), timeout=5) as sock:
                with ssl.create_default_context().wrap_socket(sock, server_hostname=target["domain"]) as tls:
                    actual = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
                    if actual == expected:
                        return
        except (OSError, ssl.SSLError):
            pass
        sleep(min(5, max(0, deadline - time.monotonic())))
    raise Failure("TLS_VERIFY_FAILED")


def ensure_upload(cloud, state, save, cert, key, check, sleep=time.sleep):
    candidate = state["candidate"]
    name = candidate["name"]
    found = cloud.find_cert(name)
    if found is None and not candidate.get("cas_attempted"):
        candidate["cas_attempted"] = True
        save()
        check()
        try:
            cloud.upload(name, cert, key, fingerprint(cert))
        except Exception:
            pass
        # Always read back, even when UploadUserCertificate reports success.
        for attempt in range(3):
            check()
            found = cloud.find_cert(name)
            if found is not None:
                break
            if attempt < 2:
                sleep(2)
    if found is None:
        raise Failure("CAS_UPLOAD_UNKNOWN")
    if fingerprint(found["cert"]) != fingerprint(cert):
        raise Failure("CAS_NAME_CONFLICT")
    validate_material(found["cert"], found["key"], state["domain"])
    candidate["cas_id"] = found["id"]
    save()
    return found["id"]


def install(cloud, state, save, cert, key, target, check, verify=verify_tls, sleep=time.sleep):
    candidate = state["candidate"]
    expected = fingerprint(cert)
    current = cloud.domain()
    current_fp = fingerprint(current["cert"]) if current["cert"] else None
    if "HTTPS" not in (current["protocol"] or "").upper():
        raise Failure("MANUAL_HTTPS_BINDING_REQUIRED")
    # First binding must be made manually to the uploaded candidate. Later updates
    # may replace only the fingerprint this target previously installed.
    if current_fp != expected:
        if not state.get("active") or current_fp != state["active"]["fingerprint"]:
            raise Failure("FC_CERTIFICATE_CONFLICT")
        check()
        try:
            cloud.install(candidate["name"], cert, key)
        except Exception:
            pass
        for attempt in range(3):
            check()
            observed = cloud.domain()
            observed_fp = fingerprint(observed["cert"]) if observed["cert"] else None
            if observed_fp == expected:
                break
            if observed_fp != current_fp:
                raise Failure("FC_CERTIFICATE_CONFLICT")
            if attempt < 2:
                sleep(2)
        else:
            raise Failure("FC_UPDATE_UNCONFIRMED")
    verify(target, cert, check)
    previous = state.get("active")
    if previous and previous["fingerprint"] != expected:
        state.setdefault("history", []).append(previous)
    state["active"] = {"fingerprint": expected, "name": candidate["name"], "cas_id": candidate["cas_id"]}
    candidate["installed"] = True
    save()


def run(cfg, event, root, cloud, credentials, account, issuer=issue, verifier=verify_tls):
    target = select(cfg, event)
    work = Path(root) / event["target"]
    scope = hashlib.sha256(json.dumps({"target": target, "acme": cfg["acme_directory"]},
                                     sort_keys=True).encode()).hexdigest()
    with Lock(work) as lock:
        path = work / "state.json"
        state = read(path, {"domain": target["domain"], "region": target["region"], "scope": scope})
        if state.get("scope") != scope:
            raise Failure("STATE_SCOPE_CHANGED")
        cloud.validate_site()
        def save():
            lock.check()
            write(path, state)
        candidate = state.get("candidate")
        if candidate:
            cleanup(cloud, target, work / candidate["run"], lock.check)
        cert = None
        if candidate and candidate.get("fingerprint"):
            cert = (work / candidate["run"] / "fullchain.pem").read_text()
            if fingerprint(cert) != candidate["fingerprint"]:
                raise Failure("STATE_CERT_CHANGED")
        if cert is None or (candidate.get("installed") and days_left(cert) < cfg.get("renew_before_days", 30)):
            if not candidate or candidate.get("fingerprint"):
                candidate = {"run": "generation-" + uuid.uuid4().hex}
                state["candidate"] = candidate
                save()
            generation = work / candidate["run"]
            generation.mkdir(exist_ok=True, mode=0o700)
            try:
                cert, key = issuer(cfg, target, generation, credentials, account, lock)
            finally:
                if not lock.quarantined:
                    cleanup(cloud, target, generation, lock.check)
            validate_material(cert, key, target["domain"])
            candidate.update(fingerprint=fingerprint(cert), name=PREFIX + fingerprint(cert)[:32])
            save()
        else:
            key = (work / candidate["run"] / "key.pem").read_text()
            validate_material(cert, key, target["domain"])
        if days_left(cert) < cfg.get("renew_before_days", 30) and not candidate.get("installed"):
            # An abandoned uninstalled candidate is never installed close to expiry.
            raise Failure("CANDIDATE_EXPIRES_SOON")
        cas_id = ensure_upload(cloud, state, save, cert, key, lock.check)
        if event["action"] == "renew":
            install(cloud, state, save, cert, key, target, lock.check, verify=verifier)
        return {"status": "verified" if event["action"] == "renew" else "uploaded",
                "target": event["target"], "cert_id": cas_id, "cert_name": candidate["name"]}
