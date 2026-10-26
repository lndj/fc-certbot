import json
import re
from pathlib import Path
from state import Failure

PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


def hostname(value):
    if not isinstance(value, str) or len(value) > 253 or value != value.lower():
        raise Failure("CONFIG_HOSTNAME")
    labels = value.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", s) for s in labels):
        raise Failure("CONFIG_HOSTNAME")
    return value


def load(path):
    cfg = json.loads(Path(path).read_text())
    if cfg.get("provider") != "esa" or not cfg.get("targets"):
        raise Failure("CONFIG_PROVIDER")
    if cfg.get("agree_tos") is not True or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", cfg.get("email", "")):
        raise Failure("EMAIL_TOS_CONFIRMATION_REQUIRED")
    if cfg.get("acme_directory") not in (PRODUCTION, STAGING):
        raise Failure("CONFIG_ACME")
    if not 7 <= cfg.get("renew_before_days", 30) <= 60:
        raise Failure("CONFIG_RENEW_WINDOW")
    if not 10 <= cfg.get("dns_timeout", 180) <= 300:
        raise Failure("CONFIG_DNS_TIMEOUT")
    if type(cfg.get("dns_stable_seconds", 300)) is not int or not 30 <= cfg.get("dns_stable_seconds", 300) <= 300:
        raise Failure("CONFIG_DNS_STABILITY")
    if not cfg.get("regions") or any(not re.fullmatch(r"(?:cn|ap|eu|us|me)-[a-z]+(?:-[a-z]+)?-?\d*", r) for r in cfg["regions"]):
        raise Failure("CONFIG_REGIONS")
    seen = set()
    for key, target in cfg["targets"].items():
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", key):
            raise Failure("CONFIG_TARGET")
        domain, zone = hostname(target["domain"]), hostname(target["zone"])
        if domain != zone and not domain.endswith("." + zone):
            raise Failure("CONFIG_ZONE_BOUNDARY")
        if target["region"] not in cfg["regions"] or target["esa_region"] not in ("cn-hangzhou", "ap-southeast-1"):
            raise Failure("CONFIG_REGION_BOUNDARY")
        if type(target["site_id"]) is not int or target["site_id"] <= 0:
            raise Failure("CONFIG_SITE")
        if not 2 <= len(target["nameservers"]) <= 6:
            raise Failure("CONFIG_NS")
        for ns in target["nameservers"]:
            hostname(ns)
        hostname(target["tls_connect_host"])
        pair = (target["region"], domain)
        if pair in seen:
            raise Failure("CONFIG_DUPLICATE_TARGET")
        seen.add(pair)
    return cfg


def select(cfg, event):
    if not isinstance(event, dict) or set(event) != {"action", "target"}:
        raise Failure("EVENT_SCOPE")
    if event["action"] not in ("issue", "renew") or event["target"] not in cfg["targets"]:
        raise Failure("EVENT_SCOPE")
    if event["action"] == "renew" and cfg["acme_directory"] != PRODUCTION:
        raise Failure("STAGING_INSTALL_FORBIDDEN")
    return cfg["targets"][event["target"]]
