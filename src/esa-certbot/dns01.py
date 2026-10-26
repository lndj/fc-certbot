"""ESA TXT ownership journal and bounded authoritative DNS propagation checks."""
import hashlib
import time
import uuid
from pathlib import Path
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
from state import Failure, read, write


def matching(record, item, target):
    return (record["site_id"] == target["site_id"] and record["type"] == "TXT"
            and record["name"].rstrip(".").lower() == item["name"]
            and record["value"] == item["value"] and record["comment"] == item["comment"])


def recover(cloud, item, target):
    matches = [r for r in cloud.records(item["name"]) if matching(r, item, target)]
    if len(matches) > 1:
        raise Failure("DNS_OWNERSHIP_AMBIGUOUS")
    return matches[0] if matches else None


def create(cloud, target, run, value, check):
    path = Path(run) / "challenges" / (hashlib.sha256(value.encode()).hexdigest() + ".json")
    item = read(path)
    if item is None:
        item = {"name": "_acme-challenge." + target["domain"], "value": value,
                "comment": "fc-certbot-" + uuid.uuid4().hex, "attempted": False, "id": None}
        check()
        write(path, item)
    if item.get("deleted"):
        raise Failure("DNS_CHALLENGE_ALREADY_CLEANED")
    if item["attempted"]:
        record = recover(cloud, item, target)
        if record is None:
            raise Failure("DNS_CREATE_UNKNOWN")
        record_id = record["id"]
    else:
        check()
        item["attempted"] = True
        write(path, item)  # Durable intent before a potentially ambiguous API result.
        try:
            check()
            record_id = cloud.create_txt(item["name"], value, item["comment"])
        except Exception:
            record_id = None
            for attempt in range(3):
                check()
                record = recover(cloud, item, target)
                if record is not None:
                    record_id = record["id"]
                    break
                if attempt < 2:
                    time.sleep(2)
            if record_id is None:
                raise Failure("DNS_CREATE_UNKNOWN") from None
    if not record_id:
        raise Failure("DNS_CREATE_UNKNOWN")
    item["id"] = record_id
    check()
    write(path, item)
    return item


def cleanup(cloud, target, run, check):
    for path in sorted((Path(run) / "challenges").glob("*.json")):
        item = read(path)
        if item.get("deleted") or not item["attempted"]:
            continue
        check()
        records = cloud.records(item["name"])
        record_id = item["id"]
        if record_id is None:
            record = recover(cloud, item, target)
            if record is None:
                # A create timeout can still commit later; do not forget this intent.
                raise Failure("DNS_CREATE_UNKNOWN")
            record_id = record["id"]
            records = [record]  # Use the fresh observation, not the earlier list.
            item["id"] = record_id
            check()
            write(path, item)
        for attempt in range(3):
            current = next((r for r in records if r["id"] == record_id), None)
            if current is None:
                if not item.get("delete_attempted"):
                    raise Failure("DNS_CLEANUP_UNCONFIRMED")
                item["deleted"] = True
                check()
                write(path, item)
                break
            if not matching(current, item, target):
                raise Failure("DNS_OWNERSHIP_CHANGED")
            check()
            item["delete_attempted"] = True
            write(path, item)
            check()
            try:
                cloud.delete_txt(record_id)
            except Exception:
                pass  # Verify unknown deletion; never switch to name-based deletion.
            records = cloud.records(item["name"])
        else:
            if any(r["id"] == record_id for r in records):
                raise Failure("DNS_CLEANUP_FAILED")
            item["deleted"] = True
            check()
            write(path, item)


def authoritative(target, name, value, deadline):
    resolver = dns.resolver.Resolver()
    def remaining():
        seconds = min(3, deadline - time.monotonic())
        if seconds <= 0:
            raise Failure("DNS_PROPAGATION_TIMEOUT")
        return seconds
    actual = {r.target.to_text().rstrip(".").lower() for r in resolver.resolve(
        target["zone"], "NS", lifetime=remaining())}
    if actual != set(target["nameservers"]):
        raise Failure("DNS_NS_MISMATCH")
    qname = dns.name.from_text(name)
    query = dns.message.make_query(qname, "TXT")
    query.flags &= ~dns.flags.RD
    for ns in sorted(actual):
        addresses = []
        for kind in ("A", "AAAA"):
            try:
                addresses.extend(r.address for r in resolver.resolve(ns, kind, lifetime=remaining()))
            except dns.exception.DNSException:
                pass
        found = False
        for address in addresses:
            try:
                response = dns.query.udp(query, address, timeout=remaining())
                if response.flags & dns.flags.TC:
                    response = dns.query.tcp(query, address, timeout=remaining())
                if not response.flags & dns.flags.AA or response.rcode() != dns.rcode.NOERROR:
                    continue
                if any(rr.rdtype == dns.rdatatype.CNAME for rr in response.answer):
                    raise Failure("DNS_CNAME_UNSUPPORTED")
                found = any(rr.name == qname and rr.rdtype == dns.rdatatype.TXT
                            and any(b"".join(r.strings).decode("ascii") == value for r in rr)
                            for rr in response.answer)
                if found:
                    break
            except (dns.exception.DNSException, OSError, UnicodeError):
                continue
        if not found:
            return False
    return True


def wait(target, item, timeout, check, probe=authoritative, sleep=time.sleep, clock=time.monotonic):
    deadline = clock() + timeout
    while clock() < deadline:
        check()
        try:
            if probe(target, item["name"], item["value"], deadline):
                return
        except dns.exception.DNSException:
            pass
        delay = min(5, deadline - clock())
        if delay > 0:
            sleep(delay)
    raise Failure("DNS_PROPAGATION_TIMEOUT")
