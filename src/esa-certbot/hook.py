"""Certbot child hook: credentials arrive only from the FC invocation context."""
import json
import os
import sys
import time
from pathlib import Path
from cloud import Cloud
from dns01 import create, cleanup, wait
from state import Failure, read


def main():
    target = json.loads(os.environ["FC_CERTBOT_TARGET"])
    if os.environ["CERTBOT_DOMAIN"] != target["domain"]:
        raise Failure("HOOK_DOMAIN_BOUNDARY")
    token = Path(os.environ["FC_CERTBOT_LOCK_TOKEN"])
    def check():
        state = read(token)
        if not state or state["expires"] <= time.time():
            raise Failure("LOCK_LOST")
    check()
    cloud = Cloud(json.loads(os.environ["FC_CERTBOT_STS"]), os.environ["FC_CERTBOT_ACCOUNT"], target)
    run = Path(os.environ["FC_CERTBOT_RUN"])
    if sys.argv[1] == "auth":
        value = os.environ["CERTBOT_VALIDATION"]
        if not 1 <= len(value) <= 512:
            raise Failure("HOOK_VALIDATION")
        item = create(cloud, target, run, value, check)
        print(json.dumps({"event": "dns_created", "at": int(time.time())}), flush=True)
        wait(target, item, int(os.environ["FC_CERTBOT_DNS_TIMEOUT"]), check,
             stable_seconds=int(os.environ["FC_CERTBOT_DNS_STABLE_SECONDS"]))
        print(json.dumps({"event": "dns_stable", "at": int(time.time())}), flush=True)
    elif sys.argv[1] == "cleanup":
        # Clean each challenge's exact ID, including earlier hooks in this run.
        cleanup(cloud, target, run, check)
    else:
        raise Failure("HOOK_ACTION")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Certbot may copy hook stderr into logs. Never include SDK bodies or TXT.
        sys.exit("FC_CERTBOT_DNS_HOOK_FAILED")
