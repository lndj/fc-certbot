import json
import os
from cloud import Cloud
from config import load, select
from engine import run
from state import Failure, require_nas


def handler(event, context):
    target_id = "invalid"
    try:
        os.umask(0o077)
        cfg = load(os.environ["FC_CERTBOT_CONFIG"])
        evt = json.loads(event) if isinstance(event, (str, bytes, bytearray)) else event
        target = select(cfg, evt)
        target_id = evt["target"]
        # The FC role credentials are refreshed for every invocation. Never read
        # ~/.aliyun, ~/.s, profile files, or deployment access-key environment vars.
        credentials = {"access_key_id": context.credentials.access_key_id,
                       "access_key_secret": context.credentials.access_key_secret,
                       "security_token": context.credentials.security_token}
        root = require_nas(os.environ["FC_CERTBOT_STATE_ROOT"])
        cloud = Cloud(credentials, context.account_id, target)
        result = run(cfg, evt, root, cloud, credentials, context.account_id)
        print(json.dumps({"event": "fc_certbot", "target": target_id, "phase": result["status"]}))
        return result
    except Exception as exc:
        code = str(exc) if isinstance(exc, Failure) else "OPERATION_FAILED"
        print(json.dumps({"event": "fc_certbot", "target": target_id, "phase": "failed", "code": code}))
        # FC records this as a failed invocation: SLS/FC alarms can consume it.
        raise RuntimeError(code) from None
