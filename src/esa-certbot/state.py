"""Small NAS journal; no automatic stale-lock takeover or secret logging."""
import json
import os
import time
import uuid
from pathlib import Path


class Failure(Exception):
    """Only fixed, non-sensitive codes cross the handler boundary."""


def read(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return default


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + "." + uuid.uuid4().hex)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


class Lock:
    # ponytail: no lease stealing. A killed invocation needs operator recovery;
    # upgrade to a fenced distributed lock before supporting automatic takeover.
    def __init__(self, root, ttl=1200):
        self.path = Path(root) / "lock"
        self.owner = uuid.uuid4().hex
        self.token = self.path / self.owner
        self.expires = time.time() + ttl
        self.quarantined = False

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.path.mkdir(mode=0o700)
        except FileExistsError:
            tokens = list(self.path.iterdir())
            if any((read(p) or {}).get("quarantined") for p in tokens):
                raise Failure("LOCK_QUARANTINED") from None
            expired = tokens and all((read(p) or {}).get("expires", 0) < time.time() for p in tokens)
            raise Failure("LOCK_STALE" if expired else "LOCK_BUSY") from None
        write(self.token, {"owner": self.owner, "expires": self.expires})
        return self

    def check(self):
        if self.quarantined or not self.token.exists() or time.time() >= self.expires:
            raise Failure("LOCK_LOST")

    def quarantine(self):
        # Keep the mutex even if writing the revocation marker fails.
        self.quarantined = True
        self.expires = 0
        write(self.token, {"owner": self.owner, "expires": 0, "quarantined": True})

    def __exit__(self, *args):
        if self.quarantined:
            return
        # An old execution cannot remove the token of a replacement owner.
        try:
            self.token.unlink()
        except FileNotFoundError:
            return
        try:
            self.path.rmdir()
        except OSError:
            pass


def require_nas(root):
    """Fail closed rather than pretending /tmp is a cross-instance lock."""
    root = Path(root).resolve()
    mounts = Path("/proc/mounts").read_text().splitlines()
    for line in mounts:
        fields = line.split()
        if fields[2] in ("nfs", "nfs4") and root.is_relative_to(Path(fields[1])):
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            return root
    raise Failure("SHARED_NAS_REQUIRED")
