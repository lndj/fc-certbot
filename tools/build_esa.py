"""Build a Linux x86_64 FC zip locally; never connects to Alibaba Cloud."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/esa-certbot"
BUILD = ROOT / "build/esa"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=SOURCE / "config.example.json")
    parser.add_argument("--reuse-deps", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if subprocess.check_output(["uv", "--version"], text=True).split()[1] != "0.6.16":
        raise SystemExit("Use uv==0.6.16 (see docs/ESA.zh-CN.md)")
    lock_digest = hashlib.sha256((SOURCE / "requirements.lock").read_bytes()).hexdigest()
    dependencies = BUILD / "python"
    marker = BUILD / "dependencies.sha256"
    BUILD.mkdir(parents=True, exist_ok=True)
    if args.reuse_deps:
        if not marker.exists() or marker.read_text() != lock_digest:
            raise SystemExit("Dependency lock changed; rebuild without --reuse-deps")
    else:
        if dependencies.exists():
            shutil.rmtree(dependencies)
        native_flags = [flag for package in ("cryptography", "cffi", "aiohttp", "frozenlist",
                                             "multidict", "propcache", "yarl")
                        for flag in ("--only-binary", package)]
        subprocess.run(["uv", "--no-config", "pip", "install", "--python-version", "3.10",
                        "--python-platform", "x86_64-manylinux_2_28", *native_flags,
                        "--build-constraints", str(ROOT / "tools/build-constraints.txt"),
                        "--require-hashes", "--target", str(dependencies),
                        "-r", str(SOURCE / "requirements.lock")], check=True)
        marker.write_text(lock_digest)
    files = [(p.name, p) for p in SOURCE.glob("*.py")]
    files.append(("config.json", args.config))
    files.extend(("python/" + str(p.relative_to(dependencies)), p) for p in dependencies.rglob("*")
                 if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
                 and "bin" not in p.relative_to(dependencies).parts)
    bundle = BUILD / "fc-certbot-esa.zip"
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, path in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100600 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes(), compresslevel=9)
    print("build/esa/fc-certbot-esa.zip sha256=" + hashlib.sha256(bundle.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
