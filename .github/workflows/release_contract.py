#!/usr/bin/env python3
"""Validate release identity and assemble a complete, checksummed asset set."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tomllib


def version_from_tag(tag):
    if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", tag):
        raise ValueError("release tag must be a stable vMAJOR.MINOR.PATCH version")
    return tag[1:]


def validate_identity(root, tag):
    version = version_from_tag(tag)
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    if manifest["package"]["version"] != version:
        raise ValueError("release tag does not match Cargo.toml")
    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()
    head = git("rev-parse", "HEAD")
    tagged = git("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    if head != tagged:
        raise ValueError("release tag does not identify the checked-out commit")
    return {"tag": tag, "version": version, "sha": head}


def expected_assets(version):
    return {
        "unifictl-x86_64-unknown-linux-gnu.tar.gz",
        "unifictl-x86_64-apple-darwin.tar.gz",
        "unifictl-aarch64-apple-darwin.tar.gz",
        "unifictl-x86_64-pc-windows-msvc.zip",
        f"unifictl_{version}_amd64.deb",
        f"unifictl_{version}_arm64.deb",
        "unifictl-x86_64.pkg.tar.zst",
        "unifictl-aarch64.pkg.tar.zst",
    }


def assemble_assets(source, destination, tag, sha, lockfile):
    version = version_from_tag(tag)
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("release source must be a full commit SHA")
    expected = expected_assets(version)
    found = {}
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError("artifact tree contains a symbolic link")
        if not path.is_file():
            continue
        if path.name not in expected or path.name in found or path.stat().st_size == 0:
            raise ValueError(f"unexpected, duplicate or empty release asset: {path.name}")
        found[path.name] = path
    if found.keys() != expected:
        raise ValueError(f"missing release assets: {', '.join(sorted(expected - found.keys()))}")
    # Refuse a stale destination so leftover assets cannot become part of a release.
    destination.mkdir()
    for name in sorted(found):
        shutil.copyfile(found[name], destination / name)
    metadata = {
        "tag": tag, "commit": sha,
        "cargo_lock_sha256": hashlib.sha256(lockfile.read_bytes()).hexdigest(),
    }
    (destination / "release-source.json").write_text(json.dumps(metadata, indent=2) + "\n")
    sums = []
    for path in sorted(destination.iterdir()):
        sums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
    (destination / "checksums.txt").write_text("".join(sums))



def compare_published_assets(expected, downloaded):
    wanted = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in expected.iterdir() if p.is_file()}
    got = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in downloaded.iterdir() if p.is_file()}
    if not wanted or wanted != got:
        raise ValueError("uploaded release assets do not exactly match the verified artifact set")


def reject_public_release(repository, tag):
    version_from_tag(tag)
    pages = json.loads(subprocess.check_output(
        ["gh", "api", f"repos/{repository}/releases", "--paginate", "--slurp"], text=True))
    if any(release["tag_name"] == tag and not release["draft"] for page in pages for release in page):
        raise ValueError("refusing to modify an already-public release; prepare a new version")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    metadata = sub.add_parser("identity")
    metadata.add_argument("--root", type=Path, default=Path("."))
    assets = sub.add_parser("assets")
    assets.add_argument("--source", type=Path, default=Path("artifacts"))
    assets.add_argument("--destination", type=Path, default=Path("dist"))
    assets.add_argument("--lockfile", type=Path, default=Path("Cargo.lock"))
    sub.add_parser("preflight")
    uploaded = sub.add_parser("uploaded")
    uploaded.add_argument("--expected", type=Path, default=Path("dist"))
    uploaded.add_argument("--downloaded", type=Path, default=Path("published"))
    args = parser.parse_args()
    tag = os.environ["RELEASE_TAG"]
    if args.command == "identity":
        identity = validate_identity(args.root, tag)
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.writelines(f"{name}={value}\n" for name, value in identity.items())
    elif args.command == "preflight":
        reject_public_release(os.environ["GITHUB_REPOSITORY"], tag)
    elif args.command == "uploaded":
        compare_published_assets(args.expected, args.downloaded)
    else:
        assemble_assets(args.source, args.destination, tag, os.environ["RELEASE_SHA"], args.lockfile)


if __name__ == "__main__":
    main()
