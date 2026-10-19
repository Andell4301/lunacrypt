#!/usr/bin/env python3
"""Bundle a built CLI with its documentation and dependency license notices."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import zipfile


ROOT = Path(__file__).resolve().parent.parent
NOTICE_NAME = re.compile(
    r"^(?:licen[sc]es?|copying|copyrights?|notices?)(?:$|[. _-])", re.IGNORECASE
)


def dependency_notices(metadata, root_id):
    sections = [
        "Third-party licenses and notices\n"
        "===============================\n\n"
        "These are the original license and notice files from Cargo's resolved\n"
        "dependencies for this target, including build and development tools.\n"
        "Some listed packages may not be included in the executable.\n"
    ]
    resolved_ids = {node["id"] for node in metadata["resolve"]["nodes"]}
    packages = sorted(metadata["packages"], key=lambda p: (p["name"], p["version"], p["id"]))
    for package in packages:
        if package["id"] == root_id or package["id"] not in resolved_ids:
            continue
        source = Path(package["manifest_path"]).resolve().parent
        files = {
            path
            for path in source.rglob("*")
            if path.is_file() and NOTICE_NAME.match(path.name)
        }
        if package["license_file"]:
            files.add(source / package["license_file"])
        if not files:
            raise ValueError(
                f"no license files found for {package['name']} {package['version']}"
            )

        sections.append(
            f"\n{'=' * 72}\n{package['name']} {package['version']}\n"
            f"License expression: {package['license'] or 'see license files'}\n"
            f"Source: {package['source'] or package.get('repository') or 'local dependency'}\n"
        )
        for path in sorted(files, key=lambda path: path.relative_to(source).as_posix()):
            if not path.resolve().is_relative_to(source):
                raise ValueError(f"license file is outside its package: {path}")
            text = path.read_bytes().decode("utf-8")
            sections.append(f"\n--- {path.relative_to(source).as_posix()} ---\n\n{text}")
            if not text.endswith("\n"):
                sections.append("\n")
    return "".join(sections).encode("utf-8")


def archive_bytes(prefix, files, windows):
    output = io.BytesIO()
    if windows:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content, mode in files:
                entry = zipfile.ZipInfo(f"{prefix}/{name}", (1980, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | mode) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(entry, content)
    else:
        # Fixed timestamps and ownership keep repeated packaging runs identical.
        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name, content, mode in files:
                    entry = tarfile.TarInfo(f"{prefix}/{name}")
                    entry.size = len(content)
                    entry.mode = mode
                    archive.addfile(entry, io.BytesIO(content))
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Rust target used for the release build")
    parser.add_argument("--output", type=Path, default=Path("dist"), help="destination directory")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)+", args.target):
        parser.error("target must be a Rust target triple")

    result = subprocess.run(
        [
            "cargo", "metadata", "--locked", "--offline", "--format-version", "1",
            "--filter-platform", args.target,
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    metadata = json.loads(result.stdout)
    root_id = metadata["resolve"]["root"]
    package = next(package for package in metadata["packages"] if package["id"] == root_id)
    if package["name"] != "lunacrypt":
        raise ValueError("expected the LunaCrypt package at the repository root")
    version = package["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)*", version):
        raise ValueError("package version is not safe for an archive filename")

    windows = "windows" in args.target.split("-")
    executable = "lunacrypt.exe" if windows else "lunacrypt"
    binary = Path(metadata["target_directory"]) / args.target / "release" / executable
    if not binary.is_file():
        raise ValueError(
            f"missing release executable: {binary}; "
            f"run cargo build --release --locked --target {args.target} first"
        )
    files = [(executable, binary.read_bytes(), 0o755)]
    for name in [
        "README.md", "SECURITY.md", "ARCHITECTURE.md", "CONTRIBUTING.md",
        "RELEASE_NOTES.md", "LICENSE-GPL-3.0",
    ]:
        files.append((name, (ROOT / name).read_bytes(), 0o644))
    files.append(("THIRD-PARTY-NOTICES.txt", dependency_notices(metadata, root_id), 0o644))

    prefix = f"lunacrypt-v{version}-{args.target}"
    filename = prefix + (".zip" if windows else ".tar.gz")
    content = archive_bytes(prefix, files, windows)
    destination = ROOT / args.output
    destination.mkdir(parents=True, exist_ok=True)
    archive_path = destination / filename
    archive_path.write_bytes(content)
    checksum_path = destination / f"{filename}.sha256"
    # Write bytes so Windows keeps the newline expected by Unix checksum tools.
    checksum_path.write_bytes(f"{hashlib.sha256(content).hexdigest()}  {filename}\n".encode("ascii"))
    print(archive_path)
    print(checksum_path)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
