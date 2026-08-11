#!/usr/bin/env python3
"""Resolve exact ViaVersion coordinates from local Maven metadata fixtures only."""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_METADATA_BYTES = 1024 * 1024
SNAPSHOT_LINE = re.compile(r"^[0-9]+(?:\.[0-9]+){2,3}-SNAPSHOT$")


def read_metadata(path: Path) -> ET.Element:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"metadata must be a regular non-symlink file: {path}")
    content = path.read_bytes()
    if not content or len(content) > MAX_METADATA_BYTES:
        raise ValueError(f"metadata has an invalid size: {path}")
    upper = content.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError(f"metadata must not contain a DTD or entity declaration: {path}")
    try:
        return ET.fromstring(content)
    except ET.ParseError as error:
        raise ValueError(f"invalid Maven metadata: {path}") from error


def text_at(root: ET.Element, path: str, label: str) -> str:
    value = root.findtext(path)
    if value is None or not value.strip():
        raise ValueError(f"metadata is missing {label}")
    return value.strip()


def resolved_jar_version(root: ET.Element, snapshot_line: str) -> str:
    for candidate in root.findall("./versioning/snapshotVersions/snapshotVersion"):
        extension = (candidate.findtext("extension") or "").strip()
        classifier = (candidate.findtext("classifier") or "").strip()
        value = (candidate.findtext("value") or "").strip()
        if extension == "jar" and not classifier:
            snapshot_base = re.escape(snapshot_line.removesuffix("-SNAPSHOT"))
            if re.fullmatch(snapshot_base + r"-\d{8}\.\d{6}-\d+", value):
                return value
    raise ValueError("snapshot metadata is missing an exact unclassified JAR version")


def normalized_repository(value: str) -> str:
    repository = value.rstrip("/")
    if not repository.startswith("https://"):
        raise ValueError("repository URL must use HTTPS")
    return repository


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Resolve local Maven metadata without downloading or executing bytecode")
    parser.add_argument("--root-metadata", required=True, type=Path)
    parser.add_argument("--snapshot-metadata", required=True, type=Path)
    parser.add_argument("--repository-url", required=True)
    arguments = parser.parse_args()

    root = read_metadata(arguments.root_metadata)
    snapshot_line = text_at(root, "./versioning/latest", "latest snapshot line")
    if not SNAPSHOT_LINE.fullmatch(snapshot_line):
        raise ValueError(f"unsafe snapshot version: {snapshot_line}")

    snapshot = read_metadata(arguments.snapshot_metadata)
    resolved = resolved_jar_version(snapshot, snapshot_line)
    repository = normalized_repository(arguments.repository_url)
    group_path = "com/viaversion/viaversion-common"
    artifact_url = (
        f"{repository}/{group_path}/{snapshot_line}/"
        f"viaversion-common-{resolved}.jar"
    )
    print(f"VIAVERSION_DEPENDENCY_VERSION={snapshot_line}")
    print(f"VIAVERSION_RESOLVED_VERSION={resolved}")
    print(f"VIAVERSION_URL={artifact_url}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
