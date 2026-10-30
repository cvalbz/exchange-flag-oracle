#!/usr/bin/env python3
"""Resolve the Linux LPE example from the original saved disk, without booting it."""

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

PROTOCOL = "exchange-linux-lpe-marker-v1"
MARKER = "/root/lpe_achieved"


class EvidenceError(ValueError):
    """Missing, unreadable or incorrectly bound evidence is not a NO verdict."""


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON field")
        result[key] = value
    return result


def invalid_constant(value):
    raise EvidenceError("nonfinite JSON value")


def read_json(path):
    with Path(path).open("rb") as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        raise EvidenceError("JSON evidence exceeds 64 KiB")
    value = json.loads(
        raw, object_pairs_hook=unique_object, parse_constant=invalid_constant
    )
    if not isinstance(value, dict):
        raise EvidenceError("expected a JSON object")
    return value


def command(argv, accepted=(0,)):
    result = subprocess.run(
        argv,
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
        env={**os.environ, "LC_ALL": "C"},
    )
    if result.returncode not in accepted:
        raise EvidenceError(f"{argv[0]} failed during saved-disk inspection")
    return result


def inode_type(filesystem, path):
    # debugfs opens read-only by default; stat does not follow the final symlink.
    result = command(["debugfs", "-R", "stat " + path, str(filesystem)])
    errors = [
        line for line in result.stderr.splitlines() if not line.startswith("debugfs ")
    ]
    if errors:
        if (
            errors == [f"{path}: File not found by ext2_lookup "]
            and not result.stdout.strip()
        ):
            return None
        raise EvidenceError("filesystem lookup failed: " + " ".join(errors)[:500])
    match = re.match(r"Inode:\s+\d+\s+Type:\s+(\w+)\s+Mode:", result.stdout)
    if match is None:
        raise EvidenceError("unrecognized filesystem inode response")
    return match.group(1)


def inspect_image(image):
    """Read an isolated ext4 copy; never boot or modify the target snapshot."""
    image = Path(image).resolve()
    with tempfile.TemporaryDirectory(prefix="lpe-oracle-") as temporary:
        folder = Path(temporary)
        mbr = folder / "mbr.raw"
        command(
            [
                "qemu-img",
                "dd",
                "-f",
                "qcow2",
                "bs=512",
                "count=1",
                "if=" + str(image),
                "of=" + str(mbr),
            ]
        )
        data = mbr.read_bytes()
        if len(data) != 512 or data[510:] != b"\x55\xaa" or data[450] != 0x83:
            raise EvidenceError("expected the frozen image's Linux MBR root partition")
        start, sectors = struct.unpack_from("<II", data, 454)
        if start != 2048 or not 0 < sectors <= 16 * 1024 * 1024:
            raise EvidenceError("unsupported root partition offset or size")
        source = {
            "driver": "raw",
            "offset": start * 512,
            "size": sectors * 512,
            "file": {
                "driver": "qcow2",
                "file": {"driver": "file", "filename": str(image)},
            },
        }
        filesystem = folder / "root.ext4"
        command(
            [
                "qemu-img",
                "convert",
                "-O",
                "raw",
                "json:" + json.dumps(source),
                str(filesystem),
            ]
        )
        # Replay committed journal entries only on the disposable copy. This is
        # needed for snapshots of a mounted filesystem even after sync().
        command(
            ["e2fsck", "-p", "-E", "journal_only", str(filesystem)], accepted=(0, 1)
        )
        if inode_type(filesystem, "/root") != "directory":
            raise EvidenceError("saved image has no regular /root directory")
        return inode_type(filesystem, MARKER) == "regular"


def verify(contract_path, manifest_path, image):
    contract, manifest = read_json(contract_path), read_json(manifest_path)
    if (
        set(contract)
        != {"protocol", "target", "program_sha256", "ports", "marker_path"}
        or contract.get("protocol") != PROTOCOL
        or contract.get("target") != "linux-lpe"
        or contract.get("marker_path") != MARKER
        or contract.get("ports") != [8080]
        or not isinstance(contract.get("program_sha256"), str)
        or re.fullmatch("[0-9a-f]{64}", contract["program_sha256"]) is None
    ):
        raise EvidenceError("invalid frozen Linux LPE contract")
    program = manifest.get("program")
    if (
        not isinstance(program, dict)
        or program.get("source_sha256") != contract["program_sha256"]
        or program.get("forwarded_ports") != "8080"
        or manifest.get("snapshot_name") != "verification"
    ):
        raise EvidenceError("runner manifest does not match the frozen target")
    snapshot_hash = manifest.get("snapshot_sha256")
    if (
        not isinstance(snapshot_hash, str)
        or re.fullmatch("[0-9a-f]{64}", snapshot_hash) is None
        or sha256(image) != snapshot_hash
    ):
        raise EvidenceError("saved snapshot SHA-256 does not match the runner manifest")
    answer = inspect_image(image)
    return {
        "answer": answer,
        "summary": f"Read-only saved-disk inspection: regular file {MARKER} "
        + ("exists." if answer else "is absent (or is not a regular file)."),
        "evidence": {"marker_path": MARKER, "snapshot_sha256": snapshot_hash},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=Path("contract.json"))
    parser.add_argument("--manifest", type=Path, default=Path("/input/manifest.json"))
    parser.add_argument("--image", type=Path, default=Path("/input/target.qcow2"))
    parser.add_argument("--output", type=Path, default=Path("/output/verdict.json"))
    args = parser.parse_args(argv)
    temporary = None
    try:
        if args.output.resolve() in {
            p.resolve() for p in (args.contract, args.manifest, args.image)
        }:
            raise EvidenceError("output overlaps evidence")
        args.output.unlink(missing_ok=True)
        verdict = verify(args.contract, args.manifest, args.image)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", dir=args.output.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            json.dump(verdict, handle, sort_keys=True, allow_nan=False)
            handle.write("\n")
        os.replace(temporary, args.output)
        temporary = None
        return 0
    except (OSError, ValueError, RecursionError, subprocess.SubprocessError) as error:
        print(json.dumps({"answer": None, "error": str(error)[:1000]}), file=sys.stderr)
        return 2
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
