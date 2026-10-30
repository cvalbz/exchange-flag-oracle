#!/usr/bin/env python3
# Generated from engine.py + verify.py by bundle.py; do not edit.

"""Deterministic, offline exchange-flag-v1 evidence verifier (Python stdlib only).

The capture and contract are trusted runner artifacts, not generator submissions.
See README.md for the exact supported evidence profile and failure taxonomy.
"""

from array import array
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import math
import re
import struct
from typing import Optional

PROTOCOL = "exchange-flag-v1"
MAX_PCAP = 64 * 1024 * 1024
MAX_STREAM = 4 * 1024 * 1024  # Both directions combined, per TCP connection.
MAX_ASSEMBLED = 16 * 1024 * 1024
MAX_RAW_PAYLOAD = 32 * 1024 * 1024
MAX_FLOWS = 256
MAX_SEGMENTS = 65536
MAX_RECORDS = 1000000
MAX_HEADER = 16384
MASK = (1 << 32) - 1
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HTTP_FIELD_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


class EvidenceError(Exception):
    """Infrastructure/misbound evidence: no Boolean verdict may be emitted."""


class Ineligible(Exception):
    """Well-formed evidence does not satisfy the protocol: Boolean false."""


def _need(condition, reason, error: type = EvidenceError):
    if not condition:
        raise error(reason)


def _object(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def _constant(_):
    raise EvidenceError("nonfinite_json_number")


def _float(text):
    value = float(text)
    _need(math.isfinite(value), "nonfinite_json_number")
    return value


def strict_json(data):
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_object,
            parse_constant=_constant,
            parse_float=_float,
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise EvidenceError("invalid_json") from exc


def _json_file(path, limit=65536):
    try:
        with open(path, "rb") as source:
            data = source.read(limit + 1)
    except OSError as exc:
        raise EvidenceError("missing_or_unreadable_json") from exc
    _need(len(data) <= limit, "json_too_large")
    return strict_json(data)


def _hex(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


@dataclass(frozen=True)
class Contract:
    target: str
    program_sha256: str
    ports: tuple

    @classmethod
    def from_dict(cls, value):
        _need(isinstance(value, dict), "invalid_contract")
        _need(value.get("protocol") == PROTOCOL, "invalid_contract_protocol")
        target = value.get("target")
        _need(
            isinstance(target, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", target) is not None,
            "invalid_contract_target",
        )
        digest = value.get("program_sha256")
        _need(_hex(digest, HEX64), "invalid_contract_program_hash")
        ports = value.get("ports")
        _need(
            isinstance(ports, list)
            and 1 <= len(ports) <= 32
            and all(type(p) is int and 1 <= p <= 65535 for p in ports),
            "invalid_contract_ports",
        )
        _need(len(set(ports)) == len(ports) and 8080 in ports, "invalid_contract_ports")
        return cls(target, digest, tuple(sorted(ports)))


def commitment(target, nonce, secret):
    return hashlib.sha256(
        PROTOCOL.encode("ascii")
        + b"\0"
        + target.encode("ascii")
        + b"\0"
        + nonce.encode("ascii")
        + b"\0"
        + secret.encode("ascii")
    ).hexdigest()


@dataclass
class Stream:
    syn: Optional[int] = None
    syn_order: int = 0
    syn_ack: bool = False
    fin: Optional[int] = None
    segments: list = field(default_factory=list)
    data: bytes = b""
    orders: Optional[array] = None

    def control(self, seq, flags, size, order):
        if flags & 2:
            _need(
                self.syn is None or self.syn == seq, "tcp_tuple_reuse_or_syn_conflict"
            )
            if self.syn is None:
                self.syn, self.syn_order, self.syn_ack = seq, order, bool(flags & 16)
            else:
                _need(self.syn_ack == bool(flags & 16), "tcp_syn_flag_conflict")
        start = (seq + bool(flags & 2)) & MASK
        if flags & 1:
            end = (start + size) & MASK
            _need(self.fin is None or self.fin == end, "tcp_fin_conflict")
            self.fin = end
        return start

    def assemble(self, budget):
        if not self.segments:
            if self.fin is not None:
                _need(
                    self.syn is not None and self.fin == ((self.syn + 1) & MASK),
                    "tcp_fin_gap_or_missing_syn",
                )
            return
        if self.syn is None:
            raise EvidenceError("missing_tcp_syn")
        _need(self.syn_order <= self.segments[0][2], "tcp_capture_started_midstream")
        origin = (self.syn + 1) & MASK
        pieces = [
            ((seq - origin) & MASK, data, order) for seq, data, order in self.segments
        ]
        length = max(offset + len(data) for offset, data, _ in pieces)
        _need(length <= MAX_STREAM, "tcp_sequence_or_stream_limit")
        budget[0] += length
        _need(budget[0] <= MAX_ASSEMBLED, "aggregate_stream_limit")
        data = bytearray(length)
        orders = array("I", [0]) * length
        for offset, content, order in pieces:  # Capture order: first observation wins.
            for index, byte in enumerate(content, offset):
                if orders[index]:
                    _need(data[index] == byte, "contradictory_tcp_overlap")
                else:
                    data[index], orders[index] = byte, order
        _need(all(orders), "tcp_gap")
        if self.fin is not None:
            _need(((self.fin - origin) & MASK) == length, "tcp_fin_gap_or_extra_data")
        self.data, self.orders = bytes(data), orders
        self.segments.clear()


@dataclass
class Flow:
    endpoints: tuple
    streams: tuple = field(default_factory=lambda: (Stream(), Stream()))


@dataclass
class Capture:
    flows: list
    first: object
    records: int
    size: int
    sha256: str


def _ip(address):
    return ".".join(str(x) for x in address)


def read_capture(path, ports, expected_size, expected_hash):
    """Read classic Ethernet PCAP. Timestamps never determine eligibility order."""
    flows, first = {}, None
    raw_size = segment_count = records = 0
    digest = hashlib.sha256()
    size = 0
    try:
        source = open(path, "rb")
    except OSError as exc:
        raise EvidenceError("missing_or_unreadable_capture") from exc
    with source:

        def read(count):
            nonlocal size
            try:
                data = source.read(count)
            except OSError as exc:
                raise EvidenceError("unreadable_capture") from exc
            size += len(data)
            _need(size <= MAX_PCAP, "capture_too_large")
            digest.update(data)
            return data

        header = read(24)
        _need(len(header) == 24, "truncated_pcap_header")
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1000000),
            b"\xa1\xb2\xc3\xd4": (">", 1000000),
            b"\x4d\x3c\xb2\xa1": ("<", 1000000000),
            b"\xa1\xb2\x3c\x4d": (">", 1000000000),
        }
        _need(header[:4] in formats, "unsupported_pcap_magic")
        endian, resolution = formats[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(
            endian + "HHiIII", header[4:]
        )
        _need((major, minor) == (2, 4), "unsupported_pcap_version")
        _need(
            0 < snaplen <= MAX_PCAP and linktype == 1,
            "unsupported_pcap_linktype_or_snaplen",
        )
        while True:
            record = read(16)
            if not record:
                break
            _need(len(record) == 16, "truncated_pcap_record_header")
            _, fraction, captured, original = struct.unpack(endian + "IIII", record)
            _need(fraction < resolution, "invalid_pcap_timestamp")
            _need(
                captured == original and 14 <= captured <= snaplen,
                "truncated_or_invalid_pcap_record",
            )
            _need(size + captured <= MAX_PCAP, "capture_too_large")
            frame = read(captured)
            _need(len(frame) == captured, "truncated_pcap_record")
            records += 1
            _need(records <= MAX_RECORDS, "pcap_record_limit")
            ethertype = frame[12:14]
            _need(ethertype not in (b"\x81\x00", b"\x88\xa8"), "unsupported_vlan")
            if ethertype != b"\x08\x00":  # ARP and non-IPv4 startup traffic.
                continue
            _need(len(frame) >= 34, "truncated_ipv4")
            ip = frame[14:]
            ihl = (ip[0] & 15) * 4
            total = int.from_bytes(ip[2:4], "big")
            _need(
                ip[0] >> 4 == 4 and 20 <= ihl <= total <= len(ip), "invalid_ipv4_length"
            )
            if ip[9] != 6:  # In particular DHCP/UDP.
                continue
            fragment = int.from_bytes(ip[6:8], "big")
            _need(fragment & 0xBFFF == 0, "unsupported_fragmented_ipv4_tcp")
            tcp = ip[ihl:total]
            _need(len(tcp) >= 20, "truncated_tcp")
            sport, dport, seq = struct.unpack("!HHI", tcp[:8])
            thl = (tcp[12] >> 4) * 4
            _need(20 <= thl <= len(tcp), "invalid_tcp_header_length")
            if sport not in ports and dport not in ports:
                continue
            _need(not (sport in ports and dport in ports), "ambiguous_target_ports")
            src, dst = (_ip(ip[12:16]), sport), (_ip(ip[16:20]), dport)
            key = tuple(sorted((src, dst)))
            if key not in flows:
                _need(len(flows) < MAX_FLOWS, "tcp_flow_limit")
                flows[key] = Flow(key)
            flow = flows[key]
            direction = 0 if src == key[0] else 1
            stream = flow.streams[direction]
            payload, flags = tcp[thl:], tcp[13]
            start = stream.control(seq, flags, len(payload), records)
            if payload:
                raw_size += len(payload)
                segment_count += 1
                _need(
                    raw_size <= MAX_RAW_PAYLOAD and segment_count <= MAX_SEGMENTS,
                    "tcp_payload_resource_limit",
                )
                stream.segments.append((start, payload, records))
                if dport in ports and first is None:
                    first = (records, key, direction, dst)
        _need(records > 0, "empty_capture")
        _need(size == expected_size, "capture_size_mismatch")
        actual_hash = digest.hexdigest()
        _need(hmac.compare_digest(actual_hash, expected_hash), "capture_hash_mismatch")
        budget = [0]
        for flow in flows.values():
            for stream in flow.streams:
                stream.assemble(budget)
            _need(
                sum(len(s.data) for s in flow.streams) <= MAX_STREAM, "tcp_stream_limit"
            )
        return Capture(list(flows.values()), first, records, size, actual_hash)


@dataclass
class Message:
    kind: str
    value: object
    body: bytes
    begin: int
    end: int
    first_order: int
    complete_order: int


def messages(stream, response=False):
    """Parse every byte as directional HTTP; bodies are never scanned as HTTP."""
    data, pos, result = stream.data, 0, []
    while pos < len(data):
        boundary = data.find(b"\r\n\r\n", pos, min(len(data), pos + MAX_HEADER + 4))
        _need(
            boundary >= 0 and boundary + 4 - pos <= MAX_HEADER,
            "incomplete_or_oversize_http_header",
            Ineligible,
        )
        lines = data[pos:boundary].split(b"\r\n")
        if response:
            match = re.fullmatch(
                rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?", lines[0]
            )
            if match is None:
                raise Ineligible("invalid_http_response_line")
            kind, value = "response", int(match[1])
        else:
            parts = lines[0].split(b" ")
            _need(
                len(parts) == 3
                and HTTP_FIELD_NAME.fullmatch(parts[0]) is not None
                and parts[2] in (b"HTTP/1.0", b"HTTP/1.1")
                and re.fullmatch(rb"/[\x21-\x7e]*", parts[1]) is not None,
                "invalid_http_request_line",
                Ineligible,
            )
            kind, value = parts[0].decode("ascii"), parts[1].decode("ascii")
        headers = {}
        _need(len(lines) <= 129, "http_header_count_limit", Ineligible)
        for line in lines[1:]:
            name, colon, content = line.partition(b":")
            _need(
                colon
                and HTTP_FIELD_NAME.fullmatch(name) is not None
                and all(byte == 9 or 32 <= byte <= 126 for byte in content),
                "invalid_http_header",
                Ineligible,
            )
            name = name.lower()
            _need(name not in headers, "duplicate_http_header", Ineligible)
            headers[name] = content.strip(b" \t")
        _need(
            b"transfer-encoding" not in headers,
            "transfer_encoding_forbidden",
            Ineligible,
        )
        length = headers.get(b"content-length", b"")
        _need(
            re.fullmatch(rb"0|[1-9][0-9]{0,7}", length) is not None,
            "missing_or_invalid_content_length",
            Ineligible,
        )
        count = int(length)
        _need(count <= MAX_STREAM, "http_body_limit", Ineligible)
        end = boundary + 4 + count
        _need(end <= len(data), "incomplete_http_body", Ineligible)
        if stream.orders is None:
            raise EvidenceError("missing_tcp_provenance")
        observed = stream.orders[pos:end]
        result.append(
            Message(
                kind,
                value,
                data[boundary + 4 : end],
                pos,
                end,
                min(observed),
                max(observed),
            )
        )
        pos = end
    return result


def _body_json(body, limit, reason):
    _need(len(body) <= limit, reason, Ineligible)
    try:
        value = strict_json(body)
    except EvidenceError as exc:
        raise Ineligible(reason) from exc
    _need(isinstance(value, dict), reason, Ineligible)
    return value


def _challenge_request(request):
    return request.kind == "GET" and request.value == "/challenge" and not request.body


def evaluate(capture, contract):
    _need(capture.first is not None, "challenge_missing", Ineligible)
    _, first_key, first_direction, endpoint = capture.first
    guest, port = endpoint
    _need(port == 8080, "first_target_payload_not_challenge", Ineligible)
    metadata, inbound = [], []
    for flow in capture.flows:
        if not any(s.data for s in flow.streams):
            continue
        server_indexes = [
            i
            for i, ep in enumerate(flow.endpoints)
            if ep[0] == guest and ep[1] in contract.ports
        ]
        _need(len(server_indexes) == 1, "foreign_target_endpoint", Ineligible)
        server_index = server_indexes[0]
        client_index = 1 - server_index
        client, server = flow.streams[client_index], flow.streams[server_index]
        _need(
            flow.endpoints[client_index][0] != guest, "target_loopback_flow", Ineligible
        )
        _need(
            client.syn is not None and not client.syn_ack,
            "missing_client_syn_or_target_initiated_flow",
        )
        _need(server.syn is not None and server.syn_ack, "missing_server_synack")
        _need(client.syn_order < server.syn_order, "tcp_handshake_order")
        inbound.append((flow, client))
        if flow.endpoints[server_index][1] != 8080:
            continue
        requests, replies = messages(client), messages(server, response=True)
        _need(len(replies) <= len(requests), "unsolicited_http_response", Ineligible)
        # Informational responses and response-before-request captures are not supported.
        for request, reply in zip(requests, replies):
            _need(reply.value >= 200, "informational_http_response", Ineligible)
            _need(
                request.complete_order < reply.first_order,
                "http_response_before_request_complete",
                Ineligible,
            )
        metadata.append((flow, client, requests, replies))
    initial = next(
        (entry for entry in metadata if entry[0].endpoints == first_key), None
    )
    if initial is None or not initial[2] or not _challenge_request(initial[2][0]):
        raise Ineligible("first_target_payload_not_challenge")
    _need(
        initial[0].streams[first_direction] is initial[1],
        "first_target_direction_invalid",
        Ineligible,
    )
    candidates = []
    for flow, client, requests, replies in metadata:
        for request, reply in zip(requests, replies):
            if _challenge_request(request) and reply.value == 200:
                candidates.append(
                    (reply.first_order, reply.complete_order, flow, reply)
                )
    _need(candidates, "commitment_missing", Ineligible)
    _, committed_at, commitment_flow, response = min(
        candidates, key=lambda entry: entry[0]
    )
    challenge = _body_json(response.body, 2048, "invalid_challenge_json")
    nonce, expected = challenge.get("nonce"), challenge.get("commitment")
    _need(
        challenge.get("protocol") == PROTOCOL
        and challenge.get("target") == contract.target
        and _hex(nonce, HEX32)
        and _hex(expected, HEX64),
        "invalid_challenge_fields",
        Ineligible,
    )
    # Only bytes belonging to an empty, canonical readiness request can precede
    # completion of the INITIAL 200 commitment. Packet indices, not timestamps.
    for flow, client in inbound:
        if not client.data or min(client.orders) > committed_at:
            continue
        entry = next((m for m in metadata if m[0] is flow), None)
        _need(entry is not None, "input_before_commitment", Ineligible)
        for request in entry[2]:
            if request.first_order <= committed_at:
                _need(
                    _challenge_request(request), "input_before_commitment", Ineligible
                )
    # A guest must not speak on another application port before commitment either.
    for flow in capture.flows:
        for index, ep in enumerate(flow.endpoints):
            if ep[0] == guest and ep[1] in contract.ports and ep[1] != 8080:
                stream = flow.streams[index]
                _need(
                    not stream.data or min(stream.orders) > committed_at,
                    "target_data_before_commitment",
                    Ineligible,
                )
    mismatch = "proof_missing"
    for flow, client, requests, _ in metadata:
        if (
            flow is commitment_flow
            or client.syn_order <= committed_at
            or not requests
            or requests[0].first_order <= committed_at
        ):
            continue
        request = requests[0]
        if request.kind != "POST" or request.value != "/proof":
            continue
        proof = _body_json(request.body, 256, "invalid_proof_json")
        _need(
            set(proof) == {"nonce", "secret"}
            and _hex(proof.get("nonce"), HEX32)
            and _hex(proof.get("secret"), HEX64),
            "invalid_proof_fields",
            Ineligible,
        )
        if proof["nonce"] != nonce:
            mismatch = "proof_nonce_mismatch"
        elif not hmac.compare_digest(
            commitment(contract.target, nonce, proof["secret"]), expected
        ):
            mismatch = "proof_commitment_mismatch"
        else:
            return {
                "commitment_packet": committed_at,
                "proof_packet": request.complete_order,
                "target_ipv4": guest,
            }
    raise Ineligible(mismatch)


def verify(contract_path, manifest_path, pcap_path):
    """Return a bounded Boolean verdict, or raise EvidenceError (no verdict)."""
    contract = Contract.from_dict(_json_file(contract_path))
    manifest = _json_file(manifest_path)
    _need(
        isinstance(manifest, dict)
        and isinstance(manifest.get("program"), dict)
        and isinstance(manifest.get("traffic"), dict),
        "invalid_manifest",
    )
    program, traffic = manifest["program"], manifest["traffic"]
    _need(_hex(program.get("source_sha256"), HEX64), "invalid_manifest_program_hash")
    _need(
        hmac.compare_digest(program["source_sha256"], contract.program_sha256),
        "program_image_hash_mismatch",
    )
    _need(
        isinstance(program.get("forwarded_ports"), str)
        and program["forwarded_ports"] == ",".join(map(str, contract.ports)),
        "manifest_forwarded_ports_mismatch",
    )
    if "target" in manifest:
        _need(manifest["target"] == contract.target, "manifest_target_mismatch")
    if "ports" in manifest:
        _need(
            isinstance(manifest["ports"], list)
            and all(type(p) is int for p in manifest["ports"])
            and manifest["ports"] == list(contract.ports),
            "manifest_ports_mismatch",
        )
    _need(
        type(traffic.get("size_bytes")) is int
        and 24 <= traffic["size_bytes"] <= MAX_PCAP,
        "invalid_manifest_capture_size",
    )
    _need(_hex(traffic.get("sha256"), HEX64), "invalid_manifest_capture_hash")
    evidence = {
        "protocol": PROTOCOL,
        "target": contract.target,
        "program_sha256": contract.program_sha256,
        "traffic_sha256": traffic["sha256"],
    }
    try:
        capture = read_capture(
            pcap_path, contract.ports, traffic["size_bytes"], traffic["sha256"]
        )
        evidence.update(
            {
                "packets": capture.records,
                "connections": len(capture.flows),
                "size_bytes": capture.size,
            }
        )
        evidence.update(evaluate(capture, contract))
        return {
            "answer": True,
            "reason": "captured_secret_proof",
            "summary": "Captured proof matches the initial pre-input commitment.",
            "evidence": evidence,
        }
    except Ineligible as exc:
        return {
            "answer": False,
            "reason": str(exc),
            "summary": "Protocol not satisfied: " + str(exc) + ".",
            "evidence": evidence,
        }

"""Small file-only CLI for engine.verify; never invokes a target or a service."""

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

# Engine API is defined above.


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", default="/input/contract.json")
    parser.add_argument("--manifest", default="/input/manifest.json")
    parser.add_argument("--pcap", default="/input/traffic.pcap")
    parser.add_argument("--output", default="/output/verdict.json")
    args = parser.parse_args(argv)
    output, temporary = Path(args.output), None
    try:
        if output.resolve() in {
            Path(p).resolve() for p in (args.contract, args.manifest, args.pcap)
        }:
            raise EvidenceError("output_overlaps_input")
        # A failed rerun must not leave a previous YES looking like a new verdict.
        output.unlink(missing_ok=True)
        verdict = verify(args.contract, args.manifest, args.pcap)
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=".verdict-",
            delete=False,
        ) as handle:
            temporary = handle.name
            json.dump(
                verdict, handle, sort_keys=True, separators=(",", ":"), allow_nan=False
            )
            handle.write("\n")
        os.replace(temporary, output)
        temporary = None
        return 0
    except (EvidenceError, OSError) as exc:
        reason = (
            str(exc)
            if isinstance(exc, EvidenceError)
            else "evidence_or_output_io_failure"
        )
        print(json.dumps({"answer": None, "error": reason}), file=sys.stderr)
        return 2
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
