from __future__ import annotations

import hashlib
import json
import uuid


def stable_json(data) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def digest_json(data) -> str:
    return sha256_hex(stable_json(data))


def make_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def new_trace_id() -> str:
    while True:
        x = uuid.uuid4().hex + uuid.uuid4().hex[:16]
        x = x[:32]
        if x != "0" * 32:
            return x


def new_span_id() -> str:
    while True:
        x = uuid.uuid4().hex[:16]
        if x != "0" * 16:
            return x


def parse_traceparent(value: str | None):
    if not value:
        return None
    parts = value.split("-")
    if len(parts) != 4:
        return None
    version, trace_id, parent_id, flags = parts
    if len(trace_id) != 32 or len(parent_id) != 16:
        return None
    if trace_id == "0" * 32 or parent_id == "0" * 16:
        return None
    return {
        "version": version,
        "trace_id": trace_id,
        "parent_id": parent_id,
        "flags": flags,
    }