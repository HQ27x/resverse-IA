from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def slugify(value: str, fallback: str = "item") -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-._")
    return value or fallback


def new_id(prefix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{prefix}_{stamp}_{secrets.token_hex(3)}"


def normalize_addr(value: Any) -> str:
    """Return a canonical 0x-prefixed lowercase address when possible."""
    if value is None:
        raise ValueError("address is required")
    text = str(value).strip()
    if not text:
        raise ValueError("address is required")
    try:
        if text.lower().startswith("0x"):
            number = int(text, 16)
        elif re.fullmatch(r"[0-9a-fA-F]+", text):
            number = int(text, 16)
        else:
            return text
    except ValueError:
        return text
    return hex(number)


def parse_offset(value: str | int) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text, 10)


def parse_hex_bytes(value: str) -> bytes:
    text = re.sub(r"(?i)0x", "", str(value))
    text = re.sub(r"[\s,;:_-]+", "", text)
    if not text:
        raise ValueError("byte string is empty")
    if len(text) % 2:
        raise ValueError("byte string must have an even number of hex digits")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"invalid hex byte string: {exc}") from exc


def to_hex(data: bytes) -> str:
    return data.hex(" ")


def truncate_text(text: str | None, max_chars: int) -> str:
    if not text:
        return ""
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "\n... [truncated]"


def ensure_dir(path: str | Path) -> Path:
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    return target


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False)


def hex_dump(data: bytes, base_offset: int = 0) -> str:
    lines: list[str] = []
    for index in range(0, len(data), 16):
        chunk = data[index : index + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{base_offset + index:08x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


def safe_filename(value: str) -> str:
    value = Path(value).name
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    return value or "binary"
