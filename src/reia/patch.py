from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from .binary import BinaryImage
from .config import ReiaError
from .policy import PolicyError, require_patch_allowed
from .store import Store
from .util import (
    hex_dump,
    new_id,
    normalize_addr,
    sha256_file,
    to_hex,
    utc_now,
)


class PatchError(ReiaError):
    pass


def create_patch_plan(
    store: Store,
    program_token: str,
    *,
    address: str | None,
    file_offset: int | None,
    new_bytes: bytes,
    reason: str,
    authorization: str | None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not new_bytes:
        raise PatchError("new patch bytes are empty")
    if not reason.strip():
        raise PatchError("patch reason is required")

    program = store.get_program(program_token)
    profile = program["profile"]
    require_patch_allowed(profile, authorization)

    path = Path(program["path"]).expanduser()
    if not path.exists() or not path.is_file():
        raise PatchError(f"binary file not found: {path}")

    actual_sha = sha256_file(path)
    expected_sha = str(program.get("sha256") or "").lower()
    if expected_sha not in ("", "unknown") and actual_sha != expected_sha:
        raise PatchError(
            "binary hash does not match the imported program; re-import it before patching"
        )
    if expected_sha in ("", "unknown"):
        raise PatchError("program has no trusted hash; re-import it before patching")

    image = BinaryImage.from_path(path)
    mapped_offset: int | None = None
    if address:
        canonical_address = normalize_addr(address)
        mapped_offset = image.address_to_offset(canonical_address)
    else:
        canonical_address = None

    if file_offset is None:
        if mapped_offset is None:
            raise PatchError("provide --address or --file-offset")
        offset = mapped_offset
    else:
        offset = int(file_offset)
        if offset < 0:
            raise PatchError("file offset must be non-negative")
        if mapped_offset is not None and mapped_offset != offset:
            raise PatchError(
                f"address {canonical_address} maps to file offset 0x{mapped_offset:x}, "
                f"not 0x{offset:x}"
            )

    original = image.read(offset, len(new_bytes))
    if original == new_bytes:
        raise PatchError("new bytes are identical to the original bytes")

    plan_id = new_id("patch")
    plan = {
        "schema_version": 1,
        "id": plan_id,
        "program_id": program["id"],
        "program_name": program["name"],
        "profile": profile,
        "target_address": canonical_address,
        "file_offset": offset,
        "file_offset_hex": hex(offset),
        "original_bytes": to_hex(original),
        "new_bytes": to_hex(new_bytes),
        "reason": reason.strip(),
        "authorization": (authorization or "").strip(),
        "status": "planned",
        "created_at": utc_now(),
        "image": image.describe(),
    }
    for key, value in (extra or {}).items():
        if key not in plan:
            plan[key] = value
    store.insert_patch_plan(plan)
    store.audit(
        "patch_plan_created",
        plan_id,
        {
            "program_id": program["id"],
            "address": canonical_address,
            "file_offset": offset,
            "original": plan["original_bytes"],
            "new": plan["new_bytes"],
            "reason": plan["reason"],
        },
    )
    return plan


def apply_patch_plan(
    store: Store,
    plan_id: str,
    *,
    patches_dir: str | Path,
    approve: bool,
    authorization: str | None = None,
) -> dict[str, Any]:
    if not approve:
        raise PatchError("patch application requires explicit --approve")

    plan = store.get_patch_plan(plan_id)
    program = store.get_program(plan["program_id"])
    profile = program["profile"]
    effective_authorization = authorization or plan.get("authorization") or ""
    require_patch_allowed(profile, effective_authorization)

    if plan["status"] != "planned":
        raise PatchError(f"patch plan is not in planned state: {plan['status']}")

    if plan.get("advisor") and (plan.get("validation") or {}).get("ok") is not True:
        raise PatchError(
            "this plan came from the Patch Advisor but did not pass validation; "
            "rebuild it with 'reia patch advise'"
        )

    source = Path(program["path"]).expanduser()
    if not source.exists() or not source.is_file():
        raise PatchError(f"binary file not found: {source}")
    actual_sha = sha256_file(source)
    if actual_sha != program["sha256"]:
        raise PatchError("binary hash changed since import; refusing to patch")

    image = BinaryImage.from_path(source)
    offset = int(plan["file_offset"])
    original = bytes.fromhex(plan["original_bytes"].replace(" ", ""))
    new = bytes.fromhex(plan["new_bytes"].replace(" ", ""))
    if len(new) != len(original):
        raise PatchError(
            f"patch length mismatch: plan replaces {len(original)} byte(s) with {len(new)}"
        )
    current = image.read(offset, len(original))
    if current != original:
        raise PatchError(
            "bytes at the target offset changed; refusing to apply a stale patch plan"
        )

    patch_dir = Path(patches_dir).expanduser().resolve() / plan_id
    patch_dir.mkdir(parents=True, exist_ok=True)
    source_name = source.name
    patched_path = patch_dir / f"{source_name}.patched"
    backup_path = patch_dir / f"{source_name}.orig"
    shutil.copy2(source, backup_path)
    shutil.copy2(source, patched_path)

    with open(patched_path, "r+b") as handle:
        handle.seek(offset)
        handle.write(new)
        handle.flush()
        os.fsync(handle.fileno())

    expected_data = image.data[:offset] + new + image.data[offset + len(new):]
    if patched_path.read_bytes() != expected_data:
        patched_path.unlink(missing_ok=True)
        raise PatchError("post-write verification failed; the patched copy was removed")

    patched_sha = sha256_file(patched_path)
    diff = render_patch_diff(plan)
    (patch_dir / "diff.txt").write_text(diff + "\n", encoding="utf-8")

    applied = dict(plan)
    applied.update(
        {
            "status": "applied",
            "applied_at": utc_now(),
            "patched_path": str(patched_path),
            "backup_path": str(backup_path),
            "original_sha256": actual_sha,
            "patched_sha256": patched_sha,
            "authorization": effective_authorization,
            "approved": True,
        }
    )
    (patch_dir / "plan.json").write_text(
        json.dumps(applied, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    store.update_patch_plan(
        plan_id,
        status="applied",
        applied_at=applied["applied_at"],
        patched_path=str(patched_path),
        backup_path=str(backup_path),
        authorization=effective_authorization,
        plan_json=json.dumps(applied, ensure_ascii=False),
    )
    store.audit(
        "patch_applied",
        plan_id,
        {
            "program_id": program["id"],
            "patched_path": str(patched_path),
            "original_sha256": actual_sha,
            "patched_sha256": patched_sha,
            "authorization": effective_authorization,
        },
    )
    return applied


def rollback_patch_plan(
    store: Store,
    plan_id: str,
    *,
    patches_dir: str | Path,
) -> dict[str, Any]:
    plan = store.get_patch_plan(plan_id)
    if plan["status"] != "applied":
        raise PatchError(f"patch plan is not applied: {plan['status']}")

    patched = Path(plan["patched_path"]) if plan.get("patched_path") else None
    rolled_back_path: str | None = None
    if patched and patched.exists():
        target = patched.with_name(f"rolledback_{patched.name}")
        if target.exists():
            target.unlink()
        patched.replace(target)
        rolled_back_path = str(target)

    updated = dict(plan)
    updated.update({"status": "rolled_back", "rolled_back_at": utc_now()})
    patch_dir = Path(patches_dir).expanduser().resolve() / plan_id
    if patch_dir.exists():
        (patch_dir / "plan.json").write_text(
            json.dumps(updated, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    store.update_patch_plan(
        plan_id,
        status="rolled_back",
        plan_json=json.dumps(updated, ensure_ascii=False),
    )
    store.audit(
        "patch_rolled_back",
        plan_id,
        {"program_id": plan["program_id"], "rolled_back_path": rolled_back_path},
    )
    return updated


def render_patch_diff(plan: dict[str, Any]) -> str:
    original = bytes.fromhex(plan["original_bytes"].replace(" ", ""))
    new = bytes.fromhex(plan["new_bytes"].replace(" ", ""))
    offset = int(plan["file_offset"])
    lines = [
        f"patch: {plan['id']}",
        f"program: {plan.get('program_name', plan['program_id'])}",
        f"profile: {plan['profile']}",
        f"address: {plan.get('target_address')}",
        f"file offset: 0x{offset:x}",
        f"reason: {plan['reason']}",
    ]
    advisor = plan.get("advisor") or {}
    if advisor:
        lines.append(f"advisor: {advisor.get('candidate_id')} ({advisor.get('kind')})")
    validation = plan.get("validation") or {}
    if validation:
        lines.append(f"validation: {'ok' if validation.get('ok') else 'failed'}")
    lines.extend(
        [
            "",
            "original:",
            hex_dump(original, offset),
            "",
            "new:",
            hex_dump(new, offset),
        ]
    )
    return "\n".join(lines)
