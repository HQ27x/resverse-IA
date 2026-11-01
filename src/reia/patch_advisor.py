"""Deterministic patch candidates and static validation.

The AI never writes bytes here. It may only pick one candidate id from a
fixed, locally generated list; the engine builds and validates the bytes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .binary import BinaryImage
from .config import ReiaError
from .ollama import OllamaError, chat
from .patch import PatchError, create_patch_plan
from .policy import require_patch_allowed
from .store import Store
from .util import normalize_addr, to_hex

try:
    import iced_x86
except ImportError:  # pragma: no cover - reported when the advisor is used
    iced_x86 = None

MAX_FUNCTION_BYTES = 8192
MAX_INSTRUCTIONS = 512
MAX_CANDIDATES = 24
MAX_RETURN_VALUE = 0xFFFFFFFF
MAX_RETURN_SPAN = 256
NOP = b"\x90"

CONDITION_NAMES = {
    0: "none",
    1: "o",
    2: "no",
    3: "b",
    4: "ae",
    5: "e",
    6: "ne",
    7: "be",
    8: "a",
    9: "s",
    10: "ns",
    11: "p",
    12: "np",
    13: "l",
    14: "ge",
    15: "le",
    16: "g",
}


def _iced() -> Any:
    if iced_x86 is None:
        raise PatchError(
            "the Patch Advisor requires iced-x86; install it with: "
            "pip install \"resverse-ia[patch]\""
        )
    return iced_x86


def _condition_name(value: int) -> str:
    return CONDITION_NAMES.get(int(value), f"cc_{int(value)}")


def _invert_condition(value: int) -> int:
    # iced numbers condition pairs consecutively: (O,NO), (B,AE), (E,NE), ...
    return value + 1 if value % 2 == 1 else value - 1


def _decode(image: BinaryImage, ip: int, data: bytes) -> tuple[list[Any], str]:
    ix = _iced()
    decoder = ix.Decoder(image.bits, data)
    decoder.ip = ip
    instructions: list[Any] = []
    error = ""
    while decoder.can_decode and len(instructions) < MAX_INSTRUCTIONS:
        start = decoder.ip
        instruction = decoder.decode()
        if instruction.len <= 0 or start + instruction.len > ip + len(data):
            error = f"truncated instruction at {hex(start)}"
            break
        decode_error = decoder.last_error
        instructions.append(instruction)
        if decode_error:
            error = f"decode error {decode_error} at {hex(start)}"
            break
    return instructions, error


def _formatter() -> Any:
    ix = _iced()
    return ix.Formatter(ix.FormatterSyntax.INTEL)


def _is_near_branch(instruction: Any) -> bool:
    ix = _iced()
    return instruction.op0_kind in (
        ix.OpKind.NEAR_BRANCH16,
        ix.OpKind.NEAR_BRANCH32,
        ix.OpKind.NEAR_BRANCH64,
    )


def _is_jcc(instruction: Any) -> bool:
    ix = _iced()
    return instruction.condition_code != ix.ConditionCode.NONE and _is_near_branch(
        instruction
    )


def _has_indirect_control_flow(instructions: list[Any]) -> bool:
    ix = _iced()
    return any(
        instruction.mnemonic in (ix.Mnemonic.JMP, ix.Mnemonic.CALL)
        and not _is_near_branch(instruction)
        for instruction in instructions
    )


def _encode_return(value: int, bits: int) -> bytes:
    if bits not in (32, 64):
        raise PatchError("return constants are supported only for x86/x64")
    if value < 0 or value > MAX_RETURN_VALUE:
        raise PatchError(
            f"return value {value} is outside the supported 32-bit range "
            f"0..{MAX_RETURN_VALUE}"
        )
    if value == 0:
        return b"\x31\xc0\xc3"
    return b"\xb8" + int(value).to_bytes(4, "little") + b"\xc3"


def _context(
    store: Store, program_token: str, function_identifier: str
) -> tuple[dict[str, Any], dict[str, Any], BinaryImage, str, int, int, bytes]:
    program = store.get_program(program_token)
    row = store.get_function(program["id"], function_identifier)
    source = Path(program["path"]).expanduser()
    if not source.exists() or not source.is_file():
        raise PatchError(f"binary file not found: {source}")

    image = BinaryImage.from_path(source)
    if image.bits not in (32, 64) or image.machine not in ("x86", "x86_64"):
        raise PatchError(
            "the Patch Advisor supports x86/x64 only "
            f"(found {image.machine or 'unknown'}/{image.bits} bits)"
        )
    if row.get("is_external"):
        raise PatchError("cannot advise on an external (imported) function")
    if row.get("is_thunk"):
        raise PatchError("cannot advise on a thunk; inspect its target instead")

    entry = normalize_addr(row["entry"])
    try:
        entry_value = int(entry, 16)
    except ValueError as exc:
        raise PatchError(f"invalid function entry: {row['entry']}") from exc

    size = int(row.get("size") or 0)
    if size <= 0:
        raise PatchError("Ghidra reported no size for this function")
    offset = image.address_to_offset(entry_value)
    section = image.section_for_address(entry_value)
    if section is None or not section.executable:
        raise PatchError(
            f"function entry {entry} is not inside an executable section"
        )

    length = min(size, MAX_FUNCTION_BYTES, len(image.data) - offset)
    if length <= 0:
        raise PatchError("function has no readable bytes in the file")
    data = image.read(offset, length)
    return program, row, image, entry, entry_value, offset, data


def _instruction_dict(instruction: Any, data: bytes, base_ip: int, fmt: Any) -> dict[str, Any]:
    start = instruction.ip - base_ip
    info: dict[str, Any] = {
        "address": hex(instruction.ip),
        "length": instruction.len,
        "bytes": to_hex(data[start : start + instruction.len]),
        "text": fmt.format(instruction),
    }
    if instruction.condition_code:
        info["condition"] = _condition_name(instruction.condition_code)
    if instruction.near_branch_target:
        info["branch_target"] = hex(instruction.near_branch_target)
    return info


def _make_candidate(
    *,
    image: BinaryImage,
    function: dict[str, Any],
    kind: str,
    detail: str,
    title: str,
    address: int,
    file_offset: int,
    original: bytes,
    new: bytes,
    instruction: dict[str, Any] | None = None,
    edit: dict[str, Any] | None = None,
    risk: list[str] | None = None,
) -> dict[str, Any]:
    candidate = {
        "id": f"{function['entry']}:{kind}:{detail}",
        "kind": kind,
        "title": title,
        "function": {"entry": function["entry"], "name": function["name"]},
        "target_address": hex(address),
        "file_offset": file_offset,
        "length": len(original),
        "original_bytes": to_hex(original),
        "new_bytes": to_hex(new),
        "instruction": instruction,
        "edit": edit or {},
        "risk": risk or [],
    }
    candidate["validation"] = validate_candidate(image, candidate)
    return candidate


def validate_candidate(image: BinaryImage, candidate: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    decoded: list[Any] = []

    try:
        address = int(str(candidate["target_address"]), 16)
        offset = int(candidate["file_offset"])
        original = bytes.fromhex(str(candidate["original_bytes"]).replace(" ", ""))
        new = bytes.fromhex(str(candidate["new_bytes"]).replace(" ", ""))
    except (KeyError, TypeError, ValueError) as exc:
        return {
            "ok": False,
            "errors": [f"malformed candidate: {exc}"],
            "warnings": [],
        }

    if not original:
        errors.append("original bytes are empty")
    if len(original) != len(new):
        errors.append(
            f"length mismatch: {len(original)} original byte(s) vs {len(new)} new byte(s)"
        )
    if original == new:
        errors.append("new bytes are identical to the original bytes")

    try:
        if image.address_to_offset(address) != offset:
            errors.append("file offset does not match the target address")
        section = image.section_for_address(address)
        if section is None or not section.executable:
            errors.append("target address is not inside an executable section")
        if image.read(offset, len(original)) != original:
            errors.append("original bytes do not match the current file")
    except ReiaError as exc:
        errors.append(str(exc))

    if len(original) == len(new) and new:
        decoded, decode_error = _decode(image, address, new)
        if decode_error:
            errors.append(decode_error)
        consumed = sum(instruction.len for instruction in decoded)
        if consumed != len(new):
            errors.append("new bytes do not decode into complete instructions")
        for instruction in decoded:
            if _is_jcc(instruction):
                target_section = image.section_for_address(
                    instruction.near_branch_target
                )
                if target_section is None or not target_section.executable:
                    errors.append(
                        "branch target "
                        f"{hex(instruction.near_branch_target)} is outside executable code"
                    )

    kind = str(candidate.get("kind") or "")
    edit = candidate.get("edit") or {}
    if kind == "return_constant" and decoded:
        sequence_length = int(edit.get("sequence_length") or 0)
        if sequence_length <= 0:
            errors.append("return candidate has no sequence length metadata")
        else:
            if any(byte != 0x90 for byte in new[sequence_length:]):
                errors.append("return candidate padding is not all NOP")
            ret_end = next(
                (
                    instruction.ip - address + instruction.len
                    for instruction in decoded
                    if instruction.mnemonic == _iced().Mnemonic.RET
                ),
                None,
            )
            if ret_end != sequence_length:
                errors.append("return sequence does not end with ret before NOP padding")
    if kind in ("skip_call", "nop_instruction") and new and any(byte != 0x90 for byte in new):
        errors.append("NOP candidate contains bytes other than 0x90")
    if kind == "invert_branch":
        before = str(edit.get("condition_before") or "")
        after = str(edit.get("condition_after") or "")
        if not before or not after or before == after:
            errors.append("branch candidate does not record an inverted condition")
        if decoded:
            actual = _condition_name(decoded[0].condition_code)
            if actual != after:
                errors.append(
                    f"inverted branch decodes as '{actual}', expected '{after}'"
                )

    if kind == "return_constant":
        warnings.append(
            "instructions before the first ret are skipped; their side effects are removed"
        )
    if kind == "skip_call":
        warnings.append(
            "the call is not emulated: its return value, register changes and memory "
            "effects are lost"
        )
    if kind == "invert_branch":
        warnings.append(
            "the condition is inverted; the original fall-through path now runs instead"
        )

    return {"ok": not errors, "errors": errors, "warnings": warnings}


def _return_candidate(
    *,
    image: BinaryImage,
    function: dict[str, Any],
    entry_value: int,
    entry_offset: int,
    data: bytes,
    ret_end: int,
    value: int,
) -> dict[str, Any] | None:
    span = ret_end - entry_value
    if span > MAX_RETURN_SPAN:
        return None
    sequence = _encode_return(value, image.bits)
    if len(sequence) > span:
        return None
    new = sequence + NOP * (span - len(sequence))
    candidate = _make_candidate(
        image=image,
        function=function,
        kind="return_constant",
        detail=str(value),
        title=f"Devolver {value} (mov eax,{value}; ret)",
        address=entry_value,
        file_offset=entry_offset,
        original=data[:span],
        new=new,
        edit={"value": value, "sequence_length": len(sequence), "span": span},
        risk=[
            "el prólogo y el cuerpo se omiten hasta el primer ret",
            "solo se soportan valores de retorno de 32 bits (EAX)",
        ],
    )
    return candidate


def _branch_candidate(
    *,
    image: BinaryImage,
    function: dict[str, Any],
    instruction: Any,
    data: bytes,
    base_ip: int,
    fmt: Any,
) -> dict[str, Any] | None:
    start = instruction.ip - base_ip
    raw = bytearray(data[start : start + instruction.len])
    if len(raw) == 2 and 0x70 <= raw[0] <= 0x7F:
        raw[0] ^= 0x01
    elif len(raw) == 6 and raw[0] == 0x0F and 0x80 <= raw[1] <= 0x8F:
        raw[1] ^= 0x01
    else:
        return None

    before = _condition_name(instruction.condition_code)
    after = _condition_name(_invert_condition(int(instruction.condition_code)))
    return _make_candidate(
        image=image,
        function=function,
        kind="invert_branch",
        detail=hex(instruction.ip),
        title=f"Invertir salto condicional {before} -> {after}",
        address=instruction.ip,
        file_offset=image.address_to_offset(instruction.ip),
        original=bytes(data[start : start + instruction.len]),
        new=bytes(raw),
        instruction=_instruction_dict(instruction, data, base_ip, fmt),
        edit={
            "condition_before": before,
            "condition_after": after,
            "branch_target": hex(instruction.near_branch_target),
        },
        risk=[
            "se conserva el destino; cambia qué ruta se ejecuta",
            "revisa que la ruta alternativa no dependa de estado no inicializado",
        ],
    )


def _call_candidate(
    *,
    image: BinaryImage,
    function: dict[str, Any],
    instruction: Any,
    data: bytes,
    base_ip: int,
    fmt: Any,
) -> dict[str, Any]:
    start = instruction.ip - base_ip
    return _make_candidate(
        image=image,
        function=function,
        kind="skip_call",
        detail=hex(instruction.ip),
        title=f"Omitir llamada a {hex(instruction.near_branch_target)}",
        address=instruction.ip,
        file_offset=image.address_to_offset(instruction.ip),
        original=data[start : start + instruction.len],
        new=NOP * instruction.len,
        instruction=_instruction_dict(instruction, data, base_ip, fmt),
        edit={"call_target": hex(instruction.near_branch_target)},
        risk=[
            "la llamada no se emula y se pierden sus efectos y valor de retorno",
            "la pila queda intacta porque el call tampoco se ejecuta",
        ],
    )


def _nop_candidate(
    *,
    image: BinaryImage,
    function: dict[str, Any],
    instruction: Any,
    data: bytes,
    base_ip: int,
    fmt: Any,
) -> dict[str, Any]:
    start = instruction.ip - base_ip
    return _make_candidate(
        image=image,
        function=function,
        kind="nop_instruction",
        detail=hex(instruction.ip),
        title=f"Convertir en NOP: {fmt.format(instruction)}",
        address=instruction.ip,
        file_offset=image.address_to_offset(instruction.ip),
        original=data[start : start + instruction.len],
        new=NOP * instruction.len,
        instruction=_instruction_dict(instruction, data, base_ip, fmt),
        risk=["la instrucción se elimina sin sustituir su efecto"],
    )


def build_candidates(
    store: Store,
    program_token: str,
    function_identifier: str,
    *,
    max_candidates: int = MAX_CANDIDATES,
) -> list[dict[str, Any]]:
    _, row, image, entry, entry_value, entry_offset, data = _context(
        store, program_token, function_identifier
    )
    instructions, decode_error = _decode(image, entry_value, data)
    if decode_error:
        raise PatchError(f"cannot disassemble function {entry}: {decode_error}")
    fmt = _formatter()
    function = {"entry": entry, "name": row["name"]}
    candidates: list[dict[str, Any]] = []

    ret_index = next(
        (
            index
            for index, instruction in enumerate(instructions)
            if instruction.mnemonic == _iced().Mnemonic.RET
        ),
        None,
    )
    if ret_index is not None and not _has_indirect_control_flow(
        instructions[: ret_index + 1]
    ):
        ret_end = instructions[ret_index].ip + instructions[ret_index].len
        for value in (0, 1):
            candidate = _return_candidate(
                image=image,
                function=function,
                entry_value=entry_value,
                entry_offset=entry_offset,
                data=data,
                ret_end=ret_end,
                value=value,
            )
            if candidate:
                candidates.append(candidate)

    for instruction in instructions:
        if len(candidates) >= max_candidates:
            break
        if not _is_jcc(instruction):
            continue
        candidate = _branch_candidate(
            image=image,
            function=function,
            instruction=instruction,
            data=data,
            base_ip=entry_value,
            fmt=fmt,
        )
        if candidate:
            candidates.append(candidate)

    for instruction in instructions:
        if len(candidates) >= max_candidates:
            break
        if not instruction.is_call_near:
            continue
        candidates.append(
            _call_candidate(
                image=image,
                function=function,
                instruction=instruction,
                data=data,
                base_ip=entry_value,
                fmt=fmt,
            )
        )

    return candidates[:max_candidates]


def build_candidate(
    store: Store,
    program_token: str,
    function_identifier: str,
    kind: str,
    *,
    address: str | None = None,
    value: int = 0,
) -> dict[str, Any]:
    _, row, image, entry, entry_value, entry_offset, data = _context(
        store, program_token, function_identifier
    )
    instructions, decode_error = _decode(image, entry_value, data)
    if decode_error:
        raise PatchError(f"cannot disassemble function {entry}: {decode_error}")
    fmt = _formatter()
    function = {"entry": entry, "name": row["name"]}

    if kind == "return_constant":
        ret = next(
            (
                instruction
                for instruction in instructions
                if instruction.mnemonic == _iced().Mnemonic.RET
            ),
            None,
        )
        if ret is None:
            raise PatchError("function has no near ret; cannot build a return constant")
        ret_index = next(
            index for index, item in enumerate(instructions) if item.ip == ret.ip
        )
        if _has_indirect_control_flow(instructions[: ret_index + 1]):
            raise PatchError(
                "function has indirect jumps or calls before ret; "
                "return_constant is not safe here"
            )
        candidate = _return_candidate(
            image=image,
            function=function,
            entry_value=entry_value,
            entry_offset=entry_offset,
            data=data,
            ret_end=ret.ip + ret.len,
            value=value,
        )
        if candidate is None:
            raise PatchError(
                "the replacement return sequence does not fit before the first ret"
            )
        return candidate

    if not address:
        raise PatchError(f"kind '{kind}' requires --address")
    instruction = next(
        (item for item in instructions if item.ip == int(address, 16)), None
    )
    if instruction is None:
        raise PatchError(f"no decoded instruction starts at {address}")

    if kind == "invert_branch":
        if not _is_jcc(instruction):
            raise PatchError(f"instruction at {address} is not a conditional jump")
        candidate = _branch_candidate(
            image=image,
            function=function,
            instruction=instruction,
            data=data,
            base_ip=entry_value,
            fmt=fmt,
        )
        if candidate is None:
            raise PatchError(
                f"unsupported conditional jump encoding at {address} "
                f"(length {instruction.len})"
            )
        return candidate

    if kind == "skip_call":
        if not instruction.is_call_near:
            raise PatchError(f"instruction at {address} is not a near call")
        return _call_candidate(
            image=image,
            function=function,
            instruction=instruction,
            data=data,
            base_ip=entry_value,
            fmt=fmt,
        )

    if kind == "nop_instruction":
        return _nop_candidate(
            image=image,
            function=function,
            instruction=instruction,
            data=data,
            base_ip=entry_value,
            fmt=fmt,
        )

    raise PatchError(f"unknown candidate kind: {kind}")


def select_candidate(
    candidates: list[dict[str, Any]], candidate_id: str
) -> dict[str, Any]:
    for candidate in candidates:
        if candidate["id"] == candidate_id:
            return candidate
    available = ", ".join(candidate["id"] for candidate in candidates) or "(none)"
    raise PatchError(f"candidate not found: {candidate_id}; available: {available}")


def create_plan_from_candidate(
    store: Store,
    program_token: str,
    candidate: dict[str, Any],
    *,
    reason: str,
    authorization: str | None,
) -> dict[str, Any]:
    validation = candidate.get("validation") or {}
    if validation.get("ok") is not True:
        detail = "; ".join(validation.get("errors") or ["unknown validation error"])
        raise PatchError(f"candidate failed validation: {detail}")
    if not reason.strip():
        raise PatchError("patch reason is required")

    extra = {
        "advisor": {
            "candidate_id": candidate["id"],
            "kind": candidate["kind"],
            "title": candidate["title"],
            "instruction": candidate.get("instruction"),
            "risk": candidate.get("risk") or [],
        },
        "validation": validation,
    }
    return create_patch_plan(
        store,
        program_token,
        address=candidate["target_address"],
        file_offset=int(candidate["file_offset"]),
        new_bytes=bytes.fromhex(candidate["new_bytes"].replace(" ", "")),
        reason=reason,
        authorization=authorization,
        extra=extra,
    )


def advise_candidate(
    store: Store,
    program_token: str,
    function_identifier: str,
    candidate_id: str,
    *,
    reason: str,
    authorization: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidates = build_candidates(store, program_token, function_identifier)
    candidate = select_candidate(candidates, candidate_id)
    plan = create_plan_from_candidate(
        store,
        program_token,
        candidate,
        reason=reason,
        authorization=authorization,
    )
    return candidate, plan


def validate_plan(store: Store, plan_id: str) -> dict[str, Any]:
    plan = store.get_patch_plan(plan_id)
    program = store.get_program(plan["program_id"])
    source = Path(program["path"]).expanduser()
    errors: list[str] = []
    warnings: list[str] = []

    try:
        image = BinaryImage.from_path(source)
        offset = int(plan["file_offset"])
        original = bytes.fromhex(str(plan["original_bytes"]).replace(" ", ""))
        new = bytes.fromhex(str(plan["new_bytes"]).replace(" ", ""))
        if len(original) != len(new):
            errors.append(
                f"length mismatch: {len(original)} original byte(s) vs {len(new)} new byte(s)"
            )
        if image.read(offset, len(original)) != original:
            errors.append("original bytes no longer match the binary on disk")
        if plan.get("target_address"):
            section = image.section_for_address(plan["target_address"])
            if section is None or not section.executable:
                errors.append("target address is not inside an executable section")
    except (ReiaError, KeyError, TypeError, ValueError) as exc:
        errors.append(f"{type(exc).__name__}: {exc}")

    if plan.get("advisor"):
        stored = plan.get("validation") or {}
        if stored.get("ok") is not True:
            errors.extend(stored.get("errors") or ["advisor validation failed"])
    else:
        warnings.append("manual plan: no semantic advisor validation")

    return {
        "plan_id": plan_id,
        "status": plan.get("status"),
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "advisor": plan.get("advisor"),
        "validation": plan.get("validation"),
    }


ADVISOR_SYSTEM_PROMPT = """\
Eres un asesor de parches dentro de Resverse IA, en un laboratorio CTF autorizado.
No escribes bytes, no escribes parches y no ejecutas nada.

Recibes una lista cerrada de candidatos generados y validados por el motor local.
Tu única tarea es elegir el candidate_id que mejor cumple la intención del analista.

Reglas:
1. Elige exactamente un candidate_id de la lista; nunca inventes uno.
2. Si ningún candidato cumple la intención, usa candidate_id null y explica por qué.
3. No propongas instrucciones, direcciones ni bytes nuevos.
4. No describas cómo eludir licencias, DRM, anti-cheat ni protecciones de malware.
5. Responde en español y SOLO con JSON válido:
{"candidate_id": "id o null", "reason": "motivo breve", "confidence": 0.0, "caveats": ["..."]}
"""


def choose_candidate_with_ai(
    candidates: list[dict[str, Any]],
    intent: str,
    *,
    function: dict[str, Any],
    model: str,
) -> dict[str, Any]:
    payload = {
        "function": function,
        "intent": intent,
        "allowed_candidate_ids": [candidate["id"] for candidate in candidates],
        "candidates": [
            {
                "candidate_id": candidate["id"],
                "kind": candidate["kind"],
                "title": candidate["title"],
                "target_address": candidate["target_address"],
                "instruction": candidate.get("instruction"),
                "risk": candidate.get("risk"),
            }
            for candidate in candidates
        ],
    }
    messages = [
        {"role": "system", "content": ADVISOR_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": "Intención del analista:\n"
            + intent
            + "\n\nCandidatos (JSON):\n"
            + json.dumps(payload, ensure_ascii=False),
        },
    ]
    try:
        answer = chat(
            messages,
            model=model,
            options={"temperature": 0.0, "num_predict": 600},
        )
    except OllamaError as exc:
        raise PatchError(str(exc)) from exc

    try:
        selection = json.loads(answer)
    except json.JSONDecodeError as exc:
        raise PatchError(f"the advisor model returned invalid JSON: {exc}") from exc
    if not isinstance(selection, dict):
        raise PatchError("the advisor model returned an unexpected JSON shape")

    candidate_id = selection.get("candidate_id")
    if candidate_id is None:
        raise PatchError(
            "the advisor model found no suitable candidate: "
            + str(selection.get("reason") or "no reason given")
        )
    if not isinstance(candidate_id, str):
        raise PatchError("the advisor model returned a non-string candidate_id")
    known = {candidate["id"] for candidate in candidates}
    if candidate_id not in known:
        raise PatchError(
            f"the advisor model selected an unknown candidate: {candidate_id}"
        )
    return selection


def advise_with_ai(
    store: Store,
    program_token: str,
    function_identifier: str,
    intent: str,
    *,
    model: str,
    reason: str,
    authorization: str | None,
) -> dict[str, Any]:
    program = store.get_program(program_token)
    require_patch_allowed(program["profile"], authorization)

    candidates = build_candidates(store, program_token, function_identifier)
    if not candidates:
        raise PatchError(
            "no deterministic candidates were found for this function; "
            "try a manual plan or a different function"
        )
    row = store.get_function(program["id"], function_identifier)
    selection = choose_candidate_with_ai(
        candidates,
        intent,
        function={
            "entry": normalize_addr(row["entry"]),
            "name": row["name"],
            "signature": row.get("signature"),
        },
        model=model,
    )
    candidate = select_candidate(candidates, str(selection["candidate_id"]))
    final_reason = (reason or str(selection.get("reason") or "")).strip()
    if not final_reason:
        final_reason = intent.strip()
    plan = create_plan_from_candidate(
        store,
        program_token,
        candidate,
        reason=final_reason,
        authorization=authorization,
    )
    return {
        "selection": selection,
        "candidate": candidate,
        "plan": plan,
        "reason": final_reason,
    }


def render_advisor_report(result: dict[str, Any], *, program_path: str = "") -> str:
    plan = result.get("plan") or result
    candidate = result.get("candidate") or {}
    selection = result.get("selection") or {}
    offset = int(plan["file_offset"])
    lines = [
        f"Cambio: {candidate.get('title') or plan.get('reason')}",
        f"Candidato: {candidate.get('id') or (plan.get('advisor') or {}).get('candidate_id')}",
    ]
    if program_path:
        lines.append(f"Archivo: {program_path}")
    lines.extend(
        [
            f"Dirección: {plan.get('target_address')}",
            f"Offset de archivo: 0x{offset:x}",
            f"Reemplazar ({len(plan['original_bytes'].split())} bytes): {plan['original_bytes']}",
            f"Por        ({len(plan['new_bytes'].split())} bytes): {plan['new_bytes']}",
        ]
    )
    validation = plan.get("validation") or candidate.get("validation") or {}
    if validation:
        lines.append(
            "Validación: " + ("OK" if validation.get("ok") else "FALLÓ")
            + (" — " + "; ".join(validation.get("warnings") or []) if validation.get("warnings") else "")
        )
    if selection:
        lines.append(
            f"Selección IA: {selection.get('candidate_id')} "
            f"(confianza {selection.get('confidence', 'n/d')})"
        )
        if selection.get("reason"):
            lines.append(f"Motivo IA: {selection['reason']}")
    lines.extend(
        [
            "",
            "Siguiente paso (no se ejecuta solo):",
            f"  reia patch validate {plan['id']}",
            f"  reia patch apply {plan['id']} --approve "
            f"--authorization \"{plan.get('authorization') or ''}\"",
            f"  reia patch rollback {plan['id']}",
        ]
    )
    return "\n".join(lines)
