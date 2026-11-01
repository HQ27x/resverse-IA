from __future__ import annotations

import json
import re
from typing import Any

ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]+")
EVIDENCE_RE = re.compile(r"F:0x[0-9a-fA-F]+")


def _canonical(value: str) -> str:
    try:
        return hex(int(value, 16))
    except ValueError:
        return value.lower()


def _collect_evidence(packet: dict[str, Any]) -> tuple[set[str], set[str]]:
    addresses: set[str] = set()
    evidence_ids: set[str] = set()

    program = packet.get("program") or {}
    if program.get("image_base"):
        addresses.add(_canonical(str(program["image_base"])))

    for card in packet.get("evidence") or []:
        for key in ("entry",):
            if card.get(key):
                addresses.add(_canonical(str(card[key])))
        evidence_id = card.get("id")
        if evidence_id:
            evidence_ids.add(str(evidence_id))
        for key in ("callers", "callees"):
            for value in card.get(key) or []:
                if isinstance(value, str):
                    addresses.add(_canonical(value))
                elif isinstance(value, dict):
                    for field in ("from", "to", "address"):
                        if value.get(field):
                            addresses.add(_canonical(str(value[field])))
        for key in ("xrefs",):
            for item in card.get(key) or []:
                if isinstance(item, dict):
                    for field in ("from", "to", "address"):
                        if item.get(field):
                            addresses.add(_canonical(str(item[field])))
                elif isinstance(item, str):
                    addresses.add(_canonical(item))
        for item in card.get("strings") or []:
            if isinstance(item, dict) and item.get("address"):
                addresses.add(_canonical(str(item["address"])))

    context = packet.get("program_context") or {}
    for key in ("exports", "imports", "strings"):
        for item in context.get(key) or []:
            if isinstance(item, dict):
                for field in ("address",):
                    if item.get(field):
                        addresses.add(_canonical(str(item[field])))

    return addresses, evidence_ids


def validate_answer(answer: str, packet: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    addresses, evidence_ids = _collect_evidence(packet)

    for address in ADDRESS_RE.findall(answer):
        if _canonical(address) not in addresses:
            warnings.append(f"address not present in evidence: {address}")

    for evidence_id in EVIDENCE_RE.findall(answer):
        if evidence_id not in evidence_ids:
            warnings.append(f"unknown evidence id: {evidence_id}")

    try:
        parsed = json.loads(answer)
    except json.JSONDecodeError:
        warnings.append("answer is not valid JSON; grounding checks are limited")
        return warnings

    if not isinstance(parsed, dict):
        warnings.append("answer JSON is not an object")
        return warnings

    claims = parsed.get("claims")
    if not isinstance(claims, list) or not claims:
        warnings.append("answer has no claims with evidence")
    else:
        for index, claim in enumerate(claims):
            if not isinstance(claim, dict):
                warnings.append(f"claim {index} is not an object")
                continue
            cited = claim.get("evidence")
            if not isinstance(cited, list) or not cited:
                warnings.append(f"claim {index} has no evidence citation")
                continue
            for evidence_id in cited:
                if str(evidence_id) not in evidence_ids:
                    warnings.append(f"claim {index} cites unknown evidence: {evidence_id}")

    for annotation in parsed.get("suggested_annotations") or []:
        if not isinstance(annotation, dict):
            continue
        target = annotation.get("target")
        if target and str(target) not in evidence_ids:
            warnings.append(f"annotation targets unknown evidence: {target}")

    return warnings
