from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .config import ReiaError, Workspace
from .patch import create_patch_plan
from .patch_advisor import (
    build_candidates,
    create_plan_from_candidate,
    select_candidate,
    validate_plan,
)
from .policy import policy_snapshot
from .store import Store
from .util import json_dumps, parse_hex_bytes, parse_offset

PROTOCOL_VERSION = "2024-11-05"

TOOLS: list[dict[str, Any]] = [
    {
        "name": "programs_list",
        "description": "List imported programs in the local Resverse IA workspace.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "program_info",
        "description": "Show metadata, counts and policy for one program. Omit program when only one exists.",
        "inputSchema": {
            "type": "object",
            "properties": {"program": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "functions_search",
        "description": "Search functions by name, address, decompiled text or referenced strings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program": {"type": "string"},
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "function_get",
        "description": "Get one function card by address, export name or function name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program": {"type": "string"},
                "identifier": {"type": "string"},
            },
            "required": ["identifier"],
            "additionalProperties": False,
        },
    },
    {
        "name": "dll_exports",
        "description": "List exports of a PE/DLL or ELF program.",
        "inputSchema": {
            "type": "object",
            "properties": {"program": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "dll_imports",
        "description": "List imports of a program.",
        "inputSchema": {
            "type": "object",
            "properties": {"program": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "strings_search",
        "description": "Search extracted strings in the local index.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program": {"type": "string"},
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "evidence_pack",
        "description": "Build a compact, citation-ready evidence packet for an AI model.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program": {"type": "string"},
                "query": {"type": "string"},
                "function": {"type": "string"},
                "max_functions": {"type": "integer", "minimum": 1, "maximum": 20},
                "max_chars": {"type": "integer", "minimum": 500, "maximum": 50000},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "patch_plan",
        "description": "Create a patch plan for a copied binary. This never applies or executes a patch.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "program": {"type": "string"},
                "address": {"type": "string"},
                "file_offset": {"type": ["integer", "string"]},
                "bytes": {"type": "string"},
                "reason": {"type": "string"},
                "authorization": {"type": "string"},
            },
            "required": ["program", "bytes", "reason", "authorization"],
            "additionalProperties": False,
        },
    },
    {
        "name": "patch_candidates",
        "description": (
            "List deterministic, statically validated edit candidates for one function. "
            "The AI may only choose an id from this list; this tool never applies a patch."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "program": {"type": "string"},
                "function": {"type": "string"},
            },
            "required": ["function"],
            "additionalProperties": False,
        },
    },
    {
        "name": "patch_build",
        "description": (
            "Create a patch plan from a candidate id. Never applies or executes the patch."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "program": {"type": "string"},
                "function": {"type": "string"},
                "candidate_id": {"type": "string"},
                "reason": {"type": "string"},
                "authorization": {"type": "string"},
            },
            "required": ["function", "candidate_id", "reason", "authorization"],
            "additionalProperties": False,
        },
    },
    {
        "name": "patch_validate",
        "description": "Re-check a patch plan against the current file without applying it.",
        "inputSchema": {
            "type": "object",
            "properties": {"plan_id": {"type": "string"}},
            "required": ["plan_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "patch_list",
        "description": "List patch plans and their status.",
        "inputSchema": {
            "type": "object",
            "properties": {"program": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "policy_show",
        "description": "Show the policy snapshot for a program profile.",
        "inputSchema": {
            "type": "object",
            "properties": {"program": {"type": "string"}},
            "additionalProperties": False,
        },
    },
]


class ToolError(Exception):
    pass


def _text_result(value: Any) -> dict[str, Any]:
    text = value if isinstance(value, str) else json_dumps(value)
    return {
        "content": [{"type": "text", "text": text}],
        "isError": False,
    }


def _error_result(message: str) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": message}],
        "isError": True,
    }


def _program_id(store: Store, arguments: dict[str, Any]) -> str:
    token = arguments.get("program")
    return store.get_program(token)["id"]


def dispatch_tool(store: Store, name: str, arguments: dict[str, Any]) -> Any:
    if name == "programs_list":
        return store.list_programs()

    if name == "program_info":
        return store.program_info(arguments.get("program"))

    if name == "functions_search":
        program = store.get_program(arguments.get("program"))
        query = str(arguments.get("query") or "")
        limit = int(arguments.get("limit") or 20)
        rows = store.search_functions(program["id"], query, limit=limit)
        return [store.function_card(row) for row in rows]

    if name == "function_get":
        program = store.get_program(arguments.get("program"))
        identifier = str(arguments.get("identifier") or "")
        return store.function_card(store.get_function(program["id"], identifier))

    if name == "dll_exports":
        program = store.get_program(arguments.get("program"))
        return store.get_exports(program["id"])

    if name == "dll_imports":
        program = store.get_program(arguments.get("program"))
        return store.get_imports(program["id"])

    if name == "strings_search":
        program = store.get_program(arguments.get("program"))
        return store.get_strings(
            program["id"],
            arguments.get("query"),
            limit=int(arguments.get("limit") or 100),
        )

    if name == "evidence_pack":
        return store.build_evidence(
            arguments.get("program"),
            query=arguments.get("query"),
            identifier=arguments.get("function"),
            max_functions=int(arguments.get("max_functions") or 5),
            max_chars=int(arguments.get("max_chars") or 6000),
        )

    if name == "patch_plan":
        program = store.get_program(arguments.get("program"))
        raw_bytes = parse_hex_bytes(str(arguments.get("bytes") or ""))
        file_offset_raw = arguments.get("file_offset")
        file_offset = parse_offset(file_offset_raw) if file_offset_raw not in (None, "") else None
        return create_patch_plan(
            store,
            program["id"],
            address=arguments.get("address"),
            file_offset=file_offset,
            new_bytes=raw_bytes,
            reason=str(arguments.get("reason") or ""),
            authorization=str(arguments.get("authorization") or ""),
        )

    if name == "patch_candidates":
        program = store.get_program(arguments.get("program"))
        return build_candidates(
            store,
            program["id"],
            str(arguments.get("function") or ""),
        )

    if name == "patch_build":
        program = store.get_program(arguments.get("program"))
        candidates = build_candidates(
            store,
            program["id"],
            str(arguments.get("function") or ""),
        )
        candidate = select_candidate(
            candidates, str(arguments.get("candidate_id") or "")
        )
        return create_plan_from_candidate(
            store,
            program["id"],
            candidate,
            reason=str(arguments.get("reason") or ""),
            authorization=str(arguments.get("authorization") or ""),
        )

    if name == "patch_validate":
        return validate_plan(store, str(arguments.get("plan_id") or ""))

    if name == "patch_list":
        program = store.get_program(arguments.get("program"))
        return store.list_patch_plans(program["id"])

    if name == "policy_show":
        program = store.get_program(arguments.get("program"))
        return policy_snapshot(program["profile"])

    raise ToolError(f"unknown tool: {name}")


def handle_request(store: Store, request: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(request, dict) or "method" not in request:
        return {
            "jsonrpc": "2.0",
            "id": request.get("id") if isinstance(request, dict) else None,
            "error": {"code": -32600, "message": "invalid request"},
        }

    method = request.get("method")
    request_id = request.get("id")
    if request_id is None:
        # Notification; no response.
        return None

    if method == "initialize":
        params = request.get("params") or {}
        protocol = params.get("protocolVersion") or PROTOCOL_VERSION
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": protocol,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "resverse-ia", "version": __version__},
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        params = request.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32602, "message": "invalid tool call"},
            }
        try:
            result = dispatch_tool(store, name, arguments)
        except (ReiaError, ToolError) as exc:
            return {"jsonrpc": "2.0", "id": request_id, "result": _error_result(str(exc))}
        except Exception as exc:
            print(f"[reia-mcp] tool {name} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": _error_result(f"{type(exc).__name__}: {exc}"),
            }
        return {"jsonrpc": "2.0", "id": request_id, "result": _text_result(result)}

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


def serve(workspace: Workspace, *, allow_external_client: bool = False) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    workspace.require_initialized()
    config = workspace.load_config()
    if config.get("profile") == "malware" and not allow_external_client:
        raise ReiaError(
            "the malware profile blocks external MCP clients; use 'reia ask' with a local model "
            "or pass --allow-external-client only if the client itself runs locally"
        )
    store = Store(workspace.db_path)
    print(f"[reia-mcp] serving {workspace.db_path}", file=sys.stderr, flush=True)
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError as exc:
                response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"parse error: {exc}"},
                }
            else:
                if isinstance(request, list):
                    responses = [
                        handle_request(store, item) for item in request if isinstance(item, dict)
                    ]
                    response = [item for item in responses if item is not None]
                    if not response:
                        continue
                else:
                    response = handle_request(store, request)
            if response is not None:
                print(json.dumps(response, ensure_ascii=False), flush=True)
    except KeyboardInterrupt:
        return 130
    finally:
        store.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Minimal MCP stdio server for Resverse IA")
    parser.add_argument("--workspace", help="Resverse IA workspace path")
    parser.add_argument(
        "--allow-external-client",
        action="store_true",
        help="only for a client that runs locally on this machine",
    )
    args = parser.parse_args(argv)
    workspace = Workspace(args.workspace) if args.workspace else Workspace()
    try:
        return serve(workspace, allow_external_client=args.allow_external_client)
    except ReiaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
