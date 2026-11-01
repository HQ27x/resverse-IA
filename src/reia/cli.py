from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .binary import BinaryImage, BinaryError
from .config import DEFAULT_MODEL, PROFILES, ReiaError, Workspace
from .grounding import validate_answer
from .mcp_server import serve as serve_mcp
from .ollama import OllamaError, ask_packet, is_local_endpoint, list_models
from .patch import (
    PatchError,
    apply_patch_plan,
    create_patch_plan,
    render_patch_diff,
    rollback_patch_plan,
)
from .patch_advisor import (
    advise_with_ai,
    build_candidate,
    build_candidates,
    create_plan_from_candidate,
    render_advisor_report,
    select_candidate,
    validate_plan,
)
from .policy import PolicyError, policy_snapshot
from .store import Store
from .util import (
    json_dumps,
    parse_hex_bytes,
    parse_offset,
    sha256_file,
    slugify,
)


def _print_json(value: Any) -> None:
    print(json_dumps(value))


def _workspace(args: argparse.Namespace, *, require: bool = True) -> Workspace:
    workspace = Workspace(args.workspace)
    if require:
        workspace.require_initialized()
    return workspace


def _store(args: argparse.Namespace) -> Store:
    workspace = _workspace(args)
    return Store(workspace.db_path)


def _profile_from(args: argparse.Namespace, workspace: Workspace) -> str:
    if getattr(args, "profile", None):
        profile = str(args.profile)
        if profile == "malware" and workspace.is_onedrive():
            raise ReiaError(
                "refusing to import a malware-profile program into a OneDrive-backed workspace; "
                "use a workspace outside OneDrive"
            )
        return profile
    return str(workspace.load_config().get("profile") or "ctf")


def _print_table(headers: list[str], rows: list[list[Any]]) -> None:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(str(value)))
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(str(value).ljust(widths[index]) for index, value in enumerate(row)))


# ----------------------------------------------------------------------
# doctor / init / config
# ----------------------------------------------------------------------
def _find_ghidra() -> Path | None:
    candidates: list[str] = []
    for env_name in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        value = os.environ.get(env_name)
        if value:
            candidates.append(value)
    for pattern in (
        "C:/ghidra*",
        "C:/Program Files/ghidra*",
        "C:/Program Files (x86)/ghidra*",
        str(Path.home() / "ghidra*"),
        str(Path.home() / "Downloads" / "ghidra*"),
    ):
        candidates.extend(glob.glob(pattern))
    for candidate in candidates:
        path = Path(candidate).expanduser()
        if (path / "support" / "analyzeHeadless.bat").exists() or (
            path / "support" / "analyzeHeadless"
        ).exists():
            return path.resolve()
    return None


def _java_info() -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            ["java", "-version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    output = (completed.stderr or completed.stdout or "").strip()
    if completed.returncode != 0:
        return False, output or "java -version failed"
    for line in output.splitlines():
        if "version" in line and '"' in line:
            return True, line.strip()
    return True, output.splitlines()[0] if output else "java found"


def _java_major(detail: str) -> int | None:
    if '"' not in detail:
        return None
    token = detail.split('"', 2)[1]
    first = token.split(".")[0]
    try:
        return int(first)
    except ValueError:
        return None


def _ghidra_java_limits(ghidra: Path) -> tuple[int | None, int | None, str]:
    properties = ghidra / "Ghidra" / "application.properties"
    version = ""
    minimum: int | None = None
    maximum: int | None = None
    try:
        for line in properties.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key == "application.version":
                version = value
            elif key == "application.java.min":
                minimum = int(value) if value else None
            elif key == "application.java.max":
                maximum = int(value) if value else None
    except (OSError, ValueError):
        pass
    return minimum, maximum, version


def _find_rea() -> tuple[str | None, str]:
    executable = shutil.which("rea")
    if executable:
        return executable, "installed in PATH"
    downloads = Path.home() / "Downloads"
    candidates = [
        downloads / "rea-main.zip",
        downloads / "rea-main" / "releases",
    ]
    for candidate in candidates:
        if candidate.exists():
            return None, f"found at {candidate}; not installed"
    return None, "not found"


def _doctor(args: argparse.Namespace) -> int:
    workspace = Workspace(args.workspace)
    checks: list[dict[str, Any]] = []

    def add(level: str, name: str, detail: str) -> None:
        checks.append({"level": level, "name": name, "detail": detail})

    py_ok = sys.version_info >= (3, 11)
    add("ok" if py_ok else "fail", "Python", sys.version.split()[0])

    if workspace.config_path.exists() and workspace.db_path.exists():
        config = workspace.load_config()
        add("ok", "Workspace", f"{workspace.root} (profile={config.get('profile')})")
        if workspace.is_onedrive():
            level = "fail" if config.get("profile") == "malware" else "warn"
            add(level, "OneDrive", "samples/projects should live outside OneDrive")
        try:
            from .db import connect, has_fts

            connection = connect(workspace.db_path)
            fts = has_fts(connection)
            connection.close()
            add("ok" if fts else "warn", "SQLite FTS5", "enabled" if fts else "unavailable; using LIKE")
        except Exception as exc:
            add("fail", "SQLite", str(exc))
    else:
        add("warn", "Workspace", f"not initialized at {workspace.root}")

    ghidra = _find_ghidra()
    ghidra_min: int | None = None
    ghidra_max: int | None = None
    ghidra_version = ""
    if ghidra:
        ghidra_min, ghidra_max, ghidra_version = _ghidra_java_limits(ghidra)
        label = str(ghidra)
        if ghidra_version:
            label += f" (Ghidra {ghidra_version})"
        add("ok", "Ghidra", label)
    else:
        add("warn", "Ghidra", "not found; set GHIDRA_INSTALL_DIR or pass --ghidra-home")

    pyghidra_ok = importlib.util.find_spec("pyghidra") is not None
    pyghidra_detail = "installed" if pyghidra_ok else "pip install pyghidra"
    if pyghidra_ok:
        try:
            from importlib.metadata import version as _package_version

            pyghidra_detail = f"installed ({_package_version('pyghidra')})"
        except Exception:
            pass
    add("ok" if pyghidra_ok else "warn", "PyGhidra", pyghidra_detail)

    java_ok, java_detail = _java_info()
    add("ok" if java_ok else "warn", "Java", java_detail)
    java_major = _java_major(java_detail) if java_ok else None
    if java_major is not None and ghidra and (ghidra_min or ghidra_max):
        below = ghidra_min is not None and java_major < ghidra_min
        above = ghidra_max is not None and java_major > ghidra_max
        if below or above:
            required = f"{ghidra_min or '?'}" if ghidra_max is None else f"{ghidra_min or '?'}-{ghidra_max}"
            add(
                "warn",
                "Java version",
                f"{java_major}; Ghidra {ghidra_version or ''} requires JDK {required}",
            )
        else:
            add(
                "ok",
                "Java version",
                f"{java_major}; compatible with Ghidra {ghidra_version or ''}",
            )

    rea_path, rea_detail = _find_rea()
    if rea_path:
        add("ok", "REA", f"{rea_path} (standalone MCP: rea serve; not a Ghidra plugin)")
    else:
        add("warn", "REA", f"{rea_detail} (optional; standalone MCP, not a Ghidra plugin)")

    try:
        models = list_models()
        add("ok", "Ollama", f"{len(models)} model(s): {', '.join(models[:5])}")
    except OllamaError as exc:
        add("warn", "Ollama", str(exc))

    if getattr(args, "json", False):
        _print_json({"workspace": str(workspace.root), "checks": checks})
    else:
        symbols = {"ok": "[ok]", "warn": "[warn]", "fail": "[fail]"}
        print(f"Resverse IA {__version__}")
        print(f"Workspace: {workspace.root}")
        for check in checks:
            print(f"{symbols.get(check['level'], '[?]'):7} {check['name']}: {check['detail']}")
    return 0


def _init(args: argparse.Namespace) -> int:
    workspace = Workspace(args.workspace)
    workspace.ensure(
        profile=args.profile,
        allow_onedrive=args.allow_onedrive,
        force=args.force,
    )
    print(f"initialized {workspace.root}")
    print(f"profile: {args.profile}")
    print(f"database: {workspace.db_path}")
    if workspace.is_onedrive() and args.profile != "malware":
        print("warning: workspace is inside OneDrive; keep malware samples and projects outside it")
    return 0


def _config_show(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    config = workspace.load_config()
    payload = {
        "workspace": str(workspace.root),
        "config": config,
        "paths": {
            "db": str(workspace.db_path),
            "projects": str(workspace.projects_dir),
            "exports": str(workspace.exports_dir),
            "patches": str(workspace.patches_dir),
            "samples": str(workspace.samples_dir),
        },
        "policy": policy_snapshot(str(config.get("profile") or "ctf")),
    }
    _print_json(payload)
    return 0


def _mcp_config_payload(workspace: Workspace) -> dict[str, Any]:
    executable = shutil.which("reia")
    if executable:
        server: dict[str, Any] = {
            "command": executable,
            "args": ["--workspace", str(workspace.root), "mcp"],
        }
    else:
        server = {
            "command": sys.executable,
            "args": ["-m", "reia", "--workspace", str(workspace.root), "mcp"],
            "env": {"PYTHONPATH": str(Path(__file__).resolve().parents[1])},
        }
    return {"mcpServers": {"resverse-ia": server}}


def _config_mcp(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    config = workspace.load_config()
    _print_json(_mcp_config_payload(workspace))
    print("", file=sys.stderr)
    print(f"profile: {config.get('profile')}", file=sys.stderr)
    print(
        "Copia este bloque en la configuración MCP de Qoder, Antigravity o Claude.",
        file=sys.stderr,
    )
    return 0


# ----------------------------------------------------------------------
# import / dll
# ----------------------------------------------------------------------
def _load_export(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReiaError(f"cannot read export: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ReiaError(f"invalid export JSON: {exc}") from exc


def _import_export(
    workspace: Workspace,
    store: Store,
    export: dict[str, Any],
    *,
    profile: str,
    path_override: str | None,
    force: bool,
) -> str:
    program_id = store.import_export(
        export,
        profile=profile,
        path_override=path_override,
        force=force,
    )
    info = store.program_info(program_id)
    print(f"program: {program_id}")
    print(f"functions: {info['counts'].get('functions', 0)}")
    print(f"exports: {info['counts'].get('exports', 0)}")
    print(f"imports: {info['counts'].get('imports', 0)}")
    print(f"strings: {info['counts'].get('strings', 0)}")
    print(f"profile: {profile}")
    return program_id


def _import_json(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    store = Store(workspace.db_path)
    profile = _profile_from(args, workspace)
    export_path = Path(args.export).expanduser().resolve()
    export = _load_export(export_path)
    _import_export(
        workspace,
        store,
        export,
        profile=profile,
        path_override=args.path,
        force=args.force,
    )
    store.close()
    return 0


def _run_ghidra_export(
    workspace: Workspace,
    binary: Path,
    *,
    ghidra_home: str | None,
    no_decompile: bool,
    max_functions: int,
    max_strings: int,
) -> Path:
    sha = sha256_file(binary)
    output = workspace.exports_dir / f"{slugify(binary.stem)}-{sha[:8]}.json"
    project_name = f"reia_{slugify(binary.stem)}_{sha[:8]}"

    env = os.environ.copy()
    src_dir = str(Path(__file__).resolve().parents[1])
    env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")

    command = [
        sys.executable,
        "-m",
        "reia.ghidra_export",
        str(binary),
        "-o",
        str(output),
        "--project-location",
        str(workspace.projects_dir),
        "--project-name",
        project_name,
        "--max-functions",
        str(max_functions),
        "--max-strings",
        str(max_strings),
    ]
    if ghidra_home:
        command.extend(["--ghidra-home", ghidra_home])
    if no_decompile:
        command.append("--no-decompile")

    print(f"analyzing {binary} with Ghidra...", file=sys.stderr)
    completed = subprocess.run(command, capture_output=True, text=True, env=env)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise ReiaError(
            "Ghidra export failed. Install Ghidra 11.3+ and pyghidra, or pass "
            "--export-json with a previously generated model.\n"
            + detail[-4000:]
        )
    if not output.exists():
        raise ReiaError(f"Ghidra export finished but output is missing: {output}")
    return output


def _dll_open(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    binary = Path(args.binary).expanduser().resolve()
    if not binary.exists() or not binary.is_file():
        raise ReiaError(f"binary not found: {binary}")
    profile = _profile_from(args, workspace)
    store = Store(workspace.db_path)

    if args.export_json:
        export_path = Path(args.export_json).expanduser().resolve()
    else:
        ghidra_home = args.ghidra_home or os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")
        if not ghidra_home:
            detected = _find_ghidra()
            ghidra_home = str(detected) if detected else None
        export_path = _run_ghidra_export(
            workspace,
            binary,
            ghidra_home=ghidra_home,
            no_decompile=args.no_decompile,
            max_functions=args.max_functions,
            max_strings=args.max_strings,
        )

    export = _load_export(export_path)
    _import_export(
        workspace,
        store,
        export,
        profile=profile,
        path_override=str(binary),
        force=args.force,
    )
    store.close()
    return 0


def _dll_info(args: argparse.Namespace) -> int:
    store = _store(args)
    info = store.program_info(args.program)
    _print_json(info)
    store.close()
    return 0


def _dll_exports(args: argparse.Namespace) -> int:
    store = _store(args)
    program = store.get_program(args.program)
    rows = store.get_exports(program["id"])
    if args.json:
        _print_json(rows)
    else:
        _print_table(
            ["name", "address", "ordinal"],
            [[row["name"], row["address"] or "", row["ordinal"] if row["ordinal"] is not None else ""] for row in rows],
        )
    store.close()
    return 0


def _dll_imports(args: argparse.Namespace) -> int:
    store = _store(args)
    program = store.get_program(args.program)
    rows = store.get_imports(program["id"])
    if args.json:
        _print_json(rows)
    else:
        _print_table(
            ["name", "library", "address"],
            [[row["name"], row["library"] or "", row["address"] or ""] for row in rows],
        )
    store.close()
    return 0


def _dll_functions(args: argparse.Namespace) -> int:
    store = _store(args)
    program = store.get_program(args.program)
    rows = store.search_functions(program["id"], args.query, limit=args.limit)
    cards = [store.function_card(row) for row in rows]
    if args.json:
        _print_json(cards)
    else:
        _print_table(
            ["entry", "name", "size", "signature"],
            [
                [
                    card["entry"],
                    card["name"],
                    card["size"] if card["size"] is not None else "",
                    (card["signature"] or "")[:100],
                ]
                for card in cards
            ],
        )
    store.close()
    return 0


def _dll_decompile(args: argparse.Namespace) -> int:
    store = _store(args)
    program = store.get_program(args.program)
    identifier = args.function or args.address
    if not identifier:
        raise ReiaError("provide --function or --address")
    card = store.function_card(store.get_function(program["id"], identifier), max_chars=0)
    if args.json:
        _print_json(card)
    else:
        print(f"entry: {card['entry']}")
        print(f"name: {card['name']}")
        print(f"signature: {card['signature']}")
        print(f"callers: {', '.join(map(str, card['callers'])) or '-'}")
        print(f"callees: {', '.join(map(str, card['callees'])) or '-'}")
        print(f"strings: {', '.join(map(str, card['strings'])) or '-'}")
        print("")
        print(card["decompiled"] or "[no decompilation available]")
    store.close()
    return 0


def _dll_strings(args: argparse.Namespace) -> int:
    store = _store(args)
    program = store.get_program(args.program)
    rows = store.get_strings(program["id"], args.query, limit=args.limit)
    if args.json:
        _print_json(rows)
    else:
        _print_table(
            ["address", "encoding", "value"],
            [[row["address"], row["encoding"] or "", row["value"][:120]] for row in rows],
        )
    store.close()
    return 0


# ----------------------------------------------------------------------
# evidence / ask
# ----------------------------------------------------------------------
def _evidence(args: argparse.Namespace) -> int:
    store = _store(args)
    packet = store.build_evidence(
        args.program,
        query=args.query,
        identifier=args.function,
        max_functions=args.max_functions,
        max_chars=args.max_chars,
    )
    text = json_dumps(packet)
    if args.output:
        Path(args.output).expanduser().resolve().write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(text)
    store.close()
    return 0


def _ask(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    store = Store(workspace.db_path)
    config = workspace.load_config()
    model = args.model or str(config.get("model") or DEFAULT_MODEL)
    packet = store.build_evidence(
        args.program,
        query=args.query or args.question,
        identifier=args.function,
        max_functions=args.max_functions,
        max_chars=args.max_chars,
    )
    if args.packet_only:
        print(json_dumps(packet))
        store.close()
        return 0

    if packet["policy"]["cloud"] == "blocked" and not is_local_endpoint():
        store.close()
        raise ReiaError(
            "this profile blocks cloud inference, but OLLAMA_HOST points to a non-local "
            "endpoint; use a localhost Ollama or 'ask --packet-only'"
        )

    try:
        answer = ask_packet(packet, args.question, model=model)
    except OllamaError as exc:
        store.close()
        raise ReiaError(
            f"{exc}\nUse --packet-only to inspect the evidence that would be sent."
        ) from exc

    warnings = validate_answer(answer, packet)
    try:
        parsed = json.loads(answer)
        print(json_dumps(parsed))
    except json.JSONDecodeError:
        print(answer)
    if warnings:
        print("[grounding warnings]", file=sys.stderr)
        for warning in warnings:
            print(f"- {warning}", file=sys.stderr)

    session_id = store.save_session(
        program_id=packet["program"]["id"],
        question=args.question,
        answer=answer,
        packet=packet,
        warnings=warnings,
        model=model,
    )
    print(f"session: {session_id}", file=sys.stderr)
    store.close()
    return 0


# ----------------------------------------------------------------------
# patch
# ----------------------------------------------------------------------
def _patch_plan(args: argparse.Namespace) -> int:
    store = _store(args)
    new_bytes = parse_hex_bytes(args.bytes)
    file_offset = parse_offset(args.file_offset) if args.file_offset is not None else None
    plan = create_patch_plan(
        store,
        args.program,
        address=args.address,
        file_offset=file_offset,
        new_bytes=new_bytes,
        reason=args.reason,
        authorization=args.authorization,
    )
    print(json_dumps(plan))
    print("")
    print(render_patch_diff(plan))
    store.close()
    return 0


def _patch_candidates(args: argparse.Namespace) -> int:
    store = _store(args)
    candidates = build_candidates(store, args.program, args.function)
    if args.json:
        _print_json(candidates)
    elif not candidates:
        print("no deterministic candidates found for this function")
    else:
        _print_table(
            ["candidate", "kind", "address", "validation", "title"],
            [
                [
                    candidate["id"],
                    candidate["kind"],
                    candidate["target_address"],
                    "ok" if candidate["validation"]["ok"] else "failed",
                    candidate["title"][:70],
                ]
                for candidate in candidates
            ],
        )
    store.close()
    return 0


def _patch_advise(args: argparse.Namespace) -> int:
    store = _store(args)
    if args.candidate_id:
        candidates = build_candidates(store, args.program, args.function)
        candidate = select_candidate(candidates, args.candidate_id)
    elif args.kind:
        candidate = build_candidate(
            store,
            args.program,
            args.function,
            args.kind,
            address=args.address,
            value=args.value,
        )
    else:
        raise ReiaError("provide --candidate-id or --kind")

    plan = create_plan_from_candidate(
        store,
        args.program,
        candidate,
        reason=args.reason,
        authorization=args.authorization,
    )
    if args.json:
        _print_json({"candidate": candidate, "plan": plan})
    else:
        print(render_advisor_report({"candidate": candidate, "plan": plan}))
        print("")
        print(render_patch_diff(plan))
    store.close()
    return 0


def _patch_ai(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    store = Store(workspace.db_path)
    config = workspace.load_config()
    model = args.model or str(config.get("model") or DEFAULT_MODEL)
    program = store.get_program(args.program)
    result = advise_with_ai(
        store,
        args.program,
        args.function,
        args.intent,
        model=model,
        reason=args.reason,
        authorization=args.authorization,
    )
    if args.json:
        _print_json(result)
    else:
        print(render_advisor_report(result, program_path=program["path"]))
        print("")
        print(render_patch_diff(result["plan"]))
    store.close()
    return 0


def _patch_validate(args: argparse.Namespace) -> int:
    store = _store(args)
    result = validate_plan(store, args.plan_id)
    if args.json:
        _print_json(result)
    else:
        print(f"plan: {result['plan_id']}")
        print(f"status: {result['status']}")
        print(f"validation: {'ok' if result['ok'] else 'failed'}")
        for error in result["errors"]:
            print(f"[error] {error}")
        for warning in result["warnings"]:
            print(f"[warn] {warning}")
    store.close()
    return 0 if result["ok"] else 1


def _patch_apply(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    store = Store(workspace.db_path)
    applied = apply_patch_plan(
        store,
        args.plan_id,
        patches_dir=workspace.patches_dir,
        approve=args.approve,
        authorization=args.authorization,
    )
    print(json_dumps(applied))
    store.close()
    return 0


def _patch_rollback(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    store = Store(workspace.db_path)
    plan = rollback_patch_plan(store, args.plan_id, patches_dir=workspace.patches_dir)
    print(json_dumps(plan))
    store.close()
    return 0


def _patch_list(args: argparse.Namespace) -> int:
    store = _store(args)
    program_id = store.get_program(args.program)["id"] if args.program else None
    rows = store.list_patch_plans(program_id)
    if args.json:
        _print_json(rows)
    else:
        _print_table(
            ["id", "program", "status", "offset", "address", "reason"],
            [
                [
                    row["id"],
                    row["program_id"],
                    row["status"],
                    hex(int(row["file_offset"])),
                    row["target_address"] or "",
                    row["reason"][:60],
                ]
                for row in rows
            ],
        )
    store.close()
    return 0


# ----------------------------------------------------------------------
# MCP
# ----------------------------------------------------------------------
def _mcp(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    return serve_mcp(workspace, allow_external_client=args.allow_external_client)


# ----------------------------------------------------------------------
# parser
# ----------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reia",
        description="Resverse IA: local-first AI-assisted reverse engineering for Ghidra.",
    )
    parser.add_argument("--workspace", help="workspace path (default: ~/.reia or REIA_HOME)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="initialize a workspace")
    init.add_argument("--profile", choices=PROFILES, default="ctf")
    init.add_argument("--allow-onedrive", action="store_true")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=_init)

    doctor = sub.add_parser("doctor", help="check the local toolchain")
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(func=_doctor)

    config = sub.add_parser("config", help="inspect workspace configuration")
    config_sub = config.add_subparsers(dest="config_command", required=True)
    config_show = config_sub.add_parser("show")
    config_show.set_defaults(func=_config_show)
    config_mcp = config_sub.add_parser("mcp", help="print MCP client configuration")
    config_mcp.set_defaults(func=_config_mcp)

    import_json = sub.add_parser("import-json", help="import a Ghidra export JSON")
    import_json.add_argument("export")
    import_json.add_argument("--profile", choices=PROFILES)
    import_json.add_argument("--path", help="path to the original binary")
    import_json.add_argument("--force", action="store_true")
    import_json.set_defaults(func=_import_json)

    dll = sub.add_parser("dll", help="open and inspect DLL/EXE/ELF programs")
    dll_sub = dll.add_subparsers(dest="dll_command", required=True)

    dll_open = dll_sub.add_parser("open", help="import and analyze a binary with Ghidra")
    dll_open.add_argument("binary")
    dll_open.add_argument("--profile", choices=PROFILES)
    dll_open.add_argument("--export-json", help="use a previously generated export instead of running Ghidra")
    dll_open.add_argument("--ghidra-home")
    dll_open.add_argument("--no-decompile", action="store_true")
    dll_open.add_argument("--max-functions", type=int, default=5000)
    dll_open.add_argument("--max-strings", type=int, default=5000)
    dll_open.add_argument("--force", action="store_true")
    dll_open.set_defaults(func=_dll_open)

    dll_info = dll_sub.add_parser("info", help="show program metadata")
    dll_info.add_argument("program", nargs="?")
    dll_info.set_defaults(func=_dll_info)

    dll_exports = dll_sub.add_parser("exports", help="list exports")
    dll_exports.add_argument("program", nargs="?")
    dll_exports.add_argument("--json", action="store_true")
    dll_exports.set_defaults(func=_dll_exports)

    dll_imports = dll_sub.add_parser("imports", help="list imports")
    dll_imports.add_argument("program", nargs="?")
    dll_imports.add_argument("--json", action="store_true")
    dll_imports.set_defaults(func=_dll_imports)

    dll_functions = dll_sub.add_parser("functions", help="search functions")
    dll_functions.add_argument("program", nargs="?")
    dll_functions.add_argument("--query")
    dll_functions.add_argument("--limit", type=int, default=20)
    dll_functions.add_argument("--json", action="store_true")
    dll_functions.set_defaults(func=_dll_functions)

    dll_decompile = dll_sub.add_parser("decompile", help="show decompiled code")
    dll_decompile.add_argument("program", nargs="?")
    dll_decompile.add_argument("--function")
    dll_decompile.add_argument("--address")
    dll_decompile.add_argument("--json", action="store_true")
    dll_decompile.set_defaults(func=_dll_decompile)

    dll_strings = dll_sub.add_parser("strings", help="list extracted strings")
    dll_strings.add_argument("program", nargs="?")
    dll_strings.add_argument("--query")
    dll_strings.add_argument("--limit", type=int, default=100)
    dll_strings.add_argument("--json", action="store_true")
    dll_strings.set_defaults(func=_dll_strings)

    evidence = sub.add_parser("evidence", help="build a citation-ready evidence packet")
    evidence.add_argument("program", nargs="?")
    evidence.add_argument("--query")
    evidence.add_argument("--function")
    evidence.add_argument("--max-functions", type=int, default=5)
    evidence.add_argument("--max-chars", type=int, default=6000)
    evidence.add_argument("-o", "--output")
    evidence.set_defaults(func=_evidence)

    ask = sub.add_parser("ask", help="ask the local Ollama model using an evidence packet")
    ask.add_argument("question")
    ask.add_argument("program", nargs="?")
    ask.add_argument("--query")
    ask.add_argument("--function")
    ask.add_argument("--model")
    ask.add_argument("--max-functions", type=int, default=5)
    ask.add_argument("--max-chars", type=int, default=6000)
    ask.add_argument("--packet-only", action="store_true")
    ask.set_defaults(func=_ask)

    patch = sub.add_parser("patch", help="Patch Lab (copies only, CTF/lab/own binaries)")
    patch_sub = patch.add_subparsers(dest="patch_command", required=True)

    patch_candidates = patch_sub.add_parser(
        "candidates", help="list deterministic edit candidates for a function"
    )
    patch_candidates.add_argument("program", nargs="?")
    patch_candidates.add_argument("--function", required=True)
    patch_candidates.add_argument("--json", action="store_true")
    patch_candidates.set_defaults(func=_patch_candidates)

    patch_advise = patch_sub.add_parser(
        "advise", help="build and validate a deterministic candidate plan"
    )
    patch_advise.add_argument("program", nargs="?")
    patch_advise.add_argument("--function", required=True)
    patch_advise.add_argument("--candidate-id")
    patch_advise.add_argument(
        "--kind",
        choices=["return_constant", "invert_branch", "skip_call", "nop_instruction"],
    )
    patch_advise.add_argument("--address")
    patch_advise.add_argument("--value", type=lambda text: int(text, 0), default=0)
    patch_advise.add_argument("--reason", required=True)
    patch_advise.add_argument("--authorization", help="CTF/lab or ownership basis")
    patch_advise.add_argument("--json", action="store_true")
    patch_advise.set_defaults(func=_patch_advise)

    patch_ai = patch_sub.add_parser(
        "ai", help="let the local model pick one validated candidate"
    )
    patch_ai.add_argument("program", nargs="?")
    patch_ai.add_argument("--function", required=True)
    patch_ai.add_argument("--intent", required=True)
    patch_ai.add_argument("--reason", default="")
    patch_ai.add_argument("--model")
    patch_ai.add_argument("--authorization", help="CTF/lab or ownership basis")
    patch_ai.add_argument("--json", action="store_true")
    patch_ai.set_defaults(func=_patch_ai)

    patch_validate = patch_sub.add_parser(
        "validate", help="re-check a patch plan against the current file"
    )
    patch_validate.add_argument("plan_id")
    patch_validate.add_argument("--json", action="store_true")
    patch_validate.set_defaults(func=_patch_validate)

    patch_plan = patch_sub.add_parser("plan", help="create a patch plan")
    patch_plan.add_argument("program", nargs="?")
    patch_plan.add_argument("--address")
    patch_plan.add_argument("--file-offset")
    patch_plan.add_argument("--bytes", required=True, help="replacement bytes, e.g. '90 90'")
    patch_plan.add_argument("--reason", required=True)
    patch_plan.add_argument("--authorization", help="CTF/lab or ownership basis")
    patch_plan.set_defaults(func=_patch_plan)

    patch_apply = patch_sub.add_parser("apply", help="apply a plan to a copy")
    patch_apply.add_argument("plan_id")
    patch_apply.add_argument("--approve", action="store_true")
    patch_apply.add_argument("--authorization")
    patch_apply.set_defaults(func=_patch_apply)

    patch_rollback = patch_sub.add_parser("rollback", help="rollback a patched copy")
    patch_rollback.add_argument("plan_id")
    patch_rollback.set_defaults(func=_patch_rollback)

    patch_list = patch_sub.add_parser("list", help="list patch plans")
    patch_list.add_argument("program", nargs="?")
    patch_list.add_argument("--json", action="store_true")
    patch_list.set_defaults(func=_patch_list)

    mcp = sub.add_parser("mcp", help="run the MCP stdio server")
    mcp.add_argument("--allow-external-client", action="store_true")
    mcp.set_defaults(func=_mcp)

    return parser


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ReiaError, PolicyError, PatchError, BinaryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
