from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any


def _log(message: str) -> None:
    print(f"[reia-ghidra] {message}", file=sys.stderr, flush=True)


def _safe_str(value: Any, default: str = "") -> str:
    try:
        return str(value)
    except Exception:
        return default


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _iterator_to_list(iterator: Any, limit: int | None = None) -> list[Any]:
    items: list[Any] = []
    while iterator.hasNext():
        items.append(iterator.next())
        if limit is not None and len(items) >= limit:
            break
    return items


def _program_metadata(program: Any, binary: Path, sha256: str) -> dict[str, Any]:
    language = program.getLanguage()
    try:
        image_base = hex(int(program.getImageBase().getOffset()))
    except Exception:
        image_base = _safe_str(program.getImageBase())
    try:
        bits = int(program.getAddressFactory().getDefaultAddressSpace().getSize())
    except Exception:
        bits = 0
    try:
        endian = "big" if language.isBigEndian() else "little"
    except Exception:
        endian = "unknown"
    try:
        processor = _safe_str(language.getProcessor())
    except Exception:
        processor = ""
    return {
        "name": _safe_str(program.getName(), binary.name),
        "path": str(binary.resolve()),
        "sha256": sha256,
        "format": _safe_str(program.getExecutableFormat()),
        "arch": processor,
        "bits": bits,
        "endian": endian,
        "image_base": image_base,
        "language": _safe_str(program.getLanguageID()),
        "executable_path": _safe_str(program.getExecutablePath()),
    }


def _sections(program: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    try:
        blocks = program.getMemory().getBlocks()
    except Exception:
        return result
    for block in blocks:
        try:
            result.append(
                {
                    "name": _safe_str(block.getName()),
                    "start": _safe_str(block.getStart()),
                    "end": _safe_str(block.getEnd()),
                    "size": int(block.getSize()),
                    "read": bool(block.isRead()),
                    "write": bool(block.isWrite()),
                    "execute": bool(block.isExecute()),
                    "volatile": bool(block.isVolatile()),
                }
            )
        except Exception:
            continue
    return result


def _entry_points(program: Any) -> list[str]:
    result: list[str] = []
    try:
        iterator = program.getSymbolTable().getExternalEntryPointIterator()
        while iterator.hasNext():
            result.append(_safe_str(iterator.next()))
    except Exception:
        pass
    return result


def _exports(program: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    try:
        symbols = program.getSymbolTable().getAllSymbols(True)
        while symbols.hasNext():
            symbol = symbols.next()
            try:
                if not symbol.isExternalEntryPoint():
                    continue
                name = _safe_str(symbol.getName())
                address = _safe_str(symbol.getAddress())
                key = (name, address)
                if key in seen:
                    continue
                seen.add(key)
                result.append({"name": name, "address": address, "ordinal": None})
            except Exception:
                continue
    except Exception:
        pass
    return result


def _imports(program: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    try:
        symbols = program.getSymbolTable().getExternalSymbols()
        while symbols.hasNext():
            symbol = symbols.next()
            try:
                name = _safe_str(symbol.getName())
                address = _safe_str(symbol.getAddress())
                library = ""
                try:
                    library = _safe_str(symbol.getParentNamespace().getName())
                except Exception:
                    pass
                key = (name, library, address)
                if key in seen:
                    continue
                seen.add(key)
                result.append({"name": name, "library": library, "address": address})
            except Exception:
                continue
    except Exception:
        pass
    return result


def _strings_and_function_strings(
    program: Any,
    function_manager: Any,
    max_strings: int,
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    strings: list[dict[str, Any]] = []
    by_function: dict[str, list[str]] = {}
    try:
        data_iterator = program.getListing().getDefinedData(True)
    except Exception:
        return strings, by_function

    while data_iterator.hasNext() and len(strings) < max_strings:
        data = data_iterator.next()
        try:
            type_name = _safe_str(data.getDataType().getName()).lower()
            if not any(token in type_name for token in ("string", "unicode", "char")):
                continue
            value = data.getValue()
            if value is None:
                continue
            text = _safe_str(value)
            if not text:
                continue
            address = data.getAddress()
            encoding = "unicode" if "unicode" in type_name else "ascii"
            strings.append(
                {
                    "address": _safe_str(address),
                    "value": text[:2000],
                    "encoding": encoding,
                }
            )
            try:
                references = program.getReferenceManager().getReferencesTo(address)
                while references.hasNext():
                    reference = references.next()
                    function = function_manager.getFunctionContaining(reference.getFromAddress())
                    if function is None:
                        continue
                    entry = _safe_str(function.getEntryPoint())
                    bucket = by_function.setdefault(entry, [])
                    if text not in bucket and len(bucket) < 30:
                        bucket.append(text[:500])
            except Exception:
                continue
        except Exception:
            continue
    return strings, by_function


def _data_types(program: Any, limit: int = 1000) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    try:
        manager = program.getDataTypeManager()
        iterator = manager.getAllDataTypes()
    except Exception:
        return result
    while iterator.hasNext() and len(result) < limit:
        data_type = iterator.next()
        try:
            class_name = data_type.getClass().getSimpleName()
            if class_name not in ("Structure", "Union", "Enum", "TypeDef"):
                continue
            result.append(
                {
                    "name": _safe_str(data_type.getName()),
                    "path": _safe_str(data_type.getPathName()),
                    "kind": class_name,
                    "length": int(data_type.getLength()),
                }
            )
        except Exception:
            continue
    return result


def export_program(
    binary: Path,
    output: Path,
    *,
    ghidra_home: str | None,
    project_location: str | None,
    project_name: str | None,
    max_functions: int,
    max_strings: int,
    decompile: bool,
) -> dict[str, Any]:
    try:
        import pyghidra
    except ImportError as exc:
        raise SystemExit(
            "pyghidra is not installed. Install Ghidra 11.3+ and run: pip install pyghidra"
        ) from exc

    install_dir = ghidra_home or os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")
    try:
        started = bool(pyghidra.started())
    except Exception:
        started = False
    if not started:
        _log(f"starting PyGhidra (install_dir={install_dir or 'auto'})")
        pyghidra.start(install_dir=Path(install_dir).expanduser() if install_dir else None)

    from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
    from ghidra.util.task import ConsoleTaskMonitor

    sha256 = _sha256(binary)
    project_dir = Path(project_location).expanduser().resolve() if project_location else output.parent / "ghidra-projects"
    project_dir.mkdir(parents=True, exist_ok=True)
    project_name = project_name or f"reia_{binary.stem}_{sha256[:8]}"

    _log(f"opening {binary} in project {project_name}")
    with pyghidra.open_program(
        str(binary),
        project_location=str(project_dir),
        project_name=project_name,
        analyze=True,
    ) as flat_api:
        program = flat_api.getCurrentProgram()
        monitor = ConsoleTaskMonitor()
        function_manager = program.getFunctionManager()
        decompiler = FlatDecompilerAPI(flat_api)
        decompiler.initialize()

        metadata = _program_metadata(program, binary, sha256)
        strings, strings_by_function = _strings_and_function_strings(
            program, function_manager, max_strings
        )

        functions: list[dict[str, Any]] = []
        iterator = function_manager.getFunctions(True)
        while iterator.hasNext() and len(functions) < max_functions:
            function = iterator.next()
            try:
                entry = _safe_str(function.getEntryPoint())
                name = _safe_str(function.getName(), entry)
                signature = ""
                try:
                    signature = _safe_str(function.getSignature())
                except Exception:
                    pass
                return_type = ""
                try:
                    return_type = _safe_str(function.getReturnType().getName())
                except Exception:
                    pass
                parameters: list[dict[str, Any]] = []
                try:
                    for parameter in function.getParameters():
                        parameters.append(
                            {
                                "name": _safe_str(parameter.getName()),
                                "type": _safe_str(parameter.getDataType().getName()),
                                "ordinal": int(parameter.getOrdinal()),
                            }
                        )
                except Exception:
                    pass
                callers: list[str] = []
                callees: list[str] = []
                try:
                    callers = [
                        _safe_str(item.getEntryPoint())
                        for item in function.getCallingFunctions(monitor)
                    ]
                except Exception:
                    pass
                try:
                    callees = [
                        _safe_str(item.getEntryPoint())
                        for item in function.getCalledFunctions(monitor)
                    ]
                except Exception:
                    pass
                xrefs: list[dict[str, str]] = []
                try:
                    references = program.getReferenceManager().getReferencesTo(
                        function.getEntryPoint()
                    )
                    while references.hasNext():
                        reference = references.next()
                        xrefs.append(
                            {
                                "from": _safe_str(reference.getFromAddress()),
                                "to": _safe_str(reference.getToAddress()),
                                "type": _safe_str(reference.getReferenceType()),
                            }
                        )
                except Exception:
                    pass

                decompiled = ""
                decompilation_error = None
                if decompile:
                    try:
                        decompiled = _safe_str(decompiler.decompile(function, 60))
                    except Exception as exc:
                        decompilation_error = f"{type(exc).__name__}: {exc}"
                try:
                    size = int(function.getBody().getNumAddresses())
                except Exception:
                    size = 0
                namespace = ""
                try:
                    namespace = _safe_str(function.getParentNamespace().getName())
                except Exception:
                    pass

                functions.append(
                    {
                        "entry": entry,
                        "name": name,
                        "namespace": namespace,
                        "signature": signature,
                        "return_type": return_type,
                        "parameters": parameters,
                        "size": size,
                        "decompiled": decompiled,
                        "callers": callers,
                        "callees": callees,
                        "strings": strings_by_function.get(entry, []),
                        "xrefs": xrefs,
                        "is_external": bool(function.isExternal()),
                        "is_thunk": bool(function.isThunk()),
                        "decompilation_error": decompilation_error,
                    }
                )
            except Exception as exc:
                _log(f"skipping function: {type(exc).__name__}: {exc}")

        try:
            decompiler.dispose()
        except Exception:
            pass

        export = {
            "schema_version": 1,
            "program": metadata,
            "functions": functions,
            "exports": _exports(program),
            "imports": _imports(program),
            "strings": strings,
            "data_types": _data_types(program),
            "entry_points": _entry_points(program),
            "sections": _sections(program),
        }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(export, ensure_ascii=False, indent=2), encoding="utf-8")
    _log(
        f"wrote {output} ({len(export['functions'])} functions, "
        f"{len(export['exports'])} exports, {len(export['strings'])} strings)"
    )
    return export


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export a Ghidra program model to JSON for Resverse IA."
    )
    parser.add_argument("binary", help="PE/ELF/Mach-O file to import and analyze")
    parser.add_argument("-o", "--output", required=True, help="output JSON path")
    parser.add_argument("--ghidra-home", help="Ghidra installation directory")
    parser.add_argument("--project-location", help="Ghidra project parent directory")
    parser.add_argument("--project-name", help="Ghidra project name")
    parser.add_argument("--max-functions", type=int, default=5000)
    parser.add_argument("--max-strings", type=int, default=5000)
    parser.add_argument("--no-decompile", action="store_true")
    args = parser.parse_args(argv)

    binary = Path(args.binary).expanduser().resolve()
    if not binary.exists():
        print(f"binary not found: {binary}", file=sys.stderr)
        return 2
    try:
        export_program(
            binary,
            Path(args.output).expanduser().resolve(),
            ghidra_home=args.ghidra_home,
            project_location=args.project_location,
            project_name=args.project_name,
            max_functions=max(1, args.max_functions),
            max_strings=max(0, args.max_strings),
            decompile=not args.no_decompile,
        )
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"ghidra export failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
