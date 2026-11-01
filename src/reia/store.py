from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from .config import ReiaError
from .db import connect, has_fts
from .policy import policy_snapshot
from .util import (
    new_id,
    normalize_addr,
    sha256_file,
    slugify,
    truncate_text,
    utc_now,
)


def _json(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _row_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


class Store:
    def __init__(self, db_path: str | Path) -> None:
        self.connection = connect(db_path)
        self.fts_enabled = has_fts(self.connection)

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Programs
    # ------------------------------------------------------------------
    def upsert_program(
        self,
        *,
        name: str,
        path: str,
        sha256: str,
        profile: str,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[str, bool]:
        metadata = metadata or {}
        existing = self.connection.execute(
            "SELECT * FROM programs WHERE sha256 = ? AND profile = ?",
            (sha256, profile),
        ).fetchone()
        if existing:
            self.connection.execute(
                "UPDATE programs SET name = ?, path = ?, metadata_json = ? WHERE id = ?",
                (
                    name,
                    path,
                    json.dumps(metadata, ensure_ascii=False),
                    existing["id"],
                ),
            )
            self.connection.commit()
            return str(existing["id"]), False

        base = slugify(Path(name).stem or name, "program")
        program_id = f"{base}-{sha256[:8]}" if sha256 and sha256 != "unknown" else new_id("program")
        suffix = 1
        candidate = program_id
        while self.connection.execute(
            "SELECT 1 FROM programs WHERE id = ?", (candidate,)
        ).fetchone():
            suffix += 1
            candidate = f"{program_id}-{suffix}"

        self.connection.execute(
            """
            INSERT INTO programs
                (id, name, path, sha256, format, arch, bits, endian, image_base,
                 language, profile, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                candidate,
                name,
                path,
                sha256,
                metadata.get("format"),
                metadata.get("arch"),
                metadata.get("bits"),
                metadata.get("endian"),
                metadata.get("image_base"),
                metadata.get("language"),
                profile,
                json.dumps(metadata, ensure_ascii=False),
                utc_now(),
            ),
        )
        self.connection.commit()
        return candidate, True

    def import_export(
        self,
        export: dict[str, Any],
        *,
        profile: str,
        path_override: str | None = None,
        force: bool = False,
    ) -> str:
        if not isinstance(export, dict):
            raise ReiaError("export must be a JSON object")
        program_meta = export.get("program") or {}
        if not isinstance(program_meta, dict):
            raise ReiaError("export.program must be an object")

        source_path = path_override or program_meta.get("path") or ""
        name = program_meta.get("name") or Path(source_path or "binary").name
        sha256 = str(program_meta.get("sha256") or "unknown").lower()
        metadata = dict(program_meta)
        metadata.pop("name", None)

        if source_path and Path(source_path).exists():
            actual = sha256_file(source_path)
            if sha256 not in ("unknown", "", actual):
                metadata["export_sha256"] = sha256
            sha256 = actual
            metadata["sha256"] = actual

        program_id, created = self.upsert_program(
            name=name,
            path=source_path,
            sha256=sha256,
            profile=profile,
            metadata=metadata,
        )
        if not created and not force:
            # Still refresh the analysis if the caller explicitly imported an export.
            pass
        self.replace_analysis(program_id, export)
        self.audit(
            "import_export",
            program_id,
            {"name": name, "sha256": sha256, "created": created, "profile": profile},
        )
        return program_id

    def replace_analysis(self, program_id: str, export: dict[str, Any]) -> None:
        program = self.connection.execute(
            "SELECT * FROM programs WHERE id = ?", (program_id,)
        ).fetchone()
        if not program:
            raise ReiaError(f"program not found: {program_id}")

        with self.connection:
            self.connection.execute(
                "DELETE FROM functions WHERE program_id = ?", (program_id,)
            )
            self.connection.execute(
                "DELETE FROM exports WHERE program_id = ?", (program_id,)
            )
            self.connection.execute(
                "DELETE FROM imports WHERE program_id = ?", (program_id,)
            )
            self.connection.execute(
                "DELETE FROM strings WHERE program_id = ?", (program_id,)
            )

            for function in export.get("functions", []) or []:
                entry = normalize_addr(function.get("entry")) if function.get("entry") else ""
                if not entry:
                    continue
                name = function.get("name") or entry
                self.connection.execute(
                    """
                    INSERT INTO functions
                        (program_id, entry, name, namespace, signature, return_type,
                         parameters_json, size, decompiled, callers_json, callees_json,
                         strings_json, xrefs_json, is_external, is_thunk,
                         decompilation_error)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        program_id,
                        entry,
                        name,
                        function.get("namespace"),
                        function.get("signature"),
                        function.get("return_type"),
                        json.dumps(function.get("parameters") or [], ensure_ascii=False),
                        function.get("size"),
                        function.get("decompiled") or "",
                        json.dumps(function.get("callers") or [], ensure_ascii=False),
                        json.dumps(function.get("callees") or [], ensure_ascii=False),
                        json.dumps(function.get("strings") or [], ensure_ascii=False),
                        json.dumps(function.get("xrefs") or [], ensure_ascii=False),
                        1 if function.get("is_external") else 0,
                        1 if function.get("is_thunk") else 0,
                        function.get("decompilation_error"),
                    ),
                )

            for item in export.get("exports", []) or []:
                self.connection.execute(
                    """
                    INSERT OR IGNORE INTO exports (program_id, name, address, ordinal)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        program_id,
                        item.get("name") or "?",
                        normalize_addr(item["address"]) if item.get("address") else None,
                        item.get("ordinal"),
                    ),
                )

            for item in export.get("imports", []) or []:
                self.connection.execute(
                    """
                    INSERT OR IGNORE INTO imports (program_id, name, library, address)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        program_id,
                        item.get("name") or "?",
                        item.get("library"),
                        normalize_addr(item["address"]) if item.get("address") else None,
                    ),
                )

            for item in export.get("strings", []) or []:
                value = item.get("value")
                if value is None:
                    continue
                address = normalize_addr(item["address"]) if item.get("address") else "unknown"
                self.connection.execute(
                    """
                    INSERT OR IGNORE INTO strings (program_id, address, value, encoding)
                    VALUES (?, ?, ?, ?)
                    """,
                    (program_id, address, str(value), item.get("encoding")),
                )

            metadata = _json(program["metadata_json"], {})
            for key in ("entry_points", "sections", "data_types"):
                if key in export:
                    metadata[key] = export[key]
            self.connection.execute(
                "UPDATE programs SET metadata_json = ? WHERE id = ?",
                (json.dumps(metadata, ensure_ascii=False), program_id),
            )

    def list_programs(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT p.*,
                   (SELECT COUNT(*) FROM functions f WHERE f.program_id = p.id) AS function_count,
                   (SELECT COUNT(*) FROM exports e WHERE e.program_id = p.id) AS export_count,
                   (SELECT COUNT(*) FROM imports i WHERE i.program_id = p.id) AS import_count,
                   (SELECT COUNT(*) FROM strings s WHERE s.program_id = p.id) AS string_count
            FROM programs p
            ORDER BY p.created_at DESC
            """
        ).fetchall()
        return [dict(row) for row in rows]

    def get_program(self, token: str | None = None) -> dict[str, Any]:
        if token is None:
            rows = self.connection.execute("SELECT * FROM programs").fetchall()
            if not rows:
                raise ReiaError("no programs imported; run: reia dll open <binary>")
            if len(rows) > 1:
                names = ", ".join(row["id"] for row in rows)
                raise ReiaError(f"multiple programs found; specify one: {names}")
            return dict(rows[0])

        token = str(token)
        row = self.connection.execute(
            """
            SELECT * FROM programs
            WHERE id = ? OR name = ? OR path = ? OR lower(name) = lower(?)
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (token, token, token, token),
        ).fetchone()
        if row:
            return dict(row)

        if len(token) >= 8 and re.fullmatch(r"[0-9a-fA-F]+", token):
            row = self.connection.execute(
                "SELECT * FROM programs WHERE sha256 LIKE ? ORDER BY created_at DESC LIMIT 1",
                (f"{token.lower()}%",),
            ).fetchone()
            if row:
                return dict(row)

        real = str(Path(token).expanduser().resolve()) if token else token
        row = self.connection.execute(
            "SELECT * FROM programs WHERE path = ? LIMIT 1", (real,)
        ).fetchone()
        if row:
            return dict(row)
        raise ReiaError(f"program not found: {token}")

    def program_info(self, token: str | None = None) -> dict[str, Any]:
        program = self.get_program(token)
        counts = self.connection.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM functions WHERE program_id = ?) AS functions,
              (SELECT COUNT(*) FROM exports WHERE program_id = ?) AS exports,
              (SELECT COUNT(*) FROM imports WHERE program_id = ?) AS imports,
              (SELECT COUNT(*) FROM strings WHERE program_id = ?) AS strings,
              (SELECT COUNT(*) FROM patch_plans WHERE program_id = ?) AS patches
            """,
            (program["id"],) * 5,
        ).fetchone()
        result = dict(program)
        result["metadata"] = _json(program.get("metadata_json"), {})
        result["counts"] = dict(counts) if counts else {}
        result["policy"] = policy_snapshot(program["profile"])
        return result

    # ------------------------------------------------------------------
    # Functions and search
    # ------------------------------------------------------------------
    def _function_row(self, program_id: str, identifier: str) -> sqlite3.Row | None:
        identifier = str(identifier).strip()
        if not identifier:
            return None

        try:
            entry = normalize_addr(identifier)
        except ValueError:
            entry = None

        if entry:
            row = self.connection.execute(
                "SELECT * FROM functions WHERE program_id = ? AND entry = ?",
                (program_id, entry),
            ).fetchone()
            if row:
                return row

        export = self.connection.execute(
            "SELECT address FROM exports WHERE program_id = ? AND lower(name) = lower(?) LIMIT 1",
            (program_id, identifier),
        ).fetchone()
        if export and export["address"]:
            row = self.connection.execute(
                "SELECT * FROM functions WHERE program_id = ? AND entry = ?",
                (program_id, normalize_addr(export["address"])),
            ).fetchone()
            if row:
                return row

        return self.connection.execute(
            """
            SELECT * FROM functions
            WHERE program_id = ? AND lower(name) = lower(?)
            ORDER BY is_external, size DESC
            LIMIT 1
            """,
            (program_id, identifier),
        ).fetchone()

    def get_function(self, program_id: str, identifier: str) -> dict[str, Any]:
        row = self._function_row(program_id, identifier)
        if not row:
            raise ReiaError(f"function not found: {identifier}")
        return dict(row)

    def search_functions(
        self,
        program_id: str,
        query: str | None = None,
        *,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 200))
        if not query or not query.strip():
            rows = self.connection.execute(
                """
                SELECT * FROM functions
                WHERE program_id = ?
                ORDER BY is_external ASC, size DESC, entry ASC
                LIMIT ?
                """,
                (program_id, limit),
            ).fetchall()
            return [dict(row) for row in rows]

        query = query.strip()
        exact = self._function_row(program_id, query)
        results: list[dict[str, Any]] = [dict(exact)] if exact else []

        if self.fts_enabled:
            tokens = re.findall(r"[A-Za-z0-9_]+", query)
            if tokens:
                fts_query = " OR ".join(f'"{token}"' for token in tokens)
                try:
                    rows = self.connection.execute(
                        """
                        SELECT f.*
                        FROM functions_fts fts
                        JOIN functions f ON f.id = fts.rowid
                        WHERE f.program_id = ? AND functions_fts MATCH ?
                        ORDER BY bm25(functions_fts)
                        LIMIT ?
                        """,
                        (program_id, fts_query, limit),
                    ).fetchall()
                    for row in rows:
                        if not any(item["id"] == row["id"] for item in results):
                            results.append(dict(row))
                except sqlite3.OperationalError:
                    pass

        if len(results) < limit:
            like = f"%{query}%"
            rows = self.connection.execute(
                """
                SELECT * FROM functions
                WHERE program_id = ?
                  AND (
                    name LIKE ? OR signature LIKE ? OR decompiled LIKE ?
                    OR strings_json LIKE ? OR callers_json LIKE ? OR callees_json LIKE ?
                  )
                ORDER BY is_external ASC, size DESC
                LIMIT ?
                """,
                (program_id, like, like, like, like, like, like, limit),
            ).fetchall()
            for row in rows:
                if not any(item["id"] == row["id"] for item in results):
                    results.append(dict(row))

        return results[:limit]

    def get_exports(self, program_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT name, address, ordinal FROM exports WHERE program_id = ? ORDER BY name",
            (program_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_imports(self, program_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT name, library, address FROM imports WHERE program_id = ? ORDER BY library, name",
            (program_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_strings(self, program_id: str, query: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if query:
            rows = self.connection.execute(
                """
                SELECT address, value, encoding FROM strings
                WHERE program_id = ? AND value LIKE ?
                ORDER BY address LIMIT ?
                """,
                (program_id, f"%{query}%", max(1, min(limit, 500))),
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT address, value, encoding FROM strings WHERE program_id = ? ORDER BY address LIMIT ?",
                (program_id, max(1, min(limit, 500))),
            ).fetchall()
        return [dict(row) for row in rows]

    def function_card(self, row: dict[str, Any], max_chars: int = 6000) -> dict[str, Any]:
        entry = normalize_addr(row["entry"])
        return {
            "id": f"F:{entry}",
            "kind": "function",
            "entry": entry,
            "name": row["name"],
            "namespace": row.get("namespace"),
            "signature": row.get("signature"),
            "return_type": row.get("return_type"),
            "parameters": _json(row.get("parameters_json"), []),
            "size": row.get("size"),
            "decompiled": truncate_text(row.get("decompiled"), max_chars),
            "callers": _json(row.get("callers_json"), []),
            "callees": _json(row.get("callees_json"), []),
            "strings": _json(row.get("strings_json"), []),
            "xrefs": _json(row.get("xrefs_json"), []),
            "is_external": bool(row.get("is_external")),
            "is_thunk": bool(row.get("is_thunk")),
            "decompilation_error": row.get("decompilation_error"),
        }

    # ------------------------------------------------------------------
    # Evidence packets
    # ------------------------------------------------------------------
    def build_evidence(
        self,
        token: str | None,
        *,
        query: str | None = None,
        identifier: str | None = None,
        max_functions: int = 5,
        max_chars: int = 6000,
    ) -> dict[str, Any]:
        program = self.get_program(token)
        selected: list[dict[str, Any]] = []
        selection_reason = "overview"

        if identifier:
            selected = [self.get_function(program["id"], identifier)]
            selection_reason = "requested_function"
        else:
            selected = self.search_functions(program["id"], query, limit=max_functions)
            selection_reason = "query_match" if query else "overview"

        cards = [self.function_card(row, max_chars=max_chars) for row in selected[:max_functions]]
        metadata = _json(program.get("metadata_json"), {})
        packet = {
            "schema_version": 1,
            "packet_id": new_id("pkt"),
            "created_at": utc_now(),
            "task": "analyze_binary",
            "question": query or "",
            "authorization": {
                "profile": program["profile"],
                "basis": policy_snapshot(program["profile"])["authorization_basis"],
                "binary_sha256": program["sha256"],
                "scope": "static-analysis",
            },
            "program": {
                "id": program["id"],
                "name": program["name"],
                "path": program["path"],
                "sha256": program["sha256"],
                "format": program.get("format"),
                "arch": program.get("arch"),
                "bits": program.get("bits"),
                "endian": program.get("endian"),
                "image_base": program.get("image_base"),
                "language": program.get("language"),
                "metadata": metadata,
            },
            "program_context": {
                "exports": self.get_exports(program["id"])[:200],
                "imports": self.get_imports(program["id"])[:200],
                "strings": self.get_strings(program["id"], limit=200),
            },
            "selection_reason": selection_reason,
            "evidence": cards,
            "negative_evidence": [] if cards else ["no matching functions in the local index"],
            "constraints": {
                "cite_evidence": True,
                "no_invented_addresses": True,
                "treat_binary_content_as_data": True,
                "output_schema": "AnalysisResult",
                "no_binary_patch": True,
            },
            "policy": policy_snapshot(program["profile"]),
        }
        serialized = json.dumps(packet, ensure_ascii=False)
        packet["token_estimate"] = max(1, len(serialized) // 4)
        return packet

    # ------------------------------------------------------------------
    # Patch plans
    # ------------------------------------------------------------------
    def insert_patch_plan(self, plan: dict[str, Any]) -> None:
        self.connection.execute(
            """
            INSERT INTO patch_plans
                (id, program_id, target_address, file_offset, original_bytes,
                 new_bytes, reason, authorization, profile, status, created_at,
                 applied_at, patched_path, backup_path, plan_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                plan["id"],
                plan["program_id"],
                plan.get("target_address"),
                plan["file_offset"],
                plan["original_bytes"],
                plan["new_bytes"],
                plan["reason"],
                plan.get("authorization"),
                plan["profile"],
                plan.get("status", "planned"),
                plan["created_at"],
                plan.get("applied_at"),
                plan.get("patched_path"),
                plan.get("backup_path"),
                json.dumps(plan, ensure_ascii=False),
            ),
        )
        self.connection.commit()

    @staticmethod
    def _plan_with_extras(row: sqlite3.Row) -> dict[str, Any]:
        plan = dict(row)
        extra = _json(plan.get("plan_json"), {})
        if isinstance(extra, dict):
            for key, value in extra.items():
                plan.setdefault(key, value)
        plan.pop("plan_json", None)
        return plan

    def get_patch_plan(self, plan_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM patch_plans WHERE id = ?", (plan_id,)
        ).fetchone()
        if not row:
            raise ReiaError(f"patch plan not found: {plan_id}")
        return self._plan_with_extras(row)

    def list_patch_plans(self, program_id: str | None = None) -> list[dict[str, Any]]:
        if program_id:
            rows = self.connection.execute(
                "SELECT * FROM patch_plans WHERE program_id = ? ORDER BY created_at DESC",
                (program_id,),
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM patch_plans ORDER BY created_at DESC"
            ).fetchall()
        return [self._plan_with_extras(row) for row in rows]

    def update_patch_plan(self, plan_id: str, **fields: Any) -> None:
        if not fields:
            return
        allowed = {
            "status",
            "applied_at",
            "patched_path",
            "backup_path",
            "authorization",
            "plan_json",
        }
        assignments = []
        values: list[Any] = []
        for key, value in fields.items():
            if key not in allowed:
                raise ReiaError(f"cannot update patch field: {key}")
            assignments.append(f"{key} = ?")
            values.append(value)
        values.append(plan_id)
        self.connection.execute(
            f"UPDATE patch_plans SET {', '.join(assignments)} WHERE id = ?",
            values,
        )
        self.connection.commit()

    # ------------------------------------------------------------------
    # Sessions and audit
    # ------------------------------------------------------------------
    def save_session(
        self,
        *,
        program_id: str | None,
        question: str,
        answer: str | None,
        packet: dict[str, Any] | None,
        warnings: list[str],
        model: str | None,
    ) -> str:
        session_id = new_id("session")
        self.connection.execute(
            """
            INSERT INTO sessions
                (id, program_id, question, answer, packet_json, warnings_json, model, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                program_id,
                question,
                answer,
                json.dumps(packet, ensure_ascii=False) if packet else None,
                json.dumps(warnings, ensure_ascii=False),
                model,
                utc_now(),
            ),
        )
        self.connection.commit()
        return session_id

    def audit(
        self,
        action: str,
        subject: str | None,
        details: dict[str, Any] | None = None,
        actor: str = "local",
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO audit (ts, action, subject, details_json, actor)
            VALUES (?, ?, ?, ?, ?)
            """,
            (utc_now(), action, subject, json.dumps(details or {}, ensure_ascii=False), actor),
        )
        self.connection.commit()

    def counts(self) -> dict[str, int]:
        row = self.connection.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM programs) AS programs,
              (SELECT COUNT(*) FROM functions) AS functions,
              (SELECT COUNT(*) FROM patch_plans) AS patches,
              (SELECT COUNT(*) FROM audit) AS audit_events
            """
        ).fetchone()
        return dict(row) if row else {}
