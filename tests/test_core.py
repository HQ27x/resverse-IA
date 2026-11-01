from __future__ import annotations

import argparse
import io
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reia.binary import BinaryError, BinaryImage
from reia.cli import (
    _ghidra_java_limits,
    _java_major,
    _mcp_config_payload,
    _profile_from,
)
from reia.config import ReiaError, Workspace
from reia.grounding import validate_answer
from reia.mcp_server import handle_request, serve
from reia.ollama import is_local_endpoint
from reia.patch import PatchError, apply_patch_plan, create_patch_plan, rollback_patch_plan
from reia.patch_advisor import (
    advise_with_ai,
    build_candidate,
    build_candidates,
    create_plan_from_candidate,
    select_candidate,
    validate_plan,
)
from reia.policy import PolicyError, policy_snapshot, require_patch_allowed
from reia.store import Store
from reia.util import normalize_addr, parse_hex_bytes, sha256_file

FIXTURE = Path(__file__).parent / "fixtures" / "sample_export.json"
TEXT_OFFSET = 0x200
IMAGE_BASE = 0x180000000
TEXT_RVA = 0x1000
VALIDATE_ADDRESS = IMAGE_BASE + TEXT_RVA
AUTHORIZATION = "CTF local lab, copy of my own challenge binary"
ADVISOR_CODE = bytes.fromhex(
    "55"  # push rbp
    "48 89 e5"  # mov rbp, rsp
    "85 c9"  # test ecx, ecx
    "74 05"  # je +5
    "e8 00 00 00 00"  # call rel32
    "b8 01 00 00 00"  # mov eax, 1
    "5d"  # pop rbp
    "c3"  # ret
)
ADVISOR_RETURN_ID = "0x180001000:return_constant:1"
ADVISOR_BRANCH_ID = "0x180001000:invert_branch:0x180001006"
ADVISOR_CALL_ID = "0x180001000:skip_call:0x180001008"


def build_minimal_pe(fill: int = 0xAA, text: bytes | None = None) -> bytes:
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)

    pe = 0x80
    data[pe : pe + 4] = b"PE\0\0"
    coff = pe + 4
    struct.pack_into("<H", data, coff, 0x8664)
    struct.pack_into("<H", data, coff + 2, 1)
    struct.pack_into("<H", data, coff + 16, 0xF0)

    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, TEXT_RVA)
    struct.pack_into("<Q", data, optional + 24, IMAGE_BASE)

    section = optional + 0xF0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<I", data, section + 8, 0x200)
    struct.pack_into("<I", data, section + 12, TEXT_RVA)
    struct.pack_into("<I", data, section + 16, 0x200)
    struct.pack_into("<I", data, section + 20, TEXT_OFFSET)
    struct.pack_into("<I", data, section + 36, 0x60000020)

    data[TEXT_OFFSET : TEXT_OFFSET + 0x200] = bytes([fill]) * 0x200
    if text:
        data[TEXT_OFFSET : TEXT_OFFSET + len(text)] = text
    return bytes(data)


class WorkspaceCase(unittest.TestCase):
    profile = "ctf"
    text_bytes: bytes | None = None

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "workspace"
        self.workspace = Workspace(self.root).ensure(profile=self.profile)
        self.binary = Path(self._tmp.name) / "reto.dll"
        self.binary.write_bytes(build_minimal_pe(text=self.text_bytes))
        self.original_sha = sha256_file(self.binary)
        self.export = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.store = Store(self.workspace.db_path)
        self.program_id = self.store.import_export(
            self.export,
            profile=self.profile,
            path_override=str(self.binary),
        )
        self.patched = None

    def tearDown(self) -> None:
        if self.patched and self.patched.exists():
            self.patched.unlink()
        self.store.close()
        self._tmp.cleanup()


class TestBinary(unittest.TestCase):
    def test_pe_metadata_and_mapping(self) -> None:
        image = BinaryImage.from_bytes(build_minimal_pe())
        self.assertEqual(image.format, "PE")
        self.assertEqual(image.bits, 64)
        self.assertEqual(image.image_base, IMAGE_BASE)
        self.assertEqual(image.entry_point, VALIDATE_ADDRESS)
        self.assertEqual(image.address_to_offset(VALIDATE_ADDRESS), TEXT_OFFSET)
        self.assertEqual(image.address_to_offset(hex(VALIDATE_ADDRESS + 7)), TEXT_OFFSET + 7)
        self.assertEqual(image.read(TEXT_OFFSET, 2), b"\xaa\xaa")
        self.assertEqual(image.machine, "x86_64")
        section = image.section_for_address(VALIDATE_ADDRESS)
        self.assertIsNotNone(section)
        self.assertTrue(section.executable)
        self.assertIsNone(image.section_for_address(IMAGE_BASE))

    def test_pe_rejects_bad_addresses(self) -> None:
        image = BinaryImage.from_bytes(build_minimal_pe())
        with self.assertRaises(BinaryError):
            image.address_to_offset(0x1000)

    def test_raw_has_no_address_mapping(self) -> None:
        image = BinaryImage.from_bytes(b"not a binary")
        self.assertEqual(image.format, "RAW")
        with self.assertRaises(BinaryError):
            image.address_to_offset(0x10)

    def test_helpers(self) -> None:
        self.assertEqual(normalize_addr("180001000"), "0x180001000")
        self.assertEqual(normalize_addr("0X180001000"), "0x180001000")
        self.assertEqual(parse_hex_bytes("90 90"), b"\x90\x90")
        with self.assertRaises(ValueError):
            parse_hex_bytes("909")


class TestStoreAndEvidence(WorkspaceCase):
    def test_import_counts(self) -> None:
        info = self.store.program_info(self.program_id)
        self.assertEqual(info["sha256"], self.original_sha)
        self.assertEqual(info["path"], str(self.binary))
        self.assertEqual(info["counts"]["functions"], 2)
        self.assertEqual(info["counts"]["exports"], 1)
        self.assertEqual(info["counts"]["imports"], 1)
        self.assertEqual(info["counts"]["strings"], 2)
        self.assertEqual(info["policy"]["authorization_basis"], "ctf-lab")

    def test_search_by_name_address_and_code(self) -> None:
        by_name = self.store.search_functions(self.program_id, "Validate")
        self.assertTrue(by_name)
        self.assertEqual(by_name[0]["entry"], "0x180001000")

        by_address = self.store.search_functions(self.program_id, "0x180001100")
        self.assertEqual(by_address[0]["name"], "check_key")

        by_code = self.store.search_functions(self.program_id, "strcmp")
        self.assertTrue(any(row["name"] == "Validate" for row in by_code))

    def test_function_lookup_and_card(self) -> None:
        card = self.store.function_card(
            self.store.get_function(self.program_id, "Validate")
        )
        self.assertEqual(card["id"], "F:0x180001000")
        self.assertIn("strcmp", card["decompiled"])
        self.assertEqual(card["callees"], ["0x180001100"])

        by_export = self.store.get_function(self.program_id, "Validate")
        self.assertEqual(by_export["entry"], "0x180001000")

    def test_evidence_packet(self) -> None:
        packet = self.store.build_evidence(
            self.program_id, query="Validate", max_functions=2
        )
        self.assertEqual(packet["schema_version"], 1)
        self.assertTrue(packet["packet_id"].startswith("pkt_"))
        self.assertEqual(packet["authorization"]["profile"], "ctf")
        self.assertEqual(packet["authorization"]["basis"], "ctf-lab")
        self.assertEqual(packet["program"]["sha256"], self.original_sha)
        self.assertTrue(packet["evidence"])
        self.assertEqual(packet["evidence"][0]["id"], "F:0x180001000")
        self.assertGreater(packet["token_estimate"], 0)
        self.assertTrue(packet["constraints"]["cite_evidence"])
        self.assertEqual(packet["policy"]["patching"], "copy-only")

    def test_evidence_for_missing_query(self) -> None:
        packet = self.store.build_evidence(self.program_id, query="nothing_matches_xyz")
        self.assertEqual(packet["evidence"], [])
        self.assertTrue(packet["negative_evidence"])

    def test_exports_imports_strings(self) -> None:
        self.assertEqual(self.store.get_exports(self.program_id)[0]["name"], "Validate")
        self.assertEqual(self.store.get_imports(self.program_id)[0]["library"], "msvcrt.dll")
        self.assertEqual(
            [row["value"] for row in self.store.get_strings(self.program_id)],
            ["Invalid key", "REIA"],
        )
        self.assertEqual(
            self.store.get_strings(self.program_id, "REIA")[0]["address"], "0x180003010"
        )


class TestGrounding(WorkspaceCase):
    def test_cited_answer_has_no_warnings(self) -> None:
        packet = self.store.build_evidence(self.program_id, query="Validate")
        answer = json.dumps(
            {
                "summary": "Validate compares the key against REIA.",
                "claims": [
                    {
                        "text": "Validate calls strcmp at 0x180001000",
                        "evidence": ["F:0x180001000"],
                    }
                ],
                "suggested_annotations": [],
            }
        )
        self.assertEqual(validate_answer(answer, packet), [])

    def test_invented_addresses_and_evidence_are_flagged(self) -> None:
        packet = self.store.build_evidence(self.program_id, query="Validate")
        answer = json.dumps(
            {
                "summary": "see 0xDEADBEEF",
                "claims": [{"text": "guess", "evidence": ["F:0x990000000"]}],
                "suggested_annotations": [{"target": "F:0x990000000", "note": "x"}],
            }
        )
        warnings = validate_answer(answer, packet)
        joined = "\n".join(warnings)
        self.assertIn("0xDEADBEEF", joined)
        self.assertIn("F:0x990000000", joined)
        self.assertIn("annotation targets unknown evidence", joined)

    def test_non_json_answer_is_flagged(self) -> None:
        packet = self.store.build_evidence(self.program_id, query="Validate")
        warnings = validate_answer("just prose", packet)
        self.assertTrue(any("not valid JSON" in warning for warning in warnings))


class TestPatchLab(WorkspaceCase):
    def _plan(self, new_bytes: bytes = b"\x90\x90") -> dict:
        return create_patch_plan(
            self.store,
            self.program_id,
            address=hex(VALIDATE_ADDRESS),
            file_offset=None,
            new_bytes=new_bytes,
            reason="NOP the check in a local CTF copy",
            authorization=AUTHORIZATION,
        )

    def test_plan_maps_address_and_reads_original(self) -> None:
        plan = self._plan()
        self.assertEqual(plan["target_address"], "0x180001000")
        self.assertEqual(plan["file_offset"], TEXT_OFFSET)
        self.assertEqual(plan["original_bytes"], "aa aa")
        self.assertEqual(plan["new_bytes"], "90 90")
        self.assertEqual(plan["status"], "planned")

    def test_apply_requires_approval(self) -> None:
        plan = self._plan()
        with self.assertRaises(PatchError):
            apply_patch_plan(
                self.store,
                plan["id"],
                patches_dir=self.workspace.patches_dir,
                approve=False,
            )

    def test_apply_patches_copy_only(self) -> None:
        plan = self._plan()
        applied = apply_patch_plan(
            self.store,
            plan["id"],
            patches_dir=self.workspace.patches_dir,
            approve=True,
        )
        self.patched = Path(applied["patched_path"])
        self.assertEqual(applied["status"], "applied")
        self.assertTrue(self.patched.exists())
        self.assertEqual(sha256_file(self.binary), self.original_sha)
        self.assertNotEqual(sha256_file(self.patched), self.original_sha)
        self.assertEqual(self.patched.read_bytes()[TEXT_OFFSET : TEXT_OFFSET + 2], b"\x90\x90")
        self.assertGreater(len(self.patched.read_bytes()), len(b"\x90\x90"))

        patch_dir = self.patched.parent
        self.assertTrue((patch_dir / "plan.json").exists())
        self.assertTrue((patch_dir / "diff.txt").exists())
        self.assertTrue(Path(applied["backup_path"]).exists())
        self.assertEqual(
            sha256_file(applied["backup_path"]), self.original_sha
        )

        # Applying twice is refused.
        with self.assertRaises(PatchError):
            apply_patch_plan(
                self.store,
                plan["id"],
                patches_dir=self.workspace.patches_dir,
                approve=True,
            )

    def test_rollback(self) -> None:
        plan = self._plan()
        applied = apply_patch_plan(
            self.store,
            plan["id"],
            patches_dir=self.workspace.patches_dir,
            approve=True,
        )
        self.patched = Path(applied["patched_path"])
        rolled = rollback_patch_plan(
            self.store, plan["id"], patches_dir=self.workspace.patches_dir
        )
        self.assertEqual(rolled["status"], "rolled_back")
        self.assertFalse(self.patched.exists())
        self.assertTrue(
            self.patched.with_name(f"rolledback_{self.patched.name}").exists()
        )
        self.patched = None

    def test_length_mismatch_is_rejected(self) -> None:
        plan = self._plan()
        self.store.connection.execute(
            "UPDATE patch_plans SET new_bytes = ? WHERE id = ?",
            ("90 90 90 90", plan["id"]),
        )
        self.store.connection.commit()
        with self.assertRaises(PatchError):
            apply_patch_plan(
                self.store,
                plan["id"],
                patches_dir=self.workspace.patches_dir,
                approve=True,
            )
        self.assertEqual(sha256_file(self.binary), self.original_sha)

    def test_stale_plan_is_rejected(self) -> None:
        plan = self._plan()
        self.binary.write_bytes(build_minimal_pe(fill=0xBB))
        with self.assertRaises(PatchError):
            apply_patch_plan(
                self.store,
                plan["id"],
                patches_dir=self.workspace.patches_dir,
                approve=True,
            )

    def test_authorization_required(self) -> None:
        with self.assertRaises(PolicyError):
            create_patch_plan(
                self.store,
                self.program_id,
                address=hex(VALIDATE_ADDRESS),
                file_offset=None,
                new_bytes=b"\x90\x90",
                reason="test",
                authorization="no",
            )


class TestPatchAdvisor(WorkspaceCase):
    text_bytes = ADVISOR_CODE

    def _candidates(self) -> list[dict]:
        return build_candidates(self.store, self.program_id, "Validate")

    def test_candidates_are_deterministic_and_valid(self) -> None:
        first = self._candidates()
        second = self._candidates()
        self.assertEqual([c["id"] for c in first], [c["id"] for c in second])
        ids = {c["id"] for c in first}
        self.assertTrue(
            {
                "0x180001000:return_constant:0",
                ADVISOR_RETURN_ID,
                ADVISOR_BRANCH_ID,
                ADVISOR_CALL_ID,
            }.issubset(ids)
        )
        for candidate in first:
            self.assertTrue(candidate["validation"]["ok"], candidate["validation"])

    def test_return_candidate_bytes(self) -> None:
        candidate = select_candidate(self._candidates(), ADVISOR_RETURN_ID)
        self.assertEqual(candidate["length"], 20)
        self.assertEqual(
            candidate["new_bytes"].split()[:6],
            ["b8", "01", "00", "00", "00", "c3"],
        )
        self.assertTrue(all(byte == "90" for byte in candidate["new_bytes"].split()[6:]))

    def test_branch_and_call_candidates(self) -> None:
        candidates = self._candidates()
        branch = select_candidate(candidates, ADVISOR_BRANCH_ID)
        self.assertEqual(branch["original_bytes"].split(), ["74", "05"])
        self.assertEqual(branch["new_bytes"].split(), ["75", "05"])
        self.assertEqual(branch["edit"]["condition_after"], "ne")

        call = select_candidate(candidates, ADVISOR_CALL_ID)
        self.assertEqual(call["new_bytes"].split(), ["90"] * 5)
        self.assertEqual(call["instruction"]["branch_target"], "0x18000100d")

    def test_nop_instruction_builder(self) -> None:
        candidate = build_candidate(
            self.store,
            self.program_id,
            "Validate",
            "nop_instruction",
            address="0x180001006",
        )
        self.assertEqual(candidate["new_bytes"].split(), ["90", "90"])
        self.assertTrue(candidate["validation"]["ok"])
        with self.assertRaises(PatchError):
            build_candidate(
                self.store,
                self.program_id,
                "Validate",
                "skip_call",
                address="0x180001006",
            )

    def test_plan_and_apply_from_candidate(self) -> None:
        candidate = select_candidate(self._candidates(), ADVISOR_RETURN_ID)
        plan = create_plan_from_candidate(
            self.store,
            self.program_id,
            candidate,
            reason="devolver 1 en copia CTF",
            authorization=AUTHORIZATION,
        )
        self.assertEqual(plan["advisor"]["candidate_id"], ADVISOR_RETURN_ID)
        self.assertTrue(plan["validation"]["ok"])

        stored = self.store.get_patch_plan(plan["id"])
        self.assertIn("advisor", stored)
        self.assertTrue(stored["validation"]["ok"])

        applied = apply_patch_plan(
            self.store,
            plan["id"],
            patches_dir=self.workspace.patches_dir,
            approve=True,
        )
        self.patched = Path(applied["patched_path"])
        expected = bytes.fromhex(candidate["new_bytes"].replace(" ", ""))
        self.assertEqual(
            self.patched.read_bytes()[TEXT_OFFSET : TEXT_OFFSET + len(expected)],
            expected,
        )
        self.assertEqual(sha256_file(self.binary), self.original_sha)

    def test_apply_refuses_failed_advisor_validation(self) -> None:
        plan = create_patch_plan(
            self.store,
            self.program_id,
            address=hex(VALIDATE_ADDRESS),
            file_offset=None,
            new_bytes=b"\x90\x90",
            reason="manual plan with failed advisor metadata",
            authorization=AUTHORIZATION,
            extra={
                "advisor": {"candidate_id": "broken", "kind": "return_constant"},
                "validation": {"ok": False, "errors": ["forced failure"]},
            },
        )
        with self.assertRaises(PatchError):
            apply_patch_plan(
                self.store,
                plan["id"],
                patches_dir=self.workspace.patches_dir,
                approve=True,
            )
        self.assertEqual(sha256_file(self.binary), self.original_sha)

    def test_validate_plan_detects_drift(self) -> None:
        candidate = select_candidate(self._candidates(), ADVISOR_BRANCH_ID)
        plan = create_plan_from_candidate(
            self.store,
            self.program_id,
            candidate,
            reason="invertir salto en copia CTF",
            authorization=AUTHORIZATION,
        )
        self.assertTrue(validate_plan(self.store, plan["id"])["ok"])

        data = bytearray(self.binary.read_bytes())
        data[TEXT_OFFSET + 6] ^= 0xFF
        self.binary.write_bytes(bytes(data))
        result = validate_plan(self.store, plan["id"])
        self.assertFalse(result["ok"])
        self.assertTrue(result["errors"])

    def test_ai_selects_only_known_candidates(self) -> None:
        selection = {
            "candidate_id": ADVISOR_RETURN_ID,
            "reason": "la intención es que la función devuelva 1",
            "confidence": 0.9,
            "caveats": [],
        }
        with mock.patch(
            "reia.patch_advisor.chat", return_value=json.dumps(selection)
        ):
            result = advise_with_ai(
                self.store,
                self.program_id,
                "Validate",
                "que la función acepte siempre",
                model="fake-model",
                reason="",
                authorization=AUTHORIZATION,
            )
        self.assertEqual(result["plan"]["advisor"]["candidate_id"], ADVISOR_RETURN_ID)
        self.assertEqual(result["reason"], selection["reason"])

        with mock.patch(
            "reia.patch_advisor.chat",
            return_value=json.dumps({"candidate_id": "0x180001000:fake:9"}),
        ):
            with self.assertRaises(PatchError):
                advise_with_ai(
                    self.store,
                    self.program_id,
                    "Validate",
                    "intención",
                    model="fake-model",
                    reason="",
                    authorization=AUTHORIZATION,
                )


class TestPolicy(unittest.TestCase):
    def test_snapshots(self) -> None:
        self.assertEqual(policy_snapshot("ctf")["patching"], "copy-only")
        malware = policy_snapshot("malware")
        self.assertEqual(malware["patching"], "disabled")
        self.assertEqual(malware["execution"], "disabled")
        self.assertEqual(malware["cloud"], "blocked")
        self.assertEqual(malware["mcp_external"], "blocked")
        self.assertEqual(policy_snapshot("analysis")["patching"], "disabled")

    def test_profile_rules(self) -> None:
        with self.assertRaises(PolicyError):
            require_patch_allowed("malware", AUTHORIZATION)
        with self.assertRaises(PolicyError):
            require_patch_allowed("ctf", None)
        require_patch_allowed("ctf", AUTHORIZATION)
        with self.assertRaises(PolicyError):
            require_patch_allowed("interop", "because I want to")
        require_patch_allowed("interop", "interoperability testing with permission")


class TestDoctorHelpers(unittest.TestCase):
    def test_java_major(self) -> None:
        self.assertEqual(_java_major('openjdk version "25.0.1" 2025-10-21 LTS'), 25)
        self.assertEqual(_java_major('java version "1.8.0_401"'), 1)
        self.assertIsNone(_java_major("no version here"))

    def test_ghidra_java_limits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ghidra = Path(tmp)
            (ghidra / "Ghidra").mkdir()
            (ghidra / "Ghidra" / "application.properties").write_text(
                "application.version=12.1.4\n"
                "application.java.min=21\n"
                "application.java.max=\n",
                encoding="utf-8",
            )
            self.assertEqual(
                _ghidra_java_limits(ghidra), (21, None, "12.1.4")
            )
        self.assertEqual(_ghidra_java_limits(Path("missing")), (None, None, ""))


class TestMcpConfig(WorkspaceCase):
    def test_payload_points_at_workspace(self) -> None:
        payload = _mcp_config_payload(self.workspace)
        server = payload["mcpServers"]["resverse-ia"]
        self.assertIn(str(self.workspace.root), server["args"])
        self.assertIn("mcp", server["args"])
        self.assertTrue(server["command"])


class TestCloudPolicy(unittest.TestCase):
    def test_local_endpoint_detection(self) -> None:
        cases = {
            "http://127.0.0.1:11434": True,
            "localhost:11434": True,
            "http://[::1]:11434": True,
            "http://192.168.1.50:11434": False,
            "https://ollama.example.com": False,
        }
        for value, expected in cases.items():
            with mock.patch.dict(os.environ, {"OLLAMA_HOST": value}):
                self.assertEqual(is_local_endpoint(), expected, value)

    def test_malware_profile_blocks_mcp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Workspace(Path(tmp) / "ws").ensure(profile="malware")
            with mock.patch("sys.stderr", io.StringIO()), mock.patch(
                "sys.stdin", io.StringIO("")
            ):
                with self.assertRaises(ReiaError):
                    serve(workspace)
                self.assertEqual(serve(workspace, allow_external_client=True), 0)

    def test_malware_import_refused_for_onedrive_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Workspace(Path(tmp) / "OneDrive" / "ws").ensure(profile="ctf")
            with self.assertRaises(ReiaError):
                _profile_from(argparse.Namespace(profile="malware"), workspace)
            self.assertEqual(
                _profile_from(argparse.Namespace(profile="ctf"), workspace), "ctf"
            )


class TestWorkspace(unittest.TestCase):
    def test_init_creates_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Workspace(Path(tmp) / "ws").ensure(profile="ctf")
            for path in (
                workspace.config_path,
                workspace.db_path,
                workspace.projects_dir,
                workspace.exports_dir,
                workspace.patches_dir,
                workspace.samples_dir,
                workspace.logs_dir,
            ):
                self.assertTrue(Path(path).exists(), str(path))
            self.assertEqual(workspace.load_config()["profile"], "ctf")

    def test_malware_refused_inside_onedrive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "OneDrive" / "ws"
            with self.assertRaises(ReiaError):
                Workspace(root).ensure(profile="malware")
            self.assertFalse(root.exists())

    def test_unknown_profile_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ReiaError):
                Workspace(Path(tmp) / "ws").ensure(profile="nope")


class TestMcp(WorkspaceCase):
    def test_initialize_and_tools_list(self) -> None:
        init = handle_request(
            self.store,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )
        self.assertEqual(init["result"]["serverInfo"]["name"], "resverse-ia")
        self.assertEqual(init["result"]["protocolVersion"], "2024-11-05")

        listing = handle_request(
            self.store, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        )
        names = {tool["name"] for tool in listing["result"]["tools"]}
        self.assertTrue(
            {
                "programs_list",
                "program_info",
                "functions_search",
                "function_get",
                "dll_exports",
                "dll_imports",
                "strings_search",
                "evidence_pack",
                "patch_candidates",
                "patch_build",
                "patch_validate",
                "patch_plan",
                "patch_list",
                "policy_show",
            }.issubset(names)
        )

    def test_tool_calls(self) -> None:
        response = handle_request(
            self.store,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "functions_search",
                    "arguments": {"query": "Validate"},
                },
            },
        )
        self.assertFalse(response["result"]["isError"])
        cards = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(cards[0]["id"], "F:0x180001000")

        packet_response = handle_request(
            self.store,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "evidence_pack",
                    "arguments": {"query": "Validate", "max_functions": 1},
                },
            },
        )
        packet = json.loads(packet_response["result"]["content"][0]["text"])
        self.assertEqual(packet["schema_version"], 1)

    def test_patch_plan_tool_never_applies(self) -> None:
        response = handle_request(
            self.store,
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "patch_plan",
                    "arguments": {
                        "program": self.program_id,
                        "address": hex(VALIDATE_ADDRESS),
                        "bytes": "90 90",
                        "reason": "local CTF copy",
                        "authorization": AUTHORIZATION,
                    },
                },
            },
        )
        self.assertFalse(response["result"]["isError"])
        plan = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(sha256_file(self.binary), self.original_sha)

    def test_unknown_program_returns_error_result(self) -> None:
        response = handle_request(
            self.store,
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "program_info", "arguments": {"program": "missing"}},
            },
        )
        self.assertTrue(response["result"]["isError"])
        self.assertIn("program not found", response["result"]["content"][0]["text"])

    def test_notification_has_no_response(self) -> None:
        self.assertIsNone(
            handle_request(
                self.store, {"jsonrpc": "2.0", "method": "notifications/initialized"}
            )
        )


class TestMcpAdvisor(WorkspaceCase):
    text_bytes = ADVISOR_CODE

    def test_candidates_and_build_never_apply(self) -> None:
        response = handle_request(
            self.store,
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "patch_candidates",
                    "arguments": {"function": "Validate"},
                },
            },
        )
        self.assertFalse(response["result"]["isError"])
        candidates = json.loads(response["result"]["content"][0]["text"])
        ids = {candidate["id"] for candidate in candidates}
        self.assertIn(ADVISOR_RETURN_ID, ids)

        build = handle_request(
            self.store,
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "patch_build",
                    "arguments": {
                        "function": "Validate",
                        "candidate_id": ADVISOR_RETURN_ID,
                        "reason": "MCP build in a CTF copy",
                        "authorization": AUTHORIZATION,
                    },
                },
            },
        )
        self.assertFalse(build["result"]["isError"])
        plan = json.loads(build["result"]["content"][0]["text"])
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(sha256_file(self.binary), self.original_sha)

        check = handle_request(
            self.store,
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "patch_validate",
                    "arguments": {"plan_id": plan["id"]},
                },
            },
        )
        self.assertFalse(check["result"]["isError"])
        validation = json.loads(check["result"]["content"][0]["text"])
        self.assertTrue(validation["ok"])


if __name__ == "__main__":
    unittest.main()
