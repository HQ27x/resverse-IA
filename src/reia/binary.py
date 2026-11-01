from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from .config import ReiaError


class BinaryError(ReiaError):
    pass


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    executable: bool = False
    writable: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "virtual_address": hex(self.virtual_address),
            "virtual_size": self.virtual_size,
            "raw_offset": self.raw_offset,
            "raw_size": self.raw_size,
            "executable": self.executable,
            "writable": self.writable,
        }


@dataclass
class BinaryImage:
    path: str
    data: bytes
    format: str
    bits: int
    endian: str
    image_base: int
    sections: list[Section] = field(default_factory=list)
    entry_point: int | None = None
    machine: str = ""

    @classmethod
    def from_path(cls, path: str | Path) -> "BinaryImage":
        target = Path(path)
        if not target.exists() or not target.is_file():
            raise BinaryError(f"binary not found: {target}")
        data = target.read_bytes()
        return cls.from_bytes(data, str(target.resolve()))

    @classmethod
    def from_bytes(cls, data: bytes, path: str = "<memory>") -> "BinaryImage":
        fmt = detect_format(data)
        if fmt == "PE":
            return _parse_pe(data, path)
        if fmt == "ELF":
            return _parse_elf(data, path)
        if fmt == "Mach-O":
            bits = 64 if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") else 32
            return cls(path=path, data=data, format="Mach-O", bits=bits, endian="little", image_base=0)
        return cls(path=path, data=data, format="RAW", bits=0, endian="little", image_base=0)

    def address_to_offset(self, address: str | int) -> int:
        value = int(address, 16) if isinstance(address, str) and address.lower().startswith("0x") else int(address)
        if self.format == "PE":
            return self._pe_address_to_offset(value)
        if self.format == "ELF":
            return self._elf_address_to_offset(value)
        raise BinaryError(
            f"address mapping is not available for {self.format}; use --file-offset instead"
        )

    def _pe_address_to_offset(self, address: int) -> int:
        rva = address - self.image_base
        if rva < 0:
            raise BinaryError(
                f"address {hex(address)} is below image base {hex(self.image_base)}"
            )
        for section in self.sections:
            start = section.virtual_address
            span = max(section.virtual_size, section.raw_size)
            if start <= rva < start + span:
                delta = rva - start
                if delta >= section.raw_size:
                    raise BinaryError(
                        f"address {hex(address)} falls in uninitialized virtual space of {section.name}"
                    )
                offset = section.raw_offset + delta
                if offset >= len(self.data):
                    raise BinaryError(f"address {hex(address)} maps outside the file")
                return offset
        # PE headers are addressable before the first section.
        if 0 <= rva < len(self.data):
            return rva
        raise BinaryError(f"address {hex(address)} is not inside a mapped PE section")

    def _elf_address_to_offset(self, address: int) -> int:
        for segment in self.sections:
            if segment.virtual_address <= address < segment.virtual_address + segment.raw_size:
                offset = segment.raw_offset + (address - segment.virtual_address)
                if offset >= len(self.data):
                    raise BinaryError(f"address {hex(address)} maps outside the file")
                return offset
        raise BinaryError(f"address {hex(address)} is not inside a loadable ELF segment")

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0:
            raise BinaryError("offset and size must be non-negative")
        end = offset + size
        if end > len(self.data):
            raise BinaryError(f"range 0x{offset:x}+0x{size:x} exceeds file size 0x{len(self.data):x}")
        return self.data[offset:end]

    def section_for_address(self, address: str | int) -> Section | None:
        value = int(address, 16) if isinstance(address, str) else int(address)
        relative = value - self.image_base if self.format == "PE" else value
        for section in self.sections:
            span = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= relative < section.virtual_address + span:
                return section
        return None

    def describe(self) -> dict[str, object]:
        return {
            "path": self.path,
            "format": self.format,
            "bits": self.bits,
            "endian": self.endian,
            "image_base": hex(self.image_base),
            "entry_point": hex(self.entry_point) if self.entry_point is not None else None,
            "size": len(self.data),
            "sections": [section.to_dict() for section in self.sections],
        }


def detect_format(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:4] in (
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
    ):
        return "Mach-O"
    return "RAW"


def _u16(data: bytes, offset: int, endian: str = "little") -> int:
    return struct.unpack_from("<H" if endian == "little" else ">H", data, offset)[0]


def _u32(data: bytes, offset: int, endian: str = "little") -> int:
    return struct.unpack_from("<I" if endian == "little" else ">I", data, offset)[0]


def _u64(data: bytes, offset: int, endian: str = "little") -> int:
    return struct.unpack_from("<Q" if endian == "little" else ">Q", data, offset)[0]


PE_MACHINES = {
    0x014C: ("x86", 32),
    0x8664: ("x86_64", 64),
    0x01C0: ("arm", 32),
    0xAA64: ("arm64", 64),
    0x0200: ("ia64", 64),
}

ELF_MACHINES = {
    3: ("x86", 32),
    62: ("x86_64", 64),
    40: ("arm", 32),
    183: ("arm64", 64),
    243: ("riscv", 64),
}


def _parse_pe(data: bytes, path: str) -> BinaryImage:
    if len(data) < 0x40:
        raise BinaryError("truncated DOS header")
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise BinaryError("invalid PE signature")
    coff = pe_offset + 4
    machine = _u16(data, coff)
    number_of_sections = _u16(data, coff + 2)
    size_of_optional = _u16(data, coff + 16)
    optional = coff + 20
    if optional + size_of_optional > len(data):
        raise BinaryError("truncated PE optional header")
    magic = _u16(data, optional)
    if magic == 0x10B:
        bits = 32
        image_base = _u32(data, optional + 28)
        entry_rva = _u32(data, optional + 16)
    elif magic == 0x20B:
        bits = 64
        image_base = _u64(data, optional + 24)
        entry_rva = _u32(data, optional + 16)
    else:
        raise BinaryError(f"unsupported PE optional header magic: 0x{magic:x}")

    arch = PE_MACHINES.get(machine, (f"machine_0x{machine:x}", bits))[0]
    section_offset = optional + size_of_optional
    sections: list[Section] = []
    for index in range(number_of_sections):
        offset = section_offset + index * 40
        if offset + 40 > len(data):
            raise BinaryError("truncated PE section table")
        raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", errors="replace") or f"section_{index}"
        virtual_size = _u32(data, offset + 8)
        virtual_address = _u32(data, offset + 12)
        raw_size = _u32(data, offset + 16)
        raw_offset = _u32(data, offset + 20)
        characteristics = _u32(data, offset + 36)
        sections.append(
            Section(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_offset=raw_offset,
                raw_size=raw_size,
                executable=bool(characteristics & 0x20000000),
                writable=bool(characteristics & 0x80000000),
            )
        )
    return BinaryImage(
        path=path,
        data=data,
        format="PE",
        bits=bits,
        endian="little",
        image_base=image_base,
        sections=sections,
        entry_point=image_base + entry_rva if entry_rva else None,
        machine=arch,
    )


def _parse_elf(data: bytes, path: str) -> BinaryImage:
    if len(data) < 0x34 or data[:4] != b"\x7fELF":
        raise BinaryError("truncated ELF header")
    elf_class = data[4]
    data_encoding = data[5]
    endian = "little" if data_encoding == 1 else "big"
    if elf_class == 1:
        bits = 32
        machine = _u16(data, 0x12, endian)
        entry = _u32(data, 0x18, endian)
        phoff = _u32(data, 0x1C, endian)
        phentsize = _u16(data, 0x2A, endian)
        phnum = _u16(data, 0x2C, endian)
    elif elf_class == 2:
        bits = 64
        machine = _u16(data, 0x12, endian)
        entry = _u64(data, 0x18, endian)
        phoff = _u64(data, 0x20, endian)
        phentsize = _u16(data, 0x36, endian)
        phnum = _u16(data, 0x38, endian)
    else:
        raise BinaryError(f"unsupported ELF class: {elf_class}")

    arch = ELF_MACHINES.get(machine, (f"machine_{machine}", bits))[0]
    sections: list[Section] = []
    base: int | None = None
    for index in range(phnum):
        offset = phoff + index * phentsize
        if offset + phentsize > len(data):
            raise BinaryError("truncated ELF program header")
        if bits == 64:
            p_type = _u32(data, offset, endian)
            p_flags = _u32(data, offset + 4, endian)
            p_offset = _u64(data, offset + 8, endian)
            p_vaddr = _u64(data, offset + 16, endian)
            p_filesz = _u64(data, offset + 32, endian)
            p_memsz = _u64(data, offset + 40, endian)
        else:
            p_type = _u32(data, offset, endian)
            p_offset = _u32(data, offset + 4, endian)
            p_vaddr = _u32(data, offset + 8, endian)
            p_filesz = _u32(data, offset + 16, endian)
            p_memsz = _u32(data, offset + 20, endian)
            p_flags = _u32(data, offset + 24, endian)
        if p_type != 1:  # PT_LOAD
            continue
        sections.append(
            Section(
                name=f"LOAD_{index}",
                virtual_address=p_vaddr,
                virtual_size=p_memsz,
                raw_offset=p_offset,
                raw_size=p_filesz,
                executable=bool(p_flags & 1),
                writable=bool(p_flags & 2),
            )
        )
        candidate = p_vaddr - p_offset
        base = candidate if base is None else min(base, candidate)

    return BinaryImage(
        path=path,
        data=data,
        format="ELF",
        bits=bits,
        endian=endian,
        image_base=base or 0,
        sections=sections,
        entry_point=entry or None,
        machine=arch,
    )
