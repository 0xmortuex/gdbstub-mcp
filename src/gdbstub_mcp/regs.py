"""Register layout discovery from the stub's target description XML.

A gdbstub describes its registers in `target.xml` (plus files it
xi:includes). Registers are numbered in document order unless a `regnum`
attribute resets the counter; the `g` packet returns them concatenated in
that order, but only up to the stub's "general" set - anything past the end
of the `g` blob must be read individually with `p`.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

# Architectures whose gdbstub sends register bytes big-endian.
_BIG_ENDIAN_ARCHS = ("powerpc", "s390", "m68k", "sparc", "hppa", "or1k", "mips")


@dataclass
class Register:
    name: str
    regnum: int
    bitsize: int
    type: str
    feature: str
    flags: list[tuple[str, int, int]] = field(default_factory=list)  # (name, start, end)


@dataclass
class Layout:
    architecture: str
    registers: list[Register]
    big_endian: bool

    def by_name(self, name: str) -> Register:
        key = name.lower().lstrip("$%")
        for r in self.registers:
            if r.name.lower() == key:
                return r
        known = ", ".join(r.name for r in self.registers)
        raise KeyError(f"no register named {name!r}; this target has: {known}")

    def pc(self) -> Register:
        for cand in ("rip", "eip", "pc"):
            for r in self.registers:
                if r.name == cand:
                    return r
        for r in self.registers:
            if r.type == "code_ptr":
                return r
        raise KeyError("could not identify the program counter register")

    def sp(self) -> Register:
        for cand in ("rsp", "esp", "sp"):
            for r in self.registers:
                if r.name == cand:
                    return r
        raise KeyError("could not identify the stack pointer register")

    def fp(self) -> Register:
        for cand in ("rbp", "ebp", "fp", "x29", "s0"):
            for r in self.registers:
                if r.name == cand:
                    return r
        raise KeyError("could not identify a frame pointer register")

    @property
    def byteorder(self) -> Literal["big", "little"]:
        return "big" if self.big_endian else "little"

    def decode(self, reg: Register, raw: bytes) -> int:
        return int.from_bytes(raw, self.byteorder)

    def encode(self, reg: Register, value: int) -> bytes:
        nbytes = reg.bitsize // 8
        if value < 0:
            value &= (1 << reg.bitsize) - 1
        if value >= 1 << reg.bitsize:
            raise ValueError(f"{value:#x} does not fit in {reg.bitsize}-bit register {reg.name}")
        return value.to_bytes(nbytes, self.byteorder)

    def split_g(self, blob: bytes) -> dict[str, bytes]:
        """Split a `g` reply into per-register bytes, in regnum order."""
        out: dict[str, bytes] = {}
        offset = 0
        for reg in sorted(self.registers, key=lambda r: r.regnum):
            n = reg.bitsize // 8
            if offset + n > len(blob):
                break
            out[reg.name] = blob[offset:offset + n]
            offset += n
        return out


_INCLUDE_RE = re.compile(r"<xi:include\s+href=\"([^\"]+)\"\s*/>")


def expand_includes(xml: str, fetch: Callable[[str], str], depth: int = 0) -> str:
    """Inline every <xi:include href="..."/> by fetching it from the stub."""
    if depth > 8:
        raise ValueError("target description includes nest too deeply")

    def repl(m: re.Match[str]) -> str:
        inner = fetch(m.group(1))
        # Drop the included file's own prolog/doctype so it nests cleanly.
        inner = re.sub(r"<\?xml[^>]*\?>", "", inner)
        inner = re.sub(r"<!DOCTYPE[^>]*>", "", inner)
        return expand_includes(inner, fetch, depth + 1)

    return _INCLUDE_RE.sub(repl, xml)


def parse_target_xml(xml: str) -> Layout:
    xml = re.sub(r"<!DOCTYPE[^>]*>", "", xml)
    # ElementTree rejects the undeclared xi: prefix if any include survived.
    xml = xml.replace("xi:include", "include")
    root = ET.fromstring(xml)
    arch_el = root.find("architecture")
    architecture = (arch_el.text or "").strip() if arch_el is not None else ""

    # Flag types are collected document-wide: a register may use a type
    # defined in another feature.
    flag_types: dict[str, list[tuple[str, int, int]]] = {}
    for fl in root.iter("flags"):
        flag_types[fl.get("id", "")] = [
            (f.get("name", ""), int(f.get("start", "0")), int(f.get("end", f.get("start", "0"))))
            for f in fl.iter("field")
            if f.get("name")
        ]

    registers: list[Register] = []
    next_num = 0
    for feature in root.iter("feature"):
        fname = feature.get("name", "")
        for reg in feature.iter("reg"):
            if reg.get("regnum") is not None:
                next_num = int(reg.get("regnum", "0"))
            rtype = reg.get("type", "int")
            registers.append(Register(
                name=reg.get("name", ""),
                regnum=next_num,
                bitsize=int(reg.get("bitsize", "0")),
                type=rtype,
                feature=fname,
                flags=flag_types.get(rtype, []),
            ))
            next_num += 1
    if not registers:
        raise ValueError("target description lists no registers")
    big = any(architecture.startswith(a) for a in _BIG_ENDIAN_ARCHS) and "el" not in architecture
    return Layout(architecture=architecture, registers=registers, big_endian=big)


def describe_flags(reg: Register, value: int) -> str:
    """Render set flag bits, e.g. eflags -> 'IF ZF', cr0 -> 'PG WP PE'."""
    names = []
    for name, start, end in reg.flags:
        width = end - start + 1
        v = (value >> start) & ((1 << width) - 1)
        if v:
            names.append(name if width == 1 else f"{name}={v}")
    return " ".join(names)
