"""ELF symbol table + DWARF line table lookups via pyelftools.

Kernels are usually linked at their run address (no PIE, no relocation), so
ELF symbol values are directly the addresses the gdbstub sees. A `load_bias`
is still supported for images loaded somewhere other than their link address.
"""

from __future__ import annotations

import bisect
import os
import re
from dataclasses import dataclass

from elftools.elf.elffile import ELFFile


@dataclass(frozen=True)
class Symbol:
    name: str
    address: int
    size: int
    kind: str  # "func" | "object" | "other"


@dataclass(frozen=True)
class LineEntry:
    address: int
    file: str
    line: int


class SymbolTable:
    def __init__(self, path: str, load_bias: int = 0):
        self.path = os.path.abspath(path)
        self.load_bias = load_bias
        with open(self.path, "rb") as fh:
            elf = ELFFile(fh)
            self.arch = elf.get_machine_arch()
            self.bits = elf.elfclass
            self.little_endian = elf.little_endian
            self.entry = elf.header["e_entry"] + load_bias
            self.symbols = self._load_symbols(elf)
            self.lines = self._load_lines(elf) if elf.has_dwarf_info() else []
            self.text = self._load_exec_sections(elf)
        self._by_name: dict[str, Symbol] = {}
        for s in self.symbols:
            self._by_name.setdefault(s.name, s)
        self._sorted = sorted((s for s in self.symbols if s.address), key=lambda s: s.address)
        self._addrs = [s.address for s in self._sorted]
        self._line_addrs = [e.address for e in self.lines]

    def _load_symbols(self, elf: ELFFile) -> list[Symbol]:
        out: list[Symbol] = []
        for secname in (".symtab", ".dynsym"):
            sec = elf.get_section_by_name(secname)
            if sec is None or not hasattr(sec, "iter_symbols"):
                continue
            for sym in sec.iter_symbols():
                stype = sym["st_info"]["type"]
                if not sym.name or stype in ("STT_SECTION", "STT_FILE"):
                    continue
                # SHN_ABS symbols are constants (e.g. `.set VECTOR, 0x80`), not
                # locations - using them as labels mislabels low addresses.
                if sym["st_shndx"] == "SHN_ABS":
                    continue
                kind = {"STT_FUNC": "func", "STT_OBJECT": "object"}.get(stype, "other")
                out.append(Symbol(sym.name, sym["st_value"] + self.load_bias, sym["st_size"], kind))
        return out

    def _load_lines(self, elf: ELFFile) -> list[LineEntry]:
        dwarf = elf.get_dwarf_info()
        entries: list[LineEntry] = []
        for cu in dwarf.iter_CUs():
            lp = dwarf.line_program_for_CU(cu)
            if lp is None:
                continue
            header = lp.header
            version = header["version"]
            file_entries = header["file_entry"]
            dirs = header["include_directory"]

            def filename(idx: int) -> str:
                # DWARF 5 file indices are 0-based, earlier versions 1-based.
                i = idx if version >= 5 else idx - 1
                if i < 0 or i >= len(file_entries):
                    return "??"
                fe = file_entries[i]
                name = fe.name.decode(errors="replace")
                d = fe.dir_index if version >= 5 else fe.dir_index - 1
                if not os.path.isabs(name) and 0 <= d < len(dirs):
                    name = os.path.join(dirs[d].decode(errors="replace"), name)
                return str(name)

            for entry in lp.get_entries():
                st = entry.state
                if st is None or st.end_sequence:
                    continue
                entries.append(LineEntry(st.address + self.load_bias, filename(st.file), st.line))
        entries.sort(key=lambda e: e.address)
        return entries

    def _load_exec_sections(self, elf: ELFFile) -> list[tuple[int, bytes]]:
        out = []
        for sec in elf.iter_sections():
            if sec["sh_flags"] & 0x4 and sec["sh_type"] == "SHT_PROGBITS":  # SHF_EXECINSTR
                out.append((sec["sh_addr"] + self.load_bias, sec.data()))
        return out

    # -- queries -------------------------------------------------------------

    def lookup(self, name: str) -> tuple[Symbol, str | None]:
        """Find a symbol by name. Returns (symbol, note) where note explains a
        non-exact match (e.g. 'kmain' -> 'mort_kmain' for a prefixed ABI)."""
        if name in self._by_name:
            return self._by_name[name], None
        suffix = [s for n, s in self._by_name.items() if n.endswith("_" + name)]
        if len(suffix) == 1:
            return suffix[0], f"resolved {name!r} to {suffix[0].name!r}"
        if len(suffix) > 1:
            names = ", ".join(sorted(s.name for s in suffix)[:10])
            raise KeyError(f"{name!r} is ambiguous: {names}")
        close = sorted(n for n in self._by_name if name.lower() in n.lower())[:10]
        hint = f" Similar: {', '.join(close)}" if close else ""
        raise KeyError(f"no symbol named {name!r} in {os.path.basename(self.path)}.{hint}")

    def symbolize(self, address: int) -> str:
        """'func+0x1c' for an address, or the bare hex if nothing covers it."""
        i = bisect.bisect_right(self._addrs, address) - 1
        if i >= 0:
            s = self._sorted[i]
            off = address - s.address
            if off == 0:
                return s.name
            if s.size == 0 or off < s.size:
                return f"{s.name}+{off:#x}"
        return f"{address:#x}"

    def containing_function(self, address: int) -> Symbol | None:
        i = bisect.bisect_right(self._addrs, address) - 1
        while i >= 0:
            s = self._sorted[i]
            if s.kind == "func" and (s.size == 0 or address < s.address + s.size):
                return s
            if s.kind == "func":
                return None
            i -= 1
        return None

    def line_for(self, address: int) -> LineEntry | None:
        # Line tables only describe code; don't attribute a stack or data
        # address to whichever line happens to precede it numerically.
        if self.code_bytes(address, 1) is None:
            return None
        i = bisect.bisect_right(self._line_addrs, address) - 1
        if i < 0:
            return None
        e = self.lines[i]
        # Don't attribute an address to a line from an unrelated function.
        fn = self.containing_function(address)
        if fn is not None and e.address < fn.address:
            return None
        return e

    def addresses_for_line(self, file: str, line: int) -> list[int]:
        target = os.path.normcase(file.replace("\\", "/"))
        matches = [
            e for e in self.lines
            if e.line == line and os.path.normcase(e.file.replace("\\", "/")).endswith(target)
        ]
        if not matches:
            files = sorted({os.path.basename(e.file) for e in self.lines})
            raise KeyError(
                f"no code at {file}:{line} in the DWARF line table. Files with line info: "
                + ", ".join(files[:20])
            )
        files_hit = {e.file for e in matches}
        if len(files_hit) > 1:
            raise KeyError(f"{file}:{line} is ambiguous across: {', '.join(sorted(files_hit))}")
        return sorted({e.address for e in matches})

    def code_bytes(self, address: int, length: int) -> bytes | None:
        for base, data in self.text:
            if base <= address < base + len(data):
                off = address - base
                return data[off:off + length]
        return None


_EXPR_RE = re.compile(r"^\s*([A-Za-z_.$][\w.$@]*)?\s*(?:([+-])\s*(0x[0-9a-fA-F]+|\d+))?\s*$")


def resolve(expr: str, syms: SymbolTable | None) -> tuple[int, str | None]:
    """Resolve an address expression to (address, note).

    Accepts: 0x1234 | 1234 | symbol | symbol+0x10 | file.c:42 (first address).
    """
    e = expr.strip()
    if not e:
        raise ValueError("empty address expression")
    try:
        return int(e, 0), None
    except ValueError:
        pass
    if ":" in e:
        file, _, line = e.rpartition(":")
        if line.isdigit():
            if syms is None:
                raise ValueError(f"{expr!r} needs an ELF with debug info - pass elf= to debug_connect")
            addrs = syms.addresses_for_line(file, int(line))
            note = None if len(addrs) == 1 else (
                f"{expr} maps to {len(addrs)} addresses; using the first ({addrs[0]:#x})"
            )
            return addrs[0], note
    m = _EXPR_RE.match(e)
    if not m or not m.group(1):
        raise ValueError(f"can't parse address expression {expr!r}")
    if syms is None:
        raise ValueError(f"{expr!r} is a symbol - pass elf= to debug_connect to enable symbols")
    sym, note = syms.lookup(m.group(1))
    addr = sym.address
    if m.group(2):
        off = int(m.group(3), 0)
        addr = addr + off if m.group(2) == "+" else addr - off
    return addr, note
