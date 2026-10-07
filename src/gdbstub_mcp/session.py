"""A debug session: one gdbstub connection plus its layout, symbols and breakpoints."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import capstone

from . import regs as regmod
from .rsp import RSPClient, RSPError
from .symbols import SymbolTable, resolve

BP_KINDS = {"sw": 0, "hw": 1, "write": 2, "read": 3, "access": 4}

SIGNALS = {
    0x02: "SIGINT (interrupted)",
    0x05: "SIGTRAP (breakpoint/step)",
    0x0B: "SIGSEGV",
    0x04: "SIGILL",
    0x09: "SIGKILL",
}


@dataclass
class Breakpoint:
    id: int
    kind: str
    address: int
    length: int
    label: str


class Session:
    def __init__(self, name: str, host: str, port: int, elf: str | None,
                 load_bias: int = 0, timeout_s: float = 10.0):
        self.name = name
        self.endpoint = f"{host}:{port}"
        self.rsp = RSPClient(host, port, connect_timeout=timeout_s, read_timeout=timeout_s)
        try:
            xml = regmod.expand_includes(
                self.rsp.read_xfer("features", "target.xml"),
                lambda annex: self.rsp.read_xfer("features", annex),
            )
            self.layout = regmod.parse_target_xml(xml)
            self.syms = SymbolTable(elf, load_bias) if elf else None
        except Exception:
            self.rsp.close()
            raise
        self.breakpoints: dict[int, Breakpoint] = {}
        self._next_bp = 1
        self.last_stop: bytes = self.rsp.stop_reason()

    # -- registers -----------------------------------------------------------

    def read_regs(self) -> dict[str, int]:
        blob = self.rsp.read_registers()
        raw = self.layout.split_g(blob)
        return {name: self.layout.decode(self.layout.by_name(name), b) for name, b in raw.items()}

    def read_reg(self, name: str) -> int:
        reg = self.layout.by_name(name)
        g = self.layout.split_g(self.rsp.read_registers())
        if reg.name in g:
            return self.layout.decode(reg, g[reg.name])
        return self.layout.decode(reg, self.rsp.read_register(reg.regnum))

    def write_reg(self, name: str, value: int) -> None:
        reg = self.layout.by_name(name)
        self.rsp.write_register(reg.regnum, self.layout.encode(reg, value))

    @property
    def word(self) -> int:
        return self.layout.pc().bitsize // 8

    # -- addresses -----------------------------------------------------------

    def resolve(self, expr: str) -> tuple[int, str | None]:
        e = expr.strip()
        # Allow registers as addresses: "$esp", "esp+8".
        head = e.lstrip("$%").split("+")[0].split("-")[0].strip()
        if head and not head[0].isdigit():
            try:
                reg = self.layout.by_name(head)
            except KeyError:
                reg = None
            if reg is not None and (e.startswith(("$", "%")) or self.syms is None
                                    or head not in {s.name for s in self.syms.symbols}):
                base = self.read_reg(reg.name)
                rest = e.lstrip("$%")[len(head):].strip()
                if rest:
                    sign, num = rest[0], rest[1:].strip()
                    off = int(num, 0)
                    base = base + off if sign == "+" else base - off
                return base, f"{reg.name} = {base:#x}" if rest else None
        return resolve(e, self.syms)

    def where(self, address: int) -> str:
        if self.syms is None:
            return f"{address:#x}"
        sym = self.syms.symbolize(address)
        text = f"{address:#x}" if sym.startswith("0x") else f"{address:#x} <{sym}>"
        line = self.syms.line_for(address)
        if line is not None:
            text += f" at {os.path.basename(line.file)}:{line.line}"
        return text

    # -- disassembly -----------------------------------------------------------

    def _capstone(self, mode_override: int | None = None) -> capstone.Cs:
        arch = (self.layout.architecture or (self.syms.arch if self.syms else "")).lower()
        bits = mode_override
        if "x86-64" in arch or "x86_64" in arch or arch == "x64":
            cs = capstone.Cs(capstone.CS_ARCH_X86, {16: capstone.CS_MODE_16, 32: capstone.CS_MODE_32}.get(bits or 64, capstone.CS_MODE_64))
        elif "i386" in arch or arch == "x86":
            cs = capstone.Cs(capstone.CS_ARCH_X86, {16: capstone.CS_MODE_16, 64: capstone.CS_MODE_64}.get(bits or 32, capstone.CS_MODE_32))
        elif "aarch64" in arch:
            cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        elif "riscv" in arch:
            mode = capstone.CS_MODE_RISCV64 if "64" in arch else capstone.CS_MODE_RISCV32
            cs = capstone.Cs(capstone.CS_ARCH_RISCV, mode | capstone.CS_MODE_RISCVC)
        elif arch.startswith("arm"):
            cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        else:
            raise RSPError(f"disassembly not supported for architecture {arch!r}")
        return cs

    def disassemble(self, address: int, count: int, bits: int | None = None) -> list[str]:
        data = self.rsp.read_memory(address, count * 16)
        out = []
        for insn in self._capstone(bits).disasm(data, address):
            label = ""
            if self.syms is not None:
                sym = self.syms.symbolize(insn.address)
                if not sym.startswith("0x"):
                    label = f" <{sym}>"
            out.append(f"{insn.address:#x}{label}:  {insn.mnemonic} {insn.op_str}".rstrip())
            if len(out) >= count:
                break
        return out

    # -- stop handling -------------------------------------------------------

    def describe_stop(self, reply: bytes) -> str:
        self.last_stop = reply
        text = reply.decode(errors="replace")
        kind = text[:1]
        if kind in ("W", "X"):
            return f"Target exited ({text}). The VM is gone - reconnect after rebooting it."
        if kind not in ("S", "T"):
            return f"Unexpected stop reply: {text}"
        sig = int(text[1:3], 16)
        reason = SIGNALS.get(sig, f"signal {sig:#x}")
        extra = ""
        for item in text[3:].split(";"):
            if item.startswith(("watch:", "rwatch:", "awatch:")):
                k, addr = item.split(":", 1)
                extra = f" - {k} hit on {self.where(int(addr, 16))}"
            elif item.startswith(("swbreak", "hwbreak")):
                extra = " - breakpoint"
        pc = self.read_reg(self.layout.pc().name)
        hit = next((b for b in self.breakpoints.values()
                    if b.address == pc and b.kind in ("sw", "hw")), None)
        if hit:
            extra = f" - breakpoint #{hit.id} ({hit.label})"
        lines = [f"Stopped: {reason}{extra}", f"pc = {self.where(pc)}"]
        try:
            lines.append("next: " + self.disassemble(pc, 1)[0].split(":", 1)[1].strip())
        except (RSPError, IndexError):
            pass
        return "\n".join(lines)

    # -- breakpoints -------------------------------------------------------

    def add_breakpoint(self, location: str, kind: str, length: int | None) -> tuple[Breakpoint, str | None]:
        if kind not in BP_KINDS:
            raise ValueError(f"kind must be one of {', '.join(BP_KINDS)}")
        address, note = self.resolve(location)
        if length is None:
            length = 1 if kind in ("sw", "hw") else self.word
        self.rsp.set_breakpoint(BP_KINDS[kind], address, length)
        bp = Breakpoint(self._next_bp, kind, address, length, location)
        self.breakpoints[bp.id] = bp
        self._next_bp += 1
        return bp, note

    def remove_breakpoint(self, bp_id: int) -> Breakpoint:
        bp = self.breakpoints.get(bp_id)
        if bp is None:
            raise KeyError(f"no breakpoint #{bp_id}; active: {sorted(self.breakpoints) or 'none'}")
        self.rsp.clear_breakpoint(BP_KINDS[bp.kind], bp.address, bp.length)
        del self.breakpoints[bp_id]
        return bp

    # -- backtrace -----------------------------------------------------------

    def _read_word(self, address: int) -> int:
        return int.from_bytes(self.rsp.read_memory(address, self.word), self.layout.byteorder)

    def backtrace(self, max_frames: int, mode: str) -> tuple[list[str], str]:
        """Return (frames, method note). mode: 'fp', 'scan', or 'auto'."""
        if mode not in ("fp", "scan", "auto"):
            raise ValueError("mode must be 'fp', 'scan', or 'auto'")
        pc = self.read_reg(self.layout.pc().name)
        frames = [pc]
        method = ""
        if mode in ("fp", "auto"):
            frames = [pc]
            # In a prologue/epilogue the frame pointer still belongs to the
            # caller, so the current function's return address is only
            # reachable from the stack pointer.
            early = self._x86_unframed_return(pc)
            if early is not None:
                frames.append(early)
            frames += self._fp_walk(max_frames - len(frames))
            method = "frame-pointer chain"
        if mode == "scan" or (mode == "auto" and len(frames) < 2):
            if self.syms is None:
                raise RSPError("stack scanning needs symbols - pass elf= to debug_connect")
            arch = self.layout.architecture.lower()
            if "i386" not in arch and "x86" not in arch:
                raise RSPError(f"stack scanning only understands x86 call instructions, "
                               f"not {arch!r} - use mode='fp'")
            frames = [pc] + self._stack_scan(max_frames - 1)
            method = ("stack scan (heuristic: any stack word pointing just after a call "
                      "instruction inside a known function - may include stale frames)")
        return [f"#{i}  {self.where(a)}" for i, a in enumerate(frames)], method

    def _x86_unframed_return(self, pc: int) -> int | None:
        """Return address for an x86 pc whose frame isn't set up (or is torn down).

        Cases: before `push ebp` executes (ret at [sp]); after it but before
        `mov ebp, esp` (ret at [sp+word]); sitting on `ret` (ret at [sp]).
        None means the normal frame-pointer chain applies.
        """
        arch = self.layout.architecture.lower()
        if self.syms is None or ("i386" not in arch and "x86" not in arch):
            return None
        fn = self.syms.containing_function(pc)
        if fn is None:
            return None
        sp = self.read_reg(self.layout.sp().name)
        code = self.rsp.read_memory(fn.address, pc - fn.address + 16)
        fp_name = self.layout.fp().name
        sp_name = self.layout.sp().name
        pushed = False
        for insn in self._capstone().disasm(code, fn.address):
            if insn.address == pc:
                if insn.mnemonic.startswith("ret"):
                    return self._read_word(sp)
                return self._read_word(sp + self.word) if pushed else self._read_word(sp)
            if insn.mnemonic == "push" and insn.op_str == fp_name:
                pushed = True
            elif insn.mnemonic == "mov" and insn.op_str == f"{fp_name}, {sp_name}":
                return None  # frame established before pc
            else:
                return None  # not a recognisable prologue - trust the fp chain
        return None

    def _fp_walk(self, limit: int) -> list[int]:
        fp_reg = self.layout.fp()
        fp = self.read_reg(fp_reg.name)
        out: list[int] = []
        seen = set()
        while fp and len(out) < limit and fp not in seen:
            seen.add(fp)
            try:
                ret = self._read_word(fp + self.word)
                nxt = self._read_word(fp)
            except RSPError:
                break
            if ret == 0:
                break
            if self.syms is not None and self.syms.containing_function(ret) is None:
                break
            out.append(ret)
            if nxt <= fp:  # stack grows down; caller frames are at higher addresses
                break
            fp = nxt
        return out

    def _stack_scan(self, limit: int, depth_bytes: int = 4096) -> list[int]:
        assert self.syms is not None
        sp = self.read_reg(self.layout.sp().name)
        try:
            data = self.rsp.read_memory(sp, depth_bytes)
        except RSPError:
            data = self.rsp.read_memory(sp, 256)
        cs = self._capstone()
        order = self.layout.byteorder
        out: list[int] = []
        for off in range(0, len(data) - self.word + 1, self.word):
            val = int.from_bytes(data[off:off + self.word], order)
            if self.syms.containing_function(val) is None:
                continue
            # Return addresses follow a call: check the instruction ending at val.
            if self._preceded_by_call(cs, val):
                out.append(val)
                if len(out) >= limit:
                    break
        return out

    def _preceded_by_call(self, cs: Any, address: int) -> bool:
        assert self.syms is not None
        for back in (5, 6, 2, 3, 7):  # common x86 call encodings; others just skip
            code = self.syms.code_bytes(address - back, back)
            if not code or len(code) != back:
                continue
            insns = list(cs.disasm(code, address - back))
            if len(insns) == 1 and insns[0].mnemonic.startswith("call") \
                    and insns[0].address + insns[0].size == address:
                return True
        return False

    def close(self) -> None:
        self.rsp.close()
