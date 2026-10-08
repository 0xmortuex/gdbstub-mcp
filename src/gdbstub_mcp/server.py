"""gdbstub-mcp: an MCP server that lets an AI agent debug a kernel through a gdbstub."""

from __future__ import annotations

import functools
import os
import string
from collections.abc import Callable
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import faults as faultmod
from . import regs as regmod
from .rsp import RSPError
from .session import Session
from .symbols import SymbolTable, resolve

mcp = MCPServer(
    "gdbstub",
    instructions=(
        "Debug a running kernel through a GDB remote stub (QEMU's -s / -gdb tcp::PORT), "
        "with no gdb binary needed. Start QEMU with `-s -S` (stub on 1234, CPU halted), "
        "then: debug_connect (pass elf= for symbols) -> debug_break on a symbol or "
        "file:line -> debug_continue -> debug_registers / debug_backtrace / debug_memory. "
        "For a crash or reboot loop, run QEMU with `-d int,cpu_reset -D <log>` and call "
        "debug_explain_fault on the log: it decodes the exception chain that led to a "
        "triple fault. Addresses accept 0x1234, symbol, symbol+0x10, file.c:42 or $reg."
    ),
)

_sessions: dict[str, Session] = {}

F = TypeVar("F", bound=Callable[..., Any])

# Failures an agent can act on. MCPServer only forwards a ToolError's message
# to the client - anything else arrives as a bare "Error executing tool X" -
# so these are re-raised as ToolError with their text intact. Anything not
# listed here is a genuine bug and stays hidden from the client.
_EXPECTED = (RSPError, KeyError, ValueError, FileNotFoundError, OSError)


def tool(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except _EXPECTED as e:
            # KeyError's str() wraps the message in quotes; use the raw text.
            msg = e.args[0] if isinstance(e, KeyError) and e.args else str(e)
            raise ToolError(str(msg)) from e

    mcp.tool()(wrapper)
    return fn


def _get(name: str) -> Session:
    s = _sessions.get(name)
    if s is None:
        known = ", ".join(sorted(_sessions)) or "none"
        raise RSPError(f"no debug session named {name!r} (active: {known}) - call debug_connect first")
    return s


def _note(note: str | None) -> str:
    return f"\n({note})" if note else ""


@tool
def debug_connect(
    name: str,
    port: int = 1234,
    host: str = "127.0.0.1",
    elf: str | None = None,
    load_bias: int = 0,
    timeout_s: float = 10.0,
) -> str:
    """Connect to a gdbstub and register the session under `name`.

    For QEMU, start it with `-s` (stub on tcp::1234) or `-gdb tcp::PORT`, and
    add `-S` to halt the CPU before the first instruction so you can set
    breakpoints before anything runs. With qemu-mcp, pass these via
    qemu_boot's extra_args, e.g. extra_args="-s -S".
    elf is the kernel image with symbols (and ideally DWARF debug info); it
    enables symbol names, file:line breakpoints and source locations.
    load_bias is added to every ELF address, for images loaded somewhere other
    than their link address (0 for a normally linked kernel).
    The target stays halted after connecting.
    """
    if name in _sessions:
        raise RSPError(f"a session named {name!r} already exists - debug_disconnect it first")
    if elf is not None and not os.path.isfile(elf):
        raise FileNotFoundError(f"ELF not found: {elf}")
    s = Session(name, host, port, elf, load_bias, timeout_s)
    _sessions[name] = s
    lines = [
        f"Connected {name!r} to {s.endpoint} ({s.layout.architecture or 'unknown arch'}, "
        f"{len(s.layout.registers)} registers).",
    ]
    if s.syms is not None:
        lines.append(
            f"Symbols: {os.path.basename(s.syms.path)} - {len(s.syms.symbols)} symbols, "
            + (f"{len(s.syms.lines)} line-table entries" if s.syms.lines else "no DWARF line info")
        )
    lines.append(s.describe_stop(s.last_stop))
    return "\n".join(lines)


@tool
def debug_disconnect(name: str) -> str:
    """Remove breakpoints, detach from the stub so the guest keeps running,
    and forget the session. A running target is halted first."""
    s = _get(name)
    if s.last_stop[:1] in (b"W", b"X"):
        # The VM already exited; there is nothing left to detach from.
        s.close()
        del _sessions[name]
        return f"Disconnected {name!r} (the target had already exited)."
    if s.rsp.running:
        s.describe_stop(s.rsp.interrupt())
    for bp_id in list(s.breakpoints):
        s.remove_breakpoint(bp_id)
    s.rsp.detach()
    s.close()
    del _sessions[name]
    return f"Disconnected {name!r}; the guest is running."


@tool
def debug_sessions() -> str:
    """List active debug sessions."""
    if not _sessions:
        return "No active debug sessions."
    rows = []
    for s in _sessions.values():
        state = "running" if s.rsp.running else "halted"
        elf = os.path.basename(s.syms.path) if s.syms else "no symbols"
        rows.append(f"{s.name}: {s.endpoint}, {state}, {elf}, {len(s.breakpoints)} breakpoints")
    return "\n".join(rows)


@tool
def debug_registers(name: str, registers: str | None = None, all: bool = False) -> str:
    """Read registers. Target must be halted.

    registers is a comma-separated list (e.g. "eip,esp,cr2,cr3"); default is
    the general set from the stub's `g` packet. all=True also reads every
    extra register the target describes (control registers, segment bases,
    FPU/SSE...). Flag registers (eflags, cr0, cr4...) are decoded.
    """
    s = _get(name)
    if registers:
        wanted = [r.strip() for r in registers.split(",") if r.strip()]
        values = {s.layout.by_name(r).name: s.read_reg(r) for r in wanted}
    else:
        values = s.read_regs()
        if all:
            for reg in s.layout.registers:
                if reg.name not in values:
                    try:
                        values[reg.name] = s.layout.decode(reg, s.rsp.read_register(reg.regnum))
                    except RSPError:
                        continue
    lines = []
    pc_name = s.layout.pc().name
    for rname, val in values.items():
        reg = s.layout.by_name(rname)
        width = max(reg.bitsize // 4, 1)
        line = f"{rname:>8} = {val:#0{width + 2}x}"
        flags = regmod.describe_flags(reg, val)
        if flags:
            line += f"  [{flags}]"
        elif rname == pc_name or (s.syms is not None and reg.type in ("code_ptr", "data_ptr")):
            where = s.where(val)
            if where != f"{val:#x}":
                line += f"  {where[len(f'{val:#x}'):].strip()}"
        lines.append(line)
    return "\n".join(lines)


@tool
def debug_set_register(name: str, register: str, value: str) -> str:
    """Write a register. value is an address expression (0x10, symbol, ...)."""
    s = _get(name)
    v, note = s.resolve(value)
    s.write_reg(register, v)
    return f"{s.layout.by_name(register).name} = {v:#x}{_note(note)}"


@tool
def debug_memory(name: str, address: str, length: int = 64, format: str = "hex") -> str:
    """Read guest memory (virtual addresses, as the CPU currently sees them).

    address accepts 0x1234, symbol, symbol+0x10, file.c:42 or $esp+8.
    format: "hex" (hexdump with ASCII), "words" (pointer-sized words,
    symbolized), or "string" (NUL-terminated string at address).
    length is capped at 4096 bytes.
    """
    if not 0 < length <= 4096:
        raise ValueError("length must be between 1 and 4096")
    s = _get(name)
    addr, note = s.resolve(address)
    data = s.rsp.read_memory(addr, length)
    if format == "string":
        raw = data.split(b"\0", 1)[0]
        return f"{s.where(addr)}: {raw.decode('latin-1')!r}{_note(note)}"
    if format == "words":
        w = s.word
        order = s.layout.byteorder
        lines = []
        for off in range(0, len(data) - w + 1, w):
            val = int.from_bytes(data[off:off + w], order)
            where = s.where(val) if s.syms else f"{val:#x}"
            lines.append(f"{addr + off:#010x}: {val:#0{w * 2 + 2}x}"
                         + (f"  {where[len(f'{val:#x}'):].strip()}" if where != f"{val:#x}" else ""))
        return "\n".join(lines) + _note(note)
    if format != "hex":
        raise ValueError('format must be "hex", "words" or "string"')
    printable = set(string.printable.encode()) - set(b"\t\n\r\x0b\x0c")
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if b in printable else "." for b in chunk)
        lines.append(f"{addr + off:#010x}: {hexpart:<47}  {asc}")
    return "\n".join(lines) + _note(note)


@tool
def debug_write_memory(name: str, address: str, hex_bytes: str) -> str:
    """Write raw bytes (hex string, e.g. "90 90 cc") to guest memory."""
    s = _get(name)
    addr, note = s.resolve(address)
    data = bytes.fromhex(hex_bytes.replace(" ", ""))
    s.rsp.write_memory(addr, data)
    return f"Wrote {len(data)} bytes at {s.where(addr)}{_note(note)}"


@tool
def debug_break(name: str, location: str, kind: str = "sw", length: int | None = None) -> str:
    """Set a breakpoint or watchpoint.

    location: 0x1234, symbol, symbol+0x10, or file.c:42.
    kind: "sw" (software breakpoint), "hw" (hardware breakpoint - use this
    before paging is enabled or for code that isn't loaded yet), or a
    watchpoint: "write", "read", "access" (length bytes, default one word).
    """
    s = _get(name)
    bp, note = s.add_breakpoint(location, kind, length)
    what = "breakpoint" if kind in ("sw", "hw") else f"{kind} watchpoint ({bp.length} bytes)"
    return f"#{bp.id} {kind} {what} at {s.where(bp.address)}{_note(note)}"


@tool
def debug_delete(name: str, id: int) -> str:
    """Remove a breakpoint/watchpoint by its # id."""
    s = _get(name)
    bp = s.remove_breakpoint(id)
    return f"Removed #{bp.id} ({bp.label})."


@tool
def debug_breakpoints(name: str) -> str:
    """List breakpoints and watchpoints."""
    s = _get(name)
    if not s.breakpoints:
        return "No breakpoints."
    return "\n".join(f"#{b.id} {b.kind:<6} {s.where(b.address)}  ({b.label})"
                     for b in s.breakpoints.values())


@tool
def debug_continue(name: str, timeout_s: float = 10.0) -> str:
    """Resume the target and wait up to timeout_s for it to stop.

    If it hasn't stopped by then it keeps running: call debug_wait to keep
    waiting, or debug_interrupt to halt it where it is.
    """
    s = _get(name)
    stepped = s.step_over_breakpoint()
    if stepped is not None and not stepped.startswith((b"T05", b"S05")):
        return s.describe_stop(stepped)  # the step itself faulted or exited
    s.rsp.resume()
    reply = s.rsp.wait_stop(timeout_s)
    if reply is None:
        return (f"Still running after {timeout_s}s (no breakpoint hit). "
                "Use debug_wait to keep waiting or debug_interrupt to halt it.")
    return s.describe_stop(reply)


@tool
def debug_wait(name: str, timeout_s: float = 10.0) -> str:
    """Wait for a running target to stop (after debug_continue timed out)."""
    s = _get(name)
    reply = s.rsp.wait_stop(timeout_s)
    if reply is None:
        return f"Still running after another {timeout_s}s."
    return s.describe_stop(reply)


@tool
def debug_interrupt(name: str) -> str:
    """Halt a running target immediately (like Ctrl-C in gdb)."""
    s = _get(name)
    return s.describe_stop(s.rsp.interrupt())


@tool
def debug_step(name: str, count: int = 1) -> str:
    """Single-step `count` machine instructions (1..1000) and show where it stopped."""
    if not 1 <= count <= 1000:
        raise ValueError("count must be between 1 and 1000")
    s = _get(name)
    reply = b""
    for _ in range(count):
        r = s.step_over_breakpoint()
        if r is None:
            s.rsp.resume(step=True)
            r = s.rsp.wait_stop(s.rsp.read_timeout)
        if r is None:
            raise RSPError("target did not stop after a single step")
        reply = r
        if not reply.startswith((b"T05", b"S05")):
            break
    return s.describe_stop(reply)


@tool
def debug_backtrace(name: str, max_frames: int = 16, mode: str = "auto") -> str:
    """Show the call stack.

    mode "fp" walks the frame-pointer chain (exact, but only if the kernel
    was built with frame pointers, e.g. -fno-omit-frame-pointer); "scan"
    scans the stack for return addresses (works on -O2 kernels without frame
    pointers, x86 only, needs elf; may include stale frames); "auto" tries
    fp and falls back to scan if the chain is empty.
    """
    s = _get(name)
    frames, method = s.backtrace(max_frames, mode)
    return "\n".join(frames) + f"\n(method: {method})"


@tool
def debug_disassemble(name: str, address: str | None = None, count: int = 12,
                      bits: int | None = None) -> str:
    """Disassemble `count` instructions from address (default: current pc).

    bits overrides the decode mode on x86 (16 for real mode, 32, 64) -
    useful in bootloader code that runs before the CPU mode matches the ELF.
    """
    s = _get(name)
    if address is None:
        addr, note = s.read_reg(s.layout.pc().name), None
    else:
        addr, note = s.resolve(address)
    if bits not in (None, 16, 32, 64):
        raise ValueError("bits must be 16, 32 or 64")
    lines = s.disassemble(addr, count, bits)
    src = s.where(addr)
    return f"{src}\n" + "\n".join(lines) + _note(note)


@tool
def debug_symbol(query: str, name: str | None = None, elf: str | None = None) -> str:
    """Look up symbols without touching the target.

    query: an address (0x100abc) -> symbol+offset and source line; a symbol or
    symbol+off -> its address, size and source line; or file.c:42 -> address.
    Uses the session's ELF (name=) or a standalone ELF path (elf=).
    """
    if name is not None:
        syms = _get(name).syms
        if syms is None:
            raise RSPError(f"session {name!r} has no ELF loaded")
    elif elf is not None:
        syms = SymbolTable(elf)
    else:
        raise ValueError("pass either name= (a session) or elf= (an ELF path)")
    addr, note = resolve(query, syms)
    out = [f"{addr:#x} = {syms.symbolize(addr)}"]
    fn = syms.containing_function(addr)
    if fn is not None:
        out.append(f"function {fn.name}: {fn.address:#x}..{fn.address + fn.size:#x} ({fn.size} bytes)")
    line = syms.line_for(addr)
    if line is not None:
        out.append(f"source: {line.file}:{line.line}")
    return "\n".join(out) + _note(note)


@tool
def debug_explain_fault(log_path: str, elf: str | None = None, max_events: int = 12) -> str:
    """Explain a crash / triple fault from a QEMU interrupt log.

    Produce the log by running QEMU with `-d int,cpu_reset -D <log_path>`
    (add `-no-reboot` so a triple fault stops the VM instead of looping).
    Decodes the exception chain (vector names, page-fault and selector error
    codes, CR2), filters out timer IRQs and software interrupts, points at
    the root cause, and symbolizes addresses when elf is given. x86 only.
    """
    if not os.path.isfile(log_path):
        raise FileNotFoundError(f"log not found: {log_path}")
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        report = faultmod.parse_log(fh.read())
    syms = SymbolTable(elf) if elf else None

    def source(addr: int) -> str | None:
        if syms is None:
            return None
        ln = syms.line_for(addr)
        return f"{os.path.basename(ln.file)}:{ln.line}" if ln else None

    return faultmod.explain(report, syms.symbolize if syms else None, source, max_events)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
