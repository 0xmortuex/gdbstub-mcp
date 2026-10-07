"""Explain x86 exception chains from a QEMU `-d int,cpu_reset` log.

With `-d int` QEMU logs every interrupt/exception it delivers:

    check_exception old: 0xffffffff new 0xe
         0: v=0e e=0002 i=0 cpl=0 IP=0008:00100123 pc=00100123 SP=0010:0010ffe0 CR2=deadbeef

and when an exception occurs while delivering a double fault it logs
`Triple fault` and resets the CPU. That chain - #PF -> #GP -> #DF -> reset -
is exactly what an OS developer needs to see, but it's buried among
thousands of timer interrupts. This module pulls it out and decodes it.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

EXCEPTIONS: dict[int, tuple[str, str]] = {
    0x00: ("#DE", "divide error"),
    0x01: ("#DB", "debug"),
    0x02: ("NMI", "non-maskable interrupt"),
    0x03: ("#BP", "breakpoint (int3)"),
    0x04: ("#OF", "overflow"),
    0x05: ("#BR", "bound range exceeded"),
    0x06: ("#UD", "invalid opcode"),
    0x07: ("#NM", "device not available (FPU/SSE used with CR0.TS/EM set)"),
    0x08: ("#DF", "double fault"),
    0x0A: ("#TS", "invalid TSS"),
    0x0B: ("#NP", "segment not present"),
    0x0C: ("#SS", "stack-segment fault"),
    0x0D: ("#GP", "general protection fault"),
    0x0E: ("#PF", "page fault"),
    0x10: ("#MF", "x87 floating-point error"),
    0x11: ("#AC", "alignment check"),
    0x12: ("#MC", "machine check"),
    0x13: ("#XM", "SIMD floating-point exception"),
    0x14: ("#VE", "virtualization exception"),
    0x15: ("#CP", "control protection exception"),
}

_SELECTOR_ERRCODE = {0x0A, 0x0B, 0x0C, 0x0D}

_CHECK_RE = re.compile(r"check_exception old: (0x[0-9a-f]+) new (0x[0-9a-f]+)")
_EVENT_RE = re.compile(r"^\s*(\d+): v=([0-9a-f]+) e=([0-9a-f]+) i=(\d)(.*)$")
_FIELD_RE = re.compile(r"(\w+)=([0-9a-f]+(?::[0-9a-f]+)?)")


@dataclass
class Event:
    seq: int
    vector: int
    error_code: int
    software: bool
    fields: dict[str, str] = field(default_factory=dict)
    regs: str = ""  # the register dump lines that follow, if any

    @property
    def pc(self) -> int | None:
        if "pc" in self.fields:
            return int(self.fields["pc"], 16)
        ip = self.fields.get("IP")
        return int(ip.split(":")[-1], 16) if ip else None

    @property
    def is_exception(self) -> bool:
        return self.vector < 32 and not self.software


@dataclass
class Report:
    events: list[Event]
    triple_fault: bool
    resets: int
    total_interrupts: int


def parse_log(text: str) -> Report:
    events: list[Event] = []
    triple = False
    resets = 0
    total = 0
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if "Triple fault" in line:
            triple = True
        if line.startswith("CPU Reset"):
            resets += 1
        m = _EVENT_RE.match(line)
        if m:
            total += 1
            ev = Event(
                seq=int(m.group(1)),
                vector=int(m.group(2), 16),
                error_code=int(m.group(3), 16),
                software=m.group(4) == "1",
                fields=dict(_FIELD_RE.findall(m.group(5))),
            )
            # Collect the register dump (EAX=.../RAX=... block) that follows.
            dump = []
            j = i + 1
            while j < len(lines) and re.match(r"^(E|R)AX=|^[A-Z0-9]{2,4}\s*=|^[A-Z]{2,4} =", lines[j]):
                dump.append(lines[j])
                j += 1
            ev.regs = "\n".join(dump)
            if ev.is_exception:
                events.append(ev)
            i = j
            continue
        i += 1
    return Report(events=events, triple_fault=triple, resets=resets, total_interrupts=total)


def decode_error_code(vector: int, code: int) -> str:
    if vector == 0x0E:
        parts = [
            "protection violation" if code & 1 else "page not present",
            "write" if code & 2 else "read",
            "user mode" if code & 4 else "kernel mode",
        ]
        if code & 8:
            parts.append("reserved bit set in a paging entry")
        if code & 16:
            parts.append("instruction fetch")
        if code & 32:
            parts.append("protection-key violation")
        return ", ".join(parts)
    if vector in _SELECTOR_ERRCODE or (vector == 0x08 and code):
        if code == 0:
            return "error code 0 (not caused by a specific selector)"
        table = "IDT" if code & 2 else ("LDT" if code & 4 else "GDT")
        index = code >> 3
        ext = " (external event)" if code & 1 else ""
        desc = f"{table} entry {index}"
        if table == "IDT":
            name = EXCEPTIONS.get(index, (f"vector {index:#x}",))[0]
            desc += f" = {name}" if index < 32 else f" (vector {index:#x})"
        return f"selector {code:#x}: {desc}{ext}"
    return f"error code {code:#x}" if code else ""


def _hint(ev: Event, next_ev: Event | None) -> str | None:
    v, code = ev.vector, ev.error_code
    if v in (0x0B, 0x0D) and code & 2:
        idx = code >> 3
        return (f"the IDT entry for vector {idx:#x} is missing or invalid - the CPU couldn't "
                f"even start your handler. Check that the IDT is loaded (lidt) and entry "
                f"{idx:#x} is filled in with a present gate and a valid code selector.")
    if v == 0x0E:
        cr2 = ev.fields.get("CR2")
        if cr2 and int(cr2, 16) < 0x1000:
            return "CR2 is in the first page - this is almost certainly a NULL pointer dereference."
        if code & 16:
            return "the fault is on an instruction fetch: the CPU jumped to an unmapped/NX address (bad function pointer or corrupted return address)."
    if v == 0x0D and code == 0:
        return ("#GP with error code 0: a privileged instruction, a non-canonical address, "
                "a bad segment load, or a far jump/iret with a bad frame.")
    if v == 0x08:
        return "a second exception occurred while delivering the first - see the chain above."
    if v == 0x06:
        return "the CPU hit bytes that aren't a valid instruction - often a jump into data or a corrupted return address."
    return None


def explain(report: Report, symbolize: Callable[[int], str] | None = None,
            source: Callable[[int], str | None] | None = None, max_events: int = 12) -> str:
    out: list[str] = []
    n = len(report.events)
    out.append(f"Parsed {report.total_interrupts} interrupt/exception entries; "
               f"{n} were CPU exceptions (hardware IRQs and software int N filtered out).")
    if report.triple_fault:
        out.append("A TRIPLE FAULT occurred: the CPU reset itself.")
    if n == 0:
        out.append("No CPU exceptions in this log. Was QEMU started with -d int (and -D <file>)?")
        return "\n".join(out)

    # Show the tail: the final chain is what matters for a crash.
    shown = report.events[-max_events:]
    if n > len(shown):
        out.append(f"(showing the last {len(shown)} of {n} exceptions)")
    out.append("")
    for k, ev in enumerate(shown):
        mnem, desc = EXCEPTIONS.get(ev.vector, (f"vec {ev.vector:#x}", "reserved"))
        line = f"[{ev.seq}] {mnem} {desc}"
        pc = ev.pc
        if pc is not None:
            loc = symbolize(pc) if symbolize else f"{pc:#x}"
            line += f" at {loc}"
            if source:
                src = source(pc)
                if src:
                    line += f" ({src})"
        out.append(line)
        ec = decode_error_code(ev.vector, ev.error_code)
        if ec:
            out.append(f"     {ec}")
        if ev.vector == 0x0E and "CR2" in ev.fields:
            cr2 = int(ev.fields["CR2"], 16)
            out.append(f"     faulting address (CR2) = {cr2:#x}"
                       + (f" = {symbolize(cr2)}" if symbolize and not symbolize(cr2).startswith("0x") else ""))
        if ev.fields.get("cpl"):
            out.append(f"     CPL {ev.fields['cpl']}")
        hint = _hint(ev, shown[k + 1] if k + 1 < len(shown) else None)
        if hint:
            out.append(f"     -> {hint}")
    if report.triple_fault:
        first = _root_of_last_chain(report.events)
        if first is not None:
            mnem = EXCEPTIONS.get(first.vector, (f"vec {first.vector:#x}",))[0]
            where = symbolize(first.pc) if symbolize and first.pc is not None else (
                f"{first.pc:#x}" if first.pc is not None else "unknown")
            out.append("")
            out.append(f"Root cause: the chain started with {mnem} at {where}.")
            missing = _missing_handlers(report.events, first)
            if missing:
                names = ", ".join(
                    EXCEPTIONS.get(v, (f"vector {v:#x}",))[0] + f" (IDT entry {v:#x})" for v in missing
                )
                out.append(f"It escalated to a triple fault because the handler for {names} "
                           f"could not be invoked. Fix the IDT entry so the original exception "
                           f"reaches your handler, then fix the {mnem} itself.")
            else:
                out.append("Fix that first; everything after it is the CPU failing to report it.")
    return "\n".join(out)


def _missing_handlers(events: list[Event], root: Event) -> list[int]:
    """IDT vectors whose gates failed during the cascade starting at root
    (#GP/#NP with the IDT bit set in the error code name the bad entry)."""
    out: list[int] = []
    start = events.index(root)
    for ev in events[start + 1:]:
        if ev.vector in (0x0B, 0x0D) and ev.error_code & 2:
            v = ev.error_code >> 3
            if v not in out:
                out.append(v)
        if ev.vector == 0x08:
            break
    return out


def _root_of_last_chain(events: list[Event]) -> Event | None:
    """Walk back from the final #DF to the exception that started the cascade.

    A cascade is consecutive exceptions whose delivery failed; QEMU numbers
    each delivery attempt, so we take the run of events ending at the last
    #DF and return its first member.
    """
    last_df = None
    for idx in range(len(events) - 1, -1, -1):
        if events[idx].vector == 0x08:
            last_df = idx
            break
    if last_df is None:
        return events[-1] if events else None
    start = last_df
    while start > 0 and events[start - 1].seq == events[start].seq - 1:
        start -= 1
    return events[start]
