# Backlog

Real, finishable improvements - pick ONE, ship it end-to-end with tests.

## Features
- [ ] `debug_explain_fault` for non-x86 logs (aarch64 `-d int` prints ESR/FAR - decode exception class).
- [ ] Shared session with qemu-mcp: `qemu_boot(..., gdb=True)` returning the port, so one call wires both.
- [ ] `debug_finish` (run until the current function returns) using the backtrace's return address + temp breakpoint.
- [ ] `debug_next` (step over calls) for x86 via capstone: if the instruction is a call, temp-break after it.
- [ ] Page-table walker: translate a virtual address through CR3 (x86 2-level, PAE, 4-level) and show each entry's flags - the #1 question after a #PF.
- [ ] GDT/IDT dumper: read GDTR/IDTR (needs QEMU monitor via qemu-mcp, or a symbol for the table) and decode every gate.
- [ ] Local variables / function arguments from DWARF location expressions (frame-base relative only, to start).

## Quality
- [ ] Integration test on aarch64 (`-M virt`) with a tiny fixture kernel.
- [ ] Ack-mode stubs that interleave `O` (console output) packets - handle and surface them.
