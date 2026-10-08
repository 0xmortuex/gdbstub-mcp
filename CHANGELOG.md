# Changelog

## Unreleased

### Fixed
- `debug_continue` from a breakpoint re-reported the same breakpoint forever (QEMU does
  this for software and hardware breakpoints): it now steps over the breakpoint at pc
  first, like gdb. Found by pagetable-mcp; the integration tests broke on a function hit
  every loop iteration, which hid it.
- Disassembly picked its mode from the emulator (`qemu-system-x86_64` -> 64-bit) instead of
  the CPU: 32-bit code showed as `push rbp`. The mode now comes from CR0.PE / EFER.LMA.
- `debug_disconnect` left the guest paused: QEMU rejects a bare `D` with E22 once the
  multiprocess extension is negotiated. Detach now sends `D;1`, checks the reply, halts a
  running target first, and handles an already-exited target.
- Backtrace caller frames showed the line *after* the call: they are now symbolized at
  `return_address - 1`, as gdb does (`_start` is `boot.s:21`, not the `hlt` on 22).
- Tool errors reach the agent as `ToolError` (mcp 2 hides other exceptions).

### Added
- `RSPClient.resume(reverse=True)` sends `bc`/`bs` when the stub advertises
  ReverseContinue/ReverseStep (QEMU replay mode), with a clear error otherwise.
- `py.typed` marker, so dependents type-check against gdbstub-mcp.

## 0.1.0 - 2026-10-07

First release.

- Speaks the GDB Remote Serial Protocol directly to QEMU's gdbstub - no gdb binary.
- Register layout discovered from the stub's `target.xml`, so any arch QEMU supports
  works; control registers (CR0/CR2/CR3/CR4, EFER) and flag registers are decoded.
- ELF symbols + DWARF line tables via pyelftools: break on `kmain`, `kmain+0x10`,
  `kernel.c:42`; every stop shows `function+offset at file:line`.
- Breakpoints (software/hardware), watchpoints (write/read/access), continue with a
  timeout, wait, interrupt, single-step.
- Backtraces: frame-pointer chain with x86 prologue/epilogue handling, or a stack scan
  for `-O2` kernels without frame pointers.
- Disassembly via capstone (x86 16/32/64-bit, AArch64, ARM, RISC-V).
- `debug_explain_fault`: decodes a QEMU `-d int,cpu_reset` log into the exception chain
  behind a triple fault - vector names, page-fault and selector error codes, CR2, the
  IDT entry that was missing, and the root cause.
