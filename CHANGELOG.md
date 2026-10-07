# Changelog

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
