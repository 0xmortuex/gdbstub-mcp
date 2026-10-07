# gdbstub-mcp

**Let your AI agent debug a kernel, and tell you why it triple-faulted.**

<!-- mcp-name: io.github.0xmortuex/gdbstub-mcp -->

gdbstub-mcp is an [MCP](https://modelcontextprotocol.io) server that gives AI agents
(Claude Code, or any MCP client) a debugger for bare-metal code running in QEMU. It
speaks the GDB Remote Serial Protocol **directly** to QEMU's built-in gdbstub, so you
don't need a `gdb` binary. That matters most on Windows and macOS, where a
cross-architecture gdb is a pain to get.

It's the companion to [qemu-mcp](https://github.com/0xmortuex/qemu-mcp). qemu-mcp
lets an agent boot a kernel and *see* the crash. gdbstub-mcp lets it find out *why*.

## What it looks like

An agent debugging a hobby kernel. This is real output, captured from the test
kernel in `tests/fixtures/kernel`:

```
> debug_break kernel.c:10
#1 sw breakpoint at 0x100029 <add+0x9> at kernel.c:10

> debug_continue
Stopped: SIGTRAP (breakpoint/step) - breakpoint #1 (kernel.c:10)
pc = 0x100029 <add+0x9> at kernel.c:10
next: mov eax, dword ptr [ebp + 8]

> debug_backtrace
#0  0x100029 <add+0x9> at kernel.c:10
#1  0x100071 <compute+0x31> at kernel.c:16
#2  0x1000b2 <kmain+0x12> at kernel.c:28
#3  0x100016 <_start+0xa> at boot.s:22

> debug_registers eip,eflags,cr0
     eip = 0x00100029  <add+0x9> at kernel.c:10
  eflags = 0x00000093  [SF AF CF]
     cr0 = 0x00000011  [ET PE]
```

And when the machine silently reboots, `debug_explain_fault` reads QEMU's interrupt
log and explains the crash:

```
> debug_explain_fault
A TRIPLE FAULT occurred: the CPU reset itself.

[0] #UD invalid opcode at triple_fault+0xa (kernel.c:23)
[1] #GP general protection fault at triple_fault+0xa (kernel.c:23)
     selector 0x32: IDT entry 6 = #UD
     -> the IDT entry for vector 0x6 is missing or invalid - the CPU couldn't
        even start your handler. ...
[2] #DF double fault at triple_fault+0xa (kernel.c:23)

Root cause: the chain started with #UD at triple_fault+0xa.
It escalated to a triple fault because the handler for #UD (IDT entry 0x6)
could not be invoked. Fix the IDT entry so the original exception reaches
your handler, then fix the #UD itself.
```

A real QEMU log of a crash is thousands of lines of timer interrupts and register
dumps. This tool picks out the exception chain, decodes the error codes, and
points at the cause.

## Why another debugger MCP?

Existing GDB MCP servers wrap a `gdb` binary and target userland programs or core
dumps. The embedded ones target microcontrollers through probe-rs or OpenOCD.
None of them is built for the osdev loop: a kernel you wrote yourself, running in
QEMU, crashing before it can print anything.

- **No gdb required.** It's pure Python (`pyelftools` + `capstone`). Run
  `pip install gdbstub-mcp` and you're set.
- **Any architecture QEMU supports.** The register layout comes from the stub's own
  `target.xml`. Control registers (CR0/CR2/CR3/CR4, EFER) are there on x86, and flag
  registers are decoded.
- **Symbols and source lines.** Break on `kmain`, `kmain+0x10` or `kernel.c:42`, and
  every stop shows `function+offset at file:line`. Prefixed ABIs work too: `kmain`
  resolves to `mort_kmain` when that name is unique.
- **Backtraces that work on real kernels.** It walks the frame-pointer chain, and
  handles x86 prologues and epilogues correctly. For `-O2` kernels without frame
  pointers it can scan the stack for return addresses instead.
- **Triple-fault diagnosis.** `debug_explain_fault`, described above. I haven't found
  another tool that does this.

## Install

```bash
pip install gdbstub-mcp
```

Claude Code:

```bash
claude mcp add gdbstub -- gdbstub-mcp
```

Other MCP clients use the same idea: run `gdbstub-mcp` as a stdio server. Python 3.10+.

## Usage

Start QEMU with its gdbstub on, with the CPU halted:

```bash
qemu-system-i386 -kernel kernel.elf -s -S -d int,cpu_reset -D int.log -no-reboot
```

- `-s` opens the stub on `tcp::1234`.
- `-S` halts the CPU before the first instruction.
- `-d int,cpu_reset -D int.log -no-reboot` is only needed for `debug_explain_fault`.

With [qemu-mcp](https://github.com/0xmortuex/qemu-mcp), pass the same flags through
`qemu_boot`'s `extra_args`:
`extra_args="-s -S -d int,cpu_reset -D int.log -no-reboot"`.

Then ask your agent something like *"connect to the kernel with kernel.elf, break in
kmain, and step until the page fault"*.

Addresses can be written as `0x1234`, `symbol`, `symbol+0x10`, `file.c:42` or `$esp+8`.

## Tools

| Tool | What it does |
|------|--------------|
| `debug_connect` | Connect to a gdbstub (`port`, default 1234) and optionally load an `elf` with symbols. Several named sessions can be open at once. |
| `debug_disconnect` | Remove breakpoints, detach (the guest keeps running) and close the session. |
| `debug_sessions` | List sessions: endpoint, running or halted, ELF, breakpoint count. |
| `debug_registers` | Read registers: a chosen list, the general set, or `all=True` for control, segment and FPU registers. Flags are decoded and pointers symbolized. |
| `debug_set_register` | Write a register. |
| `debug_memory` | Read memory as a hexdump, as symbolized pointer-sized `words`, or as a `string`. |
| `debug_write_memory` | Write bytes. |
| `debug_break` | Set a breakpoint (`sw`, or `hw` for code before paging or not yet loaded) or a watchpoint (`write`, `read`, `access`). |
| `debug_delete` / `debug_breakpoints` | Remove a breakpoint, or list them all. |
| `debug_continue` | Resume and wait up to `timeout_s` for a stop. If no stop comes, the target keeps running. |
| `debug_wait` / `debug_interrupt` | Keep waiting for a stop, or halt the target now (like Ctrl-C). |
| `debug_step` | Single-step N instructions. |
| `debug_backtrace` | Call stack by frame-pointer chain (`fp`), stack scan (`scan`), or `auto`. |
| `debug_disassemble` | Disassemble at an address or the pc. `bits=16` decodes real-mode code. |
| `debug_symbol` | Look up an address, symbol or line offline, with no target needed. |
| `debug_explain_fault` | Explain a crash or triple fault from a QEMU `-d int,cpu_reset` log (x86). |

## Limits (honest ones)

- **Machine-level, not source-level.** There's no `next`/`finish`, and no local
  variables or C expressions yet (see [BACKLOG.md](BACKLOG.md)). You get symbols,
  lines, registers, memory and disassembly, which covers most kernel debugging.
- **Stack scanning is a heuristic.** It reports any stack word that points just after
  a `call` inside a known function, so stale frames can appear. Build with
  `-fno-omit-frame-pointer` for exact backtraces.
- `debug_explain_fault` understands x86 logs only.
- Tested against QEMU's gdbstub. Other RSP stubs (OpenOCD, Bochs, real-hardware
  probes) speak the same protocol and will likely work, but they're untested.

## Tests

```bash
pip install ".[test]" anyio "ruff==0.16.0" "mypy==2.3.0"
ruff check src tests && mypy --strict src
pytest tests
```

Unit tests use a fake gdbstub on a real TCP socket, plus a real QEMU log of a triple
fault, so they need no QEMU. `tests/test_qemu_integration.py` boots the fixture kernel
in real QEMU (CI installs `qemu-system-x86`). It checks breakpoints, watchpoints, line
numbers, a 4-deep backtrace and an end-to-end triple fault, and skips itself if QEMU
isn't installed. To rebuild the fixture kernel, run `python tests/fixtures/kernel/build.py`,
which needs `pip install ziglang`.

## License

MIT
