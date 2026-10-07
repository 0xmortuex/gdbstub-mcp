"""End-to-end tests against a real QEMU running the fixture kernel.

Skipped when qemu-system-i386 isn't installed. These exercise the whole
stack - RSP over TCP, target.xml discovery, DWARF lines, breakpoints,
frame-pointer backtraces and fault explanation from a real triple fault.
"""

import os
import shutil
import socket
import subprocess
import time

import pytest

from gdbstub_mcp import server as S

HERE = os.path.dirname(__file__)
ELF = os.path.join(HERE, "fixtures", "kernel", "kernel.elf")


def _find_qemu():
    found = shutil.which("qemu-system-i386")
    if found:
        return found
    win = r"C:\Program Files\qemu\qemu-system-i386.exe"
    return win if os.path.isfile(win) else None


QEMU = _find_qemu()
pytestmark = pytest.mark.skipif(QEMU is None, reason="qemu-system-i386 not installed")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def vm(tmp_path):
    port = _free_port()
    log = str(tmp_path / "int.log")
    proc = subprocess.Popen(
        [QEMU, "-display", "none", "-kernel", ELF, "-gdb", f"tcp:127.0.0.1:{port}", "-S",
         "-d", "int,cpu_reset", "-D", log, "-no-reboot"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    yield port, log, proc
    for name in list(S._sessions):
        S._sessions.pop(name).close()
    proc.kill()
    proc.wait()


def test_break_continue_registers_backtrace(vm):
    port, _, _ = vm
    out = S.debug_connect("t", port=port, elf=ELF)
    assert "i386" in out and "line-table entries" in out
    assert "#1" in S.debug_break("t", "add")
    stop = S.debug_continue("t", 20)
    assert "breakpoint #1 (add)" in stop and "kernel.c" in stop

    regs = S.debug_registers("t", "eip,eflags,cr0")
    assert "<add>" in regs and "PE]" in regs.split("cr0")[1]

    bt = S.debug_backtrace("t", mode="fp")
    names = [ln.split("<")[1].split(">")[0].split("+")[0] for ln in bt.splitlines() if "<" in ln]
    assert names[:4] == ["add", "compute", "kmain", "_start"], bt

    assert "push" in S.debug_disassemble("t", "add", count=2)
    assert "#1" in S.debug_breakpoints("t")
    S.debug_delete("t", 1)

    assert "<add+" in S.debug_step("t", 3)
    S.debug_disconnect("t")


def test_file_line_breakpoint_and_watchpoint(vm):
    port, _, _ = vm
    S.debug_connect("t", port=port, elf=ELF)
    S.debug_break("t", "kernel.c:10")
    assert "kernel.c:10" in S.debug_continue("t", 20)
    S.debug_delete("t", 1)
    S.debug_break("t", "counter", kind="write")
    stop = S.debug_continue("t", 20)
    assert "watch hit on" in stop and "counter" in stop
    S.debug_disconnect("t")


def test_interrupt_and_memory(vm):
    port, _, _ = vm
    S.debug_connect("t", port=port, elf=ELF)
    assert "Still running" in S.debug_continue("t", 0.5)
    assert "SIGINT" in S.debug_interrupt("t")
    S.debug_write_memory("t", "counter", "78 56 34 12")
    assert "0x12345678" in S.debug_memory("t", "counter", 4, "words")
    S.debug_disconnect("t")


def test_triple_fault_end_to_end(vm):
    port, log, proc = vm
    S.debug_connect("t", port=port, elf=ELF)
    S.debug_break("t", "kmain")
    S.debug_continue("t", 20)
    S.debug_delete("t", 1)
    S.debug_write_memory("t", "trigger", "01 00 00 00")
    assert "exited" in S.debug_continue("t", 20)
    proc.wait(timeout=10)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and "Triple fault" not in open(log).read():
        time.sleep(0.1)
    text = S.debug_explain_fault(log, elf=ELF)
    assert "TRIPLE FAULT" in text
    assert "#UD invalid opcode at" in text and "triple_fault" in text
    assert "Root cause: the chain started with #UD" in text
