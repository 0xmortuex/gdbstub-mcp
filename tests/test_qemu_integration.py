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


def test_disconnect_leaves_the_guest_running(vm):
    """A bare `D` is rejected by QEMU once multiprocess is negotiated, which
    used to leave the guest silently paused after debug_disconnect."""
    port, _, _ = vm

    def read_counter():
        S.debug_connect("t", port=port, elf=ELF)
        out = S.debug_memory("t", "counter", 4, "words")
        S.debug_disconnect("t")
        return int(out.split(":")[1].split()[0], 16)

    S.debug_connect("t", port=port, elf=ELF)
    S.debug_break("t", "kmain")
    S.debug_continue("t", 20)
    assert "the guest is running" in S.debug_disconnect("t")  # also removes bp #1
    first = read_counter()
    time.sleep(0.5)
    second = read_counter()
    assert second != first, "counter did not change: the guest stayed paused after detach"


def test_disconnect_while_running_halts_then_detaches(vm):
    port, _, _ = vm
    S.debug_connect("t", port=port, elf=ELF)
    assert "Still running" in S.debug_continue("t", 0.3)
    assert "the guest is running" in S.debug_disconnect("t")


def test_caller_frames_show_the_calling_line(vm):
    """Caller frames are symbolized at return address - 1: the call itself.
    kmain calls compute on kernel.c:28; the instruction after that call
    belongs to the next statement, so naive lookup would misreport it."""
    port, _, _ = vm
    S.debug_connect("t", port=port, elf=ELF)
    S.debug_break("t", "add")
    S.debug_continue("t", 20)
    bt = S.debug_backtrace("t", mode="fp").splitlines()
    kmain_frame = next(ln for ln in bt if "<kmain+" in ln)
    assert "kernel.c:28" in kmain_frame, bt
    # boot.s: `call kmain` is line 21; the return address is the `hlt` on 22.
    start_frame = next(ln for ln in bt if "<_start+" in ln)
    assert "boot.s:21" in start_frame, bt
    S.debug_disconnect("t")


def test_reverse_resume_refused_outside_replay(vm):
    port, _, _ = vm
    S.debug_connect("t", port=port, elf=ELF)
    with pytest.raises(Exception, match="ReverseContinue"):
        S._sessions["t"].rsp.resume(reverse=True)
    S.debug_disconnect("t")


@pytest.mark.parametrize("kind", ["sw", "hw"])
def test_continue_steps_over_the_breakpoint_at_pc(vm, kind):
    """Resuming from an address with an active breakpoint re-reported the
    same breakpoint forever. kmain runs once, so a second stop there would
    mean continue never left it."""
    port, _, _ = vm
    S.debug_connect("t", port=port, elf=ELF)
    S.debug_break("t", "kmain", kind=kind)
    assert "breakpoint #1 (kmain)" in S.debug_continue("t", 20)
    assert "Still running" in S.debug_continue("t", 1.0)
    S.debug_interrupt("t")
    S.debug_disconnect("t")


def test_step_from_a_breakpoint_advances(vm):
    port, _, _ = vm
    S.debug_connect("t", port=port, elf=ELF)
    S.debug_break("t", "kmain")
    S.debug_continue("t", 20)
    assert "<kmain+0x1>" in S.debug_step("t")
    S.debug_disconnect("t")


QEMU64 = (shutil.which("qemu-system-x86_64")
          or (r"C:\Program Files\qemu\qemu-system-x86_64.exe"
              if os.path.isfile(r"C:\Program Files\qemu\qemu-system-x86_64.exe") else None))


@pytest.mark.skipif(QEMU64 is None, reason="qemu-system-x86_64 not installed")
def test_disassembly_follows_the_cpu_mode_not_the_emulator():
    """The 32-bit fixture kernel on qemu-system-x86_64: the stub describes
    64-bit registers, but the CPU runs protected-mode code."""
    port = _free_port()
    proc = subprocess.Popen(
        [QEMU64, "-display", "none", "-kernel", ELF, "-gdb", f"tcp:127.0.0.1:{port}", "-S"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        S.debug_connect("t64", port=port, elf=ELF)
        S.debug_break("t64", "add")
        assert "next: push ebp" in S.debug_continue("t64", 20)
        assert "push ebp" in S.debug_disassemble("t64", "add", count=1)
        S.debug_disconnect("t64")
    finally:
        S._sessions.pop("t64", None)
        proc.kill()
        proc.wait()
