import os

from gdbstub_mcp.faults import decode_error_code, explain, parse_log

# A real QEMU `-d int,cpu_reset` excerpt: a timer IRQ, then ud2 executed with
# the #UD, #GP and #DF IDT gates wiped -> triple fault.
LOG = os.path.join(os.path.dirname(__file__), "fixtures", "triple_fault.log")


def _report():
    with open(LOG) as fh:
        return parse_log(fh.read())


def test_real_qemu_log_chain_is_extracted():
    r = _report()
    assert r.triple_fault
    assert r.total_interrupts > len(r.events)  # timer IRQs filtered out
    assert [e.vector for e in r.events] == [0x06, 0x0D, 0x08]
    assert r.events[0].pc == 0x7000
    assert "EAX=" in r.events[0].regs


def test_explain_names_root_cause_and_missing_idt_entry():
    text = explain(_report())
    assert "TRIPLE FAULT" in text
    assert "#UD invalid opcode at 0x7000" in text
    assert "IDT entry 6 = #UD" in text
    assert "Root cause: the chain started with #UD" in text
    assert "#UD (IDT entry 0x6)" in text


def test_explain_symbolizes():
    text = explain(_report(), symbolize=lambda a: f"fn+{a:#x}", source=lambda a: "x.c:1")
    assert "at fn+0x7000 (x.c:1)" in text


def test_page_fault_decoding_and_null_hint():
    log = ("check_exception old: 0xffffffff new 0xe\n"
           "     0: v=0e e=0002 i=0 cpl=0 IP=0008:00100123 pc=00100123 "
           "SP=0010:0010ffe0 CR2=00000008\n")
    r = parse_log(log)
    assert r.events[0].fields["CR2"] == "00000008"
    text = explain(r)
    assert "page not present, write, kernel mode" in text
    assert "faulting address (CR2) = 0x8" in text
    assert "NULL pointer" in text


def test_software_interrupts_and_irqs_filtered():
    log = ("     0: v=80 e=0000 i=1 cpl=3 IP=001b:00400000 pc=00400000 SP=0023:00800000\n"
           "     1: v=20 e=0000 i=0 cpl=0 IP=0008:00100000 pc=00100000 SP=0010:00100000\n"
           "     2: v=03 e=0000 i=1 cpl=0 IP=0008:00100000 pc=00100000 SP=0010:00100000\n")
    r = parse_log(log)
    assert r.total_interrupts == 3 and r.events == []
    assert "No CPU exceptions" in explain(r)


def test_error_code_decoding():
    assert decode_error_code(0x0E, 0x15) == (
        "protection violation, read, user mode, instruction fetch")
    assert decode_error_code(0x0D, 0x0) == "error code 0 (not caused by a specific selector)"
    assert decode_error_code(0x0D, 0x10) == "selector 0x10: GDT entry 2"
    assert decode_error_code(0x0B, 0x6B) == "selector 0x6b: IDT entry 13 = #GP (external event)"
    assert decode_error_code(0x06, 0) == ""
