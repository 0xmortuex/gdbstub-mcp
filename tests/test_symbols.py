import os

import pytest

from gdbstub_mcp.symbols import Symbol, SymbolTable, resolve

ELF = os.path.join(os.path.dirname(__file__), "fixtures", "kernel", "kernel.elf")


@pytest.fixture(scope="module")
def syms():
    return SymbolTable(ELF)


def test_basic_metadata(syms):
    assert syms.arch == "x86" and syms.bits == 32
    assert syms.lines, "fixture kernel is built with -g"


def test_lookup_and_symbolize(syms):
    add, note = syms.lookup("add")
    assert note is None and add.kind == "func" and add.size > 0
    assert syms.symbolize(add.address) == "add"
    assert syms.symbolize(add.address + 3) == "add+0x3"
    with pytest.raises(KeyError, match="no symbol"):
        syms.lookup("does_not_exist")


def test_absolute_constants_are_not_used_as_labels(syms):
    # boot.s defines MAGIC/FLAGS with .set - SHN_ABS constants, not locations.
    assert all(s.name not in ("MAGIC", "FLAGS") for s in syms.symbols)
    assert syms.symbolize(0x10) == "0x10"


def test_line_lookup_both_directions(syms):
    add, _ = syms.lookup("add")
    line = syms.line_for(add.address)
    assert line is not None and line.file.endswith("kernel.c")
    assert add.address in syms.addresses_for_line("kernel.c", line.line)


def test_line_for_data_address_is_none(syms):
    counter, _ = syms.lookup("counter")
    assert syms.line_for(counter.address) is None


def test_resolve_expressions(syms):
    add, _ = syms.lookup("add")
    assert resolve("0x1234", syms) == (0x1234, None)
    assert resolve("add", syms)[0] == add.address
    assert resolve("add+0x4", syms)[0] == add.address + 4
    assert resolve("add - 2", syms)[0] == add.address - 2
    addr, _ = resolve("kernel.c:10", syms)
    assert syms.containing_function(addr).name == "add"
    with pytest.raises(ValueError, match="elf="):
        resolve("add", None)
    with pytest.raises(KeyError, match="no code at"):
        resolve("kernel.c:9999", syms)


def test_prefixed_symbol_resolution():
    # A prefixed ABI (Mort emits mort_<name>): bare names resolve if unique.
    syms = SymbolTable.__new__(SymbolTable)
    syms.path = "fake.elf"
    syms._by_name = {
        "mort_kmain": Symbol("mort_kmain", 0x10, 4, "func"),
        "a_init": Symbol("a_init", 0x20, 4, "func"),
        "b_init": Symbol("b_init", 0x30, 4, "func"),
    }
    sym, note = syms.lookup("kmain")
    assert sym.name == "mort_kmain" and note and "resolved" in note
    with pytest.raises(KeyError, match="ambiguous"):
        syms.lookup("init")
