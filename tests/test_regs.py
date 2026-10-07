import pytest

from gdbstub_mcp.regs import describe_flags, expand_includes, parse_target_xml

XML = """<?xml version="1.0"?><target><architecture>i386:x86-64</architecture>
<feature name="core">
  <flags id="cr0_t" size="8"><field name="PG" start="31" end="31"/>
    <field name="PE" start="0" end="0"/><field name="IOPL" start="12" end="13"/></flags>
  <reg name="rax" bitsize="64" type="int64" regnum="0"/>
  <reg name="rip" bitsize="64" type="code_ptr"/>
  <reg name="rsp" bitsize="64" type="data_ptr"/>
  <reg name="rbp" bitsize="64" type="data_ptr"/>
</feature>
<feature name="sys">
  <reg name="cr0" bitsize="64" type="cr0_t" regnum="40"/>
  <reg name="cr2" bitsize="64" type="int64"/>
</feature></target>"""


def test_parse_numbers_registers_in_order_and_honours_regnum():
    lay = parse_target_xml(XML)
    nums = {r.name: r.regnum for r in lay.registers}
    assert nums == {"rax": 0, "rip": 1, "rsp": 2, "rbp": 3, "cr0": 40, "cr2": 41}
    assert lay.pc().name == "rip" and lay.sp().name == "rsp" and lay.fp().name == "rbp"
    assert not lay.big_endian


def test_by_name_is_case_insensitive_and_strips_sigils():
    lay = parse_target_xml(XML)
    assert lay.by_name("$RIP").name == "rip"
    with pytest.raises(KeyError, match="has: rax"):
        lay.by_name("eip")


def test_split_g_stops_at_end_of_blob():
    lay = parse_target_xml(XML)
    blob = (1).to_bytes(8, "little") + (0x1000).to_bytes(8, "little")
    parts = lay.split_g(blob)
    assert list(parts) == ["rax", "rip"]
    assert lay.decode(lay.by_name("rip"), parts["rip"]) == 0x1000


def test_encode_roundtrip_and_overflow():
    lay = parse_target_xml(XML)
    r = lay.by_name("rax")
    assert lay.decode(r, lay.encode(r, 0x1234)) == 0x1234
    assert lay.encode(r, -1) == b"\xff" * 8
    with pytest.raises(ValueError):
        lay.encode(r, 1 << 64)


def test_describe_flags():
    lay = parse_target_xml(XML)
    cr0 = lay.by_name("cr0")
    assert describe_flags(cr0, 0x80000001) == "PG PE"
    assert describe_flags(cr0, 0x3000) == "IOPL=3"


def test_big_endian_detection():
    assert parse_target_xml(XML.replace("i386:x86-64", "powerpc:common")).big_endian
    assert not parse_target_xml(XML.replace("i386:x86-64", "mipsel")).big_endian


def test_expand_includes_strips_prologs_and_nests():
    docs = {
        "a.xml": '<?xml version="1.0"?><!DOCTYPE x><feature name="a"><xi:include href="b.xml"/></feature>',
        "b.xml": '<reg name="r0" bitsize="32"/>',
    }
    out = expand_includes('<target><xi:include href="a.xml"/></target>', docs.__getitem__)
    assert "<?xml" not in out and 'name="r0"' in out
    assert [r.name for r in parse_target_xml(out).registers] == ["r0"]


def test_empty_layout_rejected():
    with pytest.raises(ValueError, match="no registers"):
        parse_target_xml("<target><feature name='x'/></target>")
