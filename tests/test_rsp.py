import pytest

from gdbstub_mcp.regs import expand_includes, parse_target_xml
from gdbstub_mcp.rsp import RSPClient, RSPError, checksum, frame, unescape

from fake_stub import FakeStub


def test_checksum_and_frame():
    assert checksum(b"g") == 0x67
    assert frame(b"g") == b"$g#67"
    assert frame(b"") == b"$#00"


def test_unescape_handles_escapes_and_run_length():
    assert unescape(b"}\x03") == b"#"            # '#' ^ 0x20 == 0x03
    assert unescape(b"0* ") == b"0000"           # ' ' (32) -> 3 extra repeats
    assert unescape(b"ab") == b"ab"


@pytest.mark.parametrize("bad", [b"}", b"*a"])
def test_unescape_rejects_malformed(bad):
    with pytest.raises(RSPError):
        unescape(bad)


@pytest.fixture(params=[True, False], ids=["no-ack", "ack-mode"])
def stub(request):
    s = FakeStub(no_ack=request.param)
    yield s
    s.close()


def test_handshake_negotiates_no_ack_when_offered(stub):
    c = RSPClient("127.0.0.1", stub.port)
    assert c.no_ack is stub.support_no_ack
    assert c.features["qXfer:features:read"] == "+"
    c.close()


def test_registers_memory_and_breakpoints(stub):
    c = RSPClient("127.0.0.1", stub.port)
    blob = c.read_registers()
    assert int.from_bytes(blob[12:16], "little") == 0x100
    assert int.from_bytes(c.read_register(5), "little") == 0xDEADBEEF
    c.write_register(0, (7).to_bytes(4, "little"))
    assert stub.regs[0] == 7

    c.write_memory(0x20, b"hello")
    assert c.read_memory(0x20, 5) == b"hello"
    with pytest.raises(RSPError, match="E14"):
        c.read_memory(0xFFF, 16)

    c.set_breakpoint(0, 0x100, 1)
    assert (0, 0x100) in stub.breakpoints
    c.clear_breakpoint(0, 0x100, 1)
    assert not stub.breakpoints
    with pytest.raises(RSPError, match="does not support"):
        c.set_breakpoint(9, 0x100, 1)
    c.close()


def test_large_memory_read_is_chunked(stub):
    c = RSPClient("127.0.0.1", stub.port)
    stub.memory[:] = bytes(range(256)) * 16
    assert c.read_memory(0, 0x1000) == bytes(stub.memory)
    assert sum(1 for p in stub.received if p.startswith(b"m")) == 2
    c.close()


def test_target_xml_with_includes(stub):
    c = RSPClient("127.0.0.1", stub.port)
    xml = expand_includes(c.read_xfer("features", "target.xml"),
                          lambda a: c.read_xfer("features", a))
    layout = parse_target_xml(xml)
    assert layout.architecture == "i386"
    assert [r.name for r in layout.registers][:4] == ["eax", "esp", "ebp", "eip"]
    c.close()


def test_continue_wait_and_interrupt():
    stub = FakeStub(stop_after_continue=False)
    try:
        c = RSPClient("127.0.0.1", stub.port)
        c.resume()
        assert c.running
        assert c.wait_stop(0.3) is None          # still running
        with pytest.raises(RSPError, match="running"):
            c.read_registers()                   # refused while running
        reply = c.interrupt()
        assert reply.startswith(b"T02")
        assert not c.running
        c.close()
    finally:
        stub.close()


def test_step_reports_stop(stub):
    c = RSPClient("127.0.0.1", stub.port)
    c.resume(step=True)
    assert c.wait_stop(2).startswith(b"T05")
    assert stub.regs[3] == 0x101
    c.close()


def test_bad_checksum_is_nacked_and_resent():
    stub = FakeStub(no_ack=False)
    try:
        c = RSPClient("127.0.0.1", stub.port)
        stub.corrupt_next_reply = True
        assert c.stop_reason().startswith(b"T05")
        c.close()
    finally:
        stub.close()


def test_connect_failure_is_clear():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(RSPError, match="could not connect"):
        RSPClient("127.0.0.1", port, connect_timeout=0.5)
