"""A tiny in-process gdbstub over a real TCP socket, for testing RSPClient
without QEMU. It speaks just enough RSP: acks, qSupported, no-ack mode,
qXfer target.xml, ?, g, p, m, M, Z/z, c/s and the 0x03 interrupt byte.
"""

from __future__ import annotations

import socket
import threading

from gdbstub_mcp.rsp import frame

TARGET_XML = (
    '<?xml version="1.0"?><!DOCTYPE target SYSTEM "gdb-target.dtd">'
    "<target><architecture>i386</architecture>"
    '<xi:include href="core.xml"/></target>'
)
CORE_XML = (
    '<?xml version="1.0"?><feature name="org.gnu.gdb.i386.core">'
    '<flags id="i386_eflags" size="4"><field name="IF" start="9" end="9"/>'
    '<field name="ZF" start="6" end="6"/></flags>'
    '<reg name="eax" bitsize="32" type="int32" regnum="0"/>'
    '<reg name="esp" bitsize="32" type="data_ptr"/>'
    '<reg name="ebp" bitsize="32" type="data_ptr"/>'
    '<reg name="eip" bitsize="32" type="code_ptr"/>'
    '<reg name="eflags" bitsize="32" type="i386_eflags"/>'
    '<reg name="cr2" bitsize="32" type="int32"/>'
    "</feature>"
)


class FakeStub:
    def __init__(self, no_ack: bool = True, stop_after_continue: bool = True):
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]
        self.support_no_ack = no_ack
        self.stop_after_continue = stop_after_continue
        self.no_ack = False
        self.memory = bytearray(0x1000)
        # eax, esp, ebp, eip, eflags in the g packet; cr2 only via p.
        self.regs = [0x2A, 0x800, 0x810, 0x100, 0x246]
        self.cr2 = 0xDEADBEEF
        self.breakpoints: set[tuple[int, int]] = set()
        self.received: list[bytes] = []
        self.corrupt_next_reply = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        conn, _ = self.srv.accept()
        self.conn = conn
        buf = b""
        while True:
            try:
                data = conn.recv(4096)
            except OSError:
                return
            if not data:
                return
            buf += data
            while buf:
                if buf[:1] in (b"+", b"-"):
                    buf = buf[1:]
                    continue
                if buf[:1] == b"\x03":
                    buf = buf[1:]
                    self._send(b"T02thread:01;")
                    continue
                start = buf.find(b"$")
                end = buf.find(b"#", start)
                if start < 0 or end < 0 or len(buf) < end + 3:
                    break
                payload = buf[start + 1:end]
                buf = buf[end + 3:]
                if not self.no_ack:
                    conn.sendall(b"+")
                self.received.append(payload)
                self._handle(payload)

    def _send(self, payload: bytes) -> None:
        pkt = frame(payload)
        try:
            if self.corrupt_next_reply:
                self.corrupt_next_reply = False
                self.conn.sendall(pkt[:-2] + b"00")
            self.conn.sendall(pkt)
        except OSError:
            # The client closed (e.g. right after its detach packet); a real
            # stub would just drop the connection too.
            pass

    def _handle(self, p: bytes) -> None:
        s = p.decode()
        if s.startswith("qSupported"):
            extra = ";QStartNoAckMode+" if self.support_no_ack else ""
            self._send(b"PacketSize=4000;qXfer:features:read+" + extra.encode())
        elif s == "QStartNoAckMode":
            self._send(b"OK")
            self.no_ack = True
        elif s.startswith("qXfer:features:read:"):
            annex, rng = s[len("qXfer:features:read:"):].rsplit(":", 1)
            off, length = (int(x, 16) for x in rng.split(","))
            doc = (TARGET_XML if annex == "target.xml" else CORE_XML).encode()
            chunk = doc[off:off + length]
            self._send((b"l" if off + length >= len(doc) else b"m") + chunk)
        elif s == "?":
            self._send(b"T05thread:01;")
        elif s == "g":
            self._send(b"".join(r.to_bytes(4, "little").hex().encode() for r in self.regs))
        elif s.startswith("p"):
            n = int(s[1:], 16)
            val = self.regs[n] if n < len(self.regs) else self.cr2
            self._send(val.to_bytes(4, "little").hex().encode())
        elif s.startswith("P"):
            n, v = s[1:].split("=")
            self.regs[int(n, 16)] = int.from_bytes(bytes.fromhex(v), "little")
            self._send(b"OK")
        elif s.startswith("m"):
            a, n = (int(x, 16) for x in s[1:].split(","))
            if a + n > len(self.memory):
                self._send(b"E14")
            else:
                # Run-length encode a run of zeros to exercise the decoder.
                self._send(self.memory[a:a + n].hex().encode())
        elif s.startswith("M"):
            head, data = s[1:].split(":")
            a, _n = (int(x, 16) for x in head.split(","))
            raw = bytes.fromhex(data)
            self.memory[a:a + len(raw)] = raw
            self._send(b"OK")
        elif s[:1] in ("Z", "z"):
            kind, addr, _ln = s[1:].split(",")
            if kind == "9":
                self._send(b"")
                return
            key = (int(kind), int(addr, 16))
            (self.breakpoints.add if s[0] == "Z" else self.breakpoints.discard)(key)
            self._send(b"OK")
        elif s in ("c", "s"):
            if s == "s" or self.stop_after_continue:
                self.regs[3] += 1 if s == "s" else 0
                self._send(b"T05thread:01;swbreak:;")
        elif s == "D":
            self._send(b"OK")
        else:
            self._send(b"")

    def close(self) -> None:
        try:
            self.conn.close()
        except (OSError, AttributeError):
            pass
        self.srv.close()
