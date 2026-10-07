"""Minimal synchronous GDB Remote Serial Protocol (RSP) client.

RSP is what `gdb` speaks to a remote stub - here, QEMU's built-in gdbstub
(`-s` / `-gdb tcp::PORT`). Packets are `$<payload>#<2-hex checksum>`, each
acknowledged with `+` (or `-` to request a resend) until no-ack mode is
negotiated. Replies may be run-length encoded (`X*<n>` repeats X) and binary
payloads escape `#$}*` as `}` followed by the byte XOR 0x20.

Execution control is the one asynchronous part: `c`/`s` produce no reply
until the target stops, which may be never. `resume()` sends the packet and
returns immediately; `wait_stop()` waits (with a timeout) for the stop reply;
`interrupt()` sends the out-of-band 0x03 byte to force one.
"""

from __future__ import annotations

import socket
import threading
import time


class RSPError(RuntimeError):
    pass


def checksum(payload: bytes) -> int:
    return sum(payload) % 256


def frame(payload: bytes) -> bytes:
    return b"$" + payload + b"#%02x" % checksum(payload)


def unescape(data: bytes) -> bytes:
    """Undo RSP binary escaping and run-length encoding."""
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == 0x7D:  # '}' escape
            i += 1
            if i >= len(data):
                raise RSPError("truncated escape sequence in packet")
            out.append(data[i] ^ 0x20)
        elif b == 0x2A:  # '*' run-length: repeat previous byte (n - 29) more times
            i += 1
            if i >= len(data) or not out:
                raise RSPError("malformed run-length encoding in packet")
            out.extend(out[-1:] * (data[i] - 29))
        else:
            out.append(b)
        i += 1
    return bytes(out)


class RSPClient:
    def __init__(self, host: str, port: int, connect_timeout: float = 10.0,
                 read_timeout: float = 10.0):
        deadline = time.monotonic() + connect_timeout
        last_err: OSError | None = None
        self.sock: socket.socket | None = None
        while time.monotonic() < deadline:
            try:
                self.sock = socket.create_connection((host, port), timeout=5)
                break
            except OSError as e:
                last_err = e
                time.sleep(0.2)
        if self.sock is None:
            raise RSPError(f"could not connect to gdbstub on {host}:{port}: {last_err}")
        self.read_timeout = read_timeout
        self._buf = b""
        self._lock = threading.Lock()
        self.no_ack = False
        self.running = False
        self.features: dict[str, str] = {}
        self._handshake()

    # -- framing -----------------------------------------------------------

    def _recv_more(self, timeout: float) -> None:
        if self.sock is None:
            raise RSPError("gdbstub connection is closed")
        self.sock.settimeout(timeout)
        try:
            chunk = self.sock.recv(65536)
        except TimeoutError:
            raise
        except OSError as e:
            raise RSPError(f"gdbstub connection error: {e}") from None
        if not chunk:
            raise RSPError("gdbstub connection closed by the target")
        self._buf += chunk

    def _read_packet(self, timeout: float) -> bytes:
        """Read one packet, ack it, and return its decoded payload.

        Raises TimeoutError (not RSPError) if nothing complete arrives in
        `timeout` seconds, so callers waiting on a running target can tell
        "still running" apart from a broken connection.
        """
        deadline = time.monotonic() + timeout
        while True:
            start = self._buf.find(b"$")
            if start >= 0:
                end = self._buf.find(b"#", start)
                if end >= 0 and len(self._buf) >= end + 3:
                    payload = self._buf[start + 1:end]
                    sent_sum = self._buf[end + 1:end + 3]
                    self._buf = self._buf[end + 3:]
                    if not self.no_ack:
                        if int(sent_sum, 16) != checksum(payload):
                            self._send_raw(b"-")
                            continue
                        self._send_raw(b"+")
                    return unescape(payload)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            self._recv_more(remaining)

    def _send_raw(self, data: bytes) -> None:
        if self.sock is None:
            raise RSPError("gdbstub connection is closed")
        try:
            self.sock.sendall(data)
        except OSError as e:
            raise RSPError(f"gdbstub connection error: {e}") from None

    def _send_packet(self, payload: bytes) -> None:
        packet = frame(payload)
        for _ in range(5):
            self._send_raw(packet)
            if self.no_ack:
                return
            ack = self._read_ack()
            if ack == b"+":
                return
        raise RSPError(f"gdbstub kept rejecting packet {payload[:40]!r}")

    def _read_ack(self) -> bytes:
        deadline = time.monotonic() + self.read_timeout
        while True:
            # Skip anything before the ack; a stray stop reply cannot arrive
            # here because we only send while the target is halted.
            if self._buf:
                ch, self._buf = self._buf[:1], self._buf[1:]
                if ch in (b"+", b"-"):
                    return ch
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RSPError("gdbstub did not acknowledge a packet - target unresponsive")
            try:
                self._recv_more(remaining)
            except TimeoutError:
                raise RSPError("gdbstub did not acknowledge a packet - target unresponsive") from None

    def request(self, payload: str | bytes) -> bytes:
        """Send a packet and return the reply payload. Target must be halted."""
        data = payload.encode() if isinstance(payload, str) else payload
        with self._lock:
            if self.running:
                raise RSPError("target is running - interrupt it or wait for it to stop first")
            self._send_packet(data)
            try:
                reply = self._read_packet(self.read_timeout)
            except TimeoutError:
                raise RSPError(
                    f"gdbstub did not reply to {data[:40]!r} within {self.read_timeout}s"
                ) from None
        if reply.startswith(b"E") and len(reply) == 3:
            raise RSPError(f"gdbstub returned error {reply.decode()} for {data[:40]!r}")
        return reply

    # -- session -----------------------------------------------------------

    def _handshake(self) -> None:
        reply = self.request("qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386")
        for item in reply.decode(errors="replace").split(";"):
            if "=" in item:
                k, v = item.split("=", 1)
                self.features[k] = v
            elif item.endswith(("+", "-")):
                self.features[item[:-1]] = item[-1]
        if self.features.get("QStartNoAckMode") == "+":
            if self.request("QStartNoAckMode") == b"OK":
                self.no_ack = True

    def read_xfer(self, obj: str, annex: str) -> str:
        """Read a whole qXfer object (e.g. features/target.xml) in chunks."""
        out = bytearray()
        chunk = 0xFFF
        while True:
            reply = self.request(f"qXfer:{obj}:read:{annex}:{len(out):x},{chunk:x}")
            if not reply or reply[:1] not in (b"m", b"l"):
                raise RSPError(f"unexpected qXfer reply for {annex}: {reply[:40]!r}")
            out.extend(reply[1:])
            if reply[:1] == b"l":
                return out.decode()

    def stop_reason(self) -> bytes:
        return self.request("?")

    def read_registers(self) -> bytes:
        return bytes.fromhex(self.request("g").decode())

    def read_register(self, regnum: int) -> bytes:
        return bytes.fromhex(self.request(f"p{regnum:x}").decode())

    def write_register(self, regnum: int, value: bytes) -> None:
        reply = self.request(f"P{regnum:x}={value.hex()}")
        if reply != b"OK":
            raise RSPError(f"writing register {regnum} failed: {reply!r}")

    def read_memory(self, address: int, length: int) -> bytes:
        out = bytearray()
        max_chunk = 0x800
        while len(out) < length:
            n = min(max_chunk, length - len(out))
            reply = self.request(f"m{address + len(out):x},{n:x}")
            if not reply:
                raise RSPError(f"no memory readable at {address + len(out):#x}")
            out.extend(bytes.fromhex(reply.decode()))
        return bytes(out)

    def write_memory(self, address: int, data: bytes) -> None:
        reply = self.request(f"M{address:x},{len(data):x}:{data.hex()}")
        if reply != b"OK":
            raise RSPError(f"writing memory at {address:#x} failed: {reply!r}")

    def set_breakpoint(self, kind: int, address: int, length: int) -> None:
        """kind: 0 software, 1 hardware, 2 write watch, 3 read watch, 4 access watch."""
        reply = self.request(f"Z{kind},{address:x},{length:x}")
        if reply == b"":
            raise RSPError(f"gdbstub does not support breakpoint/watchpoint type Z{kind}")
        if reply != b"OK":
            raise RSPError(f"setting Z{kind} at {address:#x} failed: {reply!r}")

    def clear_breakpoint(self, kind: int, address: int, length: int) -> None:
        reply = self.request(f"z{kind},{address:x},{length:x}")
        if reply != b"OK":
            raise RSPError(f"clearing z{kind} at {address:#x} failed: {reply!r}")

    # -- execution control -------------------------------------------------

    def resume(self, step: bool = False) -> None:
        with self._lock:
            if self.running:
                raise RSPError("target is already running")
            self._send_packet(b"s" if step else b"c")
            self.running = True

    def wait_stop(self, timeout: float) -> bytes | None:
        """Wait for the stop reply after resume(). None means still running."""
        with self._lock:
            if not self.running:
                raise RSPError("target is not running")
            try:
                reply = self._read_packet(timeout)
            except TimeoutError:
                return None
            self.running = False
            return reply

    def interrupt(self, timeout: float = 5.0) -> bytes:
        with self._lock:
            if not self.running:
                raise RSPError("target is not running")
            self._send_raw(b"\x03")
            try:
                reply = self._read_packet(timeout)
            except TimeoutError:
                raise RSPError("target did not stop after interrupt") from None
            self.running = False
            return reply

    def close(self) -> None:
        if self.sock is not None:
            try:
                if not self.running:
                    # Detach so QEMU lets the guest keep running; best-effort.
                    self.sock.settimeout(1.0)
                    self.sock.sendall(frame(b"D"))
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
