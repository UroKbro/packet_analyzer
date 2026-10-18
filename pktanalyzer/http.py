"""HTTP/1.x dissection: a per-packet header parser and a stream parser.

The per-packet parser looks at one TCP segment. The stream parser is fed the
reassembled byte stream of a connection and cuts it into complete messages using
Content-Length or chunked transfer encoding, the same way a real client does.
"""
from __future__ import annotations

from .packet import printable

METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE")


def looks_like_http(data: bytes) -> bool:
    if data.startswith(b"HTTP/1."):
        return True
    sp = data.find(b" ", 0, 10)
    return sp > 0 and data[:sp] in METHODS


def _parse_header_block(block: bytes) -> dict | None:
    lines = block.split(b"\r\n")
    first = printable(lines[0].decode("latin-1"))
    parts = first.split(" ", 2)
    msg: dict = {}
    if first.startswith("HTTP/"):
        if len(parts) < 2 or not parts[1].isdigit():
            return None
        msg.update(type="response", version=parts[0], status=int(parts[1]),
                   reason=parts[2] if len(parts) > 2 else "")
    else:
        if len(parts) != 3 or not parts[2].startswith("HTTP/"):
            return None
        msg.update(type="request", method=parts[0], uri=parts[1], version=parts[2])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            key = printable(k.decode("latin-1").strip().lower())
            val = printable(v.decode("latin-1").strip())
            headers[key] = f"{headers[key]}, {val}" if key in headers else val
    msg["headers"] = headers
    for name, key in (("host", "host"), ("user-agent", "user_agent"), ("content-type", "content_type"),
                      ("server", "server"), ("location", "location"), ("authorization", "authorization")):
        if name in headers:
            msg[key] = headers[name]
    if "content-length" in headers and headers["content-length"].isdigit():
        msg["content_length"] = int(headers["content-length"])
    msg["first_line"] = first
    return msg


def parse_head(data: bytes) -> dict | None:
    """Parse the start line and headers at the front of one segment, if it is HTTP."""
    if not looks_like_http(data):
        return None
    end = data.find(b"\r\n\r\n")
    head_len = end + 4 if end >= 0 else len(data)
    msg = _parse_header_block(data[:end if end >= 0 else len(data)])
    if msg is None:
        return None
    msg["_head_len"] = head_len
    msg["complete_head"] = end >= 0
    return msg


def summary(msg: dict) -> str:
    if msg["type"] == "request":
        host = msg.get("host", "")
        return f"{msg['method']} {host}{msg['uri']} {msg['version']}" if host and msg["uri"].startswith("/") \
            else f"{msg['method']} {msg['uri']} {msg['version']}"
    return f"{msg['version']} {msg['status']} {msg['reason']}"


class HttpStreamParser:
    """Incrementally splits one direction of a TCP stream into HTTP messages."""

    MAX_BODY = 4 * 1024 * 1024

    def __init__(self):
        self.buf = bytearray()
        self.messages: list[dict] = []
        self.dead = False  # stream turned out not to be HTTP
        self._head: dict | None = None
        self._body = bytearray()
        self._mode: str | None = None  # "length", "chunked", "close"
        self._remaining = 0
        self.request_methods: list[str] = []  # set by the flow for HEAD responses

    def feed(self, data: bytes, ts: float) -> list[dict]:
        if self.dead:
            return []
        self.buf += data
        done: list[dict] = []
        while True:
            if self._head is None:
                if not self.buf:
                    break
                if not looks_like_http(bytes(self.buf[:16])):
                    if len(self.buf) >= 8:
                        self.dead = True  # not HTTP (or we joined mid-body); stop parsing
                    break
                end = self.buf.find(b"\r\n\r\n")
                if end < 0:
                    if len(self.buf) > 64 * 1024:
                        self.dead = True
                    break
                head = _parse_header_block(bytes(self.buf[:end]))
                del self.buf[:end + 4]
                if head is None:
                    self.dead = True
                    break
                head["ts"] = ts
                self._head = head
                self._body = bytearray()
                self._choose_body_mode(head)
            if not self._consume_body():
                break
            done.append(self._finish())
        return done

    def _choose_body_mode(self, head: dict) -> None:
        te = head["headers"].get("transfer-encoding", "").lower()
        if head["type"] == "response":
            method = self.request_methods.pop(0) if self.request_methods else ""
            if method == "HEAD" or head["status"] in (204, 304) or 100 <= head["status"] < 200:
                self._mode, self._remaining = "length", 0
                return
        if "chunked" in te:
            self._mode, self._remaining = "chunked", -1
        elif "content_length" in head:
            self._mode, self._remaining = "length", head["content_length"]
        elif head["type"] == "request":
            self._mode, self._remaining = "length", 0
        else:
            self._mode = "close"  # body runs until the server closes the connection

    def _consume_body(self) -> bool:
        if self._mode == "length":
            take = min(self._remaining, len(self.buf))
            self._append(self.buf[:take])
            del self.buf[:take]
            self._remaining -= take
            return self._remaining == 0
        if self._mode == "chunked":
            while True:
                if self._remaining > 0:
                    take = min(self._remaining, len(self.buf))
                    self._append(self.buf[:take])
                    del self.buf[:take]
                    self._remaining -= take
                    if self._remaining:
                        return False
                    self._remaining = -2  # expect CRLF after chunk data
                if self._remaining == -2:
                    if len(self.buf) < 2:
                        return False
                    del self.buf[:2]
                    self._remaining = -1
                line_end = self.buf.find(b"\r\n")
                if line_end < 0:
                    return False
                size_txt = bytes(self.buf[:line_end]).split(b";")[0].strip()
                try:
                    size = int(size_txt, 16)
                except ValueError:
                    self.dead = True
                    return False
                if size == 0:
                    rest = line_end + 2
                    if self.buf[rest:rest + 2] == b"\r\n":
                        del self.buf[:rest + 2]
                        return True
                    trailer_end = self.buf.find(b"\r\n\r\n", rest)
                    if trailer_end < 0:
                        return False
                    del self.buf[:trailer_end + 4]
                    return True
                del self.buf[:line_end + 2]
                self._remaining = size
        # "close" mode: everything is body until close()
        self._append(self.buf)
        self.buf.clear()
        return False

    def _append(self, chunk) -> None:
        room = self.MAX_BODY - len(self._body)
        if room > 0:
            self._body += chunk[:room]

    def _finish(self) -> dict:
        msg = self._head
        msg["body"] = bytes(self._body)
        msg["body_len"] = len(self._body)
        self._head = None
        self.messages.append(msg)
        return msg

    def close(self) -> list[dict]:
        """The connection closed: a response delimited by close is now complete."""
        if self._head is not None and self._mode == "close":
            return [self._finish()]
        return []
