"""A small protocol-aware display filter language.

It mixes Wireshark-style field comparisons with tcpdump-style shorthands::

    tcp and port 443
    ip.src == 10.0.0.5 && tcp.flags.syn
    dns.qname contains "google" or http.method == POST
    not arp and host 192.168.1.1
    net 10.0.0.0/8 and frame.len > 1000
    tcp.dport in {22 80 443}
    http.host matches "^api\\."

The text is tokenised, parsed by recursive descent into a tree of closures, and
the resulting predicate is called once per decoded packet.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable

from .packet import Packet

Predicate = Callable[[Packet], bool]


class FilterError(Exception):
    pass


TOKEN_RE = re.compile(r"""
    \s*(?:
      (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
    | (?P<op>==|!=|>=|<=|&&|\|\||[<>!(){}~=])
    | (?P<word>[A-Za-z0-9_.:/\-*]+)
    )""", re.VERBOSE)

KEYWORD_OPS = {"eq": "==", "ne": "!=", "gt": ">", "lt": "<", "ge": ">=", "le": "<=",
               "contains": "contains", "matches": "matches", "in": "in"}
COMPARE_OPS = {"==", "!=", ">", "<", ">=", "<=", "contains", "matches", "~", "=", "in"}
PROTOCOLS = {"eth", "ethernet", "vlan", "arp", "ip", "ipv4", "ipv6", "icmp", "icmpv6", "igmp", "tcp", "udp",
             "dns", "mdns", "http", "tls", "dhcp", "sll"}


def tokenize(text: str) -> list[tuple[str, str]]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise FilterError(f"unexpected character at position {pos}: {text[pos:pos + 10]!r}")
        pos = m.end()
        for kind in ("str", "op", "word"):
            if m.group(kind) is not None:
                val = m.group(kind)
                if kind == "str":
                    val = bytes(val[1:-1], "utf-8").decode("unicode_escape")
                tokens.append((kind, val))
                break
    return tokens


class _Parser:
    def __init__(self, tokens: list[tuple[str, str]]):
        self.toks = tokens
        self.i = 0

    def peek(self, offset: int = 0) -> tuple[str, str] | None:
        j = self.i + offset
        return self.toks[j] if j < len(self.toks) else None

    def next(self) -> tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise FilterError("unexpected end of filter")
        self.i += 1
        return tok

    def accept(self, *values: str) -> bool:
        tok = self.peek()
        if tok and tok[0] != "str" and tok[1].lower() in values:
            self.i += 1
            return True
        return False

    # expr := and_expr ('or' and_expr)*
    def expr(self) -> Predicate:
        left = self.and_expr()
        while self.accept("or", "||"):
            right = self.and_expr()
            left = (lambda a, b: lambda p: a(p) or b(p))(left, right)
        return left

    def and_expr(self) -> Predicate:
        left = self.not_expr()
        while True:
            if self.accept("and", "&&"):
                pass
            elif self._starts_term():
                pass  # tcpdump allows juxtaposition only after 'and'; we accept it too
            else:
                return left
            right = self.not_expr()
            left = (lambda a, b: lambda p: a(p) and b(p))(left, right)

    def _starts_term(self) -> bool:
        tok = self.peek()
        if tok is None:
            return False
        return tok[1] in ("(", "!") or (tok[0] == "word" and tok[1].lower() not in ("or", "and", ")"))

    def not_expr(self) -> Predicate:
        if self.accept("not", "!"):
            inner = self.not_expr()
            return lambda p: not inner(p)
        return self.atom()

    def atom(self) -> Predicate:
        tok = self.next()
        if tok[1] == "(":
            inner = self.expr()
            if not self.accept(")"):
                raise FilterError("missing ')'")
            return inner
        if tok[0] != "word":
            raise FilterError(f"unexpected {tok[1]!r}")
        word = tok[1].lower()
        # tcpdump shorthands: [src|dst] host X, [src|dst] port N, [src|dst] net CIDR, portrange
        direction = None
        if word in ("src", "dst") and self.peek() and self.peek()[1].lower() in ("host", "port", "net", "portrange"):
            direction, word = word, self.next()[1].lower()
        if word == "host":
            return _host_pred(self._value(), direction)
        if word == "port":
            return _port_pred(_to_int(self._value()), direction)
        if word == "portrange":
            lo, _, hi = self._value().partition("-")
            r = range(_to_int(lo), _to_int(hi) + 1)
            return _ports_in(r, direction)
        if word == "net":
            net = _network(self._value())
            return _host_pred(net, direction)
        if word in ("syn", "fin", "rst", "ack", "psh", "urg"):
            return lambda p, f="flags." + word: any(p.values("tcp." + f))
        if word in ("alerts", "alert"):
            return lambda p: bool(p.alerts)
        if word in ("warnings", "malformed"):
            return lambda p: bool(p.warnings)
        if word == "flow" and self.peek() and self.peek()[0] == "word" and self.peek()[1].isdigit():
            fid = int(self.next()[1])
            return lambda p: p.flow_id == fid
        field = tok[1]
        nxt = self.peek()
        if nxt and (nxt[1] in COMPARE_OPS or (nxt[0] == "word" and nxt[1].lower() in KEYWORD_OPS)):
            op = self.next()[1]
            op = KEYWORD_OPS.get(op.lower(), op)
            if op == "in":
                return self._in_set(field)
            value = self._value()
            return _compare(field, op, value)
        # bare protocol name or field: true if present and truthy
        if "." not in field and field.lower() not in PROTOCOLS:
            raise FilterError(f"unknown protocol or keyword {field!r}")
        return lambda p, f=field.lower(): any(v not in (False, None, 0, "") for v in p.values(f))

    def _in_set(self, field: str) -> Predicate:
        if not self.accept("{"):
            raise FilterError("expected '{' after 'in'")
        items = []
        while not self.accept("}"):
            items.append(_coerce(self._value()))
        values = set(items)
        return lambda p: any(v in values for v in p.values(field.lower()))

    def _value(self) -> str:
        tok = self.next()
        if tok[0] == "op" and tok[1] not in ("*",):
            raise FilterError(f"expected a value, got {tok[1]!r}")
        return tok[1]


def _to_int(v: str) -> int:
    try:
        return int(v, 0)
    except ValueError:
        raise FilterError(f"expected a number, got {v!r}") from None


def _network(v: str):
    try:
        return ipaddress.ip_network(v, strict=False)
    except ValueError:
        raise FilterError(f"bad network {v!r}") from None


def _addr_fields(direction: str | None) -> tuple[str, ...]:
    return {"src": ("src",), "dst": ("dst",)}.get(direction, ("src", "dst"))


def _host_pred(target, direction: str | None) -> Predicate:
    if isinstance(target, str):
        try:
            target = ipaddress.ip_address(target)
        except ValueError:
            raise FilterError(f"bad host address {target!r}") from None
    fields = _addr_fields(direction)

    def pred(p: Packet) -> bool:
        ip = p.ip or None
        if ip is None:
            arp = p.layer("arp")
            addrs = [arp.get("sender_ip"), arp.get("target_ip")] if arp else []
            addrs = addrs[:1] if direction == "src" else addrs[1:] if direction == "dst" else addrs
        else:
            addrs = [ip[f] for f in fields]
        for a in addrs:
            try:
                ia = ipaddress.ip_address(a)
            except (ValueError, TypeError):
                continue
            if ia == target if not hasattr(target, "num_addresses") else ia in target:
                return True
        return False
    return pred


def _port_pred(port: int, direction: str | None) -> Predicate:
    return _ports_in({port}, direction)


def _ports_in(ports, direction: str | None) -> Predicate:
    def pred(p: Packet) -> bool:
        if direction != "dst" and p.sport in ports:
            return True
        return direction != "src" and p.dport in ports
    return pred


def _coerce(v: str) -> Any:
    low = v.lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return int(v, 0)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        return v


def _compare(field: str, op: str, raw: str) -> Predicate:
    field = field.lower()
    value = _coerce(raw)
    # IP comparisons accept CIDR: ip.src == 10.0.0.0/8
    net = None
    if isinstance(value, str) and "/" in value and op in ("==", "=", "!="):
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            net = None
    regex = None
    if op in ("matches", "~"):
        try:
            regex = re.compile(raw, re.IGNORECASE)
        except re.error as e:
            raise FilterError(f"bad regex {raw!r}: {e}") from None

    def match_one(v: Any) -> bool:
        if v is None:
            return False
        if net is not None:
            try:
                return ipaddress.ip_address(v) in net
            except ValueError:
                return False
        if op in ("==", "="):
            return _eq(v, value)
        if op == "!=":
            return not _eq(v, value)
        if op == "contains":
            if isinstance(v, (list, tuple)):
                return any(str(raw).lower() in str(x).lower() for x in v)
            return str(raw).lower() in str(v).lower()
        if regex is not None:
            return regex.search(str(v)) is not None
        try:
            if op == ">":
                return v > value
            if op == "<":
                return v < value
            if op == ">=":
                return v >= value
            if op == "<=":
                return v <= value
        except TypeError:
            return False
        return False

    if op == "!=":
        # "field != x" holds when the field exists and none of its values equal x
        return lambda p: bool(vals := p.values(field)) and all(match_one(v) for v in vals)
    return lambda p: any(match_one(v) for v in p.values(field))


def _eq(v: Any, value: Any) -> bool:
    if isinstance(v, bool) or isinstance(value, bool):
        return bool(v) == bool(value) if isinstance(value, bool) else v == value
    if isinstance(v, str) and isinstance(value, str):
        return v.lower() == value.lower()
    if isinstance(v, (int, float)) and isinstance(value, (int, float)):
        return v == value
    return str(v).lower() == str(value).lower()


def compile_filter(text: str | None) -> Predicate:
    """Compile filter text to a predicate; empty text matches everything."""
    if not text or not text.strip():
        return lambda p: True
    parser = _Parser(tokenize(text))
    pred = parser.expr()
    if parser.peek() is not None:
        raise FilterError(f"unexpected {parser.peek()[1]!r} after end of expression")
    return pred
