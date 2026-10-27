#!/usr/bin/env python3
"""Set-theoretic ACL anomaly analyser (Cisco IOS extended ACLs).

Reads unmodified `show access-lists` output and reports pairwise
shadowing / redundancy anomalies.  Standard library only.

Modes:
  --mode 5  : full five-tuple containment (protocol, src, sport, dst, dport)
  --mode 3  : baseline projection onto (protocol, src, dst); ports ignored
  --exact   : also compute exact unreachability (E_j == empty) by
              hyper-rectangle subtraction, for evaluation only.
"""
import argparse
import csv
import ipaddress
import re
import sys

FULL_PORT = (0, 65535)
PROTO = {"ip": (0, 255), "icmp": (1, 1), "tcp": (6, 6), "udp": (17, 17),
         "gre": (47, 47), "esp": (50, 50), "ospf": (89, 89)}
PORTNAMES = {"www": 80, "http": 80, "domain": 53, "ftp": 21, "ftp-data": 20,
             "ssh": 22, "telnet": 23, "smtp": 25, "pop3": 110, "bootps": 67,
             "bootpc": 68, "tftp": 69, "ntp": 123, "snmp": 161, "syslog": 514,
             "isakmp": 500, "https": 443}


class Unsupported(Exception):
    pass


class Rule:
    __slots__ = ("seq", "action", "text", "box", "acl")

    def __init__(self, seq, action, text, box, acl=""):
        self.seq, self.action, self.text, self.box, self.acl = seq, action, text, box, acl

    def __repr__(self):
        return f"Rule({self.seq} {self.action} {self.box})"


def wildcard_to_interval(addr, wildcard):
    """Convert address + Cisco wildcard to an integer interval.

    The subnet mask is the bitwise NOT of the wildcard (32-bit).  Only
    contiguous wildcards (i.e. masks that are valid prefixes) are supported.
    """
    a = int(ipaddress.IPv4Address(addr))
    w = int(ipaddress.IPv4Address(wildcard))
    if (w + 1) & w:  # w+1 must be a power of two for a contiguous wildcard
        raise Unsupported(f"non-contiguous wildcard {wildcard}")
    mask = (~w) & 0xFFFFFFFF
    net = a & mask
    return (net, net | w)


def parse_addr(tok, i):
    if tok[i] == "any":
        return (0, 0xFFFFFFFF), i + 1
    if tok[i] == "host":
        a = int(ipaddress.IPv4Address(tok[i + 1]))
        return (a, a), i + 2
    return wildcard_to_interval(tok[i], tok[i + 1]), i + 2


def port_val(t):
    if t.isdigit():
        return int(t)
    if t in PORTNAMES:
        return PORTNAMES[t]
    raise Unsupported(f"unknown port name {t}")


def parse_port(tok, i):
    if i >= len(tok):
        return FULL_PORT, i
    op = tok[i]
    if op == "eq":
        p = port_val(tok[i + 1]); return (p, p), i + 2
    if op == "range":
        return (port_val(tok[i + 1]), port_val(tok[i + 2])), i + 3
    if op == "gt":
        return (port_val(tok[i + 1]) + 1, 65535), i + 2
    if op == "lt":
        return (0, port_val(tok[i + 1]) - 1), i + 2
    if op == "neq":
        raise Unsupported("neq (non-interval port set)")
    return FULL_PORT, i


LINE = re.compile(r"^\s*(\d+)\s+(permit|deny)\s+(.*?)\s*(\(\d+ match\(es\)\))?\s*$")


def parse_rule(line, acl=""):
    m = LINE.match(line)
    if not m:
        return None
    seq, action, body = int(m.group(1)), m.group(2), m.group(3)
    tok = body.split()
    proto = tok[0]
    if proto not in PROTO:
        if proto.isdigit():
            p = int(proto); pr = (p, p)
        else:
            raise Unsupported(f"protocol {proto}")
    else:
        pr = PROTO[proto]
    i = 1
    src, i = parse_addr(tok, i)
    sp = FULL_PORT
    if proto in ("tcp", "udp"):
        sp, i = parse_port(tok, i)
    dst, i = parse_addr(tok, i)
    dp = FULL_PORT
    if proto in ("tcp", "udp"):
        dp, i = parse_port(tok, i)
    rest = tok[i:]
    if any(t in ("established", "log", "log-input") for t in rest):
        rest = [t for t in rest if t not in ("established", "log", "log-input")]
    if rest:
        raise Unsupported("unhandled tokens: " + " ".join(rest))
    return Rule(seq, action, line.strip(), (pr, src, sp, dst, dp), acl)


def parse_show_access_lists(text):
    """Return {acl_name: [Rule, ...]} and a list of skipped lines."""
    acls, skipped, cur = {}, [], None
    for line in text.splitlines():
        h = re.match(r"^\s*(Extended|Standard) IP access list (\S+)", line)
        if h:
            cur = h.group(2); acls[cur] = []; continue
        if cur is None or not line.strip():
            continue
        try:
            r = parse_rule(line, cur)
            if r:
                acls[cur].append(r)
        except (Unsupported, ValueError, IndexError) as e:
            skipped.append((cur, line.strip(), str(e)))
    return acls, skipped


# ---------- containment -------------------------------------------------
def inside(a, b):
    return b[0] <= a[0] and a[1] <= b[1]


def contains(outer, inner, mode=5):
    dims = (0, 1, 2, 3, 4) if mode == 5 else (0, 1, 3)
    return all(inside(inner[d], outer[d]) for d in dims)


def detect(rules, mode=5):
    """Algorithm 1: pairwise containment + action comparison."""
    out = []
    n = len(rules)
    for i in range(n - 1):
        ri = rules[i]
        for j in range(i + 1, n):
            rj = rules[j]
            if contains(ri.box, rj.box, mode):
                kind = "Shadowing" if ri.action != rj.action else "Redundancy"
                out.append((kind, rj.seq, ri.seq))
    return out


# ---------- exact unreachability (evaluation only) ----------------------
def intersects(a, b):
    return all(a[d][0] <= b[d][1] and b[d][0] <= a[d][1] for d in range(5))


def subtract(a, b):
    """a minus b as a list of disjoint boxes."""
    if not intersects(a, b):
        return [a]
    res, cur = [], list(a)
    for d in range(5):
        lo, hi = cur[d]
        blo, bhi = b[d]
        if lo < blo:
            piece = list(cur); piece[d] = (lo, blo - 1); res.append(tuple(piece))
            lo = blo
        if bhi < hi:
            piece = list(cur); piece[d] = (bhi + 1, hi); res.append(tuple(piece))
            hi = bhi
        cur[d] = (lo, hi)
    return res


def unreachable_exact(rules, cap=200000):
    """Return set of seq numbers whose effective set E_j is empty."""
    dead = set()
    for j, rj in enumerate(rules):
        residual = [rj.box]
        for i in range(j):
            bi = rules[i].box
            nxt = []
            for r in residual:
                nxt.extend(subtract(r, bi))
            residual = nxt
            if not residual:
                break
            if len(residual) > cap:
                raise RuntimeError("residual explosion")
        if not residual:
            dead.add(rj.seq)
    return dead


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="file with `show access-lists` output ('-' = stdin)")
    ap.add_argument("--mode", type=int, choices=(3, 5), default=5)
    ap.add_argument("--csv", help="write report to CSV")
    ap.add_argument("--exact", action="store_true", help="also list exactly unreachable rules")
    a = ap.parse_args()
    text = sys.stdin.read() if a.input == "-" else open(a.input).read()
    acls, skipped = parse_show_access_lists(text)
    rows = []
    for name, rules in acls.items():
        byseq = {r.seq: r for r in rules}
        for kind, cov, by in detect(rules, a.mode):
            desc = (f"rule {cov} is unreachable: fully covered by rule {by} with "
                    f"{'the opposite' if kind == 'Shadowing' else 'the same'} action")
            rows.append([name, kind, cov, by, desc, byseq[cov].text, byseq[by].text])
        if a.exact:
            print(f"[{name}] exactly unreachable: {sorted(unreachable_exact(rules))}")
    for r in rows:
        print(f"[{r[0]}] {r[1]}: {r[2]} covered by {r[3]}")
    for s in skipped:
        print(f"[{s[0]}] SKIPPED ({s[2]}): {s[1]}", file=sys.stderr)
    if a.csv:
        with open(a.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["type", "covered_seq", "covering_seq", "description",
                        "covered_rule", "covering_rule"])
            w.writerows([r[1:] for r in rows])


if __name__ == "__main__":
    main()
