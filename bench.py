#!/usr/bin/env python3
"""Synthetic benchmark for the ACL anomaly analyser.

For each policy size n, POLICIES random policies are generated.  A fraction of
rules is injected with known structure:
  * dominated rules  (narrowed copy of an earlier rule; same or opposite action)
  * service splits   (same protocol/src/dst as an earlier rule, disjoint port)
  * union-only dead  (rule covered only by the union of >=2 earlier rules)
Ground truth is NOT taken from the injection log: it is the exact set of
unreachable rules (E_j == empty), computed by hyper-rectangle subtraction.
Both analyser variants (3-tuple projection, 5-tuple) are scored against it.
"""
import json
import random
import statistics
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from acl_analyser import Rule, detect, unreachable_exact, FULL_PORT  # noqa: E402

PROTOS = [((6, 6), .58), ((17, 17), .27), ((1, 1), .05), ((0, 255), .10)]
WELL_KNOWN = [20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143, 161, 389,
              443, 445, 514, 636, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443]
PLEN = [(0, .03), (8, .01), (16, .06), (24, .40), (32, .50)]


def pick(rng, table):
    x, acc = rng.random(), 0.0
    for v, p in table:
        acc += p
        if x < acc:
            return v
    return table[-1][0]


class Gen:
    def __init__(self, rng):
        self.rng = rng
        # a small address universe so that rules overlap as in real policies
        self.bases = [(10 << 24) | (rng.randrange(0, 256) << 16) for _ in range(6)] + \
                     [(172 << 24) | (rng.randrange(16, 32) << 16) for _ in range(2)] + \
                     [(192 << 24) | (168 << 16)]

    def prefix(self):
        r = self.rng
        plen = pick(r, PLEN)
        if plen == 0:
            return (0, 0xFFFFFFFF)
        base = r.choice(self.bases)
        if plen == 8:
            net = base & 0xFF000000
        else:
            addr = base | (r.randrange(0, 16) << 8) | r.randrange(1, 64)
            mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF
            net = addr & mask
        return (net, net | ((1 << (32 - plen)) - 1))

    def dport(self):
        r = self.rng
        x = r.random()
        if x < .60:
            p = r.choice(WELL_KNOWN); return (p, p)
        if x < .75:
            lo = r.choice(WELL_KNOWN); return (lo, min(65535, lo + r.choice([1, 9, 99])))
        return FULL_PORT

    def sport(self):
        return (1024, 65535) if self.rng.random() < .10 else FULL_PORT

    def rule(self):
        r = self.rng
        pr = pick(r, PROTOS)
        l4 = pr in ((6, 6), (17, 17))
        box = (pr, self.prefix(), self.sport() if l4 else FULL_PORT,
               self.prefix(), self.dport() if l4 else FULL_PORT)
        return box, ("permit" if r.random() < .7 else "deny")


def narrow_iv(rng, iv):
    lo, hi = iv
    if lo == hi or rng.random() < .3:
        return iv
    a = rng.randint(lo, hi)
    b = rng.randint(a, min(hi, a + max(0, (hi - a) // 4)))
    return (a, b)


def narrow_prefix(rng, iv):
    lo, hi = iv
    size = hi - lo + 1
    if size == 1 or rng.random() < .3:
        return iv
    bits = size.bit_length() - 1
    k = rng.randint(1, bits)               # take a sub-prefix k bits longer
    sub = size >> k
    idx = rng.randrange(0, 1 << k)
    return (lo + idx * sub, lo + (idx + 1) * sub - 1)


def make_policy(n, rng, inject=0.08, split=0.05, union=0.02, tail_p=0.9):
    g = Gen(rng)
    rules, tail = [], []
    while len(rules) + len(tail) < n:
        x = rng.random()
        if rules and x < inject:                      # dominated rule
            bi, ai = rng.choice(rules)
            pr = bi[0]
            if pr == (0, 255) and rng.random() < .5:  # protocol inclusion trap
                pr = rng.choice([(6, 6), (17, 17), (1, 1)])
            l4 = pr in ((6, 6), (17, 17))
            box = (pr, narrow_prefix(rng, bi[1]),
                   narrow_iv(rng, bi[2]) if l4 else FULL_PORT,
                   narrow_prefix(rng, bi[3]),
                   narrow_iv(rng, bi[4]) if l4 else FULL_PORT)
            act = ai if rng.random() < .5 else ("deny" if ai == "permit" else "permit")
            rules.append((box, act))
        elif rules and x < inject + split:            # service split (disjoint port)
            cands = [r for r in rules if r[0][0] in ((6, 6), (17, 17)) and r[0][4][0] == r[0][4][1]]
            if not cands:
                continue
            bi, ai = rng.choice(cands)
            p = rng.choice([q for q in WELL_KNOWN if q != bi[4][0]])
            rules.append(((bi[0], bi[1], bi[2], bi[3], (p, p)), ai))
        elif len(rules) + len(tail) + 3 <= n and x < inject + split + union:  # union-only dead rule
            box, act = g.rule()
            lo, hi = box[1]
            if hi == lo:
                continue
            mid = lo + (hi - lo + 1) // 2
            a = (box[0], (lo, mid - 1)) + box[2:]
            b = (box[0], (mid, hi)) + box[2:]
            rules.append((a, act)); rules.append((b, act))
            # covered rule straddles both halves -> no single predecessor contains it
            q = (hi - lo + 1) // 4
            c = (box[0], (lo + q, hi - q)) + box[2:]
            rules.append((c, act if rng.random() < .5 else ("deny" if act == "permit" else "permit")))
        else:
            box, act = g.rule()
            broad = any(b[1] - b[0] >= (1 << 24) - 1 for b in (box[1], box[3])) or box[0] == (0, 255)
            # good practice places broad rules late; most (not all) do so
            if broad and rng.random() < tail_p:
                tail.append((box, act))
            else:
                rules.append((box, act))
    rules = (rules + tail)[:n]
    return [Rule((k + 1) * 10, a, "", b) for k, (b, a) in enumerate(rules)]


def score(flagged, truth):
    tp = len(flagged & truth); fp = len(flagged - truth); fn = len(truth - flagged)
    return tp, fp, fn


def main():
    sizes = [int(s) for s in sys.argv[1].split(",")] if len(sys.argv) > 1 else [50, 100, 250, 500, 1000, 2000]
    per = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 2026
    out = {}
    for n in sizes:
        agg = {3: [0, 0, 0], 5: [0, 0, 0]}
        pairs3_fp = 0; pairs = {3: 0, 5: 0}
        truth_total = 0; union_only = 0; times = []
        for p in range(per):
            rng = random.Random(seed * 100003 + n * 1009 + p)
            pol = make_policy(n, rng)
            truth = unreachable_exact(pol)
            truth_total += len(truth)
            for mode in (3, 5):
                t0 = time.perf_counter()
                res = detect(pol, mode)
                dt = time.perf_counter() - t0
                if mode == 5:
                    times.append(dt * 1000)
                    union_only += len(truth - {c for _, c, _ in res})
                pairs[mode] += len(res)
                flagged = {c for _, c, _ in res}
                for k, v in enumerate(score(flagged, truth)):
                    agg[mode][k] += v
                if mode == 3:
                    # a reported pair is spurious if full 5-tuple containment fails
                    byseq = {r.seq: r for r in pol}
                    from acl_analyser import contains
                    pairs3_fp += sum(1 for _, c, b in res if not contains(byseq[b].box, byseq[c].box, 5))
        row = {"n": n, "policies": per, "unreachable": truth_total,
               "union_only_missed_by_5": union_only,
               "pairs3": pairs[3], "pairs3_spurious": pairs3_fp, "pairs5": pairs[5],
               "time_ms_mean": statistics.mean(times), "time_ms_sd": statistics.pstdev(times)}
        for mode in (3, 5):
            tp, fp, fn = agg[mode]
            row[f"tp{mode}"], row[f"fp{mode}"], row[f"fn{mode}"] = tp, fp, fn
            row[f"P{mode}"] = tp / (tp + fp) if tp + fp else 1.0
            row[f"R{mode}"] = tp / (tp + fn) if tp + fn else 1.0
        out[n] = row
        print(json.dumps(row), flush=True)
    json.dump(out, open(__file__.rsplit("/", 1)[0] + f"/results_{seed}.json", "w"), indent=1)


if __name__ == "__main__":
    main()
