#!/usr/bin/env python3
"""Sensitivity of precision/recall to service-split and union-only rates (n = 500)."""
import json
import random
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from bench import make_policy  # noqa: E402
from acl_analyser import detect, unreachable_exact  # noqa: E402

N, PER = 500, 50
for split in (0.0, 0.05, 0.10, 0.20):
    for union in (0.0, 0.02, 0.05):
        a = {3: [0, 0, 0], 5: [0, 0, 0]}
        for p in range(PER):
            rng = random.Random(777 * 100003 + p * 31 + int(split * 1000) * 7 + int(union * 1000))
            pol = make_policy(N, rng, split=split, union=union)
            truth = unreachable_exact(pol)
            for m in (3, 5):
                f = {c for _, c, _ in detect(pol, m)}
                a[m][0] += len(f & truth); a[m][1] += len(f - truth); a[m][2] += len(truth - f)
        row = {"split": split, "union": union}
        for m in (3, 5):
            tp, fp, fn = a[m]
            row[f"P{m}"] = round(tp / (tp + fp), 3) if tp + fp else 1.0
            row[f"R{m}"] = round(tp / (tp + fn), 3) if tp + fn else 1.0
        print(json.dumps(row), flush=True)
