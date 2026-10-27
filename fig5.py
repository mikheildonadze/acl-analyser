#!/usr/bin/env python3
"""Fig. 5: mean detection time vs policy size, with an O(n^2) reference anchored at n = 50."""
import json
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

res = json.load(open(sys.argv[1]))
out = sys.argv[2]
ns = sorted(int(k) for k in res)
t = [res[str(n)]["time_ms_mean"] for n in ns]
ref = [t[0] * (n / ns[0]) ** 2 for n in ns]

plt.rcParams.update({"font.family": "DejaVu Serif", "font.size": 11})
fig, ax = plt.subplots(figsize=(6.9, 4.9), dpi=300)
ax.loglog(ns, t, "-o", color="#1f3864", lw=2, ms=8, label="measured runtime")
ax.loglog(ns, ref, "--", color="#a33a3a", lw=1.8, label=r"$O(n^2)$ reference")
ax.set_xlabel(r"number of ACL rules $n$")
ax.set_ylabel("detection time (ms)")
ax.grid(True, which="both", ls=":", lw=0.6, color="#bbbbbb")
ax.legend(frameon=False, loc="upper left")
fig.tight_layout()
fig.savefig(out)
