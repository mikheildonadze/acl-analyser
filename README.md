# Abstract

Access control lists (ACLs) remain the dominant packet-filtering mechanism in enterprise networks, yet their first-match, top-down evaluation semantics makes them structurally prone to logical anomalies that no router reports at configuration time. This paper presents a set-theoretic model of Cisco IOS extended ACLs together with a lightweight, dependency-free static analyser that detects shadowing and redundancy anomalies directly from unmodified show access-lists output. Each rule is treated as a hyperrectangle in the five-dimensional packet header space, and anomaly classification is reduced to a pairwise containment test combined with an action comparison. Ground truth is computed exactly, by subtracting all preceding rules from each rule's match set, rather than taken from the author's intent. On a 15-rule policy deployed on a three-zone Cisco Packet Tracer topology, the analyser finds all nine unreachable rules, whereas a baseline that ignores transport-layer ports reports three spurious rule pairs, one of which would delete a live SSH rule. On a benchmark of 600 synthetic policies of 50 to 2000 rules containing 54 933 unreachable rules, the port-aware analyser attains a precision of 1.00 at every size, against 0.59 for the port-agnostic projection; its recall of 0.93 measures the rules that are unreachable only through a union of predecessors. A 2000-rule policy is analysed in about 1.1 s. We position the analyser against Batfish, header space analysis and VeriFlow: it trades completeness for zero dependencies and direct auditability of device output. Correlation and generalisation anomalies are outside the present scope.


# ACL anomaly analyser - reproducibility package

Python 3 standard library only (matplotlib only for fig5.py).

| File | Purpose |
|---|---|
| acl_analyser.py | Analyser (Algorithm 1) + exact oracle. `python3 acl_analyser.py tableII.txt --mode 5 --exact --csv report.csv` (`--mode 3` = port-agnostic baseline) |
| tableII.txt | Test policy of Table II (`show access-lists` text) |
| bench.py | Synthetic benchmark (Table IV): `python3 bench.py 50,100,250,500,1000,2000 100 2026` |
| sens.py | Sensitivity study (n = 500, 50 policies per setting) |
| fig5.py | Fig. 5: `python3 fig5.py results_2026.json fig5.png` |
| results_2026.json, sensitivity_results.jsonl | Raw outputs used in the paper |

Runtimes in the paper: Intel Xeon 2.8 GHz, one core, Python 3.13. Full benchmark takes about 30 minutes (dominated by the exact oracle).
