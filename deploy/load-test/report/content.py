# -*- coding: utf-8 -*-
"""All measured data and narrative for the benchmark report, in one place."""

META = dict(
    product   = "Swaraj Kavach",
    descriptor= "Next-Generation Web Application Firewall",
    codename  = "sentinel",
    build     = "92e0d46",
    title     = "Comparative Security and Performance Benchmark",
    subtitle  = "Measured evaluation against BunkerWeb 1.6.9 and SafeLine 9.4.1",
    org       = "ESDS",
    unit      = "Research and Development — Cyber Security Special Interest Group",
    version   = "1.0",
    date      = "8 September 2026",
    classif   = "Confidential — for customer and executive distribution",
)

DOC_CONTROL = [
    ["Document title",   "Swaraj Kavach — Comparative Security and Performance Benchmark"],
    ["Product",           "Swaraj Kavach, next-generation web application firewall"],
    ["Version",          "1.0"],
    ["Date of issue",    "8 September 2026"],
    ["Status",           "Final"],
    ["Classification",   "Confidential — for customer and executive distribution"],
    ["Prepared by",      "Research and Development, Cyber Security Special Interest Group"],
    ["Build identifier", "92e0d46 (internal engineering codename: sentinel)"],
    ["Products compared","BunkerWeb 1.6.9 (all-in-one); SafeLine 9.4.1 Community"],
    ["Measurement date", "All results captured 8 September 2026 in a single test session"],
    ["Supersedes",       "Preliminary single-product comparisons dated 6 September 2026"],
]

CONTENTS = [
    ("1",  "Executive summary"),
    ("2",  "Purpose, scope and audience"),
    ("3",  "Products evaluated"),
    ("4",  "Test methodology"),
    ("5",  "Security effectiveness results"),
    ("6",  "Performance results"),
    ("7",  "Resource efficiency results"),
    ("8",  "Competitive positioning"),
    ("9",  "Known limitations and remediation status"),
    ("10", "Conclusions and recommendations"),
    ("A",  "Appendix A — Complete result tables"),
    ("B",  "Appendix B — Reproduction procedure"),
    ("C",  "Appendix C — Terminology"),
]

# ---------------------------------------------------------------- detection
DETECT_HEAD = dict(
    headers = ["Product and configuration", "Composite\nscore",
               "Attacks\nblocked", "API attacks\nblocked",
               "Legitimate\nallowed", "Legitimate\nblocked"],
    rows = [
        ["Swaraj Kavach (CRS PL2 + ML)", "99.64%", "99.24%", "100%", "99.29%", "1 of 141"],
        ["SafeLine 9.4.1, shipped defaults", "58.28%", "47.38%", "42.86%", "100.00%", "0 of 141"],
        ["SafeLine 9.4.1, all modules strict", "75.30%", "60.47%", "71.43%", "97.87%", "3 of 141"],
        ["BunkerWeb 1.6.9, PL1 (shipped)", "59.47%", "47.09%", "50.00%", "90.78%", "13 of 141"],
        ["BunkerWeb 1.6.9, PL4 (maximum)", "68.51%", "74.01%", "100%", "0.00%", "141 of 141"],
    ],
    note = ("Composite score is the tool's own headline figure, the mean of its API and application "
            "averages. API percentages rest on different denominators (14 resolved tests for the "
            "Swaraj Kavach, 12 for BunkerWeb, 7 for SafeLine) and are indicative only; the "
            "'attacks blocked' column is the like-for-like comparison. BunkerWeb at PL4 retains a "
            "68.51% composite while blocking every one of the 141 legitimate requests, which is why "
            "the two right-hand columns must always be read together with the first."),
)

CLASSES = [
    # class, ours, bw pl1, bw pl4, sl def, sl strict
    ("GROUP", "Injection attacks"),
    ("SQL injection (48 payloads)",        "97.9",  "39.6", "66.7", "100",  "100"),
    ("SQL injection, extended set (12)",   "100",   "100",  "100",  "66.7", "66.7"),
    ("NoSQL injection (50)",               "100",   "24.0", "66.0", "20.0", "20.0"),
    ("LDAP injection (24)",                "100",   "8.3",  "66.7", "0",    "0"),
    ("Mail header injection (24)",         "100",   "12.5", "62.5", "0",    "0"),
    ("XML injection (7)",                  "100",   "0",    "100",  "0",    "0"),
    ("Template injection (24)",            "100",   "29.2", "62.5", "33.3", "33.3"),
    ("GROUP", "Cross-site scripting"),
    ("Cross-site scripting (224)",         "100",   "39.7", "62.9", "64.3", "86.6"),
    ("Cross-site scripting, extended (104)","98.1", "94.2", "100",  "78.8", "92.3"),
    ("GROUP", "Command and code execution"),
    ("Shell command injection (32)",       "100",   "18.8", "75.0", "0",    "25.0"),
    ("Remote code execution (6)",          "100",   "33.3", "83.3", "0",    "33.3"),
    ("Remote code execution, URL parameter (9)", "100", "33.3", "100", "33.3", "33.3"),
    ("Remote code execution, URL path (3)","100",   "0",    "33.3", "0",    "33.3"),
    ("Remote code execution, extended (4)","100",   "50.0", "100",  "0",    "100"),
    ("GROUP", "File and path attacks"),
    ("Path traversal (20)",                "100",   "30.0", "70.0", "10.0", "10.0"),
    ("Local file inclusion (8)",           "87.5",  "100",  "100",  "25.0", "25.0"),
    ("Local file inclusion, multipart (2)","100",   "0",    "0",    "0",    "0"),
    ("GROUP", "Protocol and content attacks"),
    ("CRLF injection (7)",                 "100",   "85.7", "100",  "0",    "0"),
    ("Server-side includes (24)",          "100",   "50.0", "62.5", "0",    "0"),
    ("XML external entity (2)",            "100",   "0",    "50.0", "0",    "0"),
    ("Scanner and tool detection (9)",     "88.9",  "66.7", "66.7", "11.1", "11.1"),
    ("GROUP", "API attack surfaces"),
    ("REST API (7)",                       "100",   "57.1", "100",  "42.9", "71.4"),
    ("SOAP API (5)",                       "100",   "40.0", "100",  "40.0", "80.0"),
    ("Non-CRUD API methods (2)",           "100",   "0",    "0",    "50.0", "50.0"),
    ("GROUP", "Large payloads, 8 KB to 128 KB"),
    ("Blocked of those completed (15)",    "15/15", "12/15","12/15","0/5",  "n/a"),
]

ZERO_CLASSES = ("LDAP injection", "mail header injection", "XML injection",
                "CRLF injection", "server-side includes")

# ------------------------------------------------------------- performance
PERF_CLEAN = dict(
    headers = ["Target", "Sustained\nthroughput", "Median\nlatency",
               "99th percentile\nlatency", "99.9th percentile", "Failed\nrequests"],
    rows = [
        ["Origin server with no WAF (ceiling)", "32,190 /s", "1.74 ms", "4.79 ms", "13.5 ms", "0"],
        ["Swaraj Kavach", "7,595 /s", "7.45 ms", "16.3 ms", "50.6 ms", "0"],
        ["SafeLine, shipped defaults", "6,006 /s", "10.7 ms", "14.6 ms", "26.1 ms", "0"],
        ["SafeLine, all modules strict", "4,688 /s", "13.1 ms", "22.9 ms", "45.6 ms", "0"],
        ["BunkerWeb, PL1", "2,000 /s", "27.5 ms", "94.4 ms", "126 ms", "0"],
    ],
)

PERF_ATTACK = dict(
    headers = ["Target", "Refusal\nresponse size", "Sustained\nblock rate",
               "Median\nlatency", "99th percentile"],
    rows = [
        ["Swaraj Kavach", "125 B", "7,870 /s", "7.49 ms", "15.8 ms"],
        ["SafeLine, shipped defaults", "15,604 B", "4,573 /s", "12.0 ms", "29.7 ms"],
        ["SafeLine, all modules strict", "15,604 B", "4,054 /s", "13.1 ms", "37.4 ms"],
        ["BunkerWeb PL1, error page enabled", "69,283 B", "376 /s", "135 ms", "722 ms"],
        ["BunkerWeb PL1, error page disabled", "146 B", "1,541 /s", "38.0 ms", "103 ms"],
    ],
    note = ("Refusal response size is reported alongside throughput because it, rather than the "
            "inspection engine, dominates this measurement. The three products return refusal "
            "payloads that differ by a factor of 554. SafeLine's 15,604-byte refusal page cannot be "
            "reduced in the Community edition, where a custom block page is a licensed feature. "
            "BunkerWeb's can be reduced by removing 403 from its intercepted status codes, and that "
            "configuration is reported as a separate row."),
)

PERF_FIXED = dict(
    headers = ["Target", "1,000/s\nmedian", "1,000/s\n99th pct", "1,000/s\nlost",
               "3,000/s\nmedian", "3,000/s\n99th pct", "3,000/s\nlost"],
    rows = [
        ["Swaraj Kavach", "0.65 ms", "1.63 ms", "0", "0.93 ms", "8.16 ms", "0"],
        ["SafeLine, shipped defaults", "0.81 ms", "1.97 ms", "0", "1.19 ms", "59.1 ms", "0"],
        ["SafeLine, all modules strict", "0.78 ms", "1.33 ms", "0", "1.34 ms", "14.1 ms", "0"],
        ["BunkerWeb PL1, error page enabled", "10.8 s", "30 s", "2,404", "13.4 s", "30 s", "13,073"],
        ["BunkerWeb PL1, error page disabled", "5.13 ms", "137 ms", "0", "2.79 s", "30 s", "4,672"],
    ],
    note = ("15,000 requests were sent in each 1,000-per-second arm and 45,000 in each "
            "3,000-per-second arm. The client timeout is 30 seconds, so a 99th-percentile figure of "
            "30 seconds means those requests never received a response at all. 'Lost' counts "
            "requests that received no response."),
)

# --------------------------------------------------------------- resources
RES = dict(
    headers = ["Target", "CPU\nconsumed", "CPU per\nrequest", "Processor\ncores busy",
               "Peak\nmemory", "Requests\nunanswered"],
    rows = [
        ["GROUP", "Legitimate traffic", "", "", "", ""],
        ["Swaraj Kavach (single process)", "12.73 s", "0.636 ms", "0.63", "131 MiB", "0"],
        ["SafeLine, inspection path only", "8.39 s", "0.419 ms", "0.40", "349 MiB", "0"],
        ["SafeLine, complete product (7 containers)", "11.18 s", "0.559 ms", "0.53", "1,381 MiB", "0"],
        ["BunkerWeb (single container)", "58.36 s", "2.918 ms", "2.85", "993 MiB", "0"],
        ["GROUP", "Attack traffic, every request refused", "", "", "", ""],
        ["Swaraj Kavach (single process)", "12.96 s", "0.648 ms", "0.65", "131 MiB", "0"],
        ["SafeLine, inspection path only", "14.49 s", "0.724 ms", "0.70", "328 MiB", "0"],
        ["SafeLine, complete product (7 containers)", "19.79 s", "0.989 ms", "0.97", "1,449 MiB", "0"],
        ["BunkerWeb (single container)", "640.17 s", "41.5 ms", "12.70", "1,110 MiB", "4,581 of 20,000"],
    ],
    note = ("Load held identical at 1,000 requests per second for 20 seconds, 20,000 requests "
            "offered to each target. Container processor time is read from the operating system "
            "control group, which accounts for every process inside the container; "
            "Swaraj Kavach is a single native process and is read from the kernel's own counters. An "
            "idle baseline measured over an identical window was negligible for all three products, "
            "so no figure is inflated by background activity. Processor time per request is divided "
            "by requests actually answered and cores busy by real elapsed time, so that a product "
            "which discards requests cannot appear inexpensive on both measures simultaneously."),
)

IDLE_MEM = [
    ["Swaraj Kavach (single process)", "131 MiB"],
    ["SafeLine, inspection path (2 containers)", "568 MiB"],
    ["SafeLine, complete product (7 containers)", "1,132 MiB"],
    ["BunkerWeb (single container)", "490 MiB"],
]
