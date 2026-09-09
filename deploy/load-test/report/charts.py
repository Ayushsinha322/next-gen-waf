"""Print-quality figures for the ESDS WAF benchmark report."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "figs")
OURS, BW, SL, NEU, BAD = "#0A6A5C", "#4A5F78", "#A4711F", "#8C9A95", "#8E2F2F"
plt.rcParams.update({
    "font.family": "sans-serif", "font.sans-serif": ["Lato", "DejaVu Sans"],
    "font.size": 9, "axes.edgecolor": "#C9D2CF", "axes.linewidth": .8,
    "axes.labelcolor": "#3D4B49", "text.color": "#111A19",
    "xtick.color": "#66756F", "ytick.color": "#3D4B49",
    "xtick.labelsize": 8.5, "ytick.labelsize": 9,
    "figure.dpi": 200, "savefig.dpi": 200, "savefig.bbox": "tight",
    "savefig.facecolor": "white", "figure.facecolor": "white",
})

def barh(fname, labels, values, colors, xlabel, fmt, xmax=None, figh=None, note=None):
    n = len(labels)
    fig, ax = plt.subplots(figsize=(6.6, figh or (0.44 * n + 0.85)))
    y = range(n)
    bars = ax.barh(list(y), values, color=colors, height=.62, zorder=3)
    ax.set_yticks(list(y)); ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlabel(xlabel, labelpad=7, fontsize=8.5)
    lim = xmax or max(values) * 1.22
    ax.set_xlim(0, lim)
    ax.grid(axis="x", color="#E6EBE9", linewidth=.8, zorder=0)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.tick_params(axis="y", length=0)
    for b, v in zip(bars, values):
        inside = b.get_width() > lim * .38
        ax.text(b.get_width() + (-lim * .012 if inside else lim * .012),
                b.get_y() + b.get_height() / 2, fmt(v),
                va="center", ha="right" if inside else "left",
                color="white" if inside else "#111A19",
                fontsize=8.5, fontweight="bold", zorder=4)
    if note:
        ax.annotate(note, xy=(0, -0.12), xycoords="axes fraction",
                    fontsize=7.5, color="#66756F", va="top")
    fig.savefig(os.path.join(OUT, fname)); plt.close(fig)

# ---- 1. detection: attacks blocked vs benign passed -----------------------
arms = ["Swaraj Kavach\n(CRS PL2 + ML)", "SafeLine 9.4.1\n(all modules strict)",
        "SafeLine 9.4.1\n(shipped defaults)", "BunkerWeb 1.6.9\n(PL4, maximum)",
        "BunkerWeb 1.6.9\n(PL1, shipped)"]
atk = [99.24, 60.47, 47.38, 74.01, 47.09]
ben = [99.29, 97.87, 100.00, 0.00, 90.78]
cols = [OURS, SL, SL, BW, BW]
fig, ax = plt.subplots(figsize=(6.6, 3.5))
import numpy as np
y = np.arange(len(arms)); h = .34
b1 = ax.barh(y - h/2, atk, height=h, color=cols, zorder=3, label="Attacks blocked")
b2 = ax.barh(y + h/2, ben, height=h, color=cols, alpha=.42, zorder=3, label="Legitimate traffic allowed")
ax.set_yticks(y); ax.set_yticklabels(arms, fontsize=8.5)
ax.invert_yaxis(); ax.set_xlim(0, 118)
ax.set_xticks([0, 25, 50, 75, 100])
ax.xaxis.set_major_formatter(FuncFormatter(lambda v, p: f"{v:.0f}%"))
ax.grid(axis="x", color="#E6EBE9", linewidth=.8, zorder=0)
for s in ("top", "right", "left"): ax.spines[s].set_visible(False)
ax.tick_params(axis="y", length=0)
for bars, vals in ((b1, atk), (b2, ben)):
    for b, v in zip(bars, vals):
        ax.text(b.get_width() + 1.6, b.get_y() + b.get_height()/2, f"{v:.1f}%",
                va="center", ha="left", fontsize=7.8, color="#111A19",
                fontweight="bold" if bars is b1 else "normal")
ax.legend(loc="lower right", frameon=False, fontsize=8, ncol=1,
          bbox_to_anchor=(1.0, -0.30))
fig.savefig(os.path.join(OUT, "fig1-detection.png")); plt.close(fig)

# ---- 2. clean throughput --------------------------------------------------
barh("fig2-throughput.png",
     ["Origin with no WAF\n(theoretical ceiling)", "Swaraj Kavach",
      "SafeLine (defaults)", "SafeLine (strict)", "BunkerWeb (PL1)"],
     [32190, 7595, 6006, 4688, 2000], [NEU, OURS, SL, SL, BW],
     "Sustained requests per second, legitimate traffic",
     lambda v: f"{v:,.0f}")

# ---- 3. CPU per request --------------------------------------------------
barh("fig3-cpu.png",
     ["SafeLine, request path\n(legitimate traffic)", "Swaraj Kavach\n(legitimate traffic)",
      "Swaraj Kavach\n(attack traffic)", "SafeLine, request path\n(attack traffic)",
      "BunkerWeb\n(legitimate traffic)"],
     [419, 636, 648, 724, 2918], [SL, OURS, OURS, SL, BW],
     "CPU microseconds consumed per request (lower is better)",
     lambda v: f"{v:,.0f} µs",
     note="BunkerWeb on attack traffic consumed 41,518 µs per request and is omitted from this scale.")

# ---- 4. requests lost under sustained attack -----------------------------
barh("fig4-attack.png",
     ["Swaraj Kavach", "SafeLine (defaults)", "SafeLine (strict)",
      "BunkerWeb (PL1, error page off)", "BunkerWeb (PL1, as shipped)"],
     [0, 0, 0, 4672, 13073], [OURS, SL, SL, BW, BAD],
     "Requests that received no response, of 45,000 sent at 3,000/s",
     lambda v: f"{v:,.0f}" if v else "0  (none lost)",
     xmax=16500)

# ---- 5. memory -----------------------------------------------------------
barh("fig5-memory.png",
     ["Swaraj Kavach\n(single process)", "SafeLine\n(inspection path only)",
      "BunkerWeb\n(single container)", "SafeLine\n(complete product, 7 containers)"],
     [131, 349, 993, 1381], [OURS, SL, BW, SL],
     "Peak resident memory under load, MiB",
     lambda v: f"{v:,.0f} MiB")
print("figures written to", OUT)
for f in sorted(os.listdir(OUT)): print("  ", f)
