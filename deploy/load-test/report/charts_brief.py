"""Two compact figures sized for a two-page summary."""
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt, numpy as np, os
from matplotlib.ticker import FuncFormatter

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "figs")
OURS, BW, SL, NEU, BAD = "#0A6A5C", "#4A5F78", "#A4711F", "#8C9A95", "#8E2F2F"
plt.rcParams.update({
    "font.family": "sans-serif", "font.sans-serif": ["Lato", "DejaVu Sans"],
    "font.size": 7.5, "axes.edgecolor": "#C9D2CF", "axes.linewidth": .7,
    "text.color": "#111A19", "xtick.color": "#66756F", "ytick.color": "#3D4B49",
    "xtick.labelsize": 7, "ytick.labelsize": 7.5,
    "savefig.dpi": 220, "savefig.bbox": "tight", "savefig.facecolor": "white",
    "figure.facecolor": "white",
})

# --- detection: attacks blocked vs legitimate allowed, compact ------------
arms = ["Swaraj Kavach", "SafeLine (strict)", "SafeLine (default)",
        "BunkerWeb (PL4 max)", "BunkerWeb (PL1)"]
atk = [99.24, 60.47, 47.38, 74.01, 47.09]
ben = [99.29, 97.87, 100.00, 0.00, 90.78]
cols = [OURS, SL, SL, BW, BW]
fig, ax = plt.subplots(figsize=(6.9, 1.95))
y = np.arange(len(arms)); h = .34
b1 = ax.barh(y - h/2, atk, height=h, color=cols, zorder=3)
b2 = ax.barh(y + h/2, ben, height=h, color=cols, alpha=.40, zorder=3)
ax.set_yticks(y); ax.set_yticklabels(arms)
ax.invert_yaxis(); ax.set_xlim(0, 122); ax.set_xticks([0, 50, 100])
ax.xaxis.set_major_formatter(FuncFormatter(lambda v, p: f"{v:.0f}%"))
ax.grid(axis="x", color="#E6EBE9", linewidth=.7, zorder=0)
for s in ("top", "right", "left"): ax.spines[s].set_visible(False)
ax.tick_params(axis="y", length=0)
for bars, vals, bold in ((b1, atk, True), (b2, ben, False)):
    for b, v in zip(bars, vals):
        ax.text(b.get_width() + 1.6, b.get_y() + b.get_height()/2, f"{v:.1f}",
                va="center", ha="left", fontsize=6.6,
                fontweight="bold" if bold else "normal", color="#111A19")
ax.text(0, -0.42, "solid = attacks blocked   ·   shaded = legitimate traffic allowed",
        transform=ax.transAxes, fontsize=6.6, color="#66756F", va="top")
fig.savefig(os.path.join(OUT, "brief-detection.png")); plt.close(fig)

# --- throughput, compact --------------------------------------------------
lab = ["No WAF (ceiling)", "Swaraj Kavach", "SafeLine", "BunkerWeb"]
val = [32190, 7595, 6006, 2000]
col = [NEU, OURS, SL, BW]
fig, ax = plt.subplots(figsize=(6.9, 1.32))
bars = ax.barh(range(len(lab)), val, color=col, height=.6, zorder=3)
ax.set_yticks(range(len(lab))); ax.set_yticklabels(lab)
ax.invert_yaxis(); ax.set_xlim(0, 38000)
ax.set_xticks([0, 10000, 20000, 30000])
ax.xaxis.set_major_formatter(FuncFormatter(lambda v, p: f"{v/1000:.0f}k"))
ax.grid(axis="x", color="#E6EBE9", linewidth=.7, zorder=0)
for s in ("top", "right", "left"): ax.spines[s].set_visible(False)
ax.tick_params(axis="y", length=0)
for b, v in zip(bars, val):
    ax.text(b.get_width() + 500, b.get_y() + b.get_height()/2, f"{v:,}",
            va="center", ha="left", fontsize=6.8, fontweight="bold", color="#111A19")
ax.text(0, -0.55, "sustained requests per second, legitimate traffic",
        transform=ax.transAxes, fontsize=6.6, color="#66756F", va="top")
fig.savefig(os.path.join(OUT, "brief-throughput.png")); plt.close(fig)
print("compact figures written")
