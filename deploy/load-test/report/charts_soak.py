"""Soak figures for the readiness document."""
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt, os, datetime as dt
from matplotlib.ticker import FuncFormatter

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "figs")
OURS, NEU, WARN, MUT = "#0A6A5C", "#8C9A95", "#9C5322", "#66756F"
plt.rcParams.update({
    "font.family": "sans-serif", "font.sans-serif": ["Lato", "DejaVu Sans"],
    "font.size": 7.5, "axes.edgecolor": "#C9D2CF", "axes.linewidth": .7,
    "text.color": "#111A19", "xtick.color": MUT, "ytick.color": "#3D4B49",
    "xtick.labelsize": 7, "ytick.labelsize": 7,
    "savefig.dpi": 220, "savefig.bbox": "tight", "savefig.facecolor": "white",
    "figure.facecolor": "white",
})

rows = [l.split("\t") for l in
        open(os.path.join(HERE, "soak-samples.tsv")).read().strip().split("\n")[1:]]
t0 = dt.datetime.strptime(rows[0][0], "%Y-%m-%dT%H:%M:%SZ")
def hrs(r): return (dt.datetime.strptime(r[0], "%Y-%m-%dT%H:%M:%SZ") - t0).total_seconds()/3600
h   = [hrs(r) for r in rows]
mem = [float(r[1].replace("MiB", "")) for r in rows]
fds = [float(r[3]) for r in rows]

fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(6.9, 2.75), sharex=True,
                               gridspec_kw={"height_ratios": [2, 1], "hspace": .18})

ax1.plot(h, mem, color=OURS, linewidth=1.35, zorder=3)
ax1.set_ylabel("memory, MiB", fontsize=7.5)
ax1.set_ylim(60, 215)
ax1.grid(color="#EDF1F0", linewidth=.7, zorder=0)
for s in ("top", "right"): ax1.spines[s].set_visible(False)
# annotate the three steps
for when, lo, hi in ((22.75, 141.2, 157.2), (26.75, 158.2, 174.3), (40.0, 176.3, 192.3)):
    ax1.annotate("", xy=(when, hi), xytext=(when, lo),
                 arrowprops=dict(arrowstyle="-|>", color=WARN, lw=1.0, shrinkA=0, shrinkB=0))
    ax1.text(when + .6, (lo + hi)/2, "+16 MiB", fontsize=6.4, color=WARN, va="center")
ax1.text(1.0, 74, "start-up allocation", fontsize=6.4, color=MUT)
ax1.text(6.0, 150, "gradual creep between steps, decelerating\n0.37 then 0.25 then 0.15 then 0.11 MiB/h", fontsize=6.2, color=MUT)
ax1.text(46.0, 196, "193.1", fontsize=6.6, color=OURS, fontweight="bold", ha="right")

ax2.plot(h, fds, color=NEU, linewidth=1.35, zorder=3)
ax2.set_ylabel("descriptors", fontsize=7.5)
ax2.set_ylim(0, 92); ax2.set_yticks([0, 28, 56, 81])
ax2.grid(color="#EDF1F0", linewidth=.7, zorder=0)
for s in ("top", "right"): ax2.spines[s].set_visible(False)
ax2.text(4.5, 68, "baseline 28; bounded excursions to a peak of 81, always returning",
         fontsize=6.4, color=MUT)
ax2.set_xlabel("hours elapsed", fontsize=7.5)
ax2.set_xlim(0, 47); ax2.set_xticks([0, 6, 12, 18, 24, 30, 36, 42, 46])

fig.savefig(os.path.join(OUT, "soak-trend.png")); plt.close(fig)
print("soak-trend.png written")
