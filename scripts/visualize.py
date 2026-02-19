#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH Threat Visualizer - Generates charts from analysis JSON
Compatible: Windows + Linux terminals
"""

import sys
import json
import os
import argparse

# Force UTF-8 on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.gridspec import GridSpec
    import numpy as np
except ImportError:
    print("[!] matplotlib not found. Run: pip install matplotlib numpy")
    sys.exit(1)

# Dark theme colors
DARK_BG  = "#0d1117"
CARD_BG  = "#161b22"
ACCENT   = "#58a6ff"
RED      = "#f85149"
GREEN    = "#3fb950"
YELLOW   = "#d29922"
TEXT     = "#c9d1d9"
SUBTEXT  = "#8b949e"
GRID     = "#21262d"

plt.rcParams.update({
    "figure.facecolor": DARK_BG,
    "axes.facecolor":   CARD_BG,
    "axes.edgecolor":   GRID,
    "axes.labelcolor":  TEXT,
    "xtick.color":      SUBTEXT,
    "ytick.color":      SUBTEXT,
    "text.color":       TEXT,
    "grid.color":       GRID,
    "grid.linewidth":   0.5,
    "font.family":      "monospace",
})

def load_data(json_path):
    with open(json_path, encoding="utf-8") as f:
        return json.load(f)

def plot_top_ips(ax, data):
    ips    = [x[0] for x in data["top_ips"][:10]]
    counts = [x[1] for x in data["top_ips"][:10]]
    colors = [RED if i == 0 else ACCENT for i in range(len(ips))]
    bars   = ax.barh(ips[::-1], counts[::-1], color=colors[::-1], height=0.6, edgecolor="none")
    ax.set_title("TOP 10 ATTACKER IPs", color=TEXT, fontsize=11, pad=10, loc="left")
    ax.set_xlabel("Failed Attempts", color=SUBTEXT, fontsize=8)
    ax.grid(axis="x", alpha=0.3)
    ax.tick_params(labelsize=8)
    for bar, count in zip(bars, counts[::-1]):
        ax.text(bar.get_width() + max(counts)*0.01, bar.get_y() + bar.get_height()/2,
                f"{count:,}", va="center", fontsize=7, color=SUBTEXT)

def plot_top_users(ax, data):
    users  = [x[0] for x in data["top_users"][:10]]
    counts = [x[1] for x in data["top_users"][:10]]
    colors = [YELLOW if u in ("root","admin","administrator") else ACCENT for u in users]
    bars   = ax.barh(users[::-1], counts[::-1], color=colors[::-1], height=0.6, edgecolor="none")
    ax.set_title("TOP 10 TARGETED USERNAMES", color=TEXT, fontsize=11, pad=10, loc="left")
    ax.set_xlabel("Attempts", color=SUBTEXT, fontsize=8)
    ax.grid(axis="x", alpha=0.3)
    ax.tick_params(labelsize=8)
    for bar, count in zip(bars, counts[::-1]):
        ax.text(bar.get_width() + max(counts)*0.01, bar.get_y() + bar.get_height()/2,
                f"{count:,}", va="center", fontsize=7, color=SUBTEXT)

def plot_timeline(ax, data):
    timeline = data.get("timeline", {})
    if not timeline:
        ax.text(0.5, 0.5, "No timeline data", ha="center", va="center", transform=ax.transAxes)
        return
    labels = list(timeline.keys())
    values = list(timeline.values())
    x = range(len(labels))
    ax.fill_between(x, values, alpha=0.3, color=ACCENT)
    ax.plot(x, values, color=ACCENT, linewidth=1.5)
    ax.set_title("ATTACK TIMELINE (attempts per hour)", color=TEXT, fontsize=11, pad=10, loc="left")
    ax.set_ylabel("Attempts", color=SUBTEXT, fontsize=8)
    step = max(1, len(labels)//8)
    ax.set_xticks(list(range(0, len(labels), step)))
    ax.set_xticklabels([labels[i] for i in range(0, len(labels), step)],
                       rotation=30, ha="right", fontsize=7)
    ax.grid(axis="y", alpha=0.3)

def plot_stats_card(ax, data):
    ax.axis("off")
    stats = [
        ("TOTAL FAILED",  f"{data['total_failed']:,}",  RED),
        ("UNIQUE IPs",    f"{data['unique_ips']:,}",    ACCENT),
        ("UNIQUE USERS",  f"{data['unique_users']:,}",  YELLOW),
        ("SUCCESSFUL",    f"{data['total_successful']:,}", GREEN),
    ]
    for i, (label, value, color) in enumerate(stats):
        x = (i % 2) * 0.5 + 0.1
        y = 0.75 - (i // 2) * 0.45
        ax.text(x, y + 0.18, label, fontsize=8,  color=SUBTEXT, transform=ax.transAxes)
        ax.text(x, y, value,        fontsize=22, color=color,   fontweight="bold", transform=ax.transAxes)
    ax.set_title("KEY STATISTICS", color=TEXT, fontsize=11, pad=10, loc="left")
    ax.set_facecolor(CARD_BG)

def generate_dashboard(data, outpath):
    fig = plt.figure(figsize=(16, 10), facecolor=DARK_BG)
    fig.suptitle("SSH THREAT ANALYSIS DASHBOARD",
                 fontsize=16, color=TEXT, fontweight="bold", y=0.98, x=0.02, ha="left")

    gs = GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.35,
                  left=0.06, right=0.97, top=0.93, bottom=0.08)

    plot_stats_card (fig.add_subplot(gs[0, 0]), data)
    plot_top_ips    (fig.add_subplot(gs[0, 1]), data)
    plot_top_users  (fig.add_subplot(gs[0, 2]), data)
    plot_timeline   (fig.add_subplot(gs[1, :]), data)

    os.makedirs(os.path.dirname(outpath) or ".", exist_ok=True)
    plt.savefig(outpath, dpi=150, bbox_inches="tight", facecolor=DARK_BG)
    print(f"[+] Dashboard saved -> {outpath}")
    plt.close()

def main():
    parser = argparse.ArgumentParser(description="Generate SSH threat visualizations")
    parser.add_argument("json_file", help="Path to analysis.json")
    parser.add_argument("-o", "--output", default="output/dashboard.png")
    args = parser.parse_args()

    data = load_data(args.json_file)
    generate_dashboard(data, args.output)
    print("[+] Visualization complete!")

if __name__ == "__main__":
    main()