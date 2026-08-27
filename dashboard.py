#!/usr/bin/env python3
"""
CodeAlpha Task 4 - NIDS Dashboard
Reads alerts.log (JSON-lines produced by nids.py) and renders simple
visualizations: alert counts by type, top source IPs, and a timeline.

Usage:
    python3 dashboard.py --log alerts.log
"""

import argparse
import json
from collections import Counter
from datetime import datetime

import matplotlib.pyplot as plt


def load_alerts(path):
    alerts = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"[!] No log file found at {path}. Run nids.py first to generate alerts.")
    return alerts


def plot_dashboard(alerts):
    if not alerts:
        print("[!] No alerts to display.")
        return

    types = Counter(a["type"] for a in alerts)
    sources = Counter(a["source_ip"] for a in alerts)
    timestamps = [datetime.fromisoformat(a["timestamp"]) for a in alerts]

    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    fig.suptitle("CodeAlpha Task 4 - NIDS Alert Dashboard")

    # Alerts by type
    axes[0].bar(types.keys(), types.values(), color="tomato")
    axes[0].set_title("Alerts by Type")
    axes[0].tick_params(axis="x", rotation=30)

    # Top source IPs
    top_sources = sources.most_common(10)
    if top_sources:
        labels, counts = zip(*top_sources)
        axes[1].barh(labels, counts, color="steelblue")
        axes[1].set_title("Top Source IPs")
        axes[1].invert_yaxis()

    # Timeline (alerts per minute)
    buckets = Counter(ts.strftime("%H:%M") for ts in timestamps)
    sorted_keys = sorted(buckets.keys())
    axes[2].plot(sorted_keys, [buckets[k] for k in sorted_keys], marker="o", color="darkgreen")
    axes[2].set_title("Alerts Over Time")
    axes[2].tick_params(axis="x", rotation=45)

    plt.tight_layout()
    out_path = "dashboard_output.png"
    plt.savefig(out_path, dpi=150)
    print(f"[*] Dashboard saved to {out_path}")


def main():
    parser = argparse.ArgumentParser(description="CodeAlpha Task 4 - NIDS Dashboard")
    parser.add_argument("--log", default="alerts.log", help="Path to the alerts log file")
    args = parser.parse_args()

    alerts = load_alerts(args.log)
    plot_dashboard(alerts)


if __name__ == "__main__":
    main()
