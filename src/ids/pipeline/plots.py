"""Stage ``plots``: detection rate per attack family, and the label-free drift signal per day.

Rendered as pure-vector SVG with a fixed hash salt and no metadata, so the file is byte-identical
on macOS and Linux and the CI reproducibility check can compare it. (A PNG is not: zlib output
differs between platforms even when the pixels are identical.)
"""

import matplotlib

matplotlib.use("svg")

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

from ids import schema  # noqa: E402
from ids.config import REPORTS_DIR, load_params  # noqa: E402
from ids.io import read_json  # noqa: E402

OUTPUT = REPORTS_DIR / "detection_by_attack.svg"
DRIFT_OUTPUT = REPORTS_DIR / "drift_by_day.svg"
KNOWN, UNSEEN = "#2a7ab8", "#d1495b"


def _setup() -> None:
    plt.rcParams["svg.hashsalt"] = "intrusion-detection-mlops"
    plt.rcParams["svg.fonttype"] = "none"


def _save(fig, path) -> None:
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, format="svg", metadata={"Date": None, "Creator": None})
    plt.close(fig)
    print(f"saved {path}")


def plot_drift() -> None:
    """Share of drifted features in the traffic the model lets through, per data set."""
    report = read_json(REPORTS_DIR / "drift.json")
    threshold = load_params("drift")["share_threshold"]
    order = ["test"] + [f"future_{day}" for day in schema.DAYS]  # chronological, not alphabetical
    names = [n for n in order if n in report]
    labels = ["test (training days)" if n == "test" else n.removeprefix("future_") for n in names]
    shares = [report[n]["drift_share"] for n in names]
    colours = [UNSEEN if report[n]["drift"] else KNOWN for n in names]

    _setup()
    fig, ax = plt.subplots(figsize=(8, 3.2))
    ax.bar(labels, shares, color=colours, width=0.55)
    ax.axhline(threshold, color="#555555", linewidth=1, linestyle="--")
    ax.text(
        len(names) - 0.5, threshold, f"alarm threshold {threshold:.0%}", ha="right", va="bottom", fontsize=8
    )
    for x, (name, share) in enumerate(zip(names, shares, strict=True)):
        hidden = report[name]["hidden_attacks"]
        ax.text(x, share + 0.01, f"{share:.0%}", ha="center", va="bottom", fontsize=10, weight="bold")
        ax.text(
            x,
            -0.07,
            f"{hidden:,} attack{'' if hidden == 1 else 's'}\nlet through",
            ha="center",
            va="top",
            fontsize=7.5,
            color="#555555",
            transform=ax.get_xaxis_transform(),
        )
    ax.set_ylim(0, max([*shares, threshold]) * 1.25 + 0.02)
    ax.set_ylabel("share of drifted features")
    ax.set_title(
        "Drift monitor (no labels): traffic the model lets through vs. benign training traffic", fontsize=10
    )
    ax.tick_params(axis="x", pad=28)
    ax.spines[["top", "right"]].set_visible(False)
    _save(fig, DRIFT_OUTPUT)


def plot_detection() -> None:
    details = read_json(REPORTS_DIR / "detection.json")
    bars = []  # (label, share, colour)
    for subset, colour in (("test", KNOWN), ("future", UNSEEN)):
        for category, v in details.get(subset, {}).get("by_category", {}).items():
            if category != schema.BENIGN_CATEGORY:
                bars.append((f"{category} (n={v['flows']:,})", v["share"], colour))
    bars.reverse()  # matplotlib draws barh bottom-up

    _setup()
    fig, ax = plt.subplots(figsize=(8, 0.45 * len(bars) + 1.6))
    ax.barh([b[0] for b in bars], [b[1] for b in bars], color=[b[2] for b in bars])
    for y, (_, share, colour) in enumerate(bars):
        if share > 0.85:  # inside the bar
            ax.text(share - 0.01, y, f"{share:.1%}", va="center", ha="right", fontsize=9, color="white")
        else:
            ax.text(share + 0.01, y, f"{share:.1%}", va="center", fontsize=9, color=colour, weight="bold")
    for tick, (_, _, colour) in zip(ax.get_yticklabels(), bars, strict=True):
        tick.set_color(colour)
    n_unseen = sum(b[2] == UNSEEN for b in bars)
    if 0 < n_unseen < len(bars):
        ax.axhline(n_unseen - 0.5, color="#999999", linewidth=0.8, linestyle="--")

    ax.set_xlim(0, 1.0)
    ax.set_xlabel("share of attack flows detected")
    ax.set_title("Detection rate per attack family")
    ax.legend(
        handles=[
            Patch(color=KNOWN, label="known (test, training days)"),
            Patch(color=UNSEEN, label="never seen (future days)"),
        ],
        loc="lower right",
        fontsize=8,
    )
    ax.spines[["top", "right"]].set_visible(False)
    _save(fig, OUTPUT)


def main() -> None:
    plot_detection()
    plot_drift()


if __name__ == "__main__":
    main()
