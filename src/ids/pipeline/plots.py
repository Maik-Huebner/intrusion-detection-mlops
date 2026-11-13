"""Stage ``plots``: detection rate per attack family, known vs. never-seen attacks.

Rendered as pure-vector SVG with a fixed hash salt and no metadata, so the file is byte-identical
on macOS and Linux and the CI reproducibility check can compare it. (A PNG is not: zlib output
differs between platforms even when the pixels are identical.)
"""

import matplotlib

matplotlib.use("svg")

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

from ids import schema  # noqa: E402
from ids.config import REPORTS_DIR  # noqa: E402
from ids.io import read_json  # noqa: E402

OUTPUT = REPORTS_DIR / "detection_by_attack.svg"
KNOWN, UNSEEN = "#2a7ab8", "#d1495b"


def main() -> None:
    details = read_json(REPORTS_DIR / "detection.json")
    bars = []  # (label, share, colour)
    for subset, colour in (("test", KNOWN), ("future", UNSEEN)):
        for category, v in details.get(subset, {}).get("by_category", {}).items():
            if category != schema.BENIGN_CATEGORY:
                bars.append((f"{category} (n={v['flows']:,})", v["share"], colour))
    bars.reverse()  # matplotlib draws barh bottom-up

    plt.rcParams["svg.hashsalt"] = "intrusion-detection-mlops"
    plt.rcParams["svg.fonttype"] = "none"
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
    fig.tight_layout()

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUTPUT, format="svg", metadata={"Date": None, "Creator": None})
    print(f"saved {OUTPUT}")


if __name__ == "__main__":
    main()
