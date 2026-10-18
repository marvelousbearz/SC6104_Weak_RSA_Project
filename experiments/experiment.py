"""
experiments/experiment.py

Run Bleichenbacher attack experiments and produce CSV results + plots.

Usage:
    py experiments.py first-hit --bits 1024 2048 --trials 5
    py experiments.py crack --bits 1024 2048 --trials 3
    py experiments.py padding --bits 1024

Assumes VunerableServer(bits=...) accepts a key-size parameter.
"""
import argparse
import csv
import logging
import sys
import time
import traceback
from pathlib import Path
from statistics import mean

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.vunerable_server import VunerableServer
from src.bleichenbacher_attack import BleichenbacherAttack

RESULTS_DIR = PROJECT_ROOT / "results"
PLOTS_DIR = RESULTS_DIR / "plots"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("experiments")

# Attack-type labels, keyed by the CSV "experiment" suffix used for each.
PADDING_TYPES = [
    ("PKCS1_v1_5", "crack-pkcs1-v1-5"),
    ("arbitrary", "crack-arbitrary"),
    ("OAEP", "crack-oaep"),
]

FIELDNAMES = ["experiment", "key_bits", "trial", "elapsed_seconds", "oracle_calls", "iterations", "success"]


def ensure_dirs():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)


def run_trial(bits, attack_type, full_attack):
    """
    Run one attack trial. If full_attack is False, stop right after the
    first PKCS-conforming hit (step 1 blinding + step 2a) instead of
    running the whole attack to recovery — this isolates "first-hit" cost.
    Returns a result dict; never raises (failures are captured in the row).
    """
    server = VunerableServer(key_size=bits)
    attacker = BleichenbacherAttack(server, attack_type=attack_type)

    start = time.time()
    success = False
    try:
        if full_attack:
            attacker.attack()
        else:
            attacker.find_blinding_factor()
            attacker.initialize_search()
        success = True
    except Exception:
        log.warning("Trial failed (bits=%d, attack_type=%s):\n%s", bits, attack_type, traceback.format_exc())
    elapsed = time.time() - start

    return {
        "key_bits": bits,
        "elapsed_seconds": elapsed,
        "oracle_calls": attacker.oracle_calls,
        "iterations": attacker.iterations,
        "success": success,
    }


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    log.info("Wrote %s (%d rows)", path, len(rows))


def aggregate_by(rows, key_fn):
    """Group rows by key_fn(row), return {key: (avg_time, avg_calls, n_success, n_total)}."""
    groups = {}
    for row in rows:
        groups.setdefault(key_fn(row), []).append(row)

    out = {}
    for key, group_rows in groups.items():
        ok = [r for r in group_rows if r["success"]]
        avg_time = mean(r["elapsed_seconds"] for r in ok) if ok else float("nan")
        avg_calls = mean(r["oracle_calls"] for r in ok) if ok else float("nan")
        out[key] = (avg_time, avg_calls, len(ok), len(group_rows))
    return out


def plot_grouped(group_labels, avg_times, avg_calls, title, out_path, group_axis_label="Key size (bits)"):
    """Two-panel bar chart: average elapsed time, average oracle calls, by group."""
    fig, (ax_time, ax_calls) = plt.subplots(1, 2, figsize=(11, 4.5))
    x = range(len(group_labels))

    ax_time.bar(x, avg_times, color="#3b6fa0")
    ax_time.set_xticks(list(x))
    ax_time.set_xticklabels(group_labels)
    ax_time.set_ylabel("Avg. elapsed time (s)")
    ax_time.set_xlabel(group_axis_label)
    ax_time.set_title("Average time")

    ax_calls.bar(x, avg_calls, color="#d98e3f")
    ax_calls.set_xticks(list(x))
    ax_calls.set_xticklabels(group_labels)
    ax_calls.set_ylabel("Avg. oracle calls")
    ax_calls.set_xlabel(group_axis_label)
    ax_calls.set_title("Average oracle calls")

    fig.suptitle(title)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    log.info("Wrote %s", out_path)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_first_hit(args):
    ensure_dirs()
    rows = []
    for bits in args.bits:
        for trial in range(1, args.trials + 1):
            log.info("first-hit: bits=%d trial=%d/%d", bits, trial, args.trials)
            result = run_trial(bits, attack_type="PKCS1_v1_5", full_attack=False)
            rows.append({"experiment": "first-hit", "trial": trial, **result})

    write_csv(RESULTS_DIR / "first-hit.csv", rows)

    agg = aggregate_by(rows, key_fn=lambda r: r["key_bits"])
    bits_sorted = sorted(agg.keys())
    avg_times = [agg[b][0] for b in bits_sorted]
    avg_calls = [agg[b][1] for b in bits_sorted]
    plot_grouped(
        [str(b) for b in bits_sorted], avg_times, avg_calls,
        "First PKCS-conforming hit — average over trials",
        PLOTS_DIR / "first-hit.png",
    )


def cmd_crack(args):
    ensure_dirs()
    rows = []
    for bits in args.bits:
        for trial in range(1, args.trials + 1):
            log.info("crack: bits=%d trial=%d/%d", bits, trial, args.trials)
            result = run_trial(bits, attack_type="PKCS1_v1_5", full_attack=True)
            rows.append({"experiment": "crack-pkcs1-v1-5", "trial": trial, **result})

    write_csv(RESULTS_DIR / "crack.csv", rows)

    agg = aggregate_by(rows, key_fn=lambda r: r["key_bits"])
    bits_sorted = sorted(agg.keys())
    avg_times = [agg[b][0] for b in bits_sorted]
    avg_calls = [agg[b][1] for b in bits_sorted]
    plot_grouped(
        [str(b) for b in bits_sorted], avg_times, avg_calls,
        "Full attack to recovery — average over trials",
        PLOTS_DIR / "crack.png",
    )


def cmd_padding(args):
    ensure_dirs()
    rows = []
    for bits in args.bits:
        for attack_type, experiment_name in PADDING_TYPES:
            for trial in range(1, args.trials + 1):
                log.info("padding: bits=%d type=%s trial=%d/%d", bits, attack_type, trial, args.trials)
                result = run_trial(bits, attack_type=attack_type, full_attack=True)
                rows.append({"experiment": experiment_name, "trial": trial, **result})

    write_csv(RESULTS_DIR / f"padding-{'-'.join(str(b) for b in args.bits)}.csv", rows)

    # One grouped-bar plot per bit size, comparing padding types.
    for bits in args.bits:
        bits_rows = [r for r in rows if r["key_bits"] == bits]
        agg = aggregate_by(bits_rows, key_fn=lambda r: r["experiment"])
        labels = [name for _, name in PADDING_TYPES if name in agg]
        avg_times = [agg[name][0] for name in labels]
        avg_calls = [agg[name][1] for name in labels]
        plot_grouped(
            labels, avg_times, avg_calls,
            f"Padding scheme comparison — {bits}-bit key",
            PLOTS_DIR / f"padding-{bits}.png",
            group_axis_label="Padding / target type",
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Bleichenbacher attack experiment runner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_first = subparsers.add_parser("first-hit", help="Measure time/calls to the first PKCS-conforming hit")
    p_first.add_argument("--bits", type=int, nargs="+", required=True)
    p_first.add_argument("--trials", type=int, default=5)
    p_first.set_defaults(func=cmd_first_hit)

    p_crack = subparsers.add_parser("crack", help="Measure time/calls for a full attack to recovery")
    p_crack.add_argument("--bits", type=int, nargs="+", required=True)
    p_crack.add_argument("--trials", type=int, default=3)
    p_crack.set_defaults(func=cmd_crack)

    p_pad = subparsers.add_parser("padding", help="Compare full-attack cost across PKCS#1v1.5 / arbitrary / OAEP targets")
    p_pad.add_argument("--bits", type=int, nargs="+", required=True)
    p_pad.add_argument("--trials", type=int, default=1)
    p_pad.set_defaults(func=cmd_padding)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()