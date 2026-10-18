"""Advanced, fully local experiments for the RSA weak-key audit project."""

import csv
from pathlib import Path
from statistics import median
from time import perf_counter

from src.shared_prime_attack import (
    batch_gcd_findings,
    find_shared_prime_pairs,
    generate_vulnerable_keyset,
)
from src.wiener_attack import generate_wiener_key_at_ratio, wiener_attack


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def measure(function, *args):
    started = perf_counter()
    result = function(*args)
    return result, (perf_counter() - started) * 1_000_000


def batch_gcd_benchmark():
    rows = []
    for count in (8, 16, 32, 64, 128):
        keys, _, _ = generate_vulnerable_keyset(count=count, bits=256)
        pair_times, batch_times = [], []
        for _ in range(3):
            pair_findings, pair_us = measure(find_shared_prime_pairs, keys)
            batch_findings, batch_us = measure(batch_gcd_findings, keys)
            if len(pair_findings) != 1 or len(batch_findings) != 2:
                raise RuntimeError("controlled shared-prime finding failed")
            pair_times.append(pair_us)
            batch_times.append(batch_us)
        rows.append({
            "public_keys": count,
            "naive_pairwise_us": round(median(pair_times), 2),
            "batch_gcd_us": round(median(batch_times), 2),
            "vulnerable_keys_found": 2,
        })
    return rows


def wiener_boundary_benchmark():
    rows = []
    for requested_ratio in (0.05, 0.10, 0.20, 0.30, 0.34, 0.50, 0.75, 1.00, 1.50, 2.00):
        successes, times, actual_ratios = 0, [], []
        for _ in range(5):
            public_key, private_key, actual_ratio = generate_wiener_key_at_ratio(
                requested_ratio, bits=256
            )
            recovered, attack_us = measure(wiener_attack, public_key)
            successes += recovered is not None and recovered.d == private_key.d
            times.append(attack_us)
            actual_ratios.append(actual_ratio)
        rows.append({
            "requested_ratio": requested_ratio,
            "mean_actual_ratio": round(sum(actual_ratios) / len(actual_ratios), 4),
            "trials": 5,
            "successes": successes,
            "success_rate_percent": round(successes * 100 / 5, 1),
            "median_attack_us": round(median(times), 2),
        })
    return rows


def write_csv(path, rows):
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def chart_svg(batch_rows, wiener_rows):
    """Write an accessible, no-dependency SVG with two experiment panels."""
    batch_max = max(max(row["naive_pairwise_us"], row["batch_gcd_us"]) for row in batch_rows)
    bar_width, gap, start_x = 27, 62, 95
    batch_bars = []
    batch_labels = []
    for index, row in enumerate(batch_rows):
        x = start_x + index * 88
        naive_height = row["naive_pairwise_us"] / batch_max * 210
        batch_height = row["batch_gcd_us"] / batch_max * 210
        batch_bars.append(f'<rect x="{x}" y="{318-naive_height:.1f}" width="{bar_width}" height="{naive_height:.1f}" fill="#18384A"/>')
        batch_bars.append(f'<rect x="{x+bar_width+5}" y="{318-batch_height:.1f}" width="{bar_width}" height="{batch_height:.1f}" fill="#167D86"/>')
        batch_labels.append(f'<text x="{x+28}" y="342">{row["public_keys"]}</text>')
    points = []
    wiener_labels = []
    max_ratio = max(row["requested_ratio"] for row in wiener_rows)
    min_ratio = min(row["requested_ratio"] for row in wiener_rows)
    for index, row in enumerate(wiener_rows):
        x = 705 + ((row["requested_ratio"] - min_ratio) / (max_ratio - min_ratio)) * 390
        y = 318 - row["success_rate_percent"] / 100 * 210
        points.append(f"{x:.1f},{y:.1f}")
        if row["requested_ratio"] in (0.05, 0.34, 0.75, 1.00, 1.50, 2.00):
            wiener_labels.append(f'<text x="{x:.1f}" y="342">{row["requested_ratio"]:.2f}</text>')
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="430" viewBox="0 0 1200 430" role="img" aria-label="Batch GCD and Wiener boundary experiment results">
<rect width="1200" height="430" fill="#F5F1E8"/>
<style>text{{font-family:Arial,sans-serif;fill:#46616B;font-size:15px;text-anchor:middle}} .title{{font-family:Georgia,serif;fill:#18384A;font-size:24px;font-weight:bold;text-anchor:start}} .label{{font-size:13px}} .axis{{stroke:#718A8D;stroke-width:1}} .grid{{stroke:#C8D6D1;stroke-width:1}}</style>
<text class="title" x="55" y="42">Naive pairwise GCD vs batch GCD</text><text class="title" x="650" y="42">Wiener recovery beyond the classic bound</text>
<text class="label" x="55" y="68" text-anchor="start">median audit time, microseconds</text><text class="label" x="650" y="68" text-anchor="start">success rate across five trials</text>
<line class="axis" x1="55" y1="318" x2="555" y2="318"/><line class="axis" x1="55" y1="88" x2="55" y2="318"/>
<line class="axis" x1="650" y1="318" x2="1130" y2="318"/><line class="axis" x1="650" y1="88" x2="650" y2="318"/>
<line class="grid" x1="55" y1="213" x2="555" y2="213"/><line class="grid" x1="650" y1="213" x2="1130" y2="213"/>
{''.join(batch_bars)}{''.join(batch_labels)}
<rect x="70" y="372" width="14" height="14" fill="#18384A"/><text x="145" y="384">pairwise GCD</text><rect x="235" y="372" width="14" height="14" fill="#167D86"/><text x="302" y="384">batch GCD</text>
<polyline fill="none" stroke="#167D86" stroke-width="4" points="{' '.join(points)}"/>
{''.join(f'<circle cx="{point.split(",")[0]}" cy="{point.split(",")[1]}" r="5" fill="#167D86"/>' for point in points)}{''.join(wiener_labels)}
<line x1="762" y1="88" x2="762" y2="318" stroke="#718A8D" stroke-dasharray="5 5"/><text x="769" y="105" text-anchor="start">classical 1/3 guide</text>
<text x="305" y="365">number of public keys</text><text x="890" y="365">d / N^(1/4)</text>
</svg>'''


def main():
    RESULTS.mkdir(exist_ok=True)
    batch_rows = batch_gcd_benchmark()
    wiener_rows = wiener_boundary_benchmark()
    write_csv(RESULTS / "batch_gcd_benchmark.csv", batch_rows)
    write_csv(RESULTS / "wiener_boundary.csv", wiener_rows)
    (RESULTS / "advanced_experiments.svg").write_text(
        chart_svg(batch_rows, wiener_rows), encoding="utf-8"
    )
    print("Wrote advanced results to", RESULTS)


if __name__ == "__main__":
    main()

