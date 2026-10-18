"""Advanced, fully local experiments for the Common Modulus and Wiener project."""

import csv
from pathlib import Path
from statistics import median
from time import perf_counter

from itertools import combinations
from math import gcd

from src.common_modulus_attack import find_common_modulus_pairs, generate_common_modulus_keyset
from src.wiener_attack import generate_wiener_key_at_ratio, wiener_attack


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def measure(function, *args):
    started = perf_counter()
    result = function(*args)
    return result, (perf_counter() - started) * 1_000_000


def common_modulus_benchmark():
    rows = []
    for count in (8, 16, 32, 64, 128):
        naive_times, indexed_times = [], []
        keys, expected_pair = generate_common_modulus_keyset(count=count, bits=256)
        for _ in range(3):
            naive_findings, naive_us = measure(
                lambda collection: [
                    (left, right)
                    for left, right in combinations(range(len(collection)), 2)
                    if collection[left].n == collection[right].n
                    and gcd(collection[left].e, collection[right].e) == 1
                ],
                keys,
            )
            indexed_findings, indexed_us = measure(find_common_modulus_pairs, keys)
            if naive_findings != [expected_pair] or indexed_findings != [expected_pair]:
                raise RuntimeError("controlled common-modulus finding failed")
            naive_times.append(naive_us)
            indexed_times.append(indexed_us)
        rows.append({
            "public_keys": count,
            "naive_pairwise_us": round(median(naive_times), 2),
            "indexed_scan_us": round(median(indexed_times), 2),
            "vulnerable_pairs_found": 1,
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


def chart_svg(common_rows, wiener_rows):
    """Write an accessible, no-dependency SVG with two experiment panels."""
    common_max = max(max(row["naive_pairwise_us"], row["indexed_scan_us"]) for row in common_rows) or 1
    common_bars = []
    common_labels = []
    for index, row in enumerate(common_rows):
        x = 95 + index * 88
        naive_height = row["naive_pairwise_us"] / common_max * 210
        indexed_height = row["indexed_scan_us"] / common_max * 210
        common_bars.append(f'<rect x="{x}" y="{318-naive_height:.1f}" width="27" height="{naive_height:.1f}" fill="#18384A"/>')
        common_bars.append(f'<rect x="{x+32}" y="{318-indexed_height:.1f}" width="27" height="{indexed_height:.1f}" fill="#167D86"/>')
        common_labels.append(f'<text x="{x+29}" y="342">{row["public_keys"]}</text>')
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
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="430" viewBox="0 0 1200 430" role="img" aria-label="Common-modulus and Wiener boundary experiment results">
<rect width="1200" height="430" fill="#F5F1E8"/>
<style>text{{font-family:Arial,sans-serif;fill:#46616B;font-size:15px;text-anchor:middle}} .title{{font-family:Georgia,serif;fill:#18384A;font-size:24px;font-weight:bold;text-anchor:start}} .label{{font-size:13px}} .axis{{stroke:#718A8D;stroke-width:1}} .grid{{stroke:#C8D6D1;stroke-width:1}}</style>
<text class="title" x="55" y="42">Common-modulus collection audit</text><text class="title" x="650" y="42">Wiener recovery beyond the classic bound</text>
<text class="label" x="55" y="68" text-anchor="start">median scan time, microseconds</text><text class="label" x="650" y="68" text-anchor="start">success rate across five trials</text>
<line class="axis" x1="55" y1="318" x2="555" y2="318"/><line class="axis" x1="55" y1="88" x2="55" y2="318"/>
<line class="axis" x1="650" y1="318" x2="1130" y2="318"/><line class="axis" x1="650" y1="88" x2="650" y2="318"/>
<line class="grid" x1="55" y1="213" x2="555" y2="213"/><line class="grid" x1="650" y1="213" x2="1130" y2="213"/>
{''.join(common_bars)}{''.join(common_labels)}
<rect x="70" y="372" width="14" height="14" fill="#18384A"/><text x="145" y="384">naive pairs</text><rect x="235" y="372" width="14" height="14" fill="#167D86"/><text x="320" y="384">indexed by N</text>
<polyline fill="none" stroke="#167D86" stroke-width="4" points="{' '.join(points)}"/>
{''.join(f'<circle cx="{point.split(",")[0]}" cy="{point.split(",")[1]}" r="5" fill="#167D86"/>' for point in points)}{''.join(wiener_labels)}
<line x1="762" y1="88" x2="762" y2="318" stroke="#718A8D" stroke-dasharray="5 5"/><text x="769" y="105" text-anchor="start">classical 1/3 guide</text>
<text x="305" y="365">number of public keys</text><text x="890" y="365">d / N^(1/4)</text>
</svg>'''


def main():
    RESULTS.mkdir(exist_ok=True)
    common_rows = common_modulus_benchmark()
    wiener_rows = wiener_boundary_benchmark()
    write_csv(RESULTS / "common_modulus_benchmark.csv", common_rows)
    write_csv(RESULTS / "wiener_boundary.csv", wiener_rows)
    (RESULTS / "advanced_experiments.svg").write_text(
        chart_svg(common_rows, wiener_rows), encoding="utf-8"
    )
    print("Wrote advanced results to", RESULTS)


if __name__ == "__main__":
    main()

