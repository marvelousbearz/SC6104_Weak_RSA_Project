"""Measure the controlled common-modulus and Wiener demonstrations."""

import csv
from pathlib import Path
from time import perf_counter

from src.common_modulus_attack import common_modulus_attack, generate_common_modulus_keys
from src.wiener_attack import generate_wiener_vulnerable_key, wiener_attack


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def run_common_modulus_experiment():
    rows = []
    for bits in (256, 512, 768, 1024):
        first_key, second_key, _ = generate_common_modulus_keys(bits=bits)
        message = 42
        started = perf_counter()
        recovered = common_modulus_attack(
            first_key, pow(message, first_key.e, first_key.n),
            second_key, pow(message, second_key.e, second_key.n),
        )
        elapsed_ms = (perf_counter() - started) * 1000
        rows.append({"modulus_bits": first_key.n.bit_length(), "attack_ms": elapsed_ms, "recovered": recovered == message})
    return rows


def run_wiener_experiment():
    rows = []
    for bits in (256, 512, 768):
        public_key, private_key = generate_wiener_vulnerable_key(bits)
        started = perf_counter()
        recovered = wiener_attack(public_key)
        elapsed_ms = (perf_counter() - started) * 1000
        rows.append({
            "modulus_bits": public_key.n.bit_length(),
            "private_d": private_key.d,
            "attack_ms": elapsed_ms,
            "recovered": recovered is not None and recovered.d == private_key.d,
        })
    return rows


def write_csv(path, rows):
    with path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def plot(common_rows, wiener_rows):
    """Write a zero-dependency SVG figure for the slides and report."""
    common_max = max(row["attack_ms"] for row in common_rows) or 1
    wiener_max = max(row["attack_ms"] for row in wiener_rows) or 1
    left_points = []
    for index, row in enumerate(common_rows):
        x = 92 + index * 112
        y = 255 - (row["attack_ms"] / common_max) * 150
        left_points.append(f"{x:.1f},{y:.1f}")
    bars = []
    for index, row in enumerate(wiener_rows):
        x = 535 + index * 112
        height = (row["attack_ms"] / wiener_max) * 150
        bars.append(f'<rect x="{x}" y="{255-height:.1f}" width="56" height="{height:.1f}" fill="#F0392B"/>')
    labels_left = "".join(f'<text x="{92+i*112}" y="286">{row["modulus_bits"]}</text>' for i, row in enumerate(common_rows))
    labels_right = "".join(f'<text x="{563+i*112}" y="286">{row["modulus_bits"]}</text>' for i, row in enumerate(wiener_rows))
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="960" height="360" viewBox="0 0 960 360">
<rect width="960" height="360" fill="#09090A"/>
<style>text{{font-family:Arial,sans-serif;fill:#B8B5AD;font-size:15px}} .t{{fill:#F4F1EA;font-size:20px;font-weight:bold}} .axis{{stroke:#7E7C77;stroke-width:1}} .grid{{stroke:#2D2D34;stroke-width:1}}</style>
<text class="t" x="55" y="38">Common-modulus message recovery</text><text class="t" x="510" y="38">Wiener recovery time</text>
<line class="axis" x1="55" y1="255" x2="450" y2="255"/><line class="axis" x1="55" y1="70" x2="55" y2="255"/>
<line class="axis" x1="510" y1="255" x2="900" y2="255"/><line class="axis" x1="510" y1="70" x2="510" y2="255"/>
<line class="grid" x1="55" y1="180" x2="450" y2="180"/><line class="grid" x1="510" y1="180" x2="900" y2="180"/>
<polyline fill="none" stroke="#F0392B" stroke-width="3" points="{' '.join(left_points)}"/>
{''.join(f'<circle cx="{point.split(",")[0]}" cy="{point.split(",")[1]}" r="5" fill="#F0392B"/>' for point in left_points)}
{''.join(bars)}
{labels_left}{labels_right}
<text x="55" y="324">Modulus size in bits</text><text x="510" y="324">Modulus size in bits</text>
<text x="55" y="58">milliseconds</text><text x="510" y="58">milliseconds</text>
</svg>'''
    (RESULTS / "attack_timings.svg").write_text(svg, encoding="utf-8")


def main():
    RESULTS.mkdir(exist_ok=True)
    common_rows = run_common_modulus_experiment()
    wiener_rows = run_wiener_experiment()
    write_csv(RESULTS / "common_modulus_results.csv", common_rows)
    write_csv(RESULTS / "wiener_results.csv", wiener_rows)
    plot(common_rows, wiener_rows)
    print("Wrote results to", RESULTS)


if __name__ == "__main__":
    main()

