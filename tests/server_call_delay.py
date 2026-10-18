# Measure the delay of server calls for PKCS#1 v1.5 conformity check (AI)
import time
from pathlib import Path
import sys

project_dir = Path(__file__).resolve().parent.parent
sys.path.append(str(project_dir))

from src.vunerable_server import VunerableServer

server = VunerableServer()
n, e = server.get_public_key()
modulus_bytes = (n.bit_length() + 7) // 8
test_ct = (12345).to_bytes(modulus_bytes, "big")

for _ in range(20):
    server.is_PKCS_conforming(test_ct)

samples = []
for _ in range(5):
    t0 = time.perf_counter()
    for _ in range(100):
        server.is_PKCS_conforming(test_ct)
    samples.append((time.perf_counter() - t0) / 100 * 1000)

average_ms = sum(samples) / len(samples)
print(f"Average: {average_ms:.3f} ms per call")