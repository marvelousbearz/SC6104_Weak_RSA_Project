# (AI) Implementation of OAEP decoding and MGF1 for use with the Bleichenbacher attack
import hashlib

def mgf1(seed: bytes, length: int, hash_func=hashlib.sha1) -> bytes:
    """Mask Generation Function 1, as used by OAEP."""
    h_len = hash_func().digest_size
    output = b""
    counter = 0
    while len(output) < length:
        c = counter.to_bytes(4, "big")
        output += hash_func(seed + c).digest()
        counter += 1
    return output[:length]

def oaep_decode(em: bytes, k: int, hash_func=hashlib.sha1, label: bytes = b"") -> bytes:
    h_len = hash_func().digest_size

    if len(em) != k or k < 2 * h_len + 2:
        raise ValueError("Invalid OAEP block length.")

    y = em[0]
    masked_seed = em[1:1 + h_len]
    masked_db = em[1 + h_len:]

    seed_mask = mgf1(masked_db, h_len, hash_func)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

    db_mask = mgf1(seed, k - h_len - 1, hash_func)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    l_hash = hash_func(label).digest()
    l_hash_prime = db[:h_len]

    rest = db[h_len:]
    sep_index = 0
    while sep_index < len(rest) and rest[sep_index] == 0:
        sep_index += 1

    if (
        y != 0
        or l_hash_prime != l_hash
        or sep_index == len(rest)
        or rest[sep_index] != 1
    ):
        raise ValueError("OAEP decoding failed — recovered block is not valid OAEP.")

    return rest[sep_index + 1:]