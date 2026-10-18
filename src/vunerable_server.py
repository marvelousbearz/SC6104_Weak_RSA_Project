from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
from Crypto.PublicKey import RSA
from gmpy2 import powmod

class VunerableServer:
    def __init__(self, key_size: int = 1024, plaintext: bytes | None = None):
        self.__key = RSA.generate(key_size)

        self.__cipher = PKCS1_v1_5.new(self.__key)
        self.__secret = (
            plaintext if plaintext is not None
            else b"the quick brown fox jumps over the lazy dog"
        )
        self.__secret_ciphertext = self.__cipher.encrypt(self.__secret)

        self.__query_count = 0

        self.__arbitrary_secret = (
            plaintext if plaintext is not None
            else b"attacker does not control this padding"
        )
        self.__arbitrary_ciphertext = powmod(
            int.from_bytes(self.__arbitrary_secret, "big"),
            self.__key.e,
            self.__key.n
        ).to_bytes(self.__key.size_in_bytes(), "big")

        self.__cipher_OAEP = PKCS1_OAEP.new(self.__key)
        self.__arbitrary_secret_OAEP = (
            plaintext if plaintext is not None
            else b"OAEP can be cracked if it uses the same key"
        )
        self.__arbitrary_ciphertext_OAEP = (
            self.__cipher_OAEP.encrypt(self.__arbitrary_secret_OAEP)
        )

    def get_query_count(self):
        return self.__query_count

    def get_public_key(self):
        return self.__key.n, self.__key.e

    def get_secret_ciphertext(self):
        return self.__secret_ciphertext

    def get_arbitrary_ciphertext(self):
        return self.__arbitrary_ciphertext

    def get_arbitrary_ciphertext_OAEP(self):
        return self.__arbitrary_ciphertext_OAEP

    """Check if the given ciphertext conforms to PKCS#1 v1.5 padding.
    EB = Encryption Block
    PS = Padding String
    M = Message
    EB = '\x00\x02' || PS || '\x00' || M
    """
    def is_PKCS_conforming(self, ciphertext: bytes):
        self.__query_count += 1
        modulus_bytes = self.__key.size_in_bytes()
        if not isinstance(ciphertext, bytes) or len(ciphertext) != modulus_bytes:
            return False
        ciphertext_int = int.from_bytes(ciphertext, "big")
        if ciphertext_int >= self.__key.n:
            return False

        encoded_block = powmod(ciphertext_int, self.__key.d, self.__key.n).to_bytes(
            modulus_bytes, "big"
        )
        if not encoded_block.startswith(b"\x00\x02"):
            return False

        separator = encoded_block.find(b"\x00", 2)
        return separator >= 10
    
    def reveal_private_key(self):
        return self.__key
