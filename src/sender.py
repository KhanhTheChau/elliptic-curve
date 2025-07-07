import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random
from ECC import ECC

class Sender:
    def __init__(self, ecc):
        self.ecc = ecc

    def encrypt_message(self, plaintext):
        M = plaintext.encode()
        k = random.randint(1, self.ecc.p - 1)
        C1 = self.ecc.scalar_multiply(k, self.ecc.G)
        Pk = self.ecc.scalar_multiply(k, self.ecc.Q)
        shared_x = str(Pk[0]).encode()
        key = hashlib.sha256(shared_x).digest()
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(M, AES.block_size))
        return C1, cipher.iv, ct_bytes

    def save_key(self, path, C1, iv):
        with open(path, "w") as f:
            f.write(f"{self.ecc.p},{self.ecc.a},{self.ecc.b}\n")
            f.write(f"{self.ecc.G[0]},{self.ecc.G[1]}\n")
            f.write(str(self.ecc.d) + "\n")
            f.write(f"{C1[0]},{C1[1]}\n")
            f.write(iv.hex())

