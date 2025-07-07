import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random
from ECC import ECC

class Receiver:
    def __init__(self):
        self.ecc = None
        self.last_C1 = None
        self.last_iv = None

    def load_key(self, path):
        with open(path, "r") as f:
            lines = f.read().splitlines()
        self.ecc = ECC()
        self.ecc.p, self.ecc.a, self.ecc.b = map(int, lines[0].split(","))
        gx, gy = map(int, lines[1].split(","))
        self.ecc.G = (gx, gy)
        self.ecc.d = int(lines[2])
        self.ecc.Q = self.ecc.scalar_multiply(self.ecc.d, self.ecc.G)
        x, y = map(int, lines[3].split(","))
        self.last_C1 = (x, y)
        self.last_iv = bytes.fromhex(lines[4])

    def decrypt_message(self, ciphertext):
        key = self.ecc.generate_shared_secret(self.last_C1)
        cipher = AES.new(key, AES.MODE_CBC, self.last_iv)
        pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return pt.decode()