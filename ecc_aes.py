import tkinter as tk
from tkinter import messagebox
from collections import defaultdict
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class ECC:
    def __init__(self, p=None):
        self.p = p if p else self.find_large_prime(257)
        self.a, self.b = self.generate_a_b()
        self.points = self.find_points()
        self.G = random.choice(self.points)
        self.d = 5
        self.Q = self.scalar_multiply(self.d, self.G)

    def find_large_prime(self, start):
        def is_large_prime(n):
            if n in (2, 3): return True
            if n < 2 or n % 2 == 0: return False
            d, r = n - 1, 0
            while d % 2 == 0:
                d //= 2
                r += 1
            for _ in range(5):
                a = random.randint(2, n - 2)
                x = pow(a, d, n)
                if x == 1 or x == n - 1:
                    continue
                for _ in range(r - 1):
                    x = pow(x, 2, n)
                    if x == n - 1:
                        break
                else:
                    return False
            return True

        while not is_large_prime(start):
            start += 1
        return start

    def generate_a_b(self):
        while True:
            a = random.randint(1, self.p - 1)
            b = random.randint(1, self.p - 1)
            delta = (4 * pow(a, 3, self.p) + 27 * pow(b, 2, self.p)) % self.p
            if delta != 0:
                return a, b

    def find_points(self):
        residues = defaultdict(list)
        for i in range(self.p):
            residues[pow(i, 2, self.p)].append(i)
        points = []
        for x in range(self.p):
            rhs = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
            if rhs in residues:
                for y in residues[rhs]:
                    points.append((x, y))
        return points

    def inverse_mod(self, k):
        return pow(k, -1, self.p)

    def point_add(self, P, Q):
        if P is None: return Q
        if Q is None: return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and (y1 + y2) % self.p == 0: return None
        if x1 != x2:
            m = ((y2 - y1) * self.inverse_mod(x2 - x1)) % self.p
        else:
            if y1 == 0: return None
            m = ((3 * x1 ** 2 + self.a) * self.inverse_mod(2 * y1)) % self.p
        x3 = (m ** 2 - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        return x3, y3

    def scalar_multiply(self, k, P):
        result = None
        addend = P
        while k > 0:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return result


# Dùng AES kết hợp với khóa sinh từ ECC để mã hóa và giải mã
    def generate_shared_secret(self, C1):
        shared_point = self.scalar_multiply(self.d, C1)
        shared_x = str(shared_point[0]).encode()
        return hashlib.sha256(shared_x).digest()

class ECCApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ECC Hybrid AES Encryption (1 ô chuỗi)")
        self.ecc = ECC()

        tk.Label(root, text="Nhập bản rõ hoặc chuỗi đã mã hóa:").pack()
        self.message_entry = tk.Entry(root, width=80)
        self.message_entry.pack()

        tk.Label(root, text="Văn bản đã mã hóa (dành để copy lại):").pack()
        self.encrypted_entry = tk.Entry(root, width=80)
        self.encrypted_entry.pack()

        tk.Button(root, text="Mã hóa", command=self.encrypt).pack()
        tk.Button(root, text="Giải mã", command=self.decrypt).pack()

        self.output_text = tk.Text(root, height=12, width=90)
        self.output_text.pack()

        self.fixed_iv = b"1234567890ABCDEF"
        self.fixed_C1 = self.ecc.Q

    def encrypt(self):
        try:
            message = self.message_entry.get()
            aes_key = self.ecc.generate_shared_secret(self.fixed_C1)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv=self.fixed_iv)
            padded = pad(message.encode(), AES.block_size)
            ciphertext = cipher.encrypt(padded)
            cipher_hex = ciphertext.hex()
            self.encrypted_entry.delete(0, tk.END)
            self.encrypted_entry.insert(0, cipher_hex)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Đã mã hóa:\n{cipher_hex}\n")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    def decrypt(self):
        try:
            cipher_hex = self.encrypted_entry.get()
            ciphertext = bytes.fromhex(cipher_hex)
            aes_key = self.ecc.generate_shared_secret(self.fixed_C1)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv=self.fixed_iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
            self.output_text.insert(tk.END, f"\nĐã giải mã:\n{decrypted}\n")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = ECCApp(root)
    root.mainloop()
