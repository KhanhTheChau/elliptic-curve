import tkinter as tk
from tkinter import messagebox
from collections import defaultdict
import random
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D


class ECC:
    def __init__(self, p=None):
        self.p = p if p else self.find_large_prime(17)
        self.a, self.b = self.generate_a_b()
        self.points = self.find_points()
        self.G = random.choice(self.points)
        self.d = random.randint(1, self.p - 1)
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

    def encode_message(self, message):
        all_points = self.points
        point_map = defaultdict(list)
        for x, y in all_points:
            point_map[x].append((x, y))

        points = []
        offsets = []
        for char in message:
            base_x = ord(char)
            for offset in range(100):
                x_try = (base_x + offset) % self.p
                if point_map[x_try]:
                    points.append(point_map[x_try][0])
                    offsets.append(offset)
                    break
            else:
                raise ValueError(f"Không ánh xạ được ký tự: {char}")
        return points, offsets

    def decode_message(self, points, offsets):
        message = ''
        for (x, _), offset in zip(points, offsets):
            char_code = (x - offset) % 256
            message += chr(char_code)
        return message

    def encrypt_point(self, M):
        while True:
            k = random.randint(1, self.p - 1)
            C1 = self.scalar_multiply(k, self.G)
            if C1 is None:
                continue  
            kQ = self.scalar_multiply(k, self.Q)
            C2 = self.point_add(M, kQ)
            if C2 is None:
                continue  
            return C1, C2


    def decrypt_point(self, C1, C2):
        dC1 = self.scalar_multiply(self.d, C1)
        neg_dC1 = (dC1[0], (-dC1[1]) % self.p)
        return self.point_add(C2, neg_dC1)


class ECCApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ECC Encryption App")
        self.ecc = ECC()

        self.message_label = tk.Label(root, text="Nhập thông điệp:")
        self.message_label.pack()
        self.message_entry = tk.Entry(root, width=40)
        self.message_entry.pack()

        self.encrypt_button = tk.Button(root, text="Mã hóa", command=self.encrypt)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(root, text="Giải mã", command=self.decrypt)
        self.decrypt_button.pack()

        self.output_text = tk.Text(root, height=10, width=60)
        self.output_text.pack()

        self.ciphertexts = []
        self.offsets = []

    def encrypt(self):
        try:
            message = self.message_entry.get()
            self.ecc = ECC()  
            M_points, self.offsets = self.ecc.encode_message(message)
            self.ciphertexts = [self.ecc.encrypt_point(M) for M in M_points]
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Original: {message}\n")
            self.output_text.insert(tk.END, f"Encrypted (C1, C2):\n")
            for c1, c2 in self.ciphertexts:
                self.output_text.insert(tk.END, f"{c1}, {c2}\n")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    def decrypt(self):
        try:
            decrypted = [self.ecc.decrypt_point(c1, c2) for c1, c2 in self.ciphertexts]
            recovered = self.ecc.decode_message(decrypted, self.offsets)
            self.output_text.insert(tk.END, f"\nGiải mã được: {recovered}\n")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = ECCApp(root)
    root.mainloop()
