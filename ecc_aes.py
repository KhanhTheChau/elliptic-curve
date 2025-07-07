import tkinter as tk
from tkinter import messagebox
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random

class ECC:
    def __init__(self, p=263, a=5, b=7, G=None, d=None):
        self.p = p
        self.a = a
        self.b = b
        self.G = G if G else random.choice(self.find_points())
        self.d = d if d else random.randint(2, self.p - 1)
        self.Q = self.scalar_multiply(self.d, self.G)

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

    def generate_shared_secret(self, C1):
        shared_point = self.scalar_multiply(self.d, C1)
        shared_x = str(shared_point[0]).encode()
        return hashlib.sha256(shared_x).digest()

    def find_points(self):
        from collections import defaultdict
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

class ECCApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ECC Hybrid AES Encryption (Khóa mặc định)")

        # Khóa mặc định
        self.default_ecc = ECC(G=(39, 245), d=5)
        self.fixed_C1 = self.default_ecc.Q
        self.fixed_iv = b"1234567890ABCDEF"

        self.user_ecc = None  # Chỉ sinh khi nhấn nút Mã hóa

        # Giao diện
        tk.Label(root, text="Nhập bản rõ hoặc chuỗi đã mã hóa (hex):").pack()
        self.message_entry = tk.Entry(root, width=80)
        self.message_entry.pack()

        tk.Label(root, text="Văn bản đã mã hóa (copy tự động):").pack()
        self.encrypted_entry = tk.Entry(root, width=80)
        self.encrypted_entry.pack()

        button_frame = tk.Frame(root)
        button_frame.pack()

        tk.Button(button_frame, text="Mã hóa", command=self.encrypt).grid(row=0, column=0, padx=5)
        tk.Button(button_frame, text="Giải mã", command=self.decrypt).grid(row=0, column=1, padx=5)

        self.output_text = tk.Text(root, height=12, width=90)
        self.output_text.pack()

        self.output_text.insert(tk.END, "Khóa ECC mặc định:\n")
        self.output_text.insert(tk.END, f"G (điểm sinh): {self.default_ecc.G}\n")
        self.output_text.insert(tk.END, f"d (khóa riêng): {self.default_ecc.d}\n")
        self.output_text.insert(tk.END, f"Q = d*G (khóa công khai): {self.default_ecc.Q}\n")

    def encrypt(self):
        try:
            if self.user_ecc is None:
                self.user_ecc = ECC()
                self.output_text.insert(tk.END, "\nKhóa mới được tạo để mã hóa:\n")
                self.output_text.insert(tk.END, f"G: {self.user_ecc.G}\n")
                self.output_text.insert(tk.END, f"d: {self.user_ecc.d}\n")
                self.output_text.insert(tk.END, f"Q: {self.user_ecc.Q}\n")

            aes_key = self.user_ecc.generate_shared_secret(self.user_ecc.Q)
            message = self.message_entry.get()
            cipher = AES.new(aes_key, AES.MODE_CBC, iv=self.fixed_iv)
            padded = pad(message.encode(), AES.block_size)
            ciphertext = cipher.encrypt(padded)
            cipher_hex = ciphertext.hex()
            self.encrypted_entry.delete(0, tk.END)
            self.encrypted_entry.insert(0, cipher_hex)
            self.output_text.insert(tk.END, f"\nĐã mã hóa:\n{cipher_hex}\n")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    def decrypt(self):
        try:
            cipher_hex = self.encrypted_entry.get()
            ciphertext = bytes.fromhex(cipher_hex)

            # Dùng khóa mới nếu có, ngược lại dùng khóa mặc định
            ecc_used = self.user_ecc if self.user_ecc else self.default_ecc
            aes_key = ecc_used.generate_shared_secret(ecc_used.Q)

            cipher = AES.new(aes_key, AES.MODE_CBC, iv=self.fixed_iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
            self.output_text.insert(tk.END, f"\nĐã giải mã:\n{decrypted}\n")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = ECCApp(root)
    root.mainloop()
