import tkinter as tk
from tkinter import messagebox, filedialog
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random
import os

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


class ECCApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ECC Encryption/Decryption")
        self.ecc = None
        self.private_key_created = False

        self.frame0 = tk.Frame(root)
        self.frame1 = tk.Frame(root)
        self.frame2 = tk.Frame(root)

        self.setup_frame0()
        self.setup_frame1()
        self.setup_frame2()

        self.frame0.pack()

    def setup_frame0(self):
        tk.Button(self.frame0, text="Mã hóa (Người gửi)", command=self.show_frame1, width=25).pack(pady=10)
        tk.Button(self.frame0, text="Giải mã (Người nhận)", command=self.show_frame2, width=25).pack(pady=10)

    def setup_frame1(self):
        self.input_text1 = tk.Text(self.frame1, height=4, width=50)
        self.output_text1 = tk.Text(self.frame1, height=4, width=50)
        tk.Label(self.frame1, text="Nhập nội dung cần mã hóa:").pack()
        self.input_text1.pack()
        tk.Button(self.frame1, text="Tạo khóa riêng", command=self.create_private_key, width=25).pack(pady=5)
        tk.Button(self.frame1, text="Lưu khóa riêng", command=self.save_private_key, width=25).pack(pady=5)
        tk.Button(self.frame1, text="Mã hóa", command=self.encrypt_message, width=25).pack(pady=5)
        tk.Label(self.frame1, text="Kết quả mã hóa (hex):").pack()
        self.output_text1.pack()
        tk.Button(self.frame1, text="Quay lại", command=self.show_frame0, width=25).pack(pady=5)

    def setup_frame2(self):
        self.encrypted_view = tk.Text(self.frame2, height=4, width=50)
        self.decrypted_view = tk.Text(self.frame2, height=4, width=50)
        tk.Button(self.frame2, text="Tải khóa riêng", command=self.load_private_key, width=25).pack(pady=5)
        tk.Button(self.frame2, text="Giải mã", command=self.decrypt_message, width=25).pack(pady=5)
        tk.Label(self.frame2, text="Dữ liệu đã mã hóa (hex):").pack()
        self.encrypted_view.pack()
        tk.Label(self.frame2, text="Kết quả giải mã:").pack()
        self.decrypted_view.pack()
        tk.Button(self.frame2, text="Quay lại", command=self.show_frame0, width=25).pack(pady=5)

    def show_frame0(self):
        self.frame1.pack_forget()
        self.frame2.pack_forget()
        self.frame0.pack()

    def show_frame1(self):
        self.frame0.pack_forget()
        self.frame2.pack_forget()
        self.frame1.pack()

    def show_frame2(self):
        self.frame0.pack_forget()
        self.frame1.pack_forget()
        self.frame2.pack()

    def create_private_key(self):
        self.ecc = ECC()
        self.private_key_created = True
        messagebox.showinfo("Thông báo", "Khóa riêng đã được tạo.")

    def save_private_key(self):
        if not hasattr(self, 'sender'):
            messagebox.showerror("Lỗi", "Bạn cần mã hóa trước khi lưu.")
            return
        file = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="ecc_key.txt", filetypes=[("Text files", "*.txt")])
        if file:
            self.sender.save_key(file, self.last_C1, self.last_iv)
            messagebox.showinfo("Thành công", "Khóa riêng đã được lưu.")


    def encrypt_message(self):
        if not self.ecc:
            messagebox.showerror("Lỗi", "Chưa tạo khóa.")
            return
        plaintext = self.input_text1.get("1.0", "end").strip()
        if plaintext:
            sender = Sender(self.ecc)
            C1, iv, ct = sender.encrypt_message(plaintext)
            self.output_text1.delete("1.0", "end")
            self.output_text1.insert("1.0", ct.hex())
            self.last_C1 = C1
            self.last_iv = iv
            self.sender = sender  
            messagebox.showinfo("Thành công", "Mã hóa hoàn tất.")


    def load_private_key(self):
        file = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file and os.path.exists(file):
            self.receiver = Receiver()
            self.receiver.load_key(file)
            messagebox.showinfo("Thành công", "Khóa riêng đã được tải.")
        else:
            messagebox.showerror("Lỗi", "Không tìm thấy khóa.")


    def decrypt_message(self):
        if not hasattr(self, 'receiver') or self.receiver.ecc is None:
            messagebox.showerror("Lỗi", "Bạn cần tải khóa trước.")
            return
        ct_hex = self.encrypted_view.get("1.0", "end").strip()
        try:
            ct = bytes.fromhex(ct_hex)
            plaintext = self.receiver.decrypt_message(ct)
            self.decrypted_view.delete("1.0", "end")
            self.decrypted_view.insert("1.0", plaintext)
            messagebox.showinfo("Thành công", "Giải mã thành công.")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Giải mã thất bại: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ECCApp(root)
    root.mainloop()
