import tkinter as tk
from tkinter import messagebox, filedialog
import os
from ECC import ECC
from sender import Sender
from receiver import Receiver

class ECCApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ECC App")
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
        self.frame0.configure(bg="#f0f0f0")  # Màu nền dịu

        title = tk.Label(self.frame0, text="Chọn chế độ sử dụng", font=("Arial", 20, "bold"),
                        bg="#f0f0f0", fg="#333")
        title.grid(row=0, column=0, columnspan=2, pady=30)

        encrypt_btn = tk.Button(self.frame0, text="🔐  Mã hóa (Người gửi)", command=self.show_frame1,
                                font=("Arial", 14), width=30, height=2, bg="#4CAF50", fg="white", bd=0)
        encrypt_btn.grid(row=1, column=0, padx=20, pady=10)

        decrypt_btn = tk.Button(self.frame0, text="🔓  Giải mã (Người nhận)", command=self.show_frame2,
                                font=("Arial", 14), width=30, height=2, bg="#2196F3", fg="white", bd=0)
        decrypt_btn.grid(row=2, column=0, padx=20, pady=10)


    def setup_frame1(self):
        self.frame1.configure(bg="#ffffff")

        tk.Label(self.frame1, text="📤 Giao diện người gửi", font=("Arial", 18, "bold"), bg="#ffffff").grid(row=0, column=0, columnspan=2, pady=15)

        tk.Label(self.frame1, text="Nhập nội dung cần mã hóa:", font=("Arial", 12), bg="#ffffff").grid(row=1, column=0, sticky="w", padx=10)
        self.input_text1 = tk.Text(self.frame1, height=4, width=50, font=("Arial", 11))
        self.input_text1.grid(row=2, column=0, padx=10, pady=5)

        button_frame = tk.Frame(self.frame1, bg="#ffffff")
        button_frame.grid(row=3, column=0, pady=10)

        tk.Button(button_frame, text="🔑 Tạo khóa riêng", command=self.create_private_key,
                font=("Arial", 12), width=25, bg="#ff9800", fg="white", bd=0).pack(pady=4)
        tk.Button(button_frame, text="💾 Lưu khóa riêng", command=self.save_private_key,
                font=("Arial", 12), width=25, bg="#9c27b0", fg="white", bd=0).pack(pady=4)
        tk.Button(button_frame, text="🔐 Mã hóa", command=self.encrypt_message,
                font=("Arial", 12), width=25, bg="#4CAF50", fg="white", bd=0).pack(pady=4)

        tk.Label(self.frame1, text="Kết quả mã hóa (hex):", font=("Arial", 12), bg="#ffffff").grid(row=4, column=0, sticky="w", padx=10)
        self.output_text1 = tk.Text(self.frame1, height=4, width=50, font=("Arial", 11))
        self.output_text1.grid(row=5, column=0, padx=10, pady=5)

        tk.Button(self.frame1, text="⬅ Quay lại", command=self.show_frame0,
                font=("Arial", 12), width=20, bg="#607d8b", fg="white", bd=0).grid(row=6, column=0, pady=15)


    def setup_frame2(self):
        self.frame2.configure(bg="#ffffff")

        tk.Label(self.frame2, text="📥 Giao diện người nhận", font=("Arial", 18, "bold"), bg="#ffffff").grid(row=0, column=0, columnspan=2, pady=15)

        tk.Button(self.frame2, text="📂 Tải khóa riêng", command=self.load_private_key,
                font=("Arial", 12), width=25, bg="#9c27b0", fg="white", bd=0).grid(row=1, column=0, pady=5)

        tk.Button(self.frame2, text="🔓 Giải mã", command=self.decrypt_message,
                font=("Arial", 12), width=25, bg="#2196F3", fg="white", bd=0).grid(row=2, column=0, pady=5)

        tk.Label(self.frame2, text="Dữ liệu đã mã hóa (hex):", font=("Arial", 12), bg="#ffffff").grid(row=3, column=0, sticky="w", padx=10)
        self.encrypted_view = tk.Text(self.frame2, height=4, width=50, font=("Arial", 11))
        self.encrypted_view.grid(row=4, column=0, padx=10, pady=5)

        tk.Label(self.frame2, text="Kết quả giải mã:", font=("Arial", 12), bg="#ffffff").grid(row=5, column=0, sticky="w", padx=10)
        self.decrypted_view = tk.Text(self.frame2, height=4, width=50, font=("Arial", 11))
        self.decrypted_view.grid(row=6, column=0, padx=10, pady=5)

        tk.Button(self.frame2, text="⬅ Quay lại", command=self.show_frame0,
                font=("Arial", 12), width=20, bg="#607d8b", fg="white", bd=0).grid(row=7, column=0, pady=15)


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
