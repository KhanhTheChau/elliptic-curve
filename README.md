# Elliptic Curve

# 🔐 ECC + AES Hybrid Encryption Demo (Python)

Đây là một dự án mô phỏng hệ mật mã lai sử dụng:
- **Elliptic Curve Cryptography (ECC)** để trao đổi khóa phiên an toàn,
- **AES (Advanced Encryption Standard)** để mã hóa thông điệp với tốc độ cao,
- Cùng một **giao diện người dùng bằng Tkinter** cho người gửi và người nhận.


## 📌 Mục tiêu dự án
- Mô phỏng thực tế quá trình **mã hóa - giải mã** thông điệp sử dụng thuật toán ECC kết hợp AES.
- Cung cấp giao diện đồ họa đơn giản, dễ sử dụng, phù hợp cho việc học và trình bày.
- Hiển thị và lưu các thông số mật mã (khóa riêng, điểm sinh, khóa công khai...).



## 🛠️ Công nghệ sử dụng
- **Python 3.10+**
- `Tkinter` – giao diện người dùng
- `pycryptodome` – thư viện mã hóa AES
- `hashlib` – SHA-256 cho tạo khóa AES
- `matplotlib` – (tùy chọn) để trực quan hóa đường cong elliptic




## Cài đặt thư viện

```bash
pip install -r requirements.txt
```

## Chạy ứng dụng

```bash
cd src
python app.py
```