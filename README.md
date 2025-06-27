# Elliptic Curve

**Tìm hiểu về hệ mật dựa trên đường cong Elliptic (Elliptic Curve Cryptography - ECC)**

Repo này chứa tài liệu và mã nguồn minh họa cho đề tài nghiên cứu hệ mật mã dựa trên đường cong elliptic – một nhánh quan trọng trong lĩnh vực mật mã học hiện đại. ECC cung cấp giải pháp bảo mật hiệu quả với độ dài khóa ngắn, phù hợp cho các thiết bị hạn chế tài nguyên như điện thoại, thẻ thông minh và thiết bị IoT.

---

## 📘 Giới thiệu

Elliptic Curve Cryptography (ECC) là một phương pháp mã hóa khóa công khai dựa trên toán học đường cong elliptic trên trường hữu hạn. ECC được sử dụng để:

- Sinh khóa công khai và khóa riêng
- Ký và xác minh chữ ký số (ECDSA)
- Trao đổi khóa (ECDH)
- Mã hóa và giải mã dữ liệu

So với các hệ mật như RSA hoặc DSA, ECC cung cấp mức độ bảo mật tương đương nhưng với độ dài khóa nhỏ hơn đáng kể, giúp tiết kiệm tài nguyên và nâng cao hiệu suất.

---

## 📂 Cấu trúc thư mục

elliptic-curve/
│
├── docs/ # Tài liệu lý thuyết, slide thuyết trình, báo cáo
├── src/ # Mã nguồn Python minh họa ECC
│ ├── xxx.py 
│ ├── main.py 
│ └── xxx.py 
├── requirements.txt # Các thư viện cần cài đặt
└── README.md # Mô tả dự án


---

## ⚙️ Cài đặt

### Yêu cầu

- Python 3.8 trở lên
- pip

### Cài đặt thư viện

```bash
pip install -r requirements.txt
```