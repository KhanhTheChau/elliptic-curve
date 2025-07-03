import random
from collections import defaultdict
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import numpy as np

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

def generate_a_b(n):
    while True:
        a = random.randint(1, n - 1)
        b = random.randint(1, n - 1)
        delta = (4 * pow(a, 3, n) + 27 * pow(b, 2, n)) % n
        if delta != 0:
            return a, b

def quadratic_residues(n):
    d = defaultdict(list)
    for i in range(n):
        r = pow(i, 2, n)
        d[r].append(i)
    return d

def find_points_on_curve(n, a, b):
    residues = quadratic_residues(n)
    points = []
    for x in range(n):
        rhs = (pow(x, 3, n) + a * x + b) % n
        if rhs in residues:
            for y in residues[rhs]:
                points.append((x, y))
    return points

def inverse_mod(k, p):
    return pow(k, -1, p)

def point_add(P, Q, a, p):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0: return None
    if x1 != x2:
        m = ((y2 - y1) * inverse_mod(x2 - x1, p)) % p
    else:
        if y1 == 0: return None
        m = ((3 * x1**2 + a) * inverse_mod(2 * y1, p)) % p
    x3 = (m**2 - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_multiply(k, P, a, p):
    result = None
    addend = P
    while k > 0:
        if k & 1:
            result = point_add(result, addend, a, p)
        addend = point_add(addend, addend, a, p)
        k >>= 1
    return result

def encrypt(M, G, Q, a, p):
    k = random.randint(1, p - 1)
    C1 = scalar_multiply(k, G, a, p)
    kQ = scalar_multiply(k, Q, a, p)
    C2 = point_add(M, kQ, a, p)
    return C1, C2

def decrypt(C1, C2, d, a, p):
    dC1 = scalar_multiply(d, C1, a, p)
    neg_dC1 = (dC1[0], (-dC1[1]) % p)
    return point_add(C2, neg_dC1, a, p)

def encode_message_to_points(message, a, b, p):
    all_points = find_points_on_curve(p, a, b)
    point_map = defaultdict(list)
    for x, y in all_points:
        point_map[x].append((x, y))
    points = []
    offsets = []
    for char in message:
        base_x = ord(char)
        for offset in range(100):
            x_try = (base_x + offset) % p
            if point_map[x_try]:
                points.append(point_map[x_try][0])
                offsets.append(offset)
                break
        else:
            raise ValueError("Không tìm được điểm cho ký tự: " + char)
    return points, offsets

def decode_points_to_message(points, offsets):
    message = ''
    for (x, _), offset in zip(points, offsets):
        char_code = (x - offset) % 256
        message += chr(char_code)
    return message

def plot_curve_3d(p, a, b, all_points, highlight_points=None, highlight_labels=None):
    fig = plt.figure()
    ax = fig.add_subplot(111, projection='3d')

    X, Y = zip(*all_points)
    Z = [0] * len(all_points)
    ax.scatter(X, Y, Z, c='blue', s=15, label='Điểm trên đường cong')

    if highlight_points:
        hx, hy, hz = [], [], []
        for i, (x, y) in enumerate(highlight_points):
            hx.append(x)
            hy.append(y)
            hz.append(1)
            if highlight_labels:
                ax.text(x, y, 1.5, highlight_labels[i], fontsize=10, color='black')
        ax.scatter(hx, hy, hz, c='red', s=80, label='Điểm ánh xạ', edgecolors='black')

    ax.set_xlabel('x')
    ax.set_ylabel('y')
    ax.set_zlabel('z')
    ax.set_title(f'Đường cong elliptic: y² ≡ x³ + {a}x + {b} mod {p}')
    ax.legend()
    plt.show()

def demo_full():
    p = 17
    while not is_large_prime(p):
        p += 1
    a, b = generate_a_b(p)
    all_points = find_points_on_curve(p, a, b)
    G = random.choice(all_points)
    d = random.randint(1, p - 1)
    Q = scalar_multiply(d, G, a, p)
    message = "HELLO"
    M_points, offsets = encode_message_to_points(message, a, b, p)
    ciphertexts = []
    for M in M_points:
        C1, C2 = encrypt(M, G, Q, a, p)
        ciphertexts.append((C1, C2))
    decrypted_points = []
    for C1, C2 in ciphertexts:
        M = decrypt(C1, C2, d, a, p)
        decrypted_points.append(M)
    recovered_message = decode_points_to_message(decrypted_points, offsets)
    print("Original:", message)
    print("ciphertexts:", ciphertexts)
    print("Recovered:", recovered_message)
    plot_curve_3d(p, a, b, all_points, highlight_points=M_points, highlight_labels=list(message))

demo_full()
