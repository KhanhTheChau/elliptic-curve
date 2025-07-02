import random
from collections import defaultdict

def is_large_prime(n):
    if n in (2, 3):
        return True
    if n < 2 or n % 2 == 0:
        return False
    
    # miller
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

def find_points_on_curve(n):
    residues = quadratic_residues(n)
    a, b = generate_a_b(n)
    points = []

    for x in range(n):
        rhs = (pow(x, 3, n) + a * x + b) % n
        if rhs in residues:
            for y in residues[rhs]:
                points.append((x, y))

def inverse_mod(k, p):
    return pow(k, -1, p)

def point_add(P, Q, a, p):
    if P is None: return Q
    if Q is None: return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % p == 0: return None  

    if x1 != x2: m = ((y2 - y1) * inverse_mod(x2 - x1, p)) % p
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

    