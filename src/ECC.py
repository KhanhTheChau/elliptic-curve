import hashlib
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