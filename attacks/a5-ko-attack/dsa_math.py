import random, math
from sympy import isprime, factorint
from sympy.ntheory.modular import crt

def find_small_subgroup_params(q_bits, p_bits=1024, seed=None, max_attempts=2000):
    rng = random.Random(seed)
    for _ in range(max_attempts):
        q = rng.getrandbits(q_bits) | (1 << (q_bits-1)) | 1
        
        if not isprime(q): 
            continue
        
        h_bits = p_bits - q_bits - 1
        for _ in range(2000):
            h = rng.getrandbits(h_bits) | (1 << (h_bits-1)) | 1
            p = 2*q*h + 1
            
            if p.bit_length() != p_bits: 
                continue
            
            if isprime(p):
                for _ in range(50):
                    z = rng.randrange(2, p-1)
                    g = pow(z, (p-1)//q, p)
                    if g != 1 and pow(g, q, p) == 1:
                        return p, q, g
    
    raise RuntimeError("nie znaleziono parametrow small-subgroup")

def construct_smooth_prime(bits, factor_bits=18, seed=None, max_attempts=2000):
    rng = random.Random(seed)
    for attempt in range(max_attempts):
        product = 2
        factors = [2]
        while True:
            remaining_bits = bits - product.bit_length()
            if remaining_bits <= 0:
                break
            
            fb = min(factor_bits, max(2, remaining_bits))
            f = rng.getrandbits(fb) | 1
            
            if f < 3 or not isprime(f):
                continue
            
            product *= f
            factors.append(f)
        p = product + 1
        
        if p.bit_length() == bits and isprime(p):
            return p, factors
    
    raise RuntimeError("nie znaleziono gladkiej liczby pierwszej")

def find_full_generator(p, factors_dict, seed=None):
    rng = random.Random(seed)
    for _ in range(500):
        g = rng.randrange(2, p-1)
        if all(pow(g, (p-1)//f, p) != 1 for f in factors_dict):
            return g
    
    raise RuntimeError("nie znaleziono generatora")

def bsgs(g, h, m, p):
    n = int(math.isqrt(m)) + 1
    table = {}
    e = 1
    
    for j in range(n):
        table[e] = j
        e = (e * g) % p
    
    g_inv_n = pow(pow(g, n, p), -1, p)
    gamma = h
    
    for i in range(n + 1):
        if gamma in table:
            cand = i * n + table[gamma]
            if cand < m: 
                return cand
        gamma = (gamma * g_inv_n) % p
    
    return None

def pohlig_hellman(h, g, p, factors_dict):
    n = p - 1
    residues, moduli = [], []
    
    for f, e in factors_dict.items():
        pe = f**e
        gi = pow(g, n // pe, p)
        hi = pow(h, n // pe, p)
        xi = bsgs(gi, hi, pe, p)
        if xi is None: 
            return None
        residues.append(xi); moduli.append(pe)
    
    result, mod = crt(moduli, residues)
    
    return int(result) % int(mod)

def dsa_sign(h_val, x, p, q, g, rng):
    while True:
        k = rng.randrange(1, q)
        r = pow(g, k, p) % q
        if r == 0: 
            continue
        s = (pow(k, -1, q) * (h_val + x*r)) % q
        if s == 0: 
            continue
        return r, s, k

def dsa_verify(h_val, r, s, p, q, g, y):
    if not (0 < r < q and 0 < s < q): 
        return False
    
    w = pow(s, -1, q)
    v = (pow(g,(h_val*w)%q,p) * pow(y,(r*w)%q,p)) % p % q
    
    return v == r