import argparse
import math
import os
import struct
import subprocess
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=DeprecationWarning)

try:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def ok(m):   print(f"  [OK] {m}")
def fail(m): print(f"  [!!] {m}")
def warn(m): print(f"  [!]  {m}")

def des3_ecb_block(key: bytes, block: bytes) -> bytes:
    enc = Cipher(TripleDES(key), modes.ECB()).encryptor()
    return (enc.update(block) + enc.finalize())[:8]

def des3_ecb_bulk(key: bytes, data: bytes) -> bytes:
    enc = Cipher(TripleDES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()

def xor8(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def cfb64_encrypt(key: bytes, iv: bytes, plaintext_blocks: list[bytes]) -> list[bytes]:
    state = iv
    cipherblocks = []
    for p in plaintext_blocks:
        ks = des3_ecb_block(key, state)
        c = xor8(ks, p)
        cipherblocks.append(c)
        state = c
    return cipherblocks

def gpg_support_part(plaintext_file: Path):
    print("Wsparcie 3DES w GnuPG (cipher=2, blok 8B)\n")

    out_gpg = Path("target_3des.gpg")

    res = subprocess.run(
        ["gpg", "--batch", "--yes", "--passphrase", "demo",
         "--pinentry-mode", "loopback", "--no-symkey-cache",
         "--cipher-algo", "3DES", "--compress-algo", "none",
         "--allow-old-cipher-algos", "-c", "-o", str(out_gpg),
         str(plaintext_file)],
        capture_output=True
    )
    ok(f"gpg --cipher-algo 3DES: exit={res.returncode}, plik={out_gpg.stat().st_size} B")

    packets = subprocess.run(
        ["gpg", "--list-packets", str(out_gpg)], capture_output=True, text=True
    )
    output = packets.stdout + packets.stderr
    print()
    for line in output.strip().split("\n"):
        if any(k in line for k in ["symkey", "cipher", "salt", "encrypted", "mdc"]):
            print(f"     {line.strip()}")
    print()

    if "cipher 2" in output:
        fail("Pakiet SKESK zawiera cipher=2 (3DES)")
        fail(f"Rozmiar bloku 3DES: 64 bit = 8 bajtów")
    else:
        warn("Nie znaleziono cipher=2 w pakiecie — sprawdź logi powyżej")

    return out_gpg

def truncated_birthday_part():
    print("\nTruncated birthday na realnym 3DES\n")

    key = os.urandom(24)

    N = 16384
    counters = b"".join(i.to_bytes(8, "big") for i in range(N))
    ciphertext = des3_ecb_bulk(key, counters)
    blocks = [ciphertext[i*8:(i+1)*8] for i in range(N)]

    t0 = time.perf_counter()
    seen: dict[bytes, int] = {}
    collision: tuple[int, int] | None = None
    for idx, b in enumerate(blocks):
        prefix = b[:3]
        if prefix in seen:
            collision = (seen[prefix], idx)
            break
        seen[prefix] = idx
    dt = time.perf_counter() - t0

    if collision is None:
        warn("Nie znaleziono kolizji w {N} blokach — zwieksz N")
        return None

    i, j = collision
    print(f"Wygenerowano {N} bloków 3DES-ECB (8 B każdy = {N*8//1024} KB danych)")
    print(f"Kolizja truncated(24b) znaleziona w {j+1} blokach ({dt*1000:.1f} ms)")
    print()
    print(f"  i={i}: C[i] = {blocks[i].hex()}")
    print(f"  j={j}: C[j] = {blocks[j].hex()}")
    print(f"  C[i][:3] = C[j][:3]: {blocks[i][:3].hex()} = {blocks[j][:3].hex()}")
    print(f"  Pełna (64-bit) kolizja: {blocks[i] == blocks[j]}  (wymagałaby ~32 GB)")
    print()
    ok(f"Prawo urodzin działa dla kolizja w = {j+1} blokach")
    
    return j + 1  


def forced_collision_recovery_part():
    print("\nWymuszona pełna kolizja CFB-64 + XOR recovery\n")

    key = os.urandom(24)
    iv  = bytes(8)

    P = [os.urandom(8) for _ in range(7)]
    P[3] = b"GET / HT"
    P[6] = b"SECRET!!"

    CT = cfb64_encrypt(key, iv, P[:5])

    ek_c4 = des3_ecb_block(key, CT[4])
    P5_forced = xor8(CT[2], ek_c4)
    P[5] = P5_forced

    CT += cfb64_encrypt(key, CT[4], [P5_forced, P[6]])

    print(f"  C[2] = {CT[2].hex()}  (kotwica kolizji — blok odniesienia)")
    print(f"  C[5] = {CT[5].hex()}  (wymuszona kolizja z C[2])")
    print(f"  C[2] == C[5]: {CT[2] == CT[5]}")
    print()

    xor_ct = xor8(CT[3], CT[6])
    xor_pt = xor8(P[3], P[6])

    print(f"  P[3] XOR P[6] = {xor_pt.hex()}  (nieznane atakującemu — P[6] jest sekretem)")
    print(f"  C[3] XOR C[6] = {xor_ct.hex()}  (obserwowalne z samego szyfrogramu)")
    print(f"  Równość:       {xor_ct == xor_pt}")
    print()

    P6_rec = xor8(xor8(P[3], CT[3]), CT[6])

    fail("Gdy C[i]=C[j], to P[i+1] XOR P[j+1] = C[i+1] XOR C[j+1] (bez klucza)")
    fail("Znając P[3] (blok znany), atakujący odzyskuje P[6] (blok tajny):")
    print(f"\n     P[3] znany:   {P[3]}")
    print(f"     P[6] sekret:  {P[6]}")
    print(f"     P[6] odzysk:  {P6_rec}")
    print(f"     Odzysk poprawny: {P6_rec == P[6]}\n")

    return P[3], P[6], P6_rec, xor_ct

def age_counterexample_part():
    print("\nKontrprzykład: age (ChaCha20-Poly1305)\n")

    print("age używa ChaCha20-Poly1305 (IETF RFC 8439), szyfr strumieniowy.")
    print()

    import age.file, age.keys.password, io
    msg = b"Tajny dokument SWEET32 test"
    results = []
    for _ in range(2):
        k = age.keys.password.PasswordKey(os.urandom(16))
        buf = io.BytesIO()
        enc = age.file.Encryptor([k], buf)
        enc.write(msg)
        enc.close()
        results.append(buf.getvalue())

    fail("Brak odpowiednika ataku SWEET32 w age")
    
    salt0 = results[0].split(b'\n')[1].split(b' ')[2]
    salt1 = results[1].split(b'\n')[1].split(b' ')[2]
    assert salt0 != salt1, "BUG: sole scrypt są identyczne!"
    
    ok(f"Dwie losowe wiadomości age mają różne sole scrypt (16 B, base64): {salt0.decode()} ≠ {salt1.decode()}")

    return results

def main():
    ap = argparse.ArgumentParser(description="SWEET32 / 3DES Birthday Attack")
    ap.add_argument("--plaintext-file", required=True, type=Path, help="Plik z plaintext do zaszyfrowania 3DES (dowolny plik)")
    args = ap.parse_args()

    if not args.plaintext_file.exists():
        import sys; print(f"Błąd: {args.plaintext_file} nie istnieje", file=sys.stderr)
        sys.exit(1)

    gpg_support_part(args.plaintext_file)
    
    collision_at = truncated_birthday_part()
    _, _, p6_rec, xor_ct = forced_collision_recovery_part()
    xor_ok = (p6_rec is not None)
    
    age_counterexample_part()


if __name__ == "__main__":
    main()