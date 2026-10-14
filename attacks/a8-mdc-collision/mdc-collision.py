import argparse
import hashlib
import io
import os
import subprocess
import sys
import time
from pathlib import Path

import age.file as age_file
import age.keys.password as age_pw
import age.recipients.scrypt

def ok(m):   print(f"  [OK] {m}")
def fail(m): print(f"  [!!] {m}")
def warn(m): print(f"  [!] {m}")

MDC_TRAILER = b"\xD3\x14"  # RFC 4880 par. 5.14: tag(0xD3) + length(0x14=20)


def sha1(data):   return hashlib.sha1(data).hexdigest()
def sha256(data): return hashlib.sha256(data).hexdigest()

def gpg_run(args):
    t0 = time.perf_counter()
    r = subprocess.run(args, capture_output=True)
    dt = time.perf_counter() - t0
    return r.returncode, r.stdout, r.stderr.decode("utf-8", "replace").strip(), dt

def gpg_encrypt(infile, outfile, passphrase):
    args = ["gpg", "--batch", "--yes", "--passphrase", passphrase,
            "--pinentry-mode", "loopback", "--no-symkey-cache",
            "--cipher-algo", "AES128", "-c", "-o", str(outfile), str(infile)]
    rc, _, err, _ = gpg_run(args)
    
    if rc != 0:
        raise RuntimeError(f"gpg encrypt failed: {err}")

def gpg_decrypt(infile, passphrase, ignore_mdc=False):
    args = ["gpg", "--batch", "--passphrase", passphrase,
            "--pinentry-mode", "loopback", "--no-symkey-cache"]
    
    if ignore_mdc:
        args.append("--ignore-mdc-error")
    
    args += ["-d", str(infile)]
    return gpg_run(args)

def gpg_session_key(infile, passphrase):
    args = ["gpg", "--batch", "--passphrase", passphrase,
            "--pinentry-mode", "loopback", "--no-symkey-cache",
            "--show-session-key", "-d", str(infile)]
    
    _, _, err, _ = gpg_run(args)
    
    for line in err.split("\n"):
        if "session key:" in line.lower() and "'" in line:
            return line.split("'")[1]
    
    return None


def verify_collision(data_a, data_b):
    print("Dwa rozne plaintexty o identycznym SHA-1\n")

    s1a, s1b = sha1(data_a), sha1(data_b)
    s256a, s256b = sha256(data_a), sha256(data_b)
    n_diff = sum(1 for x, y in zip(data_a, data_b) if x != y)
    first_diff = next((i for i, (x, y) in enumerate(zip(data_a, data_b)) if x != y), -1)
    
    print(f"Plaintext A: {len(data_a):,} B")
    print(f"Plaintext B: {len(data_b):,} B")
    print(f"\nBajtow roznych: {n_diff}; pierwsza roznica @ offset {first_diff}\n")

    print(f"  {'':14}SHA-1")
    print(f"  {'Plaintext A':<14}{s1a}")
    print(f"  {'Plaintext B':<14}{s1b}")
    print()
    print(f"  {'':14}SHA-256")
    print(f"  {'Plaintext A':<14}{s256a}")
    print(f"  {'Plaintext B':<14}{s256b}")
    print()
    collision_sha1 = (s1a == s1b)
    different_content = (data_a != data_b)
    if collision_sha1:
        fail(f"SHA-1 IDENTYCZNY dla obu plaintextow: {s1a}")
    else:
        warn("SHA-1 rozny — podane pliki nie tworza kolizji (sprawdz dane wejsciowe)")
    if s256a != s256b:
        ok("SHA-256 poprawnie rozroznia plaintexty (kolizja dotyczy tylko SHA-1)")
    if different_content:
        ok("Plaintexty maja rozna tresc — to nie sa te same dane")
    return {"collision": collision_sha1 and different_content, "sha1": s1a,
            "sha256_a": s256a, "sha256_b": s256b, "n_diff": n_diff, "first_diff": first_diff}


def verify_suffix_property(data_a, data_b):
    print("\nWlasnosc sufiksu Merkle-Damgard: kolizja a trailer MDC\n")
    print("Trailer pakietu MDC to bajty 0xD3 0x14 (RFC 4880 par. 5.14) — to sufiks.")
    print("Sprawdzamy, czy kolizja przenosi sie na wartosc obejmujaca trailer MDC:")

    mdc_a = sha1(data_a + MDC_TRAILER)
    mdc_b = sha1(data_b + MDC_TRAILER)
    
    print(f"  SHA-1(plaintext_A || 0xD314) = {mdc_a}")
    print(f"  SHA-1(plaintext_B || 0xD314) = {mdc_b}")
    print()
    
    suffix_collision = (mdc_a == mdc_b)
    if suffix_collision:
        fail("Kolizja PRZENOSI sie na trailer MDC — identyczna wartosc MDC dla obu")
        warn("Gdyby framing PGP byl pusty, MDC obu wiadomosci bylby bit-w-bit identyczny.")
        warn("Mechanizm integralnosci MDC NIE wiaze tresci: rozne dane = ta sama wartosc.")
    else:
        ok("Kolizja nie przenosi sie (nieoczekiwane dla poprawnej pary kolizyjnej)")
    return {"suffix_collision": suffix_collision, "mdc_a": mdc_a, "mdc_b": mdc_b}


def demonstrate_gpg_files(data_a, data_b, passphrase, workdir):
    print("\nDwa pliki .gpg rozna tresc, ten sam SHA-1 integralnosci\n")
    
    pa = workdir / "plaintext_a.bin"
    pb = workdir / "plaintext_b.bin"
    pa.write_bytes(data_a); pb.write_bytes(data_b)
    ga = workdir / "coll_a.gpg"
    gb = workdir / "coll_b.gpg"
    
    print("Szyfrowanie obu plaintextow tym samym haslem:")
    
    gpg_encrypt(pa, ga, passphrase)
    gpg_encrypt(pb, gb, passphrase)
    
    file_sha1_a = sha1(ga.read_bytes()); file_sha1_b = sha1(gb.read_bytes())
    sk_a = gpg_session_key(ga, passphrase)
    sk_b = gpg_session_key(gb, passphrase)
    
    ok(f"{ga.name}: {ga.stat().st_size} B")
    ok(f"{gb.name}: {gb.stat().st_size} B")
    
    print(f"Klucz sesji A: {sk_a}")
    print(f"Klucz sesji B: {sk_b}")
    print(f"SHA-1 pliku .gpg A: {file_sha1_a}")
    print(f"SHA-1 pliku .gpg B: {file_sha1_b}")

    print("\nDeszyfracja obu plikow:")
    rc_a, out_a, _, _ = gpg_decrypt(ga, passphrase)
    rc_b, out_b, _, _ = gpg_decrypt(gb, passphrase)
    dec_sha1_a = sha1(out_a); dec_sha1_b = sha1(out_b)
    
    if rc_a == 0 and rc_b == 0:
        ok("Oba pliki odszyfrowane poprawnie (MDC zweryfikowany przez GPG)")
    else:
        fail(f"Blad deszyfracji: rc_a={rc_a}, rc_b={rc_b}")
    
    print()
    print(f"  {'':18}{'rozmiar':>10}  SHA-1 odszyfrowanego plaintextu")
    print(f"  {'plaintext A':<18}{len(out_a):>10}  {dec_sha1_a}")
    print(f"  {'plaintext B':<18}{len(out_b):>10}  {dec_sha1_b}")
    print()
    
    content_differs = (out_a != out_b)
    sha1_collides = (dec_sha1_a == dec_sha1_b)
    
    if content_differs and sha1_collides:
        fail("Odszyfrowane tresci sa ROZNE, ale ich SHA-1 jest IDENTYCZNY.")
    elif not content_differs:
        warn("Odszyfrowane tresci identyczne, sprawdz dane wejsciowe.")
    else:
        warn("SHA-1 nie koliduje po deszyfracji, sprawdz pare kolizyjna.")
    return {"gpg_decrypt_ok": rc_a == 0 and rc_b == 0,
            "file_sha1_a": file_sha1_a, "file_sha1_b": file_sha1_b,
            "session_key_a": sk_a, "session_key_b": sk_b,
            "dec_sha1_a": dec_sha1_a, "dec_sha1_b": dec_sha1_b,
            "content_differs": content_differs, "sha1_collides": sha1_collides,
            "gpg_a": ga, "gpg_b": gb}


def analyze_prefix_barrier(gpg_results):
    print("\nBariera pelnego zawiniecia MDC (uczciwa analiza)\n")
    print("Pelna wartosc MDC liczona przez GPG to:")
    print(f"     MDC = SHA-1( 0x01 || prefix_CFB[18B] || literal_packet || 0xD314 )\n")
    print("Klucze sesji obu wiadomosci roznia sie:")
    print(f"  A: {gpg_results['session_key_a']}")
    print(f"  B: {gpg_results['session_key_b']}")
    warn("prefix CFB jest losowy i rozny dla kazdej wiadomosci\n")

def demonstrate_age(data_a, data_b, passphrase, workdir):
    print("\nKontrprzyklad: age (ChaCha20-Poly1305)\n")
    print("age nie uzywa funkcji skrotu jako kodu integralnosci. Stosuje Poly1305")

    key = age_pw.PasswordKey(passphrase)
    def age_encrypt(data):
        buf = io.BytesIO()
        enc = age_file.Encryptor([key], buf)
        enc.write(data); enc.close()
        return buf.getvalue()
    ct_a = age_encrypt(data_a); ct_b = age_encrypt(data_b)
    
    print(f"Zaszyfrowano przez age: A={len(ct_a)} B, B={len(ct_b)} B\n")

    print("Test 1: Poprawna deszyfracja obu wiadomosci age")
    dec_a = age_file.Decryptor([key], io.BytesIO(ct_a)).read()
    dec_b = age_file.Decryptor([key], io.BytesIO(ct_b)).read()
    if dec_a == data_a and dec_b == data_b:
        ok("Oba pliki age odszyfrowane poprawnie (tag Poly1305 zweryfikowany)")
    
    print("\nTest 2: Czy kolizja SHA-1 powoduje kolizje tagu integralnosci age?")
    tag_a = ct_a[-16:]; tag_b = ct_b[-16:]
    print(f"  Tag Poly1305 A (ostatnie 16B): {tag_a.hex()}")
    print(f"  Tag Poly1305 B (ostatnie 16B): {tag_b.hex()}")
    if tag_a != tag_b:
        ok("Tagi integralnosci age ROZNE — kolizja SHA-1 nie przenosi sie na Poly1305")
        ok("Poly1305 nie jest funkcja skrotu; nie istnieje analogiczny atak kolizyjny")
    else:
        warn("Tagi identyczne (nieoczekiwane)")
    
    print("\nTest 3: Modyfikacja 1 bajtu payloadu age (brak odpowiednika --ignore-mdc-error)")
    ct_mod = bytearray(ct_a)
    idx = len(ct_mod) - 20
    orig = ct_mod[idx]; ct_mod[idx] ^= 0x01
    print(f"  Zmodyfikowano bajt[{idx}]: 0x{orig:02x} -> 0x{ct_mod[idx]:02x}")
    try:
        r = age_file.Decryptor([key], io.BytesIO(bytes(ct_mod))).read()
        if r:
            fail(f"age UJAWNILO dane mimo modyfikacji! ({len(r)} B)")
            rejected = False
        else:
            ok("age zwrocilo 0 bajtow"); rejected = True
    except Exception as e:
        ok(f"age odrzucilo plik: {type(e).__name__}")
        ok("Brak flagi pozwalajacej zignorowac blad integralnosci — weryfikacja wymuszona")
        rejected = True
    return {"age_ok": dec_a == data_a and dec_b == data_b,
            "tags_differ": tag_a != tag_b, "age_rejects_modified": rejected}

def main():
    ap = argparse.ArgumentParser(description="Atak 8 — SHA-1 MDC Collision PoC (OpenPGP vs age)")
    ap.add_argument("--collision-a", required=True, type=Path, help="Pierwszy plik z pary kolizyjnej SHA-1")
    ap.add_argument("--collision-b", required=True, type=Path, help="Drugi plik z pary kolizyjnej SHA-1")
    ap.add_argument("--passphrase", required=True, help="Haslo do plikow .gpg i age")
    ap.add_argument("--workdir", default="/home/karas/Magisterka/CryptoKey/docs/atack-vectors", type=Path, help="Katalog roboczy")
    args = ap.parse_args()
    
    for f in (args.collision_a, args.collision_b):
        if not f.exists():
            print(f"Blad: plik {f} nie istnieje.", file=sys.stderr); sys.exit(1)
    
    args.workdir.mkdir(parents=True, exist_ok=True)
    data_a = args.collision_a.read_bytes()
    data_b = args.collision_b.read_bytes()

    print(f"Para kolizyjna: {args.collision_a.name}, {args.collision_b.name}")
    coll = verify_collision(data_a, data_b)
    
    if not coll["collision"]:
        warn("Podane pliki nie tworza poprawnej kolizji SHA-1 — przerywam dalsze czesci.")
        sys.exit(2)
    
    suffix = verify_suffix_property(data_a, data_b)
    gpg = demonstrate_gpg_files(data_a, data_b, args.passphrase, args.workdir)
    analyze_prefix_barrier(gpg)
    age_r = demonstrate_age(data_a, data_b, args.passphrase.encode(), args.workdir)

if __name__ == "__main__":
    main()