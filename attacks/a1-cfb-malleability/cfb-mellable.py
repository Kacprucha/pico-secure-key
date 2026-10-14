import subprocess, os, tempfile, sys

PGP_FILE = "target.gpg"
AGE_FILE = "target.age" 
AGE_KEY = "age.key"
PASSPHRASE = "demo" 
MODIFY_BYTE = 50

def gpg_decrypt(ct_bytes):
    with tempfile.NamedTemporaryFile(suffix='.gpg', delete=False) as f:
        f.write(ct_bytes); tmp = f.name
    proc = subprocess.run(
        ["gpg", "--batch",
         "--passphrase", PASSPHRASE, "--allow-old-cipher-algos",
         "--decrypt", tmp], capture_output=True)
    os.unlink(tmp)
    return proc.stdout, proc.returncode


def age_decrypt(ct_bytes):
    with tempfile.NamedTemporaryFile(suffix='.age', delete=False) as f:
        f.write(ct_bytes); tmp = f.name
    proc = subprocess.run(
        ["age", "--decrypt", "-i", AGE_KEY, "-o", "-", tmp],
        capture_output=True)
    os.unlink(tmp)
    return proc.stdout, proc.returncode, proc.stderr.decode()


def check_files():
    missing = [f for f in [PGP_FILE, AGE_FILE, AGE_KEY] if not os.path.exists(f)]
    if missing:
        print(f"Brak plików: {missing}")
        sys.exit(1)


def main():
    check_files()

    with open(PGP_FILE, "rb") as f:
        pgp_ct = bytearray(f.read())
    with open(AGE_FILE, "rb") as f:
        age_ct = bytearray(f.read())

    print(f"\nOryginalny plaintext (referencja)\n")
    pt_orig, rc_orig = gpg_decrypt(bytes(pgp_ct))
    print(f"gpg exit code: {rc_orig}")
    print(pt_orig.decode(errors='replace'))

    print("\nModyfikacja ciphertextu PGP — brak wykrycia manipulacji\n")

    pgp_mod = bytearray(pgp_ct)
    pgp_mod[MODIFY_BYTE] ^= 0x42
    pt_mod, rc_mod = gpg_decrypt(bytes(pgp_mod))

    print(f"gpg exit code: {rc_mod} ← ostrzeżenie nie błąd kryptograficzny")
    print(f"Plaintext na stdout zmodyfikowany ale odczytany przez gpg:")
    print(pt_mod.decode(errors='replace'))

    changed = [i for i, (a, b) in enumerate(zip(bytearray(pt_orig), bytearray(pt_mod))) if a != b]
    print(f"Zmienionych bajtów plaintextu: {len(changed)} z {len(pt_orig)}\n")

    print("Ta sama modyfikacja na pliku age")

    hdr_end = bytes(age_ct).find(b"---\n") + 4
    age_mod = bytearray(age_ct)
    age_payload_off = hdr_end + 30
    age_mod[age_payload_off] ^= 0x42

    print(f"Operacja: CT[{age_payload_off}] ^= 0x42  (bajt w payloadzie age)")
    print()

    pt_age, rc_age, stderr_age = age_decrypt(bytes(age_mod))
    print(f"age exit code: {rc_age}  ← błąd, odmowa deszyfracji")
    print(f"age stdout: '{pt_age.decode(errors='replace')[:60]}'  ← puste")
    print(f"age stderr: {stderr_age.strip()[:80]}")

if __name__ == "__main__":
    main()