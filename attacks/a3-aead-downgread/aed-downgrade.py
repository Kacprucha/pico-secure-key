import subprocess, os, tempfile, sys

PGP_FILE = "aead.gpg"
AGE_FILE = "plaintext.age"
AGE_KEY = "age.key"
PASSPHRASE = "demo"

def gpg_list_packets(filepath):
    proc = subprocess.run(
        ["gpg", "--list-packets", filepath],
        capture_output=True)
    return proc.stdout.decode() + proc.stderr.decode()


def gpg_decrypt(filepath, passphrase=None):
    cmd = ["gpg", "--allow-old-cipher-algos", "--batch"]
    if passphrase:
        cmd += ["--passphrase", passphrase]
    cmd += ["--decrypt", filepath]
    proc = subprocess.run(cmd, capture_output=True)
    return proc.stdout, proc.returncode, proc.stderr.decode()


def age_decrypt(ct_bytes):
    with tempfile.NamedTemporaryFile(suffix='.age', delete=False) as f:
        f.write(ct_bytes); tmp = f.name
    proc = subprocess.run(
        ["age", "--decrypt", "-i", AGE_KEY, "-o", "-", tmp],
        capture_output=True)
    os.unlink(tmp)
    return proc.stdout, proc.returncode, proc.stderr.decode()


def find_aead_ctb(data):
    for i, b in enumerate(data):
        if b == 0xD4:
            return i
    return None


def check_files():
    missing = [f for f in [PGP_FILE, AGE_FILE, AGE_KEY]
               if not os.path.exists(f)]
    if missing:
        print(f"Brak plików: {missing}")
        sys.exit(1)


def main():
    check_files()

    print("Oryginalny plik — format AEAD (tag=20)")

    with open(PGP_FILE, "rb") as f:
        ct_orig = bytearray(f.read())

    aead_offset = find_aead_ctb(ct_orig)
    if aead_offset is None:
        print(f"BŁĄD: plik {PGP_FILE} nie zawiera pakietu AEAD (tag=20).")
        sys.exit(1)

    print(gpg_list_packets(PGP_FILE))

    ctb = ct_orig[aead_offset]
    print(f"CTB byte [{aead_offset}] = 0x{ctb:02X} = {ctb:08b}b")
    print(f"tag = {ctb & 0x3F} → AEAD Encrypted Data Packet")
    print()

    stdout, rc, _ = gpg_decrypt(PGP_FILE, PASSPHRASE)
    print(f"Deszyfrowanie oryginału: exit={rc}")
    print(f"Plaintext: {stdout.decode().strip()[:80]}")

    print(" \nDowngrade — zmiana CTB byte 0xD4 → 0xD2")
    print(f"0xD4 = {0xD4:08b}b (tag=20, AEAD)")
    print(f"0xD2 = {0xD2:08b}b (tag=18, SEIPD CFB+MDC)")
    print(f"XOR = {0xD4^0xD2:08b}b = 0x{0xD4^0xD2:02X} (zmiana 2 bitów)")
    print()

    ct_downgraded = bytearray(ct_orig)
    ct_downgraded[aead_offset] = 0xD2

    with tempfile.NamedTemporaryFile(suffix='.gpg', delete=False, dir='.') as f:
        f.write(bytes(ct_downgraded))
        tmp_gpg = f.name

    print("Struktura po downgrade:")
    print(gpg_list_packets(tmp_gpg))

    print("Deszyfrowanie po downgrade")

    stdout2, rc2, stderr2 = gpg_decrypt(tmp_gpg, PASSPHRASE)
    os.unlink(tmp_gpg)

    print(f"\texit code: {rc2}")
    print(f"\tstderr: {stderr2.strip()}")
    print(f"\tstdout: '{stdout2.decode(errors='replace').strip()[:60]}'")
    print()

    if rc2 == 0 and stdout2:
        print("Podatność: GnuPG odszyfrował plik po downgrade bez błędu")
    elif rc2 != 0 and not stdout2:
        print("GnuPG blokuje odszyfrowanie")
    else:
        print(f"exit={rc2}, stdout={len(stdout2)}B")

    with open(AGE_FILE, "rb") as f:
        age_ct = bytearray(f.read())

    hdr_end = bytes(age_ct).find(b"---\n") + 4
    print("\nNagłówek pliku age:")
    for line in age_ct[:hdr_end].decode().splitlines():
        print(f"{line}")

    age_mod = bytearray(age_ct)
    x25519_pos = bytes(age_ct).find(b"-> X25519 ") + 15
    orig_b = age_mod[x25519_pos]
    age_mod[x25519_pos] ^= 0x06

    pt_age, rc_age, err_age = age_decrypt(bytes(age_mod))
    print(f"\nModyfikacja bajtu [{x25519_pos}] (jak w PGP):")
    print(f"age exit code: {rc_age}")
    print(f"age stdout: '{pt_age.decode(errors='replace')[:50]}'")
    print(f"age stderr: {err_age.strip()[:60]}")

if __name__ == "__main__":
    main()