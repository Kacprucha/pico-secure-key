import sys, os, re, time, hashlib, base64, argparse, subprocess, urllib.request
from pathlib import Path
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

def sha1_s2k(password: bytes, salt: bytes, count: int, key_len=32) -> bytes:
    data = salt + password
    gen, ctx = b"", 0
    while len(gen) < key_len:
        h = hashlib.sha1()
        h.update(b"\x00" * ctx)
        rem = count
        while rem > 0:
            take = min(rem, len(data))
            h.update(data[:take]); rem -= take
        gen += h.digest(); ctx += 1
    return gen[:key_len]


def aes_ecb(key: bytes, block: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    e = c.encryptor()
    return e.update(block) + e.finalize()


def pgp_quick_check(key: bytes, payload: bytes) -> bool:
    FRE = aes_ecb(key, b"\x00" * 16)
    PREFIX = bytes(a ^ b for a, b in zip(payload[:16], FRE))
    FRE2 = aes_ecb(key, payload[:16])
    QC = bytes(a ^ b for a, b in zip(payload[16:18], FRE2[:2]))
    return PREFIX[14:16] == QC


def age_verify(password: str, salt: bytes, N: int, efk: bytes) -> bool:
    try:
        label = b"age-encryption.org/v1/scrypt"
        kdf = Scrypt(salt=label + salt, length=32, n=N, r=8, p=1)
        wrap = kdf.derive(password.encode() if isinstance(password, str) else password)
        ChaCha20Poly1305(wrap).decrypt(b"\x00" * 12, efk, None)
        return True
    except (InvalidTag, Exception):
        return False

def parse_pgp(path: str) -> dict:
    raw = Path(path).read_bytes()
    pos = 0
    ctb = raw[pos]; pos += 1
    if ctb & 0x40:
        plen = raw[pos]; pos += 1
        if 192 <= plen < 224:
            plen = ((plen - 192) << 8) + raw[pos] + 192; pos += 1
    else:
        lb = [1, 2, 4, 1][ctb & 0x03]
        plen = int.from_bytes(raw[pos:pos+lb], 'big'); pos += lb
    skesk = raw[pos:pos+plen]; pos += plen

    if skesk[2] != 3 or skesk[3] != 2:
        raise ValueError("Plik nie używa SHA-1 S2K. Użyj --s2k-digest-algo SHA1.")

    salt = skesk[4:12]
    cc  = skesk[12]
    count = (16 + (cc & 15)) << ((cc >> 4) + 6)

    ctb2 = raw[pos]; pos += 1
    if ctb2 & 0x40:
        len2 = raw[pos]; pos += 1
        if 192 <= len2 < 224:
            len2 = ((len2 - 192) << 8) + raw[pos] + 192; pos += 1
    else:
        lb2 = [1, 2, 4, 1][ctb2 & 0x03]
        len2 = int.from_bytes(raw[pos:pos+lb2], 'big'); pos += lb2
    pos += 1
    return {"salt": salt, "count": count, "payload": raw[pos:]}


def parse_age(path: str) -> dict:
    raw  = Path(path).read_bytes()
    sep  = raw.find(b"---")
    lines = raw[:sep].decode(errors="replace").splitlines()
    for i, line in enumerate(lines):
        if line.startswith("-> scrypt"):
            parts = line.split()
            salt = base64.b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
            log2_N = int(parts[3])
            efk = base64.b64decode(lines[i+1] + "=" * (-len(lines[i+1]) % 4))
            return {"salt": salt, "N": 2**log2_N, "log2_N": log2_N, "efk": efk}
    raise ValueError("Brak stancy scrypt — użyj 'age --passphrase'.")

def attack_pgp_cpu(pgp: dict, wordlist: list) -> tuple:
    salt, count, payload = pgp["salt"], pgp["count"], pgp["payload"]
    times = []
    t_total = time.perf_counter()

    print(f"  {'#':>5}  {'Hasło':<16}  {'SHA-1 S2K [ms]':>15}  Wynik")
    print(f"  {'─'*5}  {'─'*16}  {'─'*15}  {'─'*12}")

    for i, pwd in enumerate(wordlist, 1):
        t0 = time.perf_counter()
        key = sha1_s2k(pwd.encode(), salt, count)
        ms = (time.perf_counter() - t0) * 1000
        times.append(ms)
        match = pgp_quick_check(key, payload)
        print(f"  {i:>5}  {pwd:<16}  {ms:>15.1f}  {'ZNALEZIONO!' if match else 'x'}")
        if match:
            return pwd, time.perf_counter() - t_total, times

    return None, time.perf_counter() - t_total, times


def attack_age_cpu(age: dict, wordlist: list) -> tuple:
    salt, N, efk = age["salt"], age["N"], age["efk"]
    times = []
    t_total = time.perf_counter()

    print(f"  {'#':>5}  {'Hasło':<16}  {'scrypt [ms]':>12}  Wynik")
    print(f"  {'─'*5}  {'─'*16}  {'─'*12}  {'─'*12}")

    for i, pwd in enumerate(wordlist, 1):
        t0 = time.perf_counter()
        match = age_verify(pwd, salt, N, efk)
        ms = (time.perf_counter() - t0) * 1000
        times.append(ms)
        print(f"  {i:>5}  {pwd:<16}  {ms:>12.1f}  {'ZNALEZIONO!' if match else 'x'}")
        if match:
            return pwd, time.perf_counter() - t_total, times

    return None, time.perf_counter() - t_total, times

def parse_speed(text: str) -> float | None:
    mult = {"H": 1, "kH": 1e3, "MH": 1e6, "GH": 1e9, "TH": 1e12}
    pat  = re.compile(r'Speed\.#[\d*]+\.*:\s+([\d.]+)\s+(H|kH|MH|GH|TH)/s')
    vals = []
    for m in pat.finditer(text):
        if "#*" not in m.group(0):
            vals.append(float(m.group(1)) * mult[m.group(2)])
    return sum(vals) if vals else None


def gpu_benchmark(mode: int, label: str) -> float | None:
    print(f"  hashcat --benchmark -m {mode}  [{label}]")
    print(f"  Czekam...", end="", flush=True)
    try:
        r = subprocess.run(
            ["hashcat", "--benchmark", "-m", str(mode)],
            capture_output=True, text=True, timeout=120)
        speed = parse_speed(r.stdout + r.stderr)
        def fmt(s):
            if s is None: return "BŁĄD"
            if s >= 1e9: return f"{s/1e9:.2f} GH/s"
            if s >= 1e6: return f"{s/1e6:.2f} MH/s"
            if s >= 1e3: return f"{s/1e3:.2f} kH/s"
            return f"{s:.1f} H/s"
        print(f"\r  hashcat -m {mode}: {fmt(speed):>12}")
        return speed
    except FileNotFoundError:
        print(f"\r  hashcat: nie znaleziono")
        return None
    except subprocess.TimeoutExpired:
        print(f"\r  hashcat: timeout")
        return None

def print_report(pgp: dict, age: dict,
                  pgp_pwd: str, pgp_time: float, pgp_times: list,
                  age_pwd: str, age_time: float, age_times: list,
                  gpu_sha1: float | None, gpu_scrypt_1024: float | None) -> None:

    N = age["N"]
    gpu_scrypt = (gpu_scrypt_1024 * 1024 / N) if gpu_scrypt_1024 else None

    mem_age_mb = 2 * 8 * N * 64 // 1024**2
    vram_mb = 12 * 1024
    parallel = vram_mb // mem_age_mb

    def ft(s):
        if s is None: return "N/A"
        if s < 0.001: return "<1 ms"
        if s < 1: return f"{s*1000:.0f} ms"
        if s < 60: return f"{s:.2f} s"
        return f"{s/60:.1f} min"

    def fs(s):
        if s is None: return "N/A"
        if s >= 1e9: return f"{s/1e9:.2f} GH/s"
        if s >= 1e6: return f"{s/1e6:.2f} MH/s"
        if s >= 1e3: return f"{s/1e3:.2f} kH/s"
        return f"{s:.1f} H/s"

    pgp_avg = sum(pgp_times)/len(pgp_times) if pgp_times else 0
    age_avg = sum(age_times)/len(age_times) if age_times else 0
    n_pgp = len(pgp_times)
    n_age = len(age_times)

    W = 68

    print()
    print("POMIAR CPU — czas jednej próby KDF (Ryzen 5 9600X):")
    print("KDF\t\t\t\t| ms / próbę |\tUwaga")
    print(f"{'─'*32}  {'─'*10}  {'─'*8} ")
    print(f"SHA-1 S2K (PGP, count=65M)\t| {pgp_avg:>10.0f} |\tcompute-only")
    print(f"scrypt N=2^{age['log2_N']} (age)\t\t| {age_avg:>10.0f} |\tmemory-hard")
    print()
    print(f"Na CPU SHA-1 S2K jest {pgp_avg/max(age_avg,0.1):.1f}x wolniejszy — bo iteruje 65M bajtów.")
    print("Podatność jest widoczna tylko na GPU")
    print()

    if gpu_sha1 and gpu_scrypt:
        advantage = gpu_sha1 / gpu_scrypt
        print("BENCHMARK GPU — prędkość ataku (RTX 5070, hashcat):")
        print("KDF\t\t\t\t\t\t| Prędkość GPU")
        print(f"{'─'*48}  {'─'*15}")
        print(f"SHA-1 S2K (hashcat -m 17010)\t\t\t| {fs(gpu_sha1):>20}")
        print(f"scrypt N=1024 (hashcat -m 8900)\t\t\t| {fs(gpu_scrypt_1024):>20}")
        print(f"scrypt N=2^{age['log2_N']}={N//1000}k (age, proportional to 1/N)\t| {fs(gpu_scrypt):>20}")
        print()
        print(f"Ekstrapolacja scrypt: {fs(gpu_scrypt_1024)} x 1024 / {N:,} = {fs(gpu_scrypt)}")
        print(f"GPU jest {advantage:,.0f}x szybszy łamiąc PGP niż age")
        print()

    print("DICTIONARY ATTACK (worldlist, CPU):")
    print("System\t\t\t| Próba  |\t     Czas |\tHasło")
    print(f"{'─'*24} {'─'*8} {'─'*16} {'─'*10}")
    print(f"PGP SHA-1 S2K\t\t| {n_pgp:>6} |\t {ft(pgp_time):>8} |\t{str(pgp_pwd or 'brak'):<12}")
    print(f"age scrypt N=2^{age['log2_N']}\t| {n_age:>6} |\t{ft(age_time):>8}  |\t{str(age_pwd or 'brak'):<12}")
    print()

    if gpu_sha1 and gpu_scrypt and pgp_pwd and age_pwd:
        gpu_time_pgp = n_pgp / gpu_sha1
        gpu_time_age = n_age / gpu_scrypt
        print("Te same próby na GPU (ekstrapolacja z hashcat):")
        print(f"PGP SHA-1 S2K: {ft(gpu_time_pgp)}   ({fs(gpu_sha1)})")
        print(f"age scrypt: {ft(gpu_time_age)}  ({fs(gpu_scrypt)})")
        print()

    wl = 14_000_000
    print("Szacunkowy czas ataku brute-force na pełnym rockyou.txt (14M haseł) na GPU:")
    print(f" PGP SHA-1 S2K: {ft(wl/gpu_sha1)}")
    print(f" age scrypt: {ft(wl/gpu_scrypt)}")
    print()

def get_wordlist(path: str | None) -> list:
    cache = Path("/tmp/_atak07_wl.txt")
    if path and os.path.exists(path):
        words = Path(path).read_text(errors="ignore").splitlines()
        print(f"[*] Wordlist: {path} ({len(words):,} haseł)")
        return [w for w in words if w.strip()]
    if not cache.exists():
        url = ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt")
        print("[*] Pobieram wordlist top-10k...")
        urllib.request.urlretrieve(url, str(cache))
    words = cache.read_text().splitlines()
    words = [w for w in words if w.strip()]
    print(f"[*] Wordlist: SecLists top-10k ({len(words):,} haseł)")
    return words


def parse_args():
    p = argparse.ArgumentParser(description="Demonstracja podatności SHA-1 S2K (PGP) vs scrypt (age)")
    p.add_argument("pgp_file")
    p.add_argument("age_file")
    p.add_argument("-w", "--wordlist", default=None)
    p.add_argument("--no-benchmark", action="store_true", help="Pomiń benchmark GPU (hashcat)")
    p.add_argument("--preview", type=int, default=20, metavar="N", help="Pokaż N pierwszych prób (domyślnie: 20)")
    return p.parse_args()


def main():
    args = parse_args()

    for f in [args.pgp_file, args.age_file]:
        if not os.path.exists(f):
            print(f"[!] Brak pliku: {f}"); sys.exit(1)

    try:
        pgp = parse_pgp(args.pgp_file)
        age = parse_age(args.age_file)
    except ValueError as e:
        print(f"[!] {e}"); sys.exit(1)

    print(f"\n[*] PGP — SHA-1 S2K: salt={pgp['salt'].hex()}, count={pgp['count']:,}, payload={len(pgp['payload'])}B")
    print(f"[*] age — scrypt: salt={age['salt'].hex()}, N=2^{age['log2_N']}={age['N']:,}, RAM={2*8*age['N']*64//1024**2}MB/op")

    wordlist = get_wordlist(args.wordlist)
    preview  = wordlist[:args.preview]

    gpu_sha1 = gpu_scrypt = None
    if not args.no_benchmark:
        print(f"\n[1/3] Benchmark GPU (hashcat)")
        print()
        gpu_sha1 = gpu_benchmark(17010, "GPG AES-256 SHA-1 S2K")
        print()
        gpu_scrypt = gpu_benchmark(8900,  "scrypt N=1024 baseline")

    print(f"\n[2/3] Wordlist attack — PGP SHA-1 S2K (CPU)")
    print(f"      Pokazuję pierwsze {len(preview)} haseł z wordlisty")
    print(f"      Każda próba = sha1_s2k(count=65M) + quick_check")
    print()

    pgp_pwd, pgp_time, pgp_times = attack_pgp_cpu(pgp, preview)

    if not pgp_pwd and len(wordlist) > len(preview):
        print(f"\n  Hasło nie w pierwszych {len(preview)}. Kontynuuję pełną wordlistę...")
        remaining = wordlist[len(preview):]
        for i, pwd in enumerate(remaining):
            t0 = time.perf_counter()
            key = sha1_s2k(pwd.encode(), pgp["salt"], pgp["count"])
            ms = (time.perf_counter() - t0) * 1000
            pgp_times.append(ms)
            if pgp_quick_check(key, pgp["payload"]):
                pgp_time += time.perf_counter() - t0
                pgp_pwd = pwd
                n_total = len(preview) + i + 1
                print(f"  Hasło PGP: {pwd!r}  "
                      f"(próba {n_total}, {pgp_time:.2f}s łącznie)")
                break
            if (i+1) % 50 == 0:
                print(f"\r  [{len(preview)+i+1}/{len(wordlist)}] "
                      f"{(len(preview)+i+1)/pgp_time:.1f} h/s  "
                      f"ostatnie: {pwd!r:<15}", end="", flush=True)
        else:
            print(f"\n  Hasło nie znalezione w {len(wordlist):,} hasłach")

    if pgp_pwd:
        print(f"\n  Wynik PGP: {pgp_pwd!r} znalezione w {pgp_time:.2f}s")

    print(f"\n[3/3] Wordlist attack — age scrypt (CPU)")
    print(f"      Pokazuję pierwsze {len(preview)} haseł z wordlisty")
    print(f"      Każda próba = scrypt(N=2^{age['log2_N']}, 256MB) + ChaCha20 decrypt")
    print()

    age_pwd, age_time, age_times = attack_age_cpu(age, preview)

    if not age_pwd and len(wordlist) > len(preview):
        print(f"\n  Hasło nie w pierwszych {len(preview)}. Kontynuuję pełną wordlistę...")
        remaining = wordlist[len(preview):]
        for i, pwd in enumerate(remaining):
            t0 = time.perf_counter()
            match = age_verify(pwd, age["salt"], age["N"], age["efk"])
            ms = (time.perf_counter() - t0) * 1000
            age_times.append(ms)
            if match:
                age_time += time.perf_counter() - t0
                age_pwd = pwd
                n_total = len(preview) + i + 1
                print(f"  Hasło age: {pwd!r}  "
                      f"(próba {n_total}, {age_time:.2f}s łącznie)")
                break
            if (i+1) % 10 == 0:
                print(f"\r  [{len(preview)+i+1}/{len(wordlist)}] "
                      f"ostatnie: {pwd!r:<15}", end="", flush=True)
        else:
            print(f"\n  Hasło nie znalezione")

    if age_pwd:
        print(f"\n  Wynik age: {age_pwd!r} znalezione w {age_time:.2f}s")

    print_report(pgp, age, pgp_pwd, pgp_time, pgp_times, age_pwd, age_time, age_times, gpu_sha1, gpu_scrypt)


if __name__ == "__main__":
    main()