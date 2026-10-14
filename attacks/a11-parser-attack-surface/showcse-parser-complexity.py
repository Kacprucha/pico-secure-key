import argparse
import io
import os
import re
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path

import age.file
import age.keys.password
import age.recipients.scrypt 

def ok(m):   print(f"  [OK] {m}")
def fail(m): print(f"  [!!] {m}")
def warn(m): print(f"  [!]  {m}")

def pgp_new_format_length(L: int) -> bytes:
    if L < 192:
        return bytes([L])
    elif L < 8384:
        L2 = L - 192
        return bytes([192 + (L2 >> 8), L2 & 0xFF])
    else:
        return bytes([0xFF]) + struct.pack(">I", L)

def pgp_packet_canonical(tag: int, body: bytes) -> bytes:
    return bytes([0xC0 | tag]) + pgp_new_format_length(len(body)) + body

def pgp_packet_partial(tag: int, body: bytes) -> bytes:
    out = bytearray([0xC0 | tag])
    pos, remaining = 0, len(body)
    
    while remaining > 512:
        n = 9
        
        while (1 << (n + 1)) <= remaining and n < 30:
            n += 1
        
        chunk = 1 << n
        out.append(224 + n)
        out += body[pos:pos + chunk]
        pos += chunk
        remaining -= chunk
    
    out += pgp_new_format_length(remaining)  
    out += body[pos:]
    
    return bytes(out)

def literal_body(data: bytes) -> bytes:
    return b"\x62\x00\x00\x00\x00\x00" + data

def gpg_list_packets(raw: bytes, workfile: Path, timeout=2):
    workfile.write_bytes(raw)
    try:
        r = subprocess.run(["gpg", "--batch", "--no-tty", "--no-autostart",
                            "--list-packets", str(workfile)],
                           capture_output=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
        return (r.returncode,
                r.stdout.decode("utf-8", "replace"),
                r.stderr.decode("utf-8", "replace"))
    except subprocess.TimeoutExpired:
        return None, "", "TIMEOUT"

def gpg_parse_signature(rc: int, stderr: str) -> str:
    if rc is None:
        return "TIMEOUT"
    
    if rc < 0 or rc in (134, 139):
        return f"CRASH(rc={rc})"
    
    msg = ""
    
    for line in stderr.split("\n"):
        line = line.strip()
        if line.startswith("gpg:") and ".bin" not in line and ".pgp" not in line:
            msg = re.sub(r"0x[0-9a-fA-F]+|\d+", "N", line)
            break
    
    return f"rc={rc}|{msg[:60]}"

def age_parse_signature(raw: bytes) -> str:
    import contextlib
    sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            age.file.load_header(io.BytesIO(raw))
        return "OK"
    except Exception as e:
        return type(e).__name__

def fuzz_single_bit(valid: bytes):
    for i in range(len(valid)):
        for bit in range(8):
            b = bytearray(valid)
            b[i] ^= (1 << bit)
            yield bytes(b)

def fuzz_truncations(valid: bytes, step=1):
    for L in range(0, len(valid), step):
        yield valid[:L]

def part_fuzzing_test(gpg_file: Path, age_file: Path, pubkey_file: Path):
    print("Differential fuzzing parserow\n")

    print("Metoda: wyczerpujace mutacje single-bit (kazdy offset x kazdy bit) wraz z obcieciami na kazdej dlugosci\n")

    workfile = Path("fz.bin")
    results = {}

    pgp_target = pubkey_file if (pubkey_file and pubkey_file.exists()) else gpg_file
    targets = [(f"PGP ({pgp_target.name})", pgp_target, "pgp"), (f"age ({age_file.name})", age_file, "age")]

    for label, path, kind in targets:
        if path is None or not path.exists():
            continue
        
        valid = path.read_bytes()
        sigs = {}
        crashes = hangs = 0
        max_t = 0.0
        n = 0

        gens = list(fuzz_single_bit(valid)) + list(fuzz_truncations(valid))
        for mutated in gens:
            n += 1
            t0 = time.perf_counter()
            
            if kind == "pgp":
                rc, _, err = gpg_list_packets(mutated, workfile)
                s = gpg_parse_signature(rc, err)
            else:
                s = age_parse_signature(mutated)
            
            dt = time.perf_counter() - t0
            max_t = max(max_t, dt)
            
            if "CRASH" in s: crashes += 1
            if "TIMEOUT" in s: hangs += 1
            
            sigs[s] = sigs.get(s, 0) + 1

        results[label] = {"n": n, "unique": len(sigs), "crashes": crashes, "hangs": hangs, "max_t": max_t, "sigs": sigs}

        print(f"{label}: {n} mutacji (single-bit + obciecia)")
        ok(f"  unikalnych sygnatur parsera: {len(sigs)}")
        ok(f"  crashe: {crashes}, zawieszenia(timeout): {hangs}, maks. czas: {max_t*1000:.1f} ms")
        warn(f"  10 najczestszych sygnatur parsera:")
        
        err_sigs = {k:v for k,v in sigs.items() if not (k.startswith("rc=0|") or k=="OK")}
        shown = sorted(err_sigs.items(), key=lambda x:-x[1])[:10]
        for s, c in shown:
            print(f"        {c:5}x  {s}")
        print()

    print()
    print(f"  Liczba dystynktnych sygnatur bledu parsera (galezi walidacji):")
    for label, r in results.items():
        err = sum(1 for k in r["sigs"] if not (k.startswith("rc=0|") or k == "OK"))
        print(f"    {label:<32} {err}")
    
    return results

def part_anomaly_noncanonical(content_file: Path ):
    print("\nNiekanonicznosc kodowania (partial body lengths)\n")

    data = content_file.read_bytes()

    if len(data) <= 512:
        reps = (520 // len(data)) + 1
        data = (data * reps)
        print(f"Tresc < 512 B — powielono do {len(data)} B aby uruchomic partial body lengths")
    body = literal_body(data)

    canon = pgp_packet_canonical(11, body)
    partial = pgp_packet_partial(11, body)

    print(f"Ta sama logiczna tresc ({len(data)} B) zakodowana na dwa sposoby:")
    print(f"     KANONICZNE:  naglowek={canon[:8].hex()}  rozmiar pliku={len(canon)} B")
    print(f"     PARTIAL:     naglowek={partial[:8].hex()}  rozmiar pliku={len(partial)} B")
    print()

    rc1, out1, _ = gpg_list_packets(canon, Path("canon.pgp"))
    rc2, out2, _ = gpg_list_packets(partial, Path("partial.pgp"))

    def first_line(out): return out.strip().split("\n")[0] if out.strip() else ""
    print("gpg --list-packets dla obu (rozne naglowki, ten sam typ pakietu Literal):")
    print(f"     KANONICZNE: {first_line(out1)}")
    print(f"     PARTIAL:    {first_line(out2)}")
    print()

    def extract(raw):
        wf = Path("extract.pgp")
        wf.write_bytes(raw)
        r = subprocess.run(["gpg", "--batch", "--no-tty", "--no-autostart", "-d", str(wf)],
                          capture_output=True, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout
    
    erc1, edata1 = extract(canon)
    erc2, edata2 = extract(partial)

    print("Ekstrakcja zawartej tresci (gpg -d) z obu kodowan:")
    print(f"     KANONICZNE: {len(edata1)} B wyekstrahowano")
    print(f"     PARTIAL:    {len(edata2)} B wyekstrahowano")
    print()

    diff_bytes = canon != partial
    same_content = (edata1 == edata2 == data) and erc1 == 0 and erc2 == 0
    
    if diff_bytes and same_content:
        print("Dwa rozne ciagi bajtow ekstrahuja sie do tresci o tej samej zawartosci")
        print("Format OpenPGP nie ma kanonicznej reprezentacji pakietu parser musi obslugiwac wiele kodowan tej samej tresci")
    
    return {"canon_size": len(canon), "partial_size": len(partial), "noncanonical": diff_bytes and same_content}


def part_anomaly_amplification(inner_size_mb: int, content_file: Path = None):
    print("\nAmplifikacja przez kompresje (resource exhaustion)\n")

    cap_mb = min(inner_size_mb, 64)  
    if cap_mb != inner_size_mb:
        warn(f"Ograniczono rozmiar do {cap_mb} MB (limit bezpieczenstwa demonstracji)")

    if content_file and content_file.exists():
        base = content_file.read_bytes()
        reps = (cap_mb * 1024 * 1024 // max(len(base), 1)) + 1
        inner_data = (base * reps)[:cap_mb * 1024 * 1024]
        print(f"Tresc wewnetrzna z pliku {content_file.name}, powielona do {len(inner_data):,} B")
    else:
        inner_data = b"\x00" * (cap_mb * 1024 * 1024)
        print(f"Tresc wewnetrzna: {len(inner_data):,} B zer (silnie kompresowalne)")

    inner_literal = pgp_packet_canonical(11, literal_body(inner_data))

    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    compressed = co.compress(inner_literal) + co.flush()
    comp_packet = pgp_packet_canonical(8, b"\x01" + compressed)

    bomb = Path("amplification.pgp")
    bomb.write_bytes(comp_packet)

    print(f"Rozmiar pliku .pgp na dysku:      {len(comp_packet):,} B")
    print(f"Rozmiar po dekompresji (literal): {len(inner_literal):,} B")
    
    ratio = len(inner_literal) / len(comp_packet)
    
    print(f"Wspolczynnik amplifikacji:        {ratio:.1f}x  (1 bajt pliku -> {ratio:.0f} bajtow)")
    print()

    t0 = time.perf_counter()
    try:
        r = subprocess.run(["gpg", "--list-packets", str(bomb)], capture_output=True, text=True, timeout=30)
        dt = time.perf_counter() - t0
        m = re.search(r"raw data: (\d+) bytes", r.stdout + r.stderr)
        decompressed = int(m.group(1)) if m else 0
        
        if decompressed >= len(inner_data):
            print(f"gpg w pelni zdekompresowal pakiet ({decompressed:,} B) w {dt*1000:.0f} ms")
            print("Parser realizuje dekompresje w trakcie wlasnie parsowania (--list-packets).")
        
        print("Zagniezdzanie Compressed-in-Compressed pozwala mnozyc wspolczynnik kaskadowo.")
    except subprocess.TimeoutExpired:
        print("gpg przekroczyl limit czasu (30s) — objaw wyczerpania zasobow.")
    
    return {"ratio": ratio, "file_size": len(comp_packet), "decompressed": len(inner_literal)}

def main():
    ap = argparse.ArgumentParser(description="Atak 11 — Parser Attack Surface (OpenPGP vs age)")
    ap.add_argument("--gpg-file", required=True, type=Path, help="Poprawny plik .gpg")
    ap.add_argument("--age-file", required=True, type=Path, help="Poprawny plik .age")
    ap.add_argument("--pubkey-file", type=Path, help="Plik klucza publicznego PGP (bogatszy do fuzzingu)")
    ap.add_argument("--literal-content-file", type=Path, help="Plik z trescia do demonstracji niekanonicznosci (C.1)")
    ap.add_argument("--skip-amplification", action="store_true", help="Pomin patologie C.2 (zasobozerna)")
    ap.add_argument("--inner-size-mb", type=int, default=4, help="Rozmiar tresci dla C.2 (limit 64 MB)")
    args = ap.parse_args()

    for f in [args.gpg_file, args.age_file]:
        if not f.exists():
            print(f"Blad: plik {f} nie istnieje.", file=sys.stderr); sys.exit(1)

    print(f"\nParser Attack Surface: OpenPGP vs age")

    fuzz = part_fuzzing_test(args.gpg_file, args.age_file, args.pubkey_file)

    content = args.literal_content_file or args.gpg_file
    c1 = part_anomaly_noncanonical(content)

    if args.skip_amplification:
        warn("Patologia amplifikacja pominieta na zadanie (--skip-amplification)")
        c2 = None
    else:
        c2 = part_anomaly_amplification(args.inner_size_mb, args.literal_content_file)

if __name__ == "__main__":
    main()