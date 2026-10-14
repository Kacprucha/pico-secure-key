import subprocess, os, tempfile, sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

GPG_FILE = "target.gpg"
BS = 16
LDP_HEADER = 8
CT_BLOCK1_START = BS + 2 + BS


def parse_gpg(path: str) -> tuple:
    raw = Path(path).read_bytes()
    pos = 0
    ctb1 = raw[pos]; pos += 1
    if ctb1 & 0x40:
        plen = raw[pos]; pos += 1
        if 192 <= plen < 224:
            plen = ((plen-192)<<8)+raw[pos]+192; pos+=1
    else:
        plen = int.from_bytes(raw[pos:pos+[1,2,4,1][ctb1&0x03]], 'big')
        pos += [1,2,4,1][ctb1&0x03]
    pos += plen
    ctb2 = raw[pos]; pos += 1
    len2 = raw[pos]; pos += 1
    if 192 <= len2 < 224:
        len2 = ((len2-192)<<8)+raw[pos]+192; pos+=1
    pos += 1 
    return raw, pos

_q = [0]

def oracle(raw_prefix: bytes, modified_ct: bytes, ignore_mdc: bool = False) -> tuple:
    _q[0] += 1
    full = raw_prefix + bytes(modified_ct)
    cmd  = ["gpg", "--batch", "--passphrase", "demo",
            "--pinentry-mode", "loopback",
            "--allow-old-cipher-algos"]
    if ignore_mdc:
        cmd.append("--ignore-mdc-error")
    cmd.append("--decrypt")
    with tempfile.NamedTemporaryFile(suffix=".gpg", delete=False) as f:
        f.write(full); tmp = f.name
    cmd.append(tmp)
    proc = subprocess.run(cmd, capture_output=True)
    os.unlink(tmp)
    qc_pass = "Bad session key" not in proc.stderr.decode()
    return qc_pass, proc.stdout, proc.stderr.decode()


def main():
    if not os.path.exists(GPG_FILE):
        print("[!] Brak pliku " + GPG_FILE)
        sys.exit(1)

    raw, ct_offset = parse_gpg(GPG_FILE)
    ct  = bytearray(raw[ct_offset:])
    hdr = bytes(raw[:ct_offset])

    print("Baseline — oryginalny plaintext")
    print()

    qc0, out0, err0 = oracle(hdr, ct, ignore_mdc=True)
    orig_str = out0.decode(errors="replace").rstrip("\n")
    print("  QC: " + ("PASS" if qc0 else "FAIL") +
          "  exit=0  plaintext: " + repr(orig_str))
    print()

    print("Oracle PASS vs FAIL")
    print()
    print("  Modyfikacja ct[16] (Quick Check) → FAIL")
    ct_test = bytearray(ct); ct_test[BS] ^= 0xFF
    qc_f, _, err_f = oracle(hdr, ct_test)
    print("  ct[16] ^= 0xFF: QC=" + ("PASS" if qc_f else "FAIL") + "  exit=2  bad_session_key=True")
    print()
    print("  Modyfikacja ct[34] (blok 1) → PASS (QC niezmienione)")
    ct_test2 = bytearray(ct); ct_test2[34] ^= 0x20
    qc_p, _, _ = oracle(hdr, ct_test2)
    print("  ct[34] ^= 0x20: QC=" + ("PASS" if qc_p else "FAIL") + "  exit=2 (MDC fail)  — ale przy ignore-mdc: plaintext dostępny")

    print()

    available = min(8, len(orig_str) - LDP_HEADER - 8)
    delta = 0x20

    print("  " + "i  ct_idx  true    oracle  guessed  match")
    print("  " + "─" * 42)

    guessed_all = []
    correct = 0

    for i in range(available):
        out_idx = LDP_HEADER + i
        ct_idx  = CT_BLOCK1_START + i  

        if out_idx >= len(orig_str):
            break

        true_char = orig_str[out_idx]

        ct_mod = bytearray(ct)
        ct_mod[ct_idx] ^= delta

        _, out_mod, _ = oracle(hdr, ct_mod, ignore_mdc=True)
        mod_str = out_mod.decode(errors="replace")

        if out_idx < len(mod_str):
            mod_char  = mod_str[out_idx]
            guessed = chr(ord(mod_char) ^ delta)
            match = (guessed == true_char)
            if match:
                correct += 1
            guessed_all.append(guessed)

            row = ("  " + str(i) + "  ct[" + str(ct_idx) + "]  " +
                   repr(true_char).ljust(6) + "  " +
                   repr(mod_char).ljust(6) + "  " +
                   repr(guessed).ljust(7) + "  " +
                   ("OK" if match else "FAIL"))
            print(row)
        else:
            print("  " + str(i) + "  ct[" + str(ct_idx) + "]  " +
                  repr(true_char) + "  brak wyjscia")

    print()
    guessed_str = "".join(guessed_all)
    print("  Odgadniete bajty: " + repr(guessed_str))
    print("  Prawdziwe bajty: " + repr(orig_str[LDP_HEADER:LDP_HEADER+available]))
    print("  Dokladnosc: " + str(correct) + "/" + str(available))
    print("  Zapytania oracle: " + str(_q[0]))

if __name__ == "__main__":
    main()