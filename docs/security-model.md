# Security model

The document describes **what the device protects, against whom, and what it does not protect**. It consists of two parts:

- **Part A:** threat model for the device itself and host tools.
- **Part B:** security comparison of the age and OpenPGP formats, results of attack demonstrations.

> **Status:** Research prototype from a master's thesis; no external audit. Do not use for protecting high-value data.

## Table of Contets

- [Security model](#security-model)
  - [Table of Contets](#table-of-contets)
  - [1. Purpose and scope](#1-purpose-and-scope)
  - [2. Assets](#2-assets)
  - [3. Attacker Model](#3-attacker-model)
  - [4. Assumptions and limits of trust](#4-assumptions-and-limits-of-trust)
  - [5. Security Goals and Non-Goals](#5-security-goals-and-non-goals)
  - [6. STRIDE analyse](#6-stride-analyse)
  - [7. Security of the age and OpenPGP formats](#7-security-of-the-age-and-openpgp-formats)
    - [7.1 Summary](#71-summary)
    - [7.2 Methodological caveats](#72-methodological-caveats)

---

## 1. Purpose and scope

The device performs the ECDH (P-256) operation using a private key secured within the ATECC608A. The host encrypts and decrypts files. The threat model covers:

- Pico firmware and the USB protocol,
- Pico ↔ ATECC608A communication (I2C),
- host tools `pico-crypt` (age) and `pico-pgp` (OpenPGP),
- the custom `pico-p256` stanza design.

It does not cover: host operating system security or the implementation quality of GnuPG and the age library.

## 2. Assets

| ID | Asset | Location | Value |
|---|---|---|---|
| A1 | P-256 private key | ATECC608A (slots 0–7) | critical: allows decryption of all files |
| A2 | File confidentiality | host, storage media, backups | protection objective |
| A3 | `shared_secret` (ECDH result) | passes: chip → Pico → USB → host | allows decryption of a single file |
| A4 | Session key / `file_key` | host RAM during decryption | same as above |
| A5 | Firmware integrity | Pico flash memory | basis for enforcing TUP and PIN |
| A6 | Recipient public key authenticity | host (retrieved from chip or certificate) | determines who can decrypt |
| A7 | Key availability | chip slot | loss = loss of access to files |

## 3. Attacker Model

| ID | Attacker | Capabilities | In scope |
|---|---|---|---|
| T1 | **Remote host malware** (user privileges) | launches processes, reads `/dev/ttyACM*`, replaces files, eavesdrops on its own USB traffic | yes |
| T2 | **Passive eavesdropping** on USB or I2C bus | reads traffic without modification | yes |
| T3 | **Storage/backup thief** (offline) | has the drive or `.age`/`.pgp` file, **does not have** the device | yes |
| T4 | **Physical device access** | touches the Pico and breakout board, can press the button, flash firmware via BOOTSEL, connect to I2C/SWD | partially |
| T5 | **Encrypted file holder** | analyzes and modifies the ciphertext, without access to the key | yes |
| T6 | **Malicious file provider** | submits a crafted `.age`/`.pgp` file for decryption | yes |

## 4. Assumptions and limits of trust

**Assumptions:**

1. The ATECC608A never reveals the private key (manufacturer guarantee, not verified by the project).
2. The chip's configuration and data zones have been locked following personalization.
3. The user presses the button solely in response to their own intended operation.
4. The dependent libraries (mbedTLS, `filippo.io/age`, GnuPG, CryptoAuthLib) are correct.

**The limits of trust:**

```
 UNTRUSTED                           PARTIALLY TRUSTED
┌────────────────────────┐          ┌─────────────────────────────┐
│ Host (OS, processes)   │   USB    │ Pico: firmware (TUP)        │
│ Input file             │◄────────►│  │ I2C (unencrypted)        │
│ USB bus                │          │  ▼                          │
└────────────────────────┘          │ ATECC608A: private key      │
                                    └─────────────────────────────┘
```

## 5. Security Goals and Non-Goals

**Goals:**

| ID | Goal |
|---|---|
| G1 | The private key cannot be read from the device, the host, or a backup. |
| G2 | A stolen storage medium or encrypted file does not reveal its contents without the device (T3). |
| G3 | A remote process on the host cannot silently decrypt files; physical user presence is required (T1). |
| G4 | Modification of the age ciphertext is detected before any data is returned (T5). |
| G5 | Malformed USB frames and input files do not cause crashes or data leaks (T6). |

**Non-goals:**

| ID | Non-goal | Rationale |
|---|---|---|
| N1 | Protection against active malware **during** decryption | `shared_secret` passes through the host in plaintext |
| N2 | Protection against physical use of the device by an authorized person | no chip-side authentication |
| N3 | Compatibility of the `pico-p256` format with standard `age` | P-256 vs. X25519 limitation |
| N4 | Recipient anonymity in the OpenPGP path | PKESK contains the Key ID (OpenPGP format) |

## 6. STRIDE analyse

| Category | Threat | Attacker | Mitigation | Residual risk |
|---|---|---|---|---|
| **S**poofing | Device impersonation (fake Pico returning its own public key) | T1, T4 | lack of device authentication | **high**: host trusts any CDC device |
| **T**ampering | Modification of *age* ciphertext | T5 | AEAD ChaCha20-Poly1305 (STREAM) | low |
| Tampering | Modification of OpenPGP ciphertext (CFB + MDC SHA-1) | T5 | MDC verification before returning data | **medium**: format limitations |
| Tampering | Malformed USB frame | T1, T6 | CRC32, payload limit, resynchronization | low (CRC is not authentication) |
| **R**epudiation | No proof of who decrypted or when | – | no logs | accepted (out of scope) |
| **I**nformation disclosure | Interception of `shared_secret` over USB | T1, T2 | `shared_secret` unique per file | **high** for a single file (N1) |
| Information disclosure | Reading the private key | T3, T4 | hardware chip protection, `IsSecret=1` | low (assumption 1) |
| Information disclosure | Recipient metadata leakage (Key ID in PKESK) | T5 | `--hidden-recipient` (optional) | **high** for OpenPGP (N4); *age* does not have this issue |
| **D**enial of service | Fuzzing / frame flooding | T1, T6 | fragmentation-resistant parser, 5s watchdog | low |
| Denial of service | Key destruction (`GEN_KEY`), no backup | T1, T4 | – | **high**: key without backup cannot be recovered |
| **E**levation of privilege | Bypassing TUP via direct I2C access | T4 | none | **high** |
| Elevation of privilege | Uploading malicious firmware via BOOTSEL | T4 | none (RP2040 secure boot not enabled in project config) | **high** |
| Elevation of privilege | Piggybacking on the TUP window | T1 | none | **medium** |

## 7. Security of the age and OpenPGP formats

The following analysis compares the formats, **regardless of key storage**. Each attack has a separate demonstration in `attacks/` (see `attacks/README.md`).

### 7.1 Summary

| # | Attack | Class | OpenPGP (RFC 4880) | age v1 | Demonstration | Source |
|---|---|---|:---:|:---:|---|---|
| 1 | EFail / CFB malleability | CCA, exfiltration | vulnerable | resistant (AEAD) | bit flip, garbled plaintext, `gpg` exits with code 2 | USENIX Sec. 2018 |
| 2 | Adaptive CCA on CFB (*quick check*) | CCA2 | vulnerable | resistant | simulated oracle, successfully recovering both bytes of block M2 | IACR 2005/033 |
| 3 | AEAD → CFB downgrade | downgrade | vulnerable | resistant | **skipped**: GnuPG mitigates the attack; Strenzke's attack targets the LibrePGP OCB format, not RFC 9580 SEIPD v2 (caveat in the paper) | IACR 2024/1110 |
| 4 | ElGamal cross-configuration | DLP | vulnerable | resistant (X25519) | **infeasible**: requires a vulnerable implementation (Botan < 2.17) | ACM CCS 2021 |
| 5 | KO: Key Overwriting | integrity | vulnerable | structurally resistant | **simulation** of a library without validation, full recovery of 256 bits in 18 rounds | ACM CCS 2022 |
| 6 | SWEET32 (3DES, 64-bit block) | birthday collision | vulnerable | resistant | *truncated birthday* + forced CFB-64 collision (known-key) | ACM CCS 2016 |
| 7 | Weak KDF (S2K SHA-1) | offline brute-force | weak | resistant (scrypt) | hashcat (RTX 5070): 13,186 kH/s (SHA-1 S2K) vs 3,703 H/s (scrypt, N = 16,384); extrapolation to N = 262,144 (age parameter): ~14.5 H/s, i.e., ≈ 911,610× | RFC 9580 §3.7 |
| 8 | SHA-1 collision in MDC | hash collision | vulnerable | resistant (Poly1305) | **infeasible:** successful execution required computing power inaccessible during attack reproduction | SHAttered 2017 |
| 9 | Metadata leakage (Key ID) | privacy | reveals | no identifier | recipient identification via `keyid` | PURB 2018 |
| 10 | Compression oracle | side channel | risk | no compression | guessing token via ciphertext size (19 characters) | CRIME / BREACH |
| 11 | Parser attack surface | memory / logic | complex | simple | differential fuzzing: OpenPGP vs. age error branches; compression amplification 292–1025×; ~4000 vs. ~300 lines of parser code | CVE-2025-47934 |
| 12 | Misconfiguration (misuse) | configuration | possible | impossible | `--cipher-algo 3DES`, `--digest-algo MD5` without warning | Halpin 2020 |

> Attacks 3, 4 and 8 do not have a working demonstration for the reasons described in the table.

### 7.2 Methodological caveats

When citing the results, it is important to note the following nuances, as they affect interpretation:

- **Attack 5 (KO)** operates on a simulated library without parameter validation. Current GnuPG 2.4.x rejects DSA signatures with `q < 160` bits, so the simple attack variant is blocked, though the **structural** vulnerability (lack of binding between public fields and the secret) remains. Do not present the result as a working exploit against GnuPG.
- **Attack 6 (SWEET32)** demonstrates the mechanism on a reduced scale (collision after ~4,800 blocks, whereas the full 64-bit version would require ~32 GB) and the XOR recovery of plaintexts during a forced collision with a known key. This is a proof of concept, not a practical attack on a file.
- **Attack 7 (brute-force)** compares SHA-1 S2K—forced via the `--s2k-digest-algo SHA1` flag—against `age`'s default scrypt configuration. The hashcat benchmark for scrypt uses N = 16,384, whereas the `age` file header specifies log₂(N) = 18, meaning N = 262,144. The result for `age` is an **extrapolation** (based on the linear scaling of cost with N, ~14.5 H/s) rather than a direct measurement. The ~911,610× ratio applies to a GPU with memory constraints (256 MB per thread, approx. 48 threads on an RTX 5070). On a CPU with ample RAM, scrypt's advantage is smaller. Newer versions of GnuPG use a stronger S2K ​​by default, so the result applies to a forced configuration.
- **Attacks 1 and 2** require ignoring the MDC error (using `--ignore-mdc-error` or a client that ignores the exit code). The result demonstrates an architectural vulnerability, not the default behavior of `gpg` in a terminal.
- **Attack 11:** the number of error branches is an indirect measure, not proof of a vulnerability in a specific implementation.
