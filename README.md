# pico-secure-key

A hardware-based file encryption key built on the **Raspberry Pi Pico** and **ATECC608A** (ECDH using the P-256 curve), featuring integration with the **age** and **OpenPGP** formats, alongside a comparative security analysis of both formats.

> ⚠️ **Research prototype** developed as part of a master's thesis (Warsaw University of Technology, 2026). It has not undergone a security audit and is **not suitable for protecting high-value data**. Known vulnerabilities and limitations are documented in [`docs/limitations.md`](docs/limitations.md). Vulnerability reporting: [`SECURITY.md`](SECURITY.md).

**Status:** Project concluded following the master's thesis defense. The repository is maintained on a *best-effort* basis.

<img width="4032" height="3024" alt="img_3640" src="https://github.com/user-attachments/assets/09d996d5-dc57-4d78-9645-cc0519ee886f" />

## Table of Contents

- [pico-secure-key](#pico-secure-key)
  - [Table of Contents](#table-of-contents)
  - [Motivation](#motivation)
  - [How does it works](#how-does-it-works)
  - [Key results](#key-results)
  - [Requirements](#requirements)
  - [Quick start](#quick-start)
  - [Repository structure](#repository-structure)
  - [Attack analysis: OpenPGP vs. age](#attack-analysis-openpgp-vs-age)
  - [Benchmarks](#benchmarks)
  - [Limitations](#limitations)
  - [Documentation](#documentation)

## Motivation

A private key stored on a disk or in computer memory can be stolen along with a backup or extracted by malware. A key locked within a *secure element* cannot be read—only used.

The project rests on two pillars:

1. **Implementation.** A USB device that performs the ECDH operation using a private key locked inside an ATECC608A chip. One tool (`pico-crypt`) encrypts files in the **age** format, while the other (`pico-pgp`) uses the **OpenPGP** format. Both paths utilize the same chip operation and USB protocol, so differences in results stem from the **formats** rather than the hardware.
2. **Analysis.** A comparison of 12 vulnerability classes affecting the OpenPGP format (RFC 4880)—illustrated with proof-of-concept demonstrations—against the **age** format. The thesis: the minimalist design of **age** eliminates entire classes of vulnerabilities that remain present in OpenPGP due to backward compatibility and algorithmic flexibility (*cryptographic agility*).

## How does it works

The device **does not encrypt files itself**. It performs a single operation—ECDH—using a private key that never leaves the chip. The rest (key derivation, encryption, file construction) is handled by the computer.

```
Computer  <── USB CDC ──>  Pico (firmware C)  <── I2C ──>  ATECC608A
 (host)                     + button TUP                  (P-256 private key)
```

| Component | Language | Role |
|---|---|---|
| [`firmware/`](firmware/) | C (pico-sdk, TinyUSB, CryptoAuthLib) | USB protocol, ECDH, Test of User Presence (TUP) |
| [`age-go-client/`](age-go-client/) | Go (`filippo.io/age`) | CLI for the age format, custom `pico-p256` stanza |
| [`pico-pgp/`](pico-pgp/) | C (mbedTLS) + GnuPG | CLI for OpenPGP, decryption via hardware ECDH |
| [`host/`](host/) | C | USB protocol library, tests |
| [`attacks/`](attacks/) | Python, shell | demonstrations of 12 attacks |
| [`benchmarks/`](benchmarks/) | Go, C | performance measurements |

**Encryption does not require the device**; a public key suffices. The device is only needed for decryption, and every ECDH operation requires a **physical button press** (a pattern familiar from FIDO U2F keys).

Since the ATECC608A supports only P-256 while `age` uses X25519, `.age` files created by `pico-crypt` use a custom `pico-p256` stanza type and **are not compatible with the standard age CLI** without an additional software recipient. Details: [`docs/age-integration.md`](docs/age-integration.md).

## Key results

**Implementation**

- Full file encryption and decryption workflow for both formats using an on-chip key, verified by matching the hardware ECDH implementation against an independent software implementation (mbedTLS).
- Hardware ECDH takes approximately **78 ms** (host-side median) and the duration is **constant regardless of file size**. For small files, this operation dominates the decryption time.
- Regarding the encryption process itself, `age` performs significantly faster than GPG for small files; as file size increases, the performance gap stabilizes.
- Regarding the decryption process itself, `age` performs significantly faster than GPG for small files; however, as file size increases, GPG catches up and may even outperform `age`.

Differences in encryption and decryption times between `age` and GPG may stem from the fact that GPG compresses the file prior to encryption. Consequently, the encryption process includes an additional compression step; conversely, during decryption, GPG effectively processes a smaller file than `age`, allowing it to perform the operation faster for larger file sizes.

**Format Analysis** (details in [`docs/security-model.md`](docs/security-model.md))

- Out of 12 OpenPGP vulnerability classes: **9 were demonstrated** (some in simplified or simulated variants), one was omitted because the vulnerability had already been patched in the GPG implementation under study, and two were not feasible in the test environment. - The age format is **structurally** resilient against known classes of attacks: AEAD for the entire payload, no recipient identifier, no compression, no algorithm negotiation, and a simple parser.

**What the results do not prove:** that the built device is secure, that the `pico-p256` implementation possesses the properties of standard age, or that age is generally "better" than OpenPGP. See [`docs/limitations.md`](docs/limitations.md).

## Requirements

**Hardware**

- Raspberry Pi Pico (RP2040)
- SparkFun Qwiic ATECC608A
- tactile button, Dupont wires, micro-USB cable **with data lines**
- cost approx. 74 PLN; bill of materials and schematic: [`docs/hardware.md`](docs/hardware.md)

**Software** (reference versions, Arch Linux)

`arm-none-eabi-gcc`, `arm-none-eabi-newlib`, CMake, pico-sdk, mbedTLS ≥ 3.0, Go ≥ 1.21, GnuPG 2.4.9, age 1.3.1. Attack 7 requires hashcat and a GPU. Full list and versions: [`docs/reproducibility.md`](docs/reproducibility.md).

## Quick start

> ⚠️ Chip personalization (locking configuration and data) is **irreversible**. Perform initial tests on a spare unit. See [`docs/hardware.md`](docs/hardware.md).

```bash
# 1. Dependencies (Arch Linux) and port access
sudo usermod -aG uucp $USER          # log out and log back in
sudo pacman -S --needed arm-none-eabi-gcc arm-none-eabi-newlib arm-none-eabi-binutils \
cmake ninja git base-devel mbedtls picocom gnupg go
yay -S age

# 2. Repository
git clone --recurse-submodules https://github.com/Kacprucha/pico-secure-key.git pico-secure-key
cd pico-secure-key

# 3. Firmware: build and flash (BOOTSEL + copy firmware.uf2)
cd firmware && mkdir -p build && cd build
cmake .. -DPICO_SDK_PATH=$PICO_SDK_PATH && make -j4

# 4. Chip configuration and key generation: see docs/hardware.md
```

**age**

```bash
cd age-go-client && go build -o pico-crypt ./...
./pico-crypt list-keys
./pico-crypt encrypt file.pdf           # → file.pdf.age
./pico-crypt decrypt file.pdf.age       # press the button on the device
```

**OpenPGP**

```bash
cd pico-pgp && make
python3 gen_cert.py <X‖Y hex>           # certificate, import into GnuPG, fingerprint in pico_cert.pgp.fp
./pico-pgp encrypt file.pdf             # → file.pdf.pgp
./pico-pgp decrypt file.pdf.pgp         # press the button on the device
```

Full instructions, expected results, and common issues: [`docs/reproducibility.md`](docs/reproducibility.md).

## Repository structure

```
pico-secure-key/
├── README.md  LICENSE  SECURITY.md
├── firmware/          Pico firmware: USB, protocol, ECDH, TUP
├── age-go-client/     age CLI (Go)
├── pico-pgp/          OpenPGP CLI (C)
├── host/              protocol library and tests (C)
├── attacks/           demonstrations of 12 attacks (PGP vs age)
├── analysis/          results frozen for the thesis (CSV, charts)
└── docs/              technical documentation (below)
```

## Attack analysis: OpenPGP vs. age

Each attack has a separate demonstration in [`attacks/`](attacks/). The "Nature" column describes **exactly what was demonstrated** (not all attacks work in their full, practical variant).

| # | Attack | Source | OpenPGP | age | Nature of demonstration |
|---|---|---|:---:|:---:|---|
| 1 | EFail / CFB malleability | USENIX Sec. 2018 | vulnerable | resistant | bit flip, garbled plaintext |
| 2 | Adaptive CCA on CFB | IACR 2005/033 | vulnerable | resistant | simulated oracle, reduced variant |
| 3 | Downgrade AEAD → CFB | IACR 2024/1110 | vulnerable | resistant | **skipped**: mitigated by GnuPG |
| 4 | ElGamal cross-configuration | ACM CCS 2021 | vulnerable | resistant | **infeasible**: requires Botan < 2.17 |
| 5 | KO: Key Overwriting | ACM CCS 2022 | vulnerable | structurally resistant | **simulation** of library lacking validation |
| 6 | SWEET32 (3DES) | ACM CCS 2016 | vulnerable | resistant | reduced scale + known-key collision |
| 7 | Weak KDF (S2K SHA-1) | RFC 9580 §3.7 | weak | resistant (scrypt) | hashcat; age result is an extrapolation |
| 8 | SHA-1 collision in MDC | SHAttered 2017 | vulnerable | resistant | **infeasible:** successful execution required computing power unavailable during attack replication. |
| 9 | Metadata leakage (Key ID) | PURB 2018 | reveals | missing identifier | recipient identification via `keyid` |
| 10 | Compression oracle | CRIME / BREACH | risk | no compression | simulated server, token guessing |
| 11 | Parser attack surface | CVE-2025-47934 | complex | simple | differential fuzzing |
| 12 | Misconfiguration (misuse) | Halpin 2020 | possible | impossible | demonstration of GnuPG flags |

Methodological caveats (versions, extrapolations, simulations): [`docs/security-model.md`](docs/security-model.md). Other OpenPGP implementations were not examined.

Perform demonstrations using only your own data and keys. See [`SECURITY.md`](SECURITY.md).

## Benchmarks

Detailed measurement procedure and methodology: [`docs/reproducibility.md`](docs/reproducibility.md).

| Measurement | Result | Notes |
|---|---|---|
| Hardware ECDH (ATECC608A via USB) | ~78 ms | constant, independent of file size |
| Software ECDH, Go vs mbedTLS | Go 16–28× faster | optimized assembly vs. portable C |
| Small file encryption, age vs. PGP | age 27–49× faster | dominated by GPG's file compression overhead |

## Limitations

Key limitations (full list in [`docs/limitations.md`](docs/limitations.md)):

1. **The `shared_secret` is transmitted in plaintext over USB** to an untrusted host. Malware active during decryption could decrypt this single file. The private key remains secure.
2. **Physical access allows the key to be used.** TUP is enforced only in firmware; therefore, anyone capable of communicating via I2C or flashing custom firmware can trigger ECDH without pressing the button. However, the key itself cannot be extracted.
3. **The custom `pico-p256` implementation** has not undergone peer review and is incompatible with the standard `age` format.
4. **OpenPGP certificate with a one-time master key** (the on-chip key does not perform signing); consequently, it cannot be revoked or updated, and the fingerprint changes upon regeneration.
5. **The ATECC608A lacks a public datasheet.** Documentation relies on the ATECC508A. Locking the chip configuration is irreversible.

## Documentation

| Document | Content |
|---|---|
| [`architecture.md`](docs/architecture.md) | components, client layers (age, OpenPGP), trust boundaries, design decisions |
| [`hardware.md`](docs/hardware.md) | BOM, wiring, chip configuration, personalization |
| [`protocol.md`](docs/protocol.md) | USB protocol specification (frames, commands, errors, TUP) |
| [`age-integration.md`](docs/age-integration.md) | `pico-p256` stanza, flows, interoperability |
| [`pgp-integration.md`](docs/pgp-integration.md) | certificate, PKESK, RFC 6637 KDF, test vectors |
| [`security-model.md`](docs/security-model.md) | threat model (STRIDE), summary of 12 attacks |
| [`limitations.md`](docs/limitations.md) | limitations and what the results do not prove |
| [`reproducibility.md`](docs/reproducibility.md) | reproducing the environment, tests, benchmarks, and attacks |
| [`docs/thesis/`](docs/thesis/) | master's thesis (PDF) |

---

Author: Kacper Karaś. Supervisor: Dr. Bartosz Chaber. Warsaw University of Technology, Faculty of Electrical Engineering, 2026.
