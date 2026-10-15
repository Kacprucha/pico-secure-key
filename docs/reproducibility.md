# Reproduction

Instructions for reproducing the environment, building the device, and conducting tests, benchmarks, and attack demonstrations. It outlines the **sequence of steps, expected results, and common pitfalls**.

## Table of Contents

- [Reproduction](#reproduction)
  - [Table of Contents](#table-of-contents)
  - [1. What can be reproduced and the requirements](#1-what-can-be-reproduced-and-the-requirements)
  - [2. Reference environment](#2-reference-environment)
  - [3. Installing dependencies](#3-installing-dependencies)
    - [3.1 Arch Linux](#31-arch-linux)
    - [3.2 pico-sdk](#32-pico-sdk)
    - [3.3 Project repository](#33-project-repository)
  - [4. Building firmware and uploading to Pico](#4-building-firmware-and-uploading-to-pico)
    - [Wiring](#wiring)
  - [5. ATECC608A Chip Personalization](#5-atecc608a-chip-personalization)
  - [6. Using `pico-crypt` and `pico-pgp`](#6-using-pico-crypt-and-pico-pgp)
    - [6.1 age (`pico-crypt`)](#61-age-pico-crypt)
    - [6.2 OpenPGP (`pico-pgp`)](#62-openpgp-pico-pgp)
  - [7. Benchmarks](#7-benchmarks)
    - [7.1 Prerequisites](#71-prerequisites)
    - [7.2 Running `run_benchmarks.sh`](#72-running-run_benchmarkssh)
    - [7.3 What is measured](#73-what-is-measured)
    - [7.4 Charts and Excel spreadsheet](#74-charts-and-excel-spreadsheet)
  - [8. Attack demonstrations](#8-attack-demonstrations)
    - [Critical details for success](#critical-details-for-success)
  - [9. Expected results and tolerances](#9-expected-results-and-tolerances)
  - [10. Issues encountered](#10-issues-encountered)
  - [11. Safety and reproduction ethics](#11-safety-and-reproduction-ethics)
  - [Related documents](#related-documents)

---

## 1. What can be reproduced and the requirements

The project consists of three layers with varying requirements. **Start with the lowest level** that interests you.

| Level | Scope | Requires Pico + ATECC608A hardware | Requires GPU |
|---|---|:---:|:---:|
| **0** | attack demonstrations (1, 2, 5, 6, 9–12), protocol tests without the device, software benchmarks | no | no |
| **0.5** | attack 7 (brute-force S2K vs scrypt) | no | yes (hashcat) |
| **1** | firmware, USB communication, I2C, `GET_RANDOM`, public key | yes | no |
| **2** | full workflow: chip configuration, `pico-crypt`, `pico-pgp`, hardware benchmarks | yes | no |

Level 0 requires no additional hardware and allows you to verify the main research hypothesis.

## 2. Reference environment

The results presented in this work were obtained using the configuration described below. Performance figures depend on hardware, security settings, and format compliance, and also vary according to software version.

| Element | Reference value |
|---|---|
| System | Arch Linux (kernel version 7.0.9-arch2-1) |
| Processor | AMD Ryzen 5 9600X |
| GPU | NVIDIA GeForce RTX 5070 (12 GB), driver with CUDA 13.x, hashcat via OpenCL |
| GnuPG | 2.4.9 |
| age | 1.3.1 |
| hashcat | 7.1.2 |
| Python | 3.12.3 |
| pgpy | 0.6.0 |
| Go | ≥ 1.21 |
| mbedTLS | ≥ 3.0 (required for `mbedtls/nist_kw.h`) |
| ARM toolchain | `arm-none-eabi-gcc`, `arm-none-eabi-newlib`, CMake, Ninja |
| pico-sdk | 2.3.0-1 |
| CryptoAuthLib | commit `7f0015` |
| TinyUSB | commit `da307f` |
| Hardware | Raspberry Pi Pico (RP2040), SparkFun Qwiic ATECC608A (DEV-18077), tactile button |

## 3. Installing dependencies

### 3.1 Arch Linux

```bash
# Serial port access group (Arch: uucp, not dialout)
sudo usermod -aG uucp $USER
# Log out and log back in (temporarily: newgrp uucp)

# General tools and firmware
sudo pacman -S --needed \
arm-none-eabi-gcc arm-none-eabi-newlib arm-none-eabi-binutils \
cmake ninja git base-devel \
mbedtls picocom gnupg gnuplot openocd arm-none-eabi-gdb usbutils \
go python python-pip hashcat

# age (Arch: AUR, or binary from GitHub Releases)
yay -S age
```

### 3.2 pico-sdk

```bash
git clone https://github.com/raspberrypi/pico-sdk --recurse-submodules ~/pico-sdk
cd ~/pico-sdk 
echo 'export PICO_SDK_PATH=~/pico-sdk' >> ~/.bashrc
source ~/.bashrc
```

### 3.3 Project repository

```bash
git clone --recurse-submodules https://github.com/Kacprucha/pico-secure-key.git pico-secure-key
cd pico-secure-key
git submodule status                      # write submodule hashes (CryptoAuthLib, TinyUSB)
-7f0015615a70671814a8dd956c8318d1b922791e firmware/libs/cryptoauthlib
-da307fa85b4002c875284bb82d7db1ca1bc7347d firmware/libs/tinyusb
```

## 4. Building firmware and uploading to Pico

```bash
cd firmware
mkdir -p build && cd build
cmake .. -DPICO_SDK_PATH=$PICO_SDK_PATH
make -j4 # or: ninja
```

The result is `firmware.uf2`.

**Uploading:** hold down the BOOTSEL button, connect the Pico via a USB cable (with data lines), release the button, and copy the `.uf2` file to the `RPI-RP2` drive that appears. The device will reboot.

**Verification:**

```bash
lsusb | grep 2e8a   # Raspberry Pi VID
ls /dev/ttyACM*     # CDC port
```

If you see `Permission denied`, check `groups | grep uucp`.

> **Configuration files.** The firmware requires `src/crypto/atca_config.h` (`ATCA_HAL_I2C`, `ATCA_ATECC608_SUPPORT`). Without it, CryptoAuthLib will not compile. The I2C address in the CryptoAuthLib configuration is `0xC0` (8-bit), not `0x60`.

### Wiring

Full schematic in [`hardware.md`](hardware.md). In brief: `3V3 → pin 36`, `GND → pin 38`, `SDA → GP4 (pin 6)`, `SCL → GP5 (pin 7)`, push-button between `GP15 (pin 20)` and `GND`. Power supply: **3.3 V only**.

## 5. ATECC608A Chip Personalization

> ⚠️ **The operations in this section are irreversible.** Locking the configuration and data zones cannot be undone. Perform initial tests using a **spare** breakout board. Details and the rationale for the sequence can be found in [`hardware.md`](hardware.md).

Configuration values ​​for the ECDH slot, calculated based on the 508A datasheet: `SlotConfig = 0x2087`, `KeyConfig = 0x0033` (bytes `87 20` and `33 00`).

**Post-personalization verification:**

```bash
cd host && make
./test_frame /dev/ttyACM0
./test_protocol /dev/ttyACM0
./test_ecdh /dev/ttyACM0
```

## 6. Using `pico-crypt` and `pico-pgp`

### 6.1 age (`pico-crypt`)

```bash
cd pico-crypt
go build -o pico-crypt ./...
./pico-crypt list-keys
echo "Secret text" > test.txt
./pico-crypt encrypt test.txt              # if slot is empty: prompts to generate a key
./pico-crypt decrypt test.txt.age          # press the button on the device
```

Header of the resulting file:

```bash
head -5 test.txt.age
# age-encryption.org/v1
# -> pico-p256 <eph_pub_base64> <slot>
# <encrypted_file_key_base64>
# ---
```

### 6.2 OpenPGP (`pico-pgp`)

```bash
cd pico-pgp
make
python3 gen_cert.py <X‖Y hex>                       # builds the certificate, imports it into GnuPG, and creates pico_cert.pgp.fp
./pico-pgp encrypt test.txt                         # encrypts via GPG
./pico-pgp decrypt test.txt.pgp --slot 0            # press the button
gpg --list-packets test.txt.pgp                     # should show PKESK, algo 18
```

The `pico_cert.pgp.fp` file (the **sub-key** fingerprint) is required for KDF during decryption. **Each execution of `gen_cert.py` creates a new certificate with a new fingerprint**, removes the old `pico@device` certificate from the keyring, and overwrites the `.fp` file; consequently, files encrypted using the previous certificate require that certificate's fingerprint (see [`pgp-integration.md`](pgp-integration.md)). To obtain the public key, run the `./pico-pgp export-pubkey --slot N [--port /dev/ttyACM0]` command, which retrieves and displays the public key from the physical key.

## 7. Benchmarks

Measurements are automated using two scripts in the `analysis/` directory: `run_benchmarks.sh` (Bash) runs benchmarks for both clients and collects raw data, while `generate_charts.py` converts this data into CSV files, charts, and an Excel spreadsheet.

### 7.1 Prerequisites

| Requirement | When needed |
|---|---|
| Go, `make`, `gcc`, mbedTLS | Always (steps 1 and 2) |
| `python3` | Step 3 (charts) |
| Pico on the specified port, key in the `--slot` slot | Hardware benchmarks (without `--no-hw`) |
| Imported `pico@device` certificate (`python3 gen_cert.py && gpg --import pico_cert.pgp`) | PGP hardware benchmarks |
| Firmware in button-bypass mode (see note below) | `BenchmarkDecrypt_*` |

**Python environment (one-time setup).** The script creates `analysis/venv` but **does not install dependencies** inside it; instead, it checks for them and exits with an error if any package is missing. Install them manually before the first run:

```bash
cd analysis
python3 -m venv venv
venv/bin/pip install pandas matplotlib openpyxl numpy
```

> **Decryption measurement without button press.** Decryption benchmarks use a mode that bypasses TUP (`BypassTUP=true` in the age client, `DECRYPT_FLAG_BYPASS_TUP` in the PGP client) to avoid requiring a manual button press for every iteration. TUP is enforced by the firmware, so this mode must also exist on the device side. **The TUP bypass mechanism must not be available in production firmware**, as any process on the host could trigger it (see [`protocol.md`](protocol.md)).

### 7.2 Running `run_benchmarks.sh`

```bash
cd analysis
./run_benchmarks.sh [options]
```

| Option | Default | Meaning |
|---|---|---|
| `--port PORT` | `/dev/ttyACM0` | Pico serial port |
| `--slot N` | `0` | private key slot |
| `--runs N` | `20` | number of PGP (C) benchmark repetitions |
| `--benchtime DUR` | `10s` | duration of a single Go benchmark (`go test -benchtime`) |
| `--no-hw` | disabled | skip hardware benchmarks (no Pico) |
| `--no-pgp` | disabled | skip step 1 (PGP) |
| `--no-age` | disabled | skip step 2 (age) |
| `--no-charts` | disabled | skip step 3 (charts and Excel) |
| `-h`, `--help` | | help (see §8.9, point 1) |

The script runs with `set -euo pipefail`, so it terminates on the first error. Steps:

| Step | Action | Output |
|---|---|---|
| **1. PGP** (C) | in `pico-pgp`: `make bench -s`, then `benchmarks/bench_pgp --runs N --port P --slot S [--no-hw]` with standard output redirected to a file | `results/pgp_bench.csv` |
| **2. age** (Go) | in `age-go-client`: `go test ./benchmarks/... -bench <filter> -benchtime <T> -benchmem -count 1 -v` (output also piped to a file via `tee`). The filter is `.` (all) or `BenchmarkECDH_Software` when using `--no-hw`. Then `go test -run TestFileSizes -v` filtering for lines starting with `age,` | `results/age_raw.txt`, `results/age_sizes.csv` |
| **3. Charts** | create `venv` (if missing), check packages, run `generate_charts.py --pgp … --age … --age-sizes … --out results` | `results/age_bench.csv`, `results/charts/*.png`, `results/comparison.xlsx` |

At the end, the script prints a list of the generated files (`.csv`, `.xlsx`, `.png`, `.txt`) and the command to regenerate the charts.

### 7.3 What is measured

| Benchmark | Client | What is measured | Device required |
|---|---|---|:---:|
| `BenchmarkECDH_Software` | age (Go) | Software-based ECDH P-256 (`crypto/ecdh`) | no |
| `BenchmarkECDH_Hardware` | age, PGP | `ECDH_REQUEST` time (USB + I2C + chip) | yes |
| `BenchmarkEncrypt_Soft/<size>` | age (Go) | Encryption to software key (baseline) | no |
| `BenchmarkEncrypt_Hardware/<size>` | age, PGP | Encryption to device key (PGP: `gpg` process) | yes (public key) |
| `BenchmarkDecrypt_Hardware/<size>` (PGP: `Decrypt_HW`) | age, PGP | Full decryption using the device, without waiting for button press | yes |
| `TestFileSizes` / `FileSize` rows | age, PGP | Encrypted file size, overhead, header and payload size | no |

File sizes recognized by the chart generator: **100 B, 1 KB, 64 KB, 1 MB, 10 MB, 100 MB** (sub-benchmark name must include the size label, e.g., `/1MB`).

### 7.4 Charts and Excel spreadsheet

`generate_charts.py` saves the following to `results/charts/`:

| File | Content |
|---|---|
| `01_ecdh_comparison.png` | ECDH P-256: bars for pico-pgp and age, software and hardware variants, logarithmic scale, error bars (min/max) |
| `02_encrypt_time.png` | encryption time vs. file size, hardware variant, pico-pgp vs. age (log) |
| `03_decrypt_time.png` | decryption time vs. file size, hardware variant (log) |
| `04_encrypt_decrypt_combined.png` | charts 02 and 03 side-by-side |
| `05_file_size_total.png` | encrypted file size vs. plaintext size (log/log) |
| `06_overhead_bytes.png` | overhead in bytes (encrypted size minus plaintext size) |
| `07_overhead_pct.png` | overhead as a percentage of plaintext size |

`comparison.xlsx` spreadsheet:

| Sheet | Content |
|---|---|
| `Summary` | operation × size table: PGP and age times, PGP min/max, encrypted sizes, overhead, header and payload sizes |
| `PGP Raw` | all parsed PGP rows |
| `age Raw` | all parsed age rows |
| `age Sizes` | content of `age_sizes.csv` | Charts 05–07 use `age_sizes.csv` (auto-detected alongside the `--age` file if the option is not specified). The generator terminates with an error if no input data is provided (i.e., both the `--pgp` and `--age` files are missing or empty).

## 8. Attack demonstrations

Each demonstration is self-contained. Scripts and descriptions are located in `attacks/`.

Detailed attack descriptions can be found in [`security-model.md`](security-model.md).

### Critical details for success

- **Attacks 1 and 2** require legacy mode flags: `--rfc2440` or `--cipher-algo` combined with `--allow-old-cipher-algos` and `--compress-algo none`. The oracle ignores MDC errors (`--ignore-mdc-error`).
- **Attack 5:** the input is an exported key (`gpg --export-secret-keys`), **not** a file created with `--symmetric`. Generate the passphrase-protected EdDSA key using a batch file (`gpg --batch --pinentry-mode loopback --gen-key`). Current versions of GnuPG reject keys with `q < ~160` bits, so full extraction works on a simulated library without validation.
- **Attack 7:** mode 22301 corresponds to Telegram SHA-256, not GPG. Use 17010.
- **Attack 11:** the fuzzing target for GnuPG is the **public key**, not the SKESK. Fuzzing the SKESK invokes `gpg-agent` (~500 ms per attempt).

## 9. Expected results and tolerances

| Result | Reference value | Reproduction tolerance |
|---|---|---|
| Hardware ECDH (host, median) | ~78 ms | Depends on USB host and firmware. Same order of magnitude (tens of ms). Higher variance with USB hubs |
| Software ECDH: Go vs mbedTLS | Go ~16–28× faster | Depends on CPU and Go version. The direction of the difference should remain consistent |
| Small file encryption: age vs PGP | age ~27–49× faster | Dominated by `gpg` process overhead. Depends on system and `gpg-agent` |
| age header | 168 B + 16 B per 64 KiB | Deterministic |
| hashcat SHA-1 S2K (RTX 5070) | 13,186.3 kH/s | Depends on GPU, driver, hashcat version |
| hashcat scrypt, N = 16384 | 3,703 H/s | Same as above |
| age scrypt, N = 262144 | ~14.5 H/s (extrapolated) | Linear scaling with N |

**Qualitative** results (direction of difference, detection/non-detection of modification, exit codes) should be identical. **Quantitative** results (timings, throughput) depend on the platform.

## 10. Issues encountered

| Symptom | Cause | Solution |
|---|---|---|
| `Permission denied` on `/dev/ttyACM0` | missing `uucp` group | `usermod -aG uucp`, log out and back in |
| Missing `stdio.h` during firmware build | missing `arm-none-eabi-newlib` | install the package |
| CryptoAuthLib fails to compile | missing `atca_config.h` | create the file |
| `ATCA_COMM_FAIL` despite `0x60` being detected | address `0x60` in library config | set to `0xC0` |
| RNG entropy test fails | chip not locked (fixed pattern) | lock the configuration or skip the test for now |
| `GenKey` returns an error | configuration not locked or missing bit 13 in `WriteConfig` | see [`hardware.md`](hardware.md) |
| Hardware benchmark skipped | device missing or slot 0 empty | connect device, generate key |
| No response after pressing button | TUP window expired (10 s) | retry the operation |
| hashcat: "CUDA SDK Toolkit not installed" | missing CUDA SDK | use OpenCL (works; reference result obtained this way) |
| GnuPG "unsafe hash" during attack 5 | newer GnuPG version | intended behavior; use the simulation from the repository |
| Varying number of error branches in attack 11 | depends on GnuPG version and mutation set | use the same version and mutation seed |

## 11. Safety and reproduction ethics

- **Perform attack demonstrations only using your own data and keys.** This applies especially to attacks 1, 2, 5, 7, and 9. Only perform password cracking (using hashcat) on files you have generated yourself.
- **Do not use test keys for any other purpose.** The keys `pico@device`, `debug@test.com`, and `test@example.com` were created for testing purposes. Remove them from your keyring when finished (`gpg --delete-secret-and-public-keys`).
- **Irreversibility.** Ensure the configuration is correct before locking the chip.
- **This project is a prototype.** Reproducing it does not make it a product. See [`limitations.md`](limitations.md).

---

## Related documents

- [`hardware.md`](hardware.md): wiring and chip configuration
- [`protocol.md`](protocol.md): test frames and CRC vectors
- [`architecture.md`](architecture.md): components, client layers, design decisions
- [`security-model.md`](security-model.md): description of attacks and caveats
- [`limitations.md`](limitations.md): what the results support and what they do not prove
