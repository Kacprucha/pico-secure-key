# Information about third-party software

The **pico-secure-key** project uses third-party software. This file lists the components, their licenses, and usage details, and includes the terms that must be included upon redistribution.

The project's own code is released under the license described in the [`LICENSE`](LICENSE) file. Licenses for external components apply independently and take precedence for their respective code.

## Table of Contents

- [Information about third-party software](#information-about-third-party-software)
  - [Table of Contents](#table-of-contents)
  - [1. Summary](#1-summary)
    - [1.1 Firmware](#11-firmware)
    - [1.2 Host tools](#12-host-tools)
  - [2. CryptoAuthLib (Microchip license)](#2-cryptoauthlib-microchip-license)
    - [2.1 Implications for the project](#21-implications-for-the-project)
    - [2.2 How the library is included](#22-how-the-library-is-included)

---

## 1. Summary

### 1.1 Firmware

| Component | License (SPDX) | Role | Inclusion Method | Version |
|---|---|---|---|---|
| [pico-sdk](https://github.com/raspberrypi/pico-sdk) | BSD-3-Clause | RP2040 libraries: GPIO, I2C, watchdog, USB, system startup | build dependency, linked | 2.3.0-1 |
| [TinyUSB](https://github.com/hathach/tinyusb) | MIT | USB stack (CDC device) | pico-sdk or project submodule, linked | 0.20.0 |
| [CryptoAuthLib](https://github.com/MicrochipTech/cryptoauthlib) | **Microchip proprietary license** (non-OSI) | ATECC608A driver (`atcab_*`, HAL) | git submodule, linked | 3.7.9 |

### 1.2 Host tools

| Component | License (SPDX) | Role | Integration method | Version |
|---|---|---|---|---|
| [mbedTLS](https://github.com/Mbed-TLS/mbedtls) | Apache-2.0 (to the best of my knowledge, dual-licensed: `Apache-2.0 OR GPL-2.0-or-later`) | SHA-256, SHA-1, AES Key Unwrap (`nist_kw`), ECDH in tests | linked library (`pico-pgp`, tests, C benchmarks) | 4.1.0 |
| [filippo.io/age](https://github.com/FiloSottile/age) | BSD-3-Clause | age format (`Recipient`, `Identity`, STREAM) | Go module | 1.3.1 |
| [GnuPG](https://gnupg.org/) | GPL-3.0-or-later | OpenPGP content encryption and decryption | **separate process** (`fork`/`exec`), not linked | 2.4.9 |
| [age](https://github.com/FiloSottile/age) (`age` program) | BSD-3-Clause | reference point for benchmarks and attacks | separate process | 1.3.1 |

---

## 2. CryptoAuthLib (Microchip license)

CryptoAuthLib **is not** open-source software in the OSI sense. Microchip's proprietary license applies; the full text (from the library's `LICENSE` file) is provided below. Redistribution of source code or binaries containing this library requires the inclusion of these terms and the warranty disclaimer.

```text
(c) 2015-2026 Microchip Technology Inc. and its subsidiaries.

Subject to your compliance with these terms, you may use the Microchip Software
and any derivatives exclusively with Microchip products. It is your
responsibility to comply with third party license terms applicable to your
use of third party software (including open source software) that may
accompany Microchip Software.

Redistribution of this Microchip Software in source or binary form is allowed
and must include the above terms of use and the following disclaimer with the
distribution and accompanying materials.

THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT,
SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
MICROCHIP HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE.
TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL
CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF
FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
```

### 2.1 Implications for the project

| Condition | Consequence |
|---|---|
| use "exclusively with Microchip products" (including "derivatives") | firmware linked with CryptoAuthLib must be treated as **intended solely for Microchip chips** (specifically: ATECC608A). Porting to a different secure element requires replacing the library (the HAL and chip operation layers are decoupled from it; see [`architecture.md`](architecture.md)) |
| responsibility for license compliance of other components | also applies to components bundled with the firmware (pico-sdk, TinyUSB) |
| redistribution subject to conditions and clauses | the text above must accompany any distribution of source code or binaries containing the library |
| incompatibility with copyleft licenses | the firmware **cannot** be licensed under GPL or AGPL, as Microchip's additional restrictions are incompatible with them |

### 2.2 How the library is included

- The library is included as a **Git submodule** (`firmware/libs/cryptoauthlib`). The repository does not contain the library's source code itself, but rather a reference to a specific commit. The library's own `LICENSE` file remains within the submodule.
- The project's own code (`hal_i2c_pico.c`, `atecc608a.c`, `atca_config.h`) utilizes the library's interfaces and is licensed separately.