# Limitations

This document consolidates the **project limitations**—covering architecture, security, hardware, implementation, and research methodology—in one place. It also outlines what the results **do not demonstrate**.

Principle: each limitation is accompanied by its cause, impact, and—where possible—a workaround or direction for future work. Technical details can be found in the linked documents at the end.

> **Status:** research prototype from a master's thesis. It has not undergone a security audit and is not suitable for protecting high-value data.

## Table of Contents

- [Limitations](#limitations)
  - [Table of Contents](#table-of-contents)
  - [1. Summary](#1-summary)
  - [2. Security architecture and model](#2-security-architecture-and-model)
    - [L1.`shared_secret` in plaintext on USB](#l1shared_secret-in-plaintext-on-usb)
    - [L2. Enforcement of TUP solely in firmware](#l2-enforcement-of-tup-solely-in-firmware)
    - [L3. Model limitations](#l3-model-limitations)
  - [3. Cryptography and formats](#3-cryptography-and-formats)
    - [L4. P-256 instead of X25519, custom `pico-p256` stanza](#l4-p-256-instead-of-x25519-custom-pico-p256-stanza)
    - [L5. OpenPGP certificate without a self-signature](#l5-openpgp-certificate-without-a-self-signature)
    - [L5a. Scope of OpenPGP format support](#l5a-scope-of-openpgp-format-support)
  - [4. Hardware](#4-hardware)
    - [L6. No public ATECC608A datasheet](#l6-no-public-atecc608a-datasheet)
    - [L7. Irreversible configuration lock](#l7-irreversible-configuration-lock)
    - [Other hardware limitations](#other-hardware-limitations)
  - [5. Implementation and tools](#5-implementation-and-tools)
  - [6. Methodology: attack demonstrations](#6-methodology-attack-demonstrations)
  - [7. Functional scope](#7-functional-scope)
  - [8. What the results do not prove](#8-what-the-results-do-not-prove)
  - [Related documents](#related-documents)

---

## 1. Summary

| # | Limitation | Area | Severity |
|---|---|---|:---:|
| L1 | `shared_secret` transmitted in plaintext via USB to an untrusted host | security | high |
| L2 | Physical access allows *use* of the key (TUP implemented only in firmware) | security | high |
| L3 | `GEN_KEY` irreversibly destroys the key; no backup | availability | high |
| L4 | `pico-p256` format incompatible with standard `age`; unreviewed design | format | high |
| L5 | OpenPGP certificate with a one-time primary key (no revocation, unauthenticated User ID) | format | medium |
| L6 | ATECC608A lacks a public datasheet | hardware | medium |
| L7 | Chip configuration lock is irreversible | hardware | medium |
| L8 | Attack demonstrations involve simulations, extrapolations, or reduced scale | methodology | medium |
| L9 | Testing limited to Linux (Arch) | scope | low |

## 2. Security architecture and model

### L1.`shared_secret` in plaintext on USB

**Cause.** "Secure element + untrusted host" architecture: the chip performs ECDH, while the remainder of the decryption process takes place on the host; consequently, the ECDH result must be transmitted to the host. The USB channel is unencrypted, and the chip operates in *output-in-clear* mode.

**Impact.** Malware active on the host **during** decryption can intercept the secret and decrypt that specific file. The private key remains secure, and the exposure is limited to a single file (as the secret is ephemeral).

**Workaround.** None within this architecture. Eliminating the risk requires an encrypted channel (e.g., SCP03 in the SE050) or performing the entire file decryption inside the device. The architecture protects against **offline** attacks (disk theft, backups) but not against active malware.

### L2. Enforcement of TUP solely in firmware

**Cause.** The ATECC608A does not have key usage authentication configured (`ReqAuth = 0`). The button is checked by the Pico firmware.

**Impact.** Anyone capable of I2C communication (connecting to SDA/SCL) or flashing custom firmware via BOOTSEL can trigger ECDH operations while bypassing the button check. Physical access thus enables **use** of the key to decrypt known files, though not its **extraction**. By comparison, in U2F keys, the button is typically wired into the hardware path rather than relying solely on firmware logic.

**Workaround.** Hardware-level button integration, an external authentication factor, secure boot, or disabling BOOTSEL. Outside the project scope.

### L3. Model limitations

- **TUP protects against remote misuse, not against a person with physical access** who manually presses the button. This is a deliberate design choice, shared with U2F keys.
- **No replay protection and no frame authentication.** CRC32 detects accidental corruption, not an attack.
- **No device authentication by the host.** The host trusts any CDC device that responds to the protocol.
- **The I2C channel is unencrypted.** With physical access, the ECDH result can be intercepted.
- **No audit** of the code or cryptographic design.

## 3. Cryptography and formats

### L4. P-256 instead of X25519, custom `pico-p256` stanza

**Cause.** The ATECC608A supports only P-256. age uses X25519, and these curves are not interchangeable.

**Impact.**

- `.age` files created by `pico-crypt` **are not compatible** with the standard age CLI (they require `pico-crypt` for decryption). The format includes a `pico-p256` stanza.
- The stanza is a **custom construction** (ECDH P-256 + HKDF-SHA256 + AEAD), modeled after age and `age-plugin-yubikey` stanzas. It has not undergone peer review or formal analysis. One should not assume properties that have not been proven (e.g., key binding to the ciphertext).
- The resilience of age against attacks described in the paper applies to the **age format and its library**. It does not automatically extend to the custom construction.

**Alternatives considered.** Option B (X25519 key in the data slot) required the key to leave the chip, while Option C (chip acting as a PIN guardian, key in flash) reduced security. Option A was selected. See [`architecture.md`](architecture.md).

### L5. OpenPGP certificate without a self-signature

**Cause.** The key on the chip is an ECDH key and is not used for signing, whereas an OpenPGP certificate requires a self-signature. The `gen_cert.py` script constructs the certificate using a **temporary, random ECDSA master key** (software-based)—the private part of which is not saved—and the ECDH subkey with a point retrieved from the device.

**Impact.** The certificate is formally valid (two self-signatures, AES-256 preference, GnuPG imports it without self-signature warnings), but:

- **it cannot be revoked, extended, or modified**, because the private master key ceases to exist once the script finishes,
- **the User ID is unauthenticated.** Anyone can construct a certificate with the same User ID but a different subkey, so the subkey fingerprint must be used for verification,
- GnuPG does not assign trust to the certificate, so encryption requires `--trust-model always`,
- **re-running the script changes the fingerprint** (due to a new creation timestamp), and files encrypted for the previous certificate can only be decrypted using its corresponding `.fp` file,
- the script uses the **internal pgpy API** (version 0.6.0) and removes existing `pico@device` certificates from the keyring without prompting.

### L5a. Scope of OpenPGP format support

- only PKESK version 3, algorithm 18 (ECDH) with the P-256 curve is supported,
- the parser does not support *partial body length* headers, unnecessary packets, or keys for other curves,
- neither signing nor signature verification is implemented.

## 4. Hardware

### L6. No public ATECC608A datasheet

The ATECC608A is covered by an NDA. The design documentation relies on the public **ATECC508A Complete Data Sheet** and the *ATECC608A Summary Sheet*. While the product family is backward-compatible, configuration values, execution times, and behavioral details **had to be verified empirically** using a physical unit. The `SlotConfig`/`KeyConfig` values ​​in [`hardware.md`](hardware.md) are calculated based on the 508A datasheet, not the manufacturer's 608A documentation.

### L7. Irreversible configuration lock

The configuration and data zones cannot be modified once locked. A chip locked with an incorrect configuration is irreparable; a new one must be purchased. Prior to locking, `GenKey` returns an error, and the RNG outputs a fixed test pattern.

### Other hardware limitations

- **Single hardware unit**: one Pico board and one breakout board. Unit-to-unit variation was not tested.
- **Only 8 usable key slots** (0–7). The P-256 public key does not fit into slots 0–7, and the OpenPGP certificate requires slot 8.
- **Memory endurance:** 400,000 write cycles per byte. This is irrelevant for ECDH operations but applies to data and configuration writes.
- **RP2040 without secure boot** in the project configuration; BOOTSEL is physically accessible.

## 5. Implementation and tools

- **Tested exclusively on Arch Linux.** Not verified on Windows or macOS. Package names, the `uucp` group, and port paths are Linux-specific.
- **PGP encryption via the `gpg` subprocess.** Depends on the installed GnuPG and its behavior (options, exit codes, warnings).
- **USB protocol lacks frame versioning.** Backward compatibility relies on `ERR_UNKNOWN_CMD`. See [`protocol.md`](protocol.md).
- **Protocol lacks replay protection and encryption.** See above (L1).
- **Dependencies:** mbedTLS ≥ 3.0 (required for `nist_kw`), CryptoAuthLib, `filippo.io/age`, GnuPG 2.4.x, pgpy 0.6.0. Version changes may alter behavior (e.g., newer GnuPG versions rejecting small DSA parameters).

## 6. Methodology: attack demonstrations

- **GnuPG 2.4.9** and **age 1.3.1** were examined. Other OpenPGP implementations (such as Sequoia, RNP, OpenPGP.js, or LibrePGP variants other than GnuPG) were not tested and may behave differently.
- The comparison focuses on **file encryption**, not email. Some attacks (e.g., EFail) are primarily relevant in the context of email clients.
- The comparison covers the **format and its reference implementations**. The resilience of the format itself does not prove the correctness of any specific implementation's code.
- The set of 12 attacks does not constitute an exhaustive review of the vulnerabilities affecting both formats.

## 7. Functional scope

Not implemented or out of scope:

| Feature | Status |
|---|---|
| Digital signatures (not supported by *age*; not implemented for OpenPGP) | None |
| Multi-user and device sharing | None |
| On-device X25519 support | Not possible (chip limitation) |
| Encrypted host-to-device channel (e.g., SCP03) | None |
| Hardware-path button, secure boot | None |
| Non-Linux systems | Unverified |
| Certification (FIDO, Common Criteria) | None |

## 8. What the results do not prove

The results **support** the thesis that the *age* minimalism eliminates entire classes of format vulnerabilities. They **do not prove** that:

1. **The built device is secure.** There has been no audit. Known vulnerabilities: L1, L2, L2a.
2. **The custom `pico-p256` stanza possesses the security properties of standard *age*.** It is a new design.
3. **The hardware key protects against every attack on the host.** It protects against offline attacks and unauthorized remote use, but not against active malware during decryption.
4. ***age* is generally "more secure" than OpenPGP.** The findings apply to the 12 attack classes and specific implementations examined. OpenPGP includes features that *age* intentionally omits (signatures, certificates, web of trust, broad interoperability).

---

## Related documents

- [`architecture.md`](architecture.md): design decisions and architectural constraints
- [`security-model.md`](security-model.md): full threat model and overview of 12 attacks
- [`hardware.md`](hardware.md): chip configuration, irreversibility of the lock
- [`protocol.md`](protocol.md): USB protocol discrepancies and limitations
