# Security Policy

## Project status

**pico-secure-key** is a research prototype developed as part of a master's thesis. It has not undergone an external audit and **is not intended for protecting high-value data**. Do not rely on it as the sole safeguard for information whose disclosure or loss would be harmful to you or others.

This repository is maintained on a *best-effort* basis, without guarantees regarding response times or any obligation to release updates or fixes.

## Vulnerability reporting

**Do not report vulnerabilities via public issues.**

Use a **private GitHub report** (*Security → Report a vulnerability*).

In the report, please provide the following information if possible:

- version (tag or commit hash) and environment (OS, versions of GnuPG, age, firmware),
- description of the issue and its impact,
- reproduction steps (ideally a minimal example),
- whether the issue concerns the firmware, USB protocol, `pico-crypt`, `pico-pgp`, or the documentation.

**What to expect:** an acknowledgment of receipt within a reasonable timeframe (aiming for a few business days, though not guaranteed), an assessment of the report, and information on next steps. For reports involving significant impact, I propose coordinating the deployment of a fix following joint testing. I am happy to credit the reporter in the acknowledgments if they wish.

## Scope

### Covered areas

- Pico firmware (frame parser, command handling, TUP),
- USB protocol and host library,
- `pico-crypt` (including the `pico-p256` component and key derivation),
- `pico-pgp` (PKESK parser, KDF, session key handling),
- documentation errors that could lead to an insecure configuration (e.g., incorrect chip configuration values).

### Out of Scope

- **Known limitations** described in [`docs/limitations.md`](docs/limitations.md) and [`docs/security-model.md`](docs/security-model.md), specifically:
- plaintext `shared_secret` over USB and the absence of an encrypted channel,
- the ability to *use* the key given physical access to the device (TUP implemented only in firmware),
- the single-use nature of the OpenPGP certificate's master key (no revocation or updates, unauthenticated User ID),
- the custom, unreviewed `pico-p256` implementation. 

New information regarding these limitations, such as a proven method of exploitation, is welcome, but I do not consider them to be undisclosed vulnerabilities.
- invasive attacks on the ATECC608A silicon, supply chain attacks targeting components,
- vulnerabilities in dependencies (GnuPG, age, mbedTLS, CryptoAuthLib, pico-sdk, TinyUSB). Please report these to the respective maintainers. If they relate to how these dependencies are used in this project, please notify me as well,
- vulnerabilities in the OpenPGP and age formats described in the paper (these are the subject of the research).

## Responsible use of attack demonstrations

The [`attacks/`](attacks/) directory contains demonstrations of attacks against the OpenPGP format for **educational and research** purposes. Use them only:

- on your own data and keys,
- in a controlled test environment,
- to crack passwords for files you generated yourself (applicable to tools such as hashcat).

You must not use them against other people's data, systems, or keys without the owner's consent. The author accepts no liability for misuse. Some demonstrations are simulations or reduced-scale versions (see [`docs/limitations.md`](docs/limitations.md)) and are not ready-to-use attack tools.

This repository does not contain or distribute private keys, other than test keys created solely for demonstration purposes. Do not use them for any other purpose.

## Safe use

If you use the project despite the warnings:

- **do not lock the chip** (configuration and data zones) until you have verified the configuration on a spare unit; locking is irreversible,
- **lock the slots** after generating the key (see [`docs/security-model.md`](docs/security-model.md)),
- **do not perform decryption** on a computer you suspect is infected,
- remove test keys from the GnuPG keyring when they are no longer needed,
- verify the values ​​from [`docs/hardware.md`](docs/hardware.md) on your own unit before writing the configuration; the documentation is based on the ATECC508A datasheet, not the ATECC608A manufacturer documentation.
