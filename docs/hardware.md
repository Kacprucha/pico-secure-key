# Hardware

This document describes the device hardware: the bill of materials (BOM), wiring diagram, electrical specifications, ATECC608A chip configuration, and the personalization and diagnostics procedure.

> **Note on chip documentation.** The ATECC608A does not have a public datasheet (it is covered by a Microchip NDA). The numerical values ​​and register descriptions in this document are derived from the public **ATECC508A Complete Data Sheet (DS20005927A)** and the *ATECC608A Summary Sheet*. The product family is backward-compatible, but **verify every value on your specific unit before writing the configuration** (configuration zone dump; see [6](#6-equipment-diagnostics-and-verification)).

## Spis treści

- [Hardware](#hardware)
  - [Spis treści](#spis-treści)
  - [1. Bill of Materials (BOM)](#1-bill-of-materials-bom)
  - [2. Wiring diagram](#2-wiring-diagram)
    - [2.1 ATECC608A ↔ Pico (I2C0)](#21-atecc608a--pico-i2c0)
    - [2.2 TUP button and LED](#22-tup-button-and-led)
    - [2.3 Diagram](#23-diagram)
  - [3. ATECC608A: memory organization](#3-atecc608a-memory-organization)
    - [3.1 Slot map in the project](#31-slot-map-in-the-project)
  - [4. Slot configuration](#4-slot-configuration)
    - [4.1 Requirements for the ECDH key slot](#41-requirements-for-the-ecdh-key-slot)
    - [4.2 ECDH output mode](#42-ecdh-output-mode)
  - [5. Chip personalization procedure](#5-chip-personalization-procedure)
  - [6. Equipment diagnostics and verification](#6-equipment-diagnostics-and-verification)
  - [7. Problems encountered](#7-problems-encountered)
  - [8. Physical security](#8-physical-security)

---

## 1. Bill of Materials (BOM)

| Component | Model | Notes | Price (PLN) |
|---|---|---|---|
| Microcontroller | Raspberry Pi Pico W (RP2040) | non-wireless version | 25.41 |
| Secure element | SparkFun Cryptographic Co-Processor Breakout – ATECC608A (Qwiic), DEV-18077 | older version SparkX SPX-15838 has the same chip and pinout | 23.37 |
| Button | Tactile, NO, 6×6 mm or 12×12 mm, 2.54 mm pitch | User Presence Test (TUP) | 1.99 |
| Wires | Qwiic cable + Qwiic-to-Dupont adapter | | 19.80 |
| USB cable | micro-USB **with data lines** | charge-only cables will not work | 3.90 |
| **Total** | | | **74.47** |

Product prices do not include shipping costs. Parts were purchased between March and April 2026.

**Why a breakout board instead of the bare chip:** the board comes with soldered I2C pull-up resistors and a decoupling capacitor, and the 2.54 mm headers allow the entire setup to be connected using four wires without a breadboard or soldering. Prices are estimates (year 2026); please check current pricing.

## 2. Wiring diagram

### 2.1 ATECC608A ↔ Pico (I2C0)

| SparkFun Breakout | Raspberry Pi Pico W | Physical Pin |
|---|---|---|
| `3V3` (or `VCC`) | 3V3(OUT) | 36 |
| `GND` | GND | 38 |
| `SDA` | GP4 (I2C0 SDA) | 6 |
| `SCL` | GP5 (I2C0 SCL) | 7 |

> ⚠️ **3.3V power only.** The Qwiic system is 3.3V only. Never connect the breakout to VBUS (5V). The chip's absolute maximum rating is 6.0V, but the other components on the board do not have that same tolerance.

Qwiic cable (JST 1mm, 4-pin); Qwiic wire colors: black = GND, red = 3V3, blue = SDA, yellow = SCL.

### 2.2 TUP button and LED

| Element | Pico | Physical pin | Notes |
|---|---|---|---|
| Button, pin 1 | GP15 | 20 | input with internal pull-up (~50 kΩ) |
| Button, pin 2 | GND | 23 | any GND pin |
| Status LED | GP25 | – | built-in Pico LED; lights up during the TUP window |

Pin change: `BUTTON_PIN` in `user_presence.h`.

### 2.3 Diagram

```
                 Raspberry Pi Pico
              ┌──────────────────────┐
  USB ───────►│ micro-USB            │      ATECC608A SparkFun
              │                      │      ┌─────────────┐
              │           GP4  SDA ◄─┼──────┼──► SDA      │
              │           GP5  SCL ◄─┼──────┼──► SCL      │
              │           3V3  ◄─────┼──────┼──► 3V3      │
              │           GND  ◄─────┼──────┼──► GND      │ 
        ┌─────┼──►  GND              │      └─────────────┘
  TUP  /      │                      │
        └─────┼──►  GP15             │
              └──────────────────────┘
```

## 3. ATECC608A: memory organization

| Zone | Size | Content |
|---|---|---|
| Configuration | 128 B | serial number, I2C address, `SlotConfig`, `KeyConfig`, counters, lock flags |
| Data | 1208 B, 16 slots | keys, certificates, data |
| OTP | 64 B | one-time write data or usage log |
| SRAM | volatile | `TempKey`, buffers (cleared on sleep) |

| Slots | Size | Typical use |
|---|---|---|
| 0–7 | 36 B | private or secret key (P-256 fits in 32 B + alignment) |
| 8 | 416 B | general data, certificates |
| 9–14 | 72 B | P-256 public key (X‖Y), signature, certificate |
| 15 | 72 B | same as 9–14; the only one with *limited use* functionality (128 uses) |

The P-256 public key (64 B) fits only in slots 8–15. Therefore, private keys are placed in slots 0–7.

### 3.1 Slot map in the project

| Slot | Usage | Type |
|---|---|---|
| 0 | device master key | ECC P-256, ECDH |
| 1–7 | additional user keys (rotation, contexts) | ECC P-256, ECDH |

## 4. Slot configuration

Each slot has a 16-bit `SlotConfig` (bytes 20–51 of the configuration zone) and a 16-bit `KeyConfig` (bytes 96–127). Multi-byte values ​​are stored **least significant byte first**.

### 4.1 Requirements for the ECDH key slot

Based on the ATECC508A datasheet:

| Field | Value | Reason |
|---|---|---|
| `IsSecret` (SlotConfig bit 7) | 1 | plaintext read prohibited; required for keys |
| `EncryptRead` (bit 6) | 0 | private key is not readable anyway |
| `ReadKey` bit 2 | 1 | **ECDH permission** |
| `ReadKey` bit 3 | **0** | ECDH result output in plaintext (not to slot N+1) |
| `ReadKey` bits 1 and 0 | 1 | internal and external signatures (optional, unused in the project) |
| `WriteConfig` bit 13 (SlotConfig bits 15–12) | 1 | `GenKey` permission (key generation) |
| `KeyType` (KeyConfig bits 4–2) | `0b100` | P-256 curve |
| `Private` (KeyConfig bit 0) | 1 | slot contains an ECC private key |
| `PubInfo` (KeyConfig bit 1) | 1 | public key can be recalculated (`GenKey` in public mode) |
| `Lockable` (KeyConfig bit 5) | optional | individual slot locking |

### 4.2 ECDH output mode

| Mode | `ReadKey` bit 3 | API Function | Use Case |
|---|---|---|---|
| **A: Plain (selected)** | 0 | `atcab_ecdh()` | Secret returned to the host via I2C |
| B: Encrypted | 1 | `atcab_ecdh_ioenc()` | Written to slot N+1; read encrypted using the I/O protection key |

Mode B protects the secret on the I2C bus but requires an additional key in a separate slot and significantly complicates the configuration. In this architecture, the secret must still pass via USB to an untrusted host, so the benefit is limited. See [`architecture.md`](architecture.md).

## 5. Chip personalization procedure

The sequence matters, and **locking is irreversible**.

```
1. Check communication       i2c scan → 0x60; atcab_info → byte [2] = 0x60
2. Read configuration        atcab_read_config_zone() → save dump to file
3. Write configuration       SlotConfig / KeyConfig for slots 0–7
4. Verify write              read back and compare with expected map
5. Lock config zone (Lock, mode 0)       ← IRREVERSIBLE
6. Generate keys             GenKey (creation mode) for slots 0..N
7. Lock data zone (Lock, mode 1)             ← IRREVERSIBLE
```

Consequences of the sequence, based on the datasheet:

- **`GenKey` returns an error before the configuration is locked.** A key cannot be generated on a fresh chip without first locking the configuration.
- **Before the configuration is locked, the RNG returns a fixed pattern** `FF FF 00 00 FF FF 00 00 …` (test mode). An entropy test using `GET_RANDOM` will fail on an unlocked chip. This is not a hardware defect.
- Locking a slot (`SlotLocked`) prevents subsequent key changes. Calling `GenKey` in creation mode on an existing key **destroys it permanently**.
- Firmware should not use `PrivWrite` (external key import). Microchip recommends generating keys exclusively inside the chip.

## 6. Equipment diagnostics and verification

Sequential steps, starting with the simplest. Each must be completed before moving on to the next.

| # | Test | Tool | Expected result |
|---|---|---|---|
| 1 | Pico visible to the system | `lsusb`, `ls /dev/ttyACM*` | VID `2E8A`, CDC port |
| 2 | Port access | `groups` | user in `uucp` group (Arch) |
| 3 | I2C scan | `i2c_scan.c` | device at `0x60` |
| 4 | Chip communication | `atcab_info()` | `00 00 60 xx` (byte 2 = `0x60`) |
| 5 | ECDH vs. software implementation | `test_ecdh_verify` | identical `shared_secret` |
| 6 | TUP | `test_tup` | `PENDING`, result after button press |

## 7. Problems encountered

| Symptom | Probable cause | Solution |
|---|---|---|
| Pico not visible as `/dev/ttyACM0` | Cable lacks data lines | Use a data-capable cable |
| `Permission denied` on port | Missing `uucp` group membership | `sudo usermod -aG uucp $USER`, log out and back in |
| I2C scanner finds nothing | Incorrect SDA/SCL wiring, no power | Check pins 6/7/36/38 |
| Scanner finds `0x60`, but CryptoAuthLib returns `ATCA_COMM_FAIL` | Address `0x60` used instead of `0xC0` in config | Set `atcai2c.address = 0xC0` |
| No response after sleep | Wake sequence skipped | Perform wake (100 kHz, ≥60 µs low), wait 1.5 ms |
| `ATCA_NOT_INITIALIZED` | `atcab_init()` missing | Initialize library before first call |
| `GenKey` returns error | Config zone unlocked, bit 13 missing in `WriteConfig`, or slot locked | Correct configuration (§5, §6) |
| `GET_PUBLIC_KEY` returns `ERR_CHIP_FAIL` | Slot does not yet contain a key | Generate a key |
| `ECDH` returns error | ECDH not permitted in `ReadKey` or invalid point | Check `SlotConfig`, use X‖Y format without `0x04` prefix |
| Button unresponsive | Incorrect pin, missing interrupt | check GP15 / pin 20 and ground |

## 8. Physical security

The chip implements physical security measures: an active shield, internal memory encryption, glitch protection, and voltage tampering detection. The manufacturer notes that no security measure is absolute.

Limitations of **this specific implementation**:

- the I2C bus is exposed on the breakout pins and is unencrypted (ECDH "output in clear" mode),
- the Pico firmware is open and not read-protected; however, it does not contain the private key,
- the TUP button protects against remote abuse, not against someone with physical access,
- the prototype lacks an enclosure and tamper-evidence features.

Full threat analysis: [`security-model.md`](security-model.md).
