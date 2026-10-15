# USB protocol specification

Communication protocol between the host and the Raspberry Pi Pico firmware. The transport mechanism is USB CDC (virtual serial port), and the application layer consists of binary frames with a CRC32 checksum.

## Table of Contents

- [USB protocol specification](#usb-protocol-specification)
  - [Table of Contents](#table-of-contents)
  - [1. Transport](#1-transport)
  - [2. Frame format](#2-frame-format)
  - [3. Reception and resynchronization](#3-reception-and-resynchronization)
  - [4. Command register](#4-command-register)
  - [5. Command description](#5-command-description)
    - [5.1 `GET_STATUS` (0x01)](#51-get_status-0x01)
    - [5.2 `GET_PUBLIC_KEY` (0x02)](#52-get_public_key-0x02)
    - [5.3 `ECDH_REQUEST` (0x03)](#53-ecdh_request-0x03)
    - [5.4 `GET_RANDOM` (0x04)](#54-get_random-0x04)
    - [5.5 `GEN_KEY` (0x05)](#55-gen_key-0x05)
    - [5.6 `USER_PRESENCE_PENDING` (0x06)](#56-user_presence_pending-0x06)
    - [5.7 `ECDH_REQUEST_BYPASS_TUP` (0x07)](#57-ecdh_request_bypass_tup-0x07)
    - [5.8 `GET_I2C_TIME` (0x08)](#58-get_i2c_time-0x08)
  - [6. Error codes](#6-error-codes)
  - [7. Test of user presence (TUP)](#7-test-of-user-presence-tup)
    - [7.1 Przebieg](#71-przebieg)
    - [7.2 Host requirements](#72-host-requirements)
  - [8. Requirements for host implementation](#8-requirements-for-host-implementation)
  - [9. Safety notes](#9-safety-notes)
    - [Related documents](#related-documents)

---

## 1. Transport

| Parameter         | Value                                                        |
| ----------------- | ------------------------------------------------------------ |
| Interface         | USB CDC (ACM), TinyUSB                                       |
| Port on Linux     | `/dev/ttyACM*`                                               |
| Mode              | raw byte stream                                              |
| Communication model | **request–response**, one request frame, one response frame |

The device does not send frames on its own initiative. Every frame from the device is a response to the most recent request. The host should not send a new request before receiving the response to the previous one (except for retries following `USER_PRESENCE_PENDING`).

## 2. Frame format

```
 offset   0       1       2        3        4 … 4+LEN-1     4+LEN … 7+LEN
        ┌───────┬───────┬────────┬────────┬───────────────┬──────────────────┐
        │  STX  │  CMD  │ LEN_LO │ LEN_HI │     DATA      │  CRC32 (LE, 4 B) │
        │ 0x02  │ 1 B   │  1 B   │  1 B   │  LEN bajtów   │                  │
        └───────┴───────┴────────┴────────┴───────────────┴──────────────────┘
```
| Field   | Size               | Description                                         |
| ------- | ------------------ | --------------------------------------------------- |
| `STX`   | 1 B                | Start-of-frame marker, always `0x02`                |
| `CMD`   | 1 B                | Command code (request) or `CMD \| 0x80` (response)  |
| `LEN`   | 2 B, little-endian | Length of the `DATA` field in bytes (`LEN_LO`, `LEN_HI`) |
| `DATA`  | 0–128 B            | Command-specific payload                            |
| `CRC32` | 4 B, little-endian | Checksum of `STX … DATA` (excluding the CRC itself) |

**Sizes:** Frame overhead (`FRAME_OVERHEAD`) is 8 B (4 B header + 4 B CRC). The maximum payload (`MAX_PAYLOAD`) is 255 B, so the maximum frame size is **263 B**. A frame with `LEN > 255` is discarded.

**Response:** The response command code is `CMD | 0x80` (e.g., `GET_STATUS` 0x01 → response 0x81).

**Error frame:** `CMD = 0xFF`, `LEN = 1`, `DATA` = error code.

## 3. Reception and resynchronization

USB can deliver a single frame in fragments or multiple frames at once. The firmware assembles the data in the receive buffer (256 B) and operates according to the following rules.

```
          new bites from USB
                 │
                 ▼
        append to the RX buffer
                 │
        is rx_pos ≥ 8 (FRAME_OVERHEAD)? ── no ──► wait for data
                 │ yes
        is buffer[0] == STX? ──── no ──► shift buffer to the next STX,
                 │ yes                    respond ERR_BAD_CRC, end
        LEN ≤ 255 and rx_pos ≥ 8+LEN? ─ no ─► wait for data
                 │ yes
        CRC correct? ─── no ──► (see note) return ERR_BAD_CRC
                 │ yes
        execute the command, remove 8+LEN bytes from the buffer
```

**Distinguishing between an incomplete frame and a corrupted one.** If the buffer starts with `STX` but is too short relative to `LEN`, the frame is **incomplete**. The firmware waits for further data and **does not clear the buffer**. Clearing the buffer due to fragmentation would result in the loss of valid data (see the `test_partial_frame` test).

The receive buffer is not cleared following a command error. If the frame boundary cannot be safely determined, the host can restore the state by waiting approximately 100 ms (until the device stops responding to pending data) and sending `GET_STATUS`.

## 4. Command register

| Code   | Name                    | Request (`DATA`)                           | Response (`DATA`)                  | TUP      |
| ------ | ----------------------- | ------------------------------------------ | -----------------------------------| :------: |
| `0x01` | `GET_STATUS`            | –                                          | ASCII string with firmware version | no       |
| `0x02` | `GET_PUBLIC_KEY`        | `[slot 1 B]`                               | `X‖Y`, 64 B                        | no       |
| `0x03` | `ECDH_REQUEST`          | `[slot 1 B][pub 64 B]` (65 B)              | `shared_secret`, 32 B              | yes      |
| `0x04` | `GET_RANDOM`            | `[n 1 B]` (optional)                       | `n` bytes, `n ≤ 32`                | no       |
| `0x05` | `GEN_KEY`               | `[slot 1 B]`                               | `X‖Y`, 64 B                        | yes      |
| `0x06` | `USER_PRESENCE_PENDING` | - (command only as **response**, 0x85)     | `[seconds][operation]`             | –        |
| `0x07` | `ECDH_REQUEST_BYPASS_TUP` | `[slot 1 B][pub 64 B]` (65 B)            | `shared_secret`, 32 B              | no       |
| `0x08` | `GET_I2C_TIME`          | `[slot 1 B][pub 64 B]`                     | `[seconds]`                        | no       |
| `0xFF` | `ERROR`                 | – (response only)                          | `[error code]`                     | –        |

## 5. Command description

### 5.1 `GET_STATUS` (0x01)

Returns the firmware version identifier as ASCII text, without a null terminator. It is used to verify that the device is responding and for auto-detection.

### 5.2 `GET_PUBLIC_KEY` (0x02)

| | |
| --------- | ------------------------------------------------------------ |
| Request   | `[slot]`: slot number 0–7                                    |
| Response  | 64 B: `X` (32 B) ‖ `Y` (32 B), big-endian, **without `0x04` prefix** |
| Errors    | `ERR_BAD_LENGTH` (invalid size or slot), `ERR_CHIP_FAIL` (slot without key or I2C error) |

The `ERR_CHIP_FAIL` response for an empty slot signifies "key does not exist." Internally, the firmware calls `atcab_get_pubkey()` (public `GenKey` mode), which **does not change** the key.

The 64-byte format without the `0x04` prefix is ​​compatible with the `GenKey`/`Verify` format in ATECC. Libraries expecting the point in uncompressed format (65 bytes) require the addition of the `0x04` prefix.

### 5.3 `ECDH_REQUEST` (0x03)

| | |
| --------- | ------------------------------------------------------------ |
| Request   | `[slot 1 B][pub 64 B]`: private key slot number and the other party's public key (`X‖Y`, without `0x04`) |
| Response  | 32 B: X-coordinate of the ECDH point (`shared_secret`) |
| TUP       | required                                            |
| Errors    | `ERR_BAD_LENGTH`, `ERR_USER_PRESENCE_REQUIRED` / `PENDING`, `ERR_CHIP_FAIL` |

The operation uses the private key from the specified slot. The slot must have ECDH and clear output enabled in `SlotConfig` (see [`hardware.md`](hardware.md)). The firmware rejects a point where `X` or `Y` consists entirely of zeros.

The result does not undergo any further key derivation function on the device side. The host employs its own KDF (HKDF-SHA256 for age, OpenPGP KDF for PGP). The firmware zeroes out the secret buffer after sending the response.

### 5.4 `GET_RANDOM` (0x04)

Before the ATECC608A configuration zone is locked, the RNG returns a fixed pattern `FF FF 00 00 FF FF 00 00 …` (test mode). This is not an error (see [`hardware.md`](hardware.md)).

Used exclusively to test whether the ATECC608A is correctly configured.

### 5.5 `GEN_KEY` (0x05)

Generates a new P-256 key pair in the specified slot (`GenKey` in creation mode) and returns the public key (64 B).

> ⚠️ **Irreversible operation.** Destroys the existing key in the slot. Requires the configuration zone to be locked and bit 13 of the slot's `WriteConfig` to be set. If the slot has already been locked (`SlotLocked`), the chip will return an error and the key will remain intact. Requiring TUP is recommended (see [`security-model.md`](security-model.md)).

### 5.6 `USER_PRESENCE_PENDING` (0x06)

It appears only in responses (frame code: `0x85`). It informs the host that the operation requires a button press. The `DATA` field consists of 2 bytes:

| Byte | Meaning                                              |
| ---- | ---------------------------------------------------- |
| 0    | number of seconds remaining in the TUP window (default: 10) |
| 1    | pending operation code: `0x01` = ECDH                |

Details are provided in point 8.

### 5.7 `ECDH_REQUEST_BYPASS_TUP` (0x07)

Same as `ECDH_REQUEST`, but it does not require user presence confirmation for the operation to succeed.

This command is used during GPG and age performance measurements so that the act of pressing a button does not affect the measured time.

> ⚠️ **This is a dangerous command intended solely for the measurement process**; for actual deployment, **support for this command must be removed**. 

### 5.8 `GET_I2C_TIME` (0x08)

This command is used exclusively for testing the communication timing between the Raspberry Pi Pico and the ATECC608A component.

The command requires valid data to perform the ECDH operation and returns the execution time for these operations.

> ⚠️ **This is a dangerous command intended solely for the measurement process**; for actual deployment, **support for this command must be removed**. 

## 6. Error codes

Error frame: `CMD = 0xFF`, `DATA = [code]`.

| Code   | Name                         | Meaning                                      | Typical cause                                                |
| ------ | ---------------------------- | -------------------------------------------- | ------------------------------------------------------------ |
| `0x01` | `ERR_UNKNOWN_CMD`            | unknown command code                         | host version newer than firmware                             |
| `0x02` | `ERR_BAD_CRC`                | CRC error or invalid frame start             | transmission interference, buffer garbage                    |
| `0x03` | `ERR_BAD_LENGTH`             | invalid payload length, slot, or point       | incorrect size, zero point, slot out of range                |
| `0x04` | `ERR_CHIP_FAIL`              | ATECC608A error                              | slot without key, I2C error, rejected point, config error    |
| `0x05` | `ERR_BAD_SLOT`               | slot number not supported by device          | slot outside 0–7 range                                |
| `0x06` | `ERR_USER_PRESENCE_REQUIRED` | operation requires button press              | no press (usually precedes `PENDING`)                        |
| `0x07` | `ERR_USER_PRESENCE_TIMEOUT`  | TUP window expired                           | button not pressed within 10 s                               |


**Host-side error handling rules:**

- `ERR_BAD_CRC`: retry the request (safe for `GET_*` and `ECDH_REQUEST`).
- `ERR_CHIP_FAIL`: do not automatically retry more than a few times. The user message should indicate the probable cause (empty slot, missing chip).
- `ERR_UNKNOWN_CMD`: version mismatch; abort.

## 7. Test of user presence (TUP)

Sensitive operations require physically pressing a button connected to GP15. The mechanism is modeled on the *test of user presence* from FIDO U2F.

### 7.1 Przebieg

```
Host                              Firmware                       User
 │                                    │                            │
 │── ECDH_REQUEST(slot, pub) ────────►│                            │
 │                                    │ tup_check() == false       │
 │                                    │ tup_request() → LED ON     │
 │◄── 0x85 PENDING [10, 0x01] ────────│                            │
 │   (host displays a message)        │                            │
 │                                    │◄──── button proessed  ─────┤
 │   wait for 500 ms                  │      flag set in ISR       │
 │── ECDH_REQUEST (again)   ──────►   │                            │
 │                                    │ tup_check() == true        │
 │                                    │ LED OFF, flag deleted      │
 │                                    │ ECDH in ATECC608A          │
 │◄── 0x83 shared_secret (32 B) ──────│                            │
```

### 7.2 Host requirements

- After receiving a `PENDING` response, the host displays a message to the user (e.g., "Press the button on the device").
- The host retries **the same** request approximately every 500 ms, up to a maximum of 25 retries (~12.5 s). After this time, it reports a timeout.
- The host distinguishes the `PENDING` response from the actual response based on the **command code in the frame** (`0x85` vs `0x83`), not the `DATA` content. The host library must return the response code to the caller (`cmd_out`).

## 8. Requirements for host implementation

1. **Looping read.** A single `read()` call might return a partial frame (since CDC delivers data in packets). First, read the 4-byte header to obtain `LEN`, then read `LEN + 4` bytes—all with a timeout.
2. **Response frame verification:** Check for `STX`, a response code equal to `CMD | 0x80` or `0xFF`, `LEN ≤ 128`, and a valid CRC. A response failing these checks indicates a communication error.
3. **Error differentiation.** An `0xFF` frame carries the error code in `DATA[0]`.
4. **Auto-detection.** Scan for `/dev/ttyACM*` devices and verify them using `GET_STATUS`. Do not assume the first port found is the target device.
5. **State cleanup after error.** Following a timeout or CRC error, wait briefly and flush any remaining bytes before issuing the next request.
6. **Zeroing secrets.** After using `shared_secret`, zero out the buffer.
7. **One request at a time** and exclusive port access (using `flock` or equivalent) to prevent two processes from interleaving frames.

## 9. Safety notes

- **Lack of channel authentication and encryption.** Frames are transmitted over USB in plaintext. An attacker on the host can see all traffic (see [`security-model.md`](security-model.md)).
- **CRC32 is not a MAC.** An attacker on the host can send their own frames with valid checksums.
- **No replay protection.** The protocol uses neither nonces nor counters. Replaying an `ECDH_REQUEST` yields the same secret for the same point but requires a TUP (Touch-to-Use/User Presence) interaction each time.
- **Input validation** in the firmware covers: `STX`, `LEN`, CRC, per-command payload length, slot range, and zero point. The parser performs no dynamic allocations and uses fixed-size buffers.

---

### Related documents

- [`architecture.md`](architecture.md): age and OpenPGP flows utilizing the protocol
- [`hardware.md`](hardware.md): slot configuration required by `ECDH_REQUEST` and `GEN_KEY`
- [`security-model.md`](security-model.md): threats related to the USB channel and TUP