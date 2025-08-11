# tf1024 — Production‑grade Threefish‑1024 file encryption (key‑file based)

**tf1024** is a minimalist, security‑first CLI that encrypts/decrypts files using **Threefish‑1024** as the core block cipher, with modern, boring‑secure framing:

- **Key file only** (no passwords here). You supply a binary key file; the tool never touches passwords/KDFs.
- **Per‑file subkeys** via **HKDF‑SHA‑512** using a random 32‑byte salt in the header.
- **Confidentiality**: Threefish‑1024 used as a keystream (CTR‑style). A 16‑byte **nonce** is placed in the cipher **tweak** and also echoed inside the 128‑byte counter block we encrypt to produce each keystream block.
- **Integrity**: **Encrypt‑then‑MAC (EtM)** using **HMAC‑SHA‑512**, truncated to 32 bytes. **Verify before decrypt**. New files use **framed AAD** (see `mac_id = 0x02`).
- **Streaming** I/O for huge files; **atomic replace** for `--inplace`; **zeroize** wipes key material from memory.
- Clean, versioned header; strict input validation and size bounds.

> If you want a production‑grade Threefish app that “uses the algorithm properly,” this is a deliberately conservative design: no password KDFs, no exotic constructions, well‑separated keys, and a standard EtM layout.

---

## Table of contents

- [Why this design?](#why-this-design)
- [Security properties](#security-properties)
- [File format](#file-format)
- [Install](#install)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
- [Associated Data (AAD)](#associated-data-aad)
- [Key management](#key-management)
- [Performance & tuning](#performance--tuning)
- [Threat model & non‑goals](#threat-model--non-goals)
- [Interoperability & compatibility](#interoperability--compatibility)
- [FAQ](#faq)
- [Changelog](#changelog)
- [License](#license)

---

## Why this design?

Threefish‑1024 is a large‑block **tweakable** cipher (128‑byte block, 128‑bit tweak). We use it in a **counter/keystream mode**:
- A random **per‑file nonce** is placed in the tweak.
- The **block index** is embedded into a zero‑padded 128‑byte counter block (which also carries the nonce) before encryption.
- Encrypting that counter block with Threefish outputs a 128‑byte **keystream block** we XOR with the file bytes.

To avoid nonce misuse or key reuse across files, we derive **per‑file subkeys** from a master key using **HKDF‑SHA‑512** with a **random 32‑byte salt** stored in the header. Integrity is provided with **HMAC‑SHA‑512** (truncated to 32 bytes) in classic **Encrypt‑then‑MAC** with full **verify‑then‑decrypt**.

This gives you a **boring, conservative** scheme that’s easy to audit and avoids exotic assumptions.

---

## Security properties

- **Confidentiality** under Threefish‑1024 keystream mode with per‑file unique subkeys and nonces.
- **Integrity & authenticity** via HMAC‑SHA‑512 (tag truncated to 32 bytes = 256 bits).
- **Verify‑then‑decrypt** prevents malleability/bit‑flips from reaching plaintext consumers.
- **Key separation**: subkeys are independently derived for encryption and MAC using distinct HKDF `info` labels.
- **No passwords**: you bring a binary key file (≥32 bytes; **128 recommended**). No password‑KDF parameters to misconfigure.
- **Streaming**: memory bounded by `chunk_size` (default 1 MiB; max 8 MiB).

> **Not protected:** File size and basic header fields are visible; AAD is authenticated but not encrypted; no deniability or multi‑recipient envelopes.

---

## File format

All multi‑byte integers are **little‑endian**. Layout:

```
magic[8]      = 54 46 31 30 32 34 00 01   # "TF1024\0\x01"
version[2]    = 01 00                      # 0x0001
flags[2]      = 00 00                      # reserved
kdf_id[1]     = 01                         # HKDF-SHA512
mac_id[1]     = 02                         # HMAC-SHA512/32 with framed AAD (default)
                                            # (01 = legacy, unframed AAD)
chunk_size[4] = <u32> bytes (multiple of 128, ≤ 8 MiB)
salt[32]      = random per-file
nonce[16]     = random per-file (nonce used as Threefish tweak; also echoed in ctr block)
reserved[8]   = 00 ... 00
-----------------------------------------   # header length = 74 bytes
ciphertext[..]
tag[32]       = HMAC-SHA512(input), first 32 bytes
```

**HMAC input** depends on `mac_id`:

- `mac_id = 0x02` (framed, **default for new files**):
  ```
  input = header
        || "tf1024/aad-len-le64"
        || LE64(len(AAD))
        || AAD
        || ciphertext
  ```
- `mac_id = 0x01` (legacy):
  ```
  input = header || AAD || ciphertext
  ```

Header fields are validated and bounded; unknown versions/IDs/flags cause decryption to refuse.

---

## Install

### Prerequisites
- Rust toolchain (stable). Install from <https://rustup.rs>.
- Builds on Linux, macOS, and Windows.

### Build

```bash
# clone your repo or unpack the source, then:
cd tf1024
cargo build --release
```
The binary will be at `target/release/tf1024` (or `tf1024.exe` on Windows).

---

## Quick start

```bash
# 1) Generate a 128-byte master key file (recommended size)
./target/release/tf1024 gen-key -o master.key -n 128

# 2) Encrypt a file (writes file.tf by default)
./target/release/tf1024 encrypt -k master.key -i file

#    With explicit output and 2 MiB chunk size:
./target/release/tf1024 encrypt -k master.key -i file -o file.tf --chunk-kib 2048

#    With AAD (authenticated, not encrypted):
./target/release/tf1024 encrypt -k master.key -i file --aad metadata.json

# 3) Decrypt
./target/release/tf1024 decrypt -k master.key -i file.tf -o file.dec
```

**Windows (PowerShell):**
```powershell
.	arget
elease	f1024.exe gen-key -o master.key -n 128
.	arget
elease	f1024.exe encrypt -k master.key -i file
.	arget
elease	f1024.exe decrypt -k master.key -i file.tf -o file.dec
```

**In‑place** (atomic replace via temp file):
```bash
./target/release/tf1024 encrypt -k master.key -i file --inplace
./target/release/tf1024 decrypt -k master.key -i file.tf --inplace
```

---

## Command reference

### `gen-key`
Generate a random binary key file.
```
tf1024 gen-key [--no-overwrite] [-o OUT] [-n BYTES]
```
- `-o, --out` path to write (default `tf1024.key`)
- `-n, --bytes` bytes of entropy (min 32, **recommend 128**)
- `--no-overwrite` **atomic** refusal to clobber an existing file

> On Unix, the file is created with `0600` perms when possible. On Windows, ACLs inherit from the directory.

### `encrypt`
Encrypt a file.
```
tf1024 encrypt -k KEY -i INPUT [-o OUTPUT] [--aad AAD_FILE] [--chunk-kib N] [--inplace] [--overwrite]
```
- `-k, --key`    master key file (binary)
- `-i, --input`  file to encrypt
- `-o, --output` output file. If omitted, `INPUT.tf` is used (unless `--inplace`).
- `--aad`        path to **associated data** to authenticate (not stored in ciphertext)
- `--chunk-kib`  chunk size in KiB; must be a multiple of `128` bytes (default `1024`, max `8192`)
- `--inplace`    encrypt in place (atomic replace via tmp file)
- `--overwrite`  allow overwriting existing output files

### `decrypt`
Decrypt a file.
```
tf1024 decrypt -k KEY -i INPUT [-o OUTPUT] [--aad AAD_FILE] [--inplace] [--overwrite]
```
- `--aad` must match the one used at encryption (if any).

Decryption will **verify MAC first**; on failure you’ll see `MAC verification failed (wrong key or AAD?)` and no output is written.

---

## Associated Data (AAD)

AAD lets you bind extra context (e.g., JSON metadata) into the authentication without encrypting it. New files **frame** the AAD by including a domain string and its length before MAC’ing, eliminating concatenation ambiguity.

```bash
tf1024 encrypt -k master.key -i report.pdf --aad metadata.json
# later
tf1024 decrypt -k master.key -i report.pdf.tf --aad metadata.json
```
If you supply the wrong AAD (or omit it when it was used), MAC verification fails and decryption aborts.

---

## Key management

- **Size**: at least 32 bytes; **128 bytes recommended**.
- **Generation**: `tf1024 gen-key -o master.key -n 128`.
- **Backups**: keep copies in separate secure locations; losing the key loses all data.
- **Permissions**:
  - **Unix**: created with `0600` when possible; keep in a private directory.
  - **Windows**: consider restricting ACLs:
    ```powershell
    icacls master.key /inheritance:r
    icacls master.key /grant:r "$env:USERNAME:(R,W)"
    ```
- **Rotation**: to rotate keys, generate a new key and re‑encrypt data as needed.

> This tool intentionally does **not** implement password‑based encryption. If you want that, generate your key file with a separate KDF tool and feed the resulting key to tf1024.

---

## Performance & tuning

- **Streaming**: only one chunk is buffered at a time. Default is **1 MiB**; you can raise up to **8 MiB** with `--chunk-kib` for better throughput on fast disks.
- **Truncation**: HMAC‑SHA‑512 is truncated to **32 bytes** (256‑bit tag) and compared in constant time.
- **Parallelism**: current implementation is single‑threaded by design (predictable, simple). If you need multi‑GB/s, a parallel mode can be added without changing the format.

---

## Threat model & non‑goals

**Goals**
- Confidentiality and integrity of file contents under a single master key.
- One‑key, single‑recipient design with robust streaming semantics.
- Safe defaults; refusal on unknown header values; bounded resource use.

**Non‑goals**
- Metadata hiding (file size, header fields are visible).
- Deniability, forward secrecy, or multi‑recipient envelopes.
- Password UX (deliberate: this is key‑file based).

---

## Interoperability & compatibility

- **Cipher**: Threefish‑1024 from the Rust `threefish` crate.
- **Format**: Versioned: `MAGIC = "TF1024\0\x01"`, `version = 1`.
  - `kdf_id = 0x01` (HKDF‑SHA‑512)
  - `mac_id = 0x02` (framed AAD, **default for new files**) or `0x01` (legacy, accepted on decrypt)
- The tool **rejects unknown versions/IDs/flags**.

---

## FAQ

**Why not Skein/HMAC‑Skein?**  
We use HMAC‑SHA‑512 and HKDF‑SHA‑512 because the crates are mature and widely reviewed. The cipher itself remains Threefish‑1024.

**Why truncate the HMAC tag to 32 bytes?**  
32 bytes (256 bits) is conventional and plenty; we compute the full 64‑byte MAC and compare the first 32 bytes in constant time.

**Is this SIV?**  
No. This is classic Encrypt‑then‑MAC. If you want misuse resistance (SIV), a two‑pass SIV variant could be added later as a new `mac_id` or `version`.

**Can I encrypt directories?**  
Not directly; wrap this via a script or tarball first.

---


## License

Dual‑licensed under **Apache‑2.0 OR MIT**. Do what works for your project.
