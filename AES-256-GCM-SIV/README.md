# sivcrypt-pro

A fast, chunked, **AES‑256‑GCM‑SIV** file encryption CLI that’s safe for very large files, supports **atomic in-place replace**, **Argon2id passphrase** derivation, **key files**, **read‑only verification**, **stdout streaming**, and an optional **best‑effort wipe** of the original file when writing to a different output.

> **Why this tool?**  
> It combines robust operations (file locking, symlink refusal, metadata preservation, progress reporting) with a safer crypto layout that binds every chunk to its position, preventing cut‑and‑paste reordering attacks that some chunked formats allow.

---

## Features

- **AES‑256‑GCM‑SIV** AEAD (misuse‑resistant to nonce reuse; still uses unique nonces per chunk)
- **Chunked encryption/decryption** for bounded memory; great for huge files
- **Order integrity**: per‑chunk nonce is derived from `base_nonce8 || u32_be(index)` (not stored); the **header is AAD**, so tampering with parameters or reordering chunks fails authentication
- **Two keying modes**:
  - 32‑byte **key file** (with strict permission checks on Unix)
  - **Argon2id** passphrase (`AES_PASSWORD` env or interactive prompt) with tunable memory/time/lanes
- **Atomic replace** of the target path via `atomic-write-file` (works on Unix and Windows)
- **Operational hardening**: exclusive/shared file locks, symlink refusal, progress bar, restore original permissions & mtime
- **Modes**: encrypt, decrypt, **verify** (read‑only auth check)
- **I/O flexibility**: `--out` to a file or **`--stdout`** for pipelines
- **Optional wipe**: `--wipe-input` (single random pass + delete) when writing to a different `--out`
- **Backward compatible**: can decrypt older **v2** files; writes safer **v3** format
- `#![forbid(unsafe_code)]` and **zeroizes** key material

---

## Install / Build

Prerequisites: recent Rust toolchain (stable).

```bash
git clone <your-repo-or-local-path> sivcrypt-pro
cd sivcrypt-pro
cargo build --release

# optional: install to cargo bin dir
cargo install --path .
```

The binary will be at `target/release/sivcrypt-pro` (or on Windows, `target\release\sivcrypt-pro.exe`).

---

## Quick Start

Encrypt a file in place (interactive password prompt, Argon2id KDF):
```bash
sivcrypt-pro --password --encrypt ./data.bin
```

Decrypt to a new path:
```bash
sivcrypt-pro --decrypt --out ./plain.bin ./data.bin.siv
```

Verify (read‑only authentication check; no output written):
```bash
sivcrypt-pro --verify ./data.bin.siv
```

Stream to stdout for pipelines (headers included on encrypt):
```bash
# encrypt to stdout (send to a file)
sivcrypt-pro --password --encrypt --stdout ./big.iso > big.iso.siv

# decrypt from file to stdout (e.g., pipe to another tool)
sivcrypt-pro --decrypt --stdout ./big.iso.siv | sha256sum
```

Encrypt using a 32‑byte key file:
```bash
sivcrypt-pro --keyfile ./secret.key --encrypt ./movie.mkv
```

Encrypt to a different output, then wipe the original plaintext (single random pass + delete):
```bash
sivcrypt-pro --password --out ./data.bin.siv --wipe-input --yes --encrypt ./data.bin
```

> ⚠️ **Wipe caveat**: Application‑level overwrites cannot defeat filesystem snapshots/journaling, SSD wear‑leveling, cloud sync history, or backups. Use full‑disk encryption or a verified secure‑erase flow for forensic resistance.

---

## Usage

```
USAGE:
    sivcrypt-pro [OPTIONS] [--encrypt | --decrypt | --verify] <FILE>

MODES (choose one or auto-detected if omitted):
    --encrypt               Encrypt the input file
    --decrypt               Decrypt the input file
    --verify                Read-only integrity check (no writes)

I/O:
    --out <PATH>            Write output to this path (conflicts with --stdout)
    --stdout                Stream output to stdout (ciphertext for encrypt, plaintext for decrypt)
    --chunk-size <N>        Chunk size (e.g., 4M, 8M, 1M). Max 64M. Default: 4M
    --quiet                 Suppress progress output
    --yes                   Assume “yes” for overwrite and wipe confirmations

KEYING:
    --keyfile <PATH>        Use a 32-byte key file (encryption & decryption). Enforces strict perms on Unix
    --password              Derive key from passphrase (Argon2id) for ENCRYPTION. For decrypt/verify the tool auto-detects.

ARGON2 (applies when --password at ENCRYPTION time):
    --kdf-mem-mib <MiB>     Memory cost in MiB (default: 256)
    --kdf-iters <N>         Time/iterations (default: 3)
    --kdf-lanes <N>         Parallelism/lanes (default: 1)

WIPE (applies only when writing to a different --out):
    --wipe-input            After success, overwrite the original file once with random data and delete it
                            Requires --yes to confirm. Not a forensic-grade erase.

ENVIRONMENT:
    AES_PASSWORD            If set, used as the passphrase instead of prompting (be mindful of env leaks)
```

Exit status is non‑zero on error (bad key/passphrase, corruption, I/O failures).

---

## Security Design

- **Cipher**: AES‑256‑GCM‑SIV (AEAD). We use 96‑bit nonces, unique per chunk.
- **Header‑as‑AAD**: The full 64‑byte header is passed as **Associated Data** for every chunk, binding algorithm, version, salt, Argon2 params, chunk size, file size, and the file’s random `base_nonce8` to the ciphertext.
- **Nonce derivation (v3)**: For chunk index *i* (0‑based), `nonce = base_nonce8 || u32_be(i)`. Nonces are **not stored** in the body. Any chunk reordering or splicing breaks authentication.
- **KDF**: When using `--password`, the key is derived with **Argon2id** using configurable parameters. The file header stores the Argon2 parameters and the per‑file random salt for correct decryption later.
- **Atomic replace**: Output is written to a temporary file in the same directory, fsynced, then atomically replaced over the destination. Prevents partial/corrupt outputs on crash.
- **Key hygiene**: Passphrases are read without echo; derived keys are zeroized from memory when possible.
- **Legacy v2 support**: Decrypts v2 files that stored per‑chunk nonces in the body. That layout allowed whole‑chunk reordering without detection; v3 closes that gap.

> **Not covered**: metadata secrecy (filenames, sizes, timestamps), deniability, or forensic‑grade deletion. Pair with full‑disk encryption if those matter.

---

## File Format (v3)

**Header** (64 bytes; used as AAD for all chunks):

| Field            | Bytes | Format     | Notes                                   |
|------------------|------:|------------|-----------------------------------------|
| Magic            | 10    | ASCII      | `AESGCM-SIV`                            |
| Version          | 1     | u8         | `3` for v3                              |
| Algorithm        | 1     | u8         | `1` = AES‑256‑GCM‑SIV                   |
| Flags            | 2     | u16 LE     | bit 0: key from Argon2                  |
| Chunk size       | 4     | u32 LE     | plaintext chunk size                    |
| File size        | 8     | u64 LE     | total plaintext size                    |
| base_nonce8      | 8     | bytes      | random per file                         |
| salt16           | 16    | bytes      | random per file (Argon2 only; else zero)|
| Argon2 m_cost    | 4     | u32 LE     | in KiB (Argon2 only; else zero)         |
| Argon2 t_cost    | 4     | u32 LE     | iterations (Argon2 only; else zero)     |
| Argon2 lanes     | 4     | u32 LE     | parallelism (Argon2 only; else zero)    |
| Reserved         | 2     | zero       | padding to 64 bytes                     |

**Body**:

For each chunk index *i*:

```
ciphertext_i (len = min(chunk_size, remaining_plain)) || tag_i (16 bytes)
```

- Nonce for chunk *i*: `nonce = base_nonce8 || u32_be(i)`
- AAD for all chunks: the 64‑byte header above

**v2 (legacy) body**: `nonce(12) || ciphertext || tag(16)` per chunk (nonce stored explicitly).

---

## Performance & Tuning

- **Chunk size** (`--chunk-size`): default 4 MiB. Larger chunks reduce overhead slightly and may improve throughput; smaller chunks lower memory footprint (at the cost of more I/O). Max 64 MiB by default.
- **Argon2 parameters** (when `--password`): increase `--kdf-mem-mib` for stronger defense against GPU/ASIC cracking (trade‑off: slower). Defaults are **256 MiB**, **3** iterations, **1** lane—sane for modern desktops. Tune for your environment.
- **Huge files**: The 32‑bit chunk counter allows up to ~4.29 billion chunks. With 4 MiB chunks, that’s ~16 PiB—effectively unbounded for typical use.

---

## Operational Notes

- **Atomicity ≠ secure wipe**: Atomic replace avoids partial files; it doesn’t scrub the old data blocks. Use `--wipe-input` only as a convenience, not as a guarantee.
- **Key files on Unix**: The tool refuses world/group‑readable key files (recommend `chmod 600 secret.key`).
- **Environment variables**: `AES_PASSWORD` is convenient but can leak via process table, history, or crash dumps. Prefer interactive prompts for high‑value secrets.
- **Stdout mode**: Writes binary data to stdout; progress goes to stderr. Redirect or pipe as needed.

---

## Examples

Encrypt with a passphrase and custom KDF cost:
```bash
sivcrypt-pro --password --kdf-mem-mib 512 --kdf-iters 4 --encrypt ./archive.tar
```

Decrypt to stdout and verify with a hash:
```bash
sivcrypt-pro --decrypt --stdout ./archive.tar.siv | sha256sum
```

Verify a file without writing output:
```bash
sivcrypt-pro --verify ./archive.tar.siv
```

Encrypt using a key file and a larger chunk:
```bash
sivcrypt-pro --keyfile ./key.key --chunk-size 8M --encrypt ./video.mp4
```

Encrypt to a new file and wipe the original plaintext:
```bash
sivcrypt-pro --password --out ./video.mp4.siv --wipe-input --yes --encrypt ./video.mp4
```

---

## Troubleshooting

- **“authentication failed / wrong key”**: The passphrase or keyfile is incorrect, or the file is corrupted. For password‑based files, ensure `AES_PASSWORD` isn’t set unintentionally.
- **“file already appears encrypted”**: You tried to encrypt an already encrypted file; pass `--encrypt` explicitly to force (not generally recommended).
- **“key file must be exactly 32 bytes”**: The key file must contain 32 raw bytes. To generate: `head -c 32 /dev/urandom > key.key && chmod 600 key.key` (Unix).

---

## License

MIT. See `LICENSE` (or add one to your repo).

---

## Security Disclaimer

No software can guarantee perfect security in all environments. Understand your threat model. For maximal protection, combine this tool with full‑disk encryption, strict OS hardening, and robust key management.

