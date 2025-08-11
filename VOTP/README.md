# votp 2.2

**Versatile, hardened one-time-pad XOR transformer**  
+ **Deterministic key generator** (built in by default)

---

## Features

- **OTP XOR**: Encrypts or decrypts data with a key file (stream XOR).
- **Deterministic keygen**: Creates high-strength key material from a password & salt.
- **Secure file handling**:
  - Unix: restrictive `chmod(0600)`
  - Windows: restrictive ACLs
  - Exclusive file locks, no following symlinks
- Optional SHA-256 verification (`--verify`)
- Optional progress bar (`--progress`)
- Unix extended attribute preservation (`--features xattrs`)

---

## Installation

```sh
# Build with keygen (default)
cargo build --release

# Or without keygen (small build)
cargo build --release --no-default-features
```

Binary will be at:
```
target/release/votp
```

---

## Key Size Format

When generating keys, size uses the format:

```
<n><B|KB|MB|GB>
```

- `B`  = bytes
- `KB` = kibibytes (×1024)
- `MB` = mebibytes (×1024²)
- `GB` = gibibytes (×1024³)
- **Maximum**: 20 GiB

Examples:
```
32B   → 32 bytes
1KB   → 1024 bytes
10MB  → 10 × 1024² bytes
2GB   → 2 × 1024³ bytes
```

---

## Key Generation Usage

Generate cryptographic key material from a password & salt.  
**Important:** The salt must be unique per key.

```
votp keygen <size> [OPTIONS]
```

### Options

| Option                | Description                                                | Default                |
|-----------------------|------------------------------------------------------------|------------------------|
| `<size>`              | Key size (`B|KB|MB|GB` format)                             | — (required)           |
| `-o`, `--output`      | Output file path                                           | `key.key`              |
| `-a`, `--algo`        | Stream algorithm: `blake3` or `chacha`                     | `blake3`               |
| `-s`, `--salt`        | Base64 salt (must be ≥ 12 chars, ~9 bytes raw)              | — (required)           |
| `--argon2-memory`     | Argon2 memory in KiB                                       | `65536` (64 MiB)       |
| `--argon2-time`       | Argon2 iterations/time cost                                | `3`                    |
| `--argon2-par`        | Argon2 parallelism (0 = auto)                              | `0`                    |
| `--gen-salt <n>`      | Generate and print a new random salt of N bytes, then exit | —                      |

### Examples

**1. Generate a salt (16 bytes)**
```sh
votp keygen 1KB --gen-salt 16
```

**2. Generate a 1MB Blake3 key**
```sh
votp keygen 1MB --salt "BASE64_SALT_FROM_STEP1"
```

**3. Generate a 32B ChaCha key with custom output**
```sh
votp keygen 32B -a chacha -o my.key --salt "BASE64_SALT"
```

**4. Generate a 10MB key with custom Argon2 parameters**
```sh
votp keygen 10MB   --argon2-memory 131072   --argon2-time 5   --argon2-par 4   --salt "BASE64_SALT"
```

---

## OTP XOR Usage

Encrypts or decrypts data with a key file by XORing the streams.

```
votp xor [OPTIONS]
```

Or, without the explicit `xor` subcommand:
```
votp [OPTIONS]
```

### Options

| Option                | Description                                                           |
|-----------------------|-----------------------------------------------------------------------|
| `-i`, `--input`       | Input file (`-` for stdin)                                             |
| `-k`, `--key`         | Key file path (or use `$OTP_KEY` env var)                              |
| `-o`, `--output`      | Output file (`-` for stdout)                                           |
| `--in-place`          | Modify the input file in place                                         |
| `--min-len`           | Require key length ≥ data length                                       |
| `--strict-len`        | Require key length == data length                                      |
| `--expect <sha256>`   | (verify feature) Expect output SHA-256 hash to match given value       |
| `--progress`          | (progress feature) Show a progress bar                                 |

### Examples

**1. Encrypt file with key**
```sh
votp xor -i secret.txt -k key.key -o secret.enc
```

**2. Decrypt back**
```sh
votp xor -i secret.enc -k key.key -o secret.txt
```

**3. Encrypt in-place**
```sh
votp xor -i secret.txt -k key.key --in-place
```

**4. Require exact key length**
```sh
votp xor -i file.bin -k key.bin --strict-len
```

**5. Require at least file length**
```sh
votp xor -i file.bin -k key.bin --min-len
```

**6. With SHA-256 verification**
```sh
votp xor -i file.bin -k key.bin -o out.bin --expect deadbeef...hash...
```

**7. With progress bar**
```sh
votp xor -i bigfile.iso -k bigkey.key -o out.iso --progress
```

---

## Security Notes

- One-time-pad security **requires**:
  - Truly random, secret key
  - Key used only once
  - Key length exactly equal to data length
- The deterministic `keygen` mode is **not a true OTP**, but can produce strong keys from a password and salt.
- Always use unique salts and keep them secret with the password.

---

## License

MIT OR Apache-2.0
