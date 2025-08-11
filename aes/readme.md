# AES – One-Command File Encryption (v2)

Fast, reliable AES-256-GCM-SIV encryption/decryption for files.  
No setup hassle – just one command and you’re done.

---

## Quick Start

```bash
# Encrypt
aes myfile.txt

# Decrypt
aes myfile.txt

# Force encrypt/decrypt
aes --encrypt myfile.txt
aes --decrypt myfile.txt
```

The tool auto-detects whether a file is encrypted.  
By default it looks for `key.key` in the same directory.

---

## Key Options

You must supply a 32-byte key **either** via file or password:

### Key File (default)
```bash
# Create a random key
head -c 32 /dev/urandom > key.key   # Linux/macOS
# or
openssl rand -out key.key 32       # cross-platform

# Ensure safe permissions
chmod 600 key.key
```

By default, the tool loads `key.key` from the file’s directory.  
Use `--keyfile` to point elsewhere:

```bash
aes --keyfile /path/to/my.key secret.pdf
```

### Password-Derived Key
Derive a strong key from your password using Argon2id:

```bash
aes --password secret.pdf
```

You’ll be prompted securely (no echo).  
You can also set an environment variable for automation:

```bash
export AES_PASSWORD="MySuperSecretPassphrase"
aes secret.pdf
```

---

## Output Control

- `--out path` – Write to a new file instead of overwriting input.
- `--yes` – Skip overwrite confirmation prompts.
- `--quiet` – Suppress progress bar output.

---

## Chunk Size (Large Files)

Files are encrypted/decrypted **in chunks** to avoid high RAM usage.

Default: `4M` (4 MiB per chunk)  
Max: `64M`

You can change it:

```bash
aes --chunk-size 8M bigfile.iso
```

---

## Encryption Format (v2)

Each encrypted file contains:

| Field                | Size         | Description                                      |
|----------------------|--------------|--------------------------------------------------|
| Magic                | 10 bytes     | `"AESGCM-SIV"`                                   |
| Version              | 1 byte       | `0x02`                                           |
| Algorithm ID         | 1 byte       | `0x01` = AES-256-GCM-SIV                         |
| Flags                | 2 bytes      | Bit 0 = Argon2 password key                      |
| Chunk Size           | 4 bytes LE   | In bytes                                         |
| File Size            | 8 bytes LE   | Original plaintext length                        |
| Base Nonce           | 8 bytes      | Random per-file nonce prefix                     |
| Salt                 | 16 bytes     | Argon2 salt (all zeros if key file used)         |
| Argon2 m_cost_kib    | 4 bytes LE   | Memory cost (0 if not used)                      |
| Argon2 t_cost        | 4 bytes LE   | Iteration count (0 if not used)                  |
| Argon2 lanes         | 4 bytes LE   | Parallelism (0 if not used)                      |
| *(padding to 64B)*   |              |                                                  |
| **Chunk Records**    | Variable     | For each chunk: nonce (12B) + ciphertext + tag   |

### Security
- **AES-256-GCM-SIV**: misuse-resistant AEAD mode.
- **AAD**: The full header is authenticated, preventing swap/tamper.
- **Chunked AEAD**: Each chunk gets a unique nonce and authentication tag.
- **Argon2id**: Memory-hard KDF for password-derived keys.

---

## Examples

```bash
# Encrypt file with key file
aes notes.txt

# Decrypt file with key file
aes notes.txt

# Encrypt file with password prompt
aes --password notes.txt

# Decrypt file with password from env
AES_PASSWORD=Secret aes notes.txt

# Encrypt large file with custom chunk size
aes --chunk-size 8M movie.mkv

# Output to different file
aes --out notes.enc notes.txt
```

---

## Notes

- **Do not lose your key** – there is no recovery if lost.
- The tool refuses to operate on symlinks for safety.
- Works cross-platform (Linux, macOS, Windows).
- Requires Rust 1.70+ to build.

---

## Build

```bash
cargo build --release
```

The binary will be at `target/release/aes`.

---

## License

MIT – do what you like, just don’t blame us if you lose your key 😉
