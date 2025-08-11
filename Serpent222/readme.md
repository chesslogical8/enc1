# Serpent 2

A secure file-encryption tool written in Rust using the **Serpent** block cipher in **CBC mode** with **PKCS#7 padding** and **HMAC-SHA256** authentication.  
Passwords are stretched with **Argon2id** and keys are zeroized with the [`secrecy`](https://docs.rs/secrecy) crate.

## Features

- **Argon2id** password-based key derivation  
  - Default: 64 MiB memory, 3 iterations, 1 lane  
  - Parameters are stored in the file header and authenticated
- **HKDF-SHA256** to split the master key into encryption (`k_enc`) and authentication (`k_auth`) keys
- **Serpent (CBC)** encryption with **PKCS#7 padding**
- **HMAC-SHA256** in **encrypt-then-MAC** mode for full header + ciphertext integrity
- **Self-describing file format**  
  - Magic bytes, version, KDF parameters, salt, and IV are all in the header  
  - Entire header is covered by the HMAC
- **Secret zeroization** via `secrecy`
- **Clap**-powered CLI with `encrypt` / `decrypt` subcommands
- **Structured logging** with `env_logger`
- `--force` flag to allow overwriting existing files
- Password confirmation prompt when encrypting

## Requirements

- Rust toolchain (1.70 or newer recommended)
- Internet connection to fetch dependencies

## Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/serpent2.git
cd serpent2

# Build and install to your cargo bin path
cargo install --path .
```

## Usage

Encrypt a file (outputs `<input>.enc` by default):

```bash
serpent2 encrypt -i secret.txt
```

Decrypt a file (outputs `<input>.dec` by default):

```bash
serpent2 decrypt -i secret.txt.enc
```

Specify an explicit output path:

```bash
serpent2 encrypt -i secret.txt -o encrypted.bin
serpent2 decrypt -i encrypted.bin -o decrypted.txt
```

Force overwrite an existing output:

```bash
serpent2 encrypt -i file.txt -o file.txt.enc --force
```

## File Format

All multi-byte integers are little-endian. Layout:

| Field             | Size (bytes) | Notes |
|-------------------|--------------|-------|
| `magic`           | 4            | ASCII `"SRP2"` |
| `version`         | 2            | Format version (`0x0001`) |
| `kdf_id`          | 1            | `1` = Argon2id |
| `argon2_m_kib`    | 4            | Memory cost (KiB) |
| `argon2_t`        | 4            | Iterations |
| `argon2_p`        | 4            | Parallelism |
| `salt`            | 16           | Random salt for Argon2id |
| `iv`              | 16           | CBC IV |
| `ciphertext`      | n            | PKCS#7 padded |
| `tag`             | 32           | HMAC-SHA256 over `header || ciphertext` |

## Logging

By default, only warnings and errors are printed. To enable info-level logging:

```bash
RUST_LOG=info serpent2 encrypt -i secret.txt
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/foo`)
3. Commit your changes (`git commit -m "Add foo feature"`)
4. Push to the branch (`git push origin feature/foo`)
5. Open a Pull Request

## License

This project is licensed under MIT or Apache-2.0. See [LICENSE](LICENSE) for details.
