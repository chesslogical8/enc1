# rse — Rust Safe Encrypt

**rse** is a single-file, cross-platform CLI for **safe, chunked, authenticated file encryption**.  
It uses modern, misuse-resistant cryptography and performs atomic file writes for crash-safety.

---

## Overview

This tool doesn’t invent new crypto — it assembles well-tested primitives from established crates into a custom file format that’s easy to audit:

- **Encryption:** [XChaCha20-Poly1305](https://docs.rs/chacha20poly1305/) AEAD  
- **Key derivation:** [Argon2id](https://docs.rs/argon2/) (tunable memory/time/parallelism)  
- **Subkey derivation:** [HKDF-SHA512](https://docs.rs/hkdf/)  
- **Integrity:** [BLAKE3](https://docs.rs/blake3/) keyed MAC (header) + hash (trailer)  

Files are split into independently encrypted chunks with unique keys (via HKDF), allowing safe use of a constant nonce per chunk. The header is authenticated twice — once by binding the wrapped file key to the suite ID and UUID via AEAD associated data, and again with a BLAKE3 keyed MAC derived from the file key.

Atomic I/O ensures files are either fully written or not modified at all: data is written to a `.part` temp file, `fsync`’d, then renamed into place.

---

## Why it’s large for a single `main.rs`

Unlike minimal CLI wrappers, **rse** implements:
- Custom binary header/trailer format  
- Cross-platform atomic write handling  
- Streaming encryption/decryption with per-chunk AEAD keys  
- Full integrity verification without writing decrypted output (`verify` mode)  

The cryptography itself comes from robust crates; the “homebrew” parts are the safe composition and file format logic.

---

## Documentation

A full usage guide, examples, and file format specification are available in:

```
/docs/rse_guide.html
```

Open that file in your browser for complete instructions.

---

## Quick Start

```bash
# Build
cargo build --release

# Encrypt (prompts twice for passphrase)
./target/release/rse encrypt -i file.txt -o file.txt.rse

# Decrypt (prompts for passphrase)
./target/release/rse decrypt -i file.txt.rse -o file.txt

# Inspect header
./target/release/rse inspect -i file.txt.rse

# Verify integrity end-to-end
./target/release/rse verify -i file.txt.rse
```

---

**License:** MIT (or your preferred license)  
**Version:** 0.1.0  
**Platform:** Windows & Linux
