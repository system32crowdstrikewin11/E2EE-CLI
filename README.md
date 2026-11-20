# E2EE-CLI — `aegires-cli`

Cross-platform Rust CLI for **Aegires-gen3 (`dcenc2`)** end-to-end encrypted text, streaming media, and Discord messaging.

> 📖 **Full interactive guide & tutorial: <https://system32crowdstrikewin11.github.io/E2EE-CLI/>**
>
> Read the guide for complete documentation, command reference, protocol details, and troubleshooting.

## Features

- Argon2id key derivation (64 MiB, 3 passes) with context binding
- AES-128 / 192 / 256-GCM authenticated encryption
- 64 KiB streaming media encryption (`ef` / `df`)
- Discord mode: paste a message link, auto-detect sender/channel, and decrypt
- Live chat loop with inline attachment upload/download/decrypt
- Pure Rust: keys and Discord tokens live in RAM only and are zeroized on exit

## Build

```bash
# Requires Rust: https://rustup.rs
git clone https://github.com/system32crowdstrikewin11/E2EE-CLI.git
cd E2EE-CLI
cargo build --release
./target/release/aegires-cli --help
```

## Quick start

```bash
# Offline mode: encrypt / decrypt a message
./target/release/aegires-cli
# then, in the REPL:
#   e -p aes256 <message>
#   d <§ciphertext>

# Discord mode
./target/release/aegires-cli --login
```

## Documentation

The full guide is published with GitHub Pages:

**<https://system32crowdstrikewin11.github.io/E2EE-CLI/>**

A local copy is also included in this repository as [`index.html`](index.html).

## License

[MIT](LICENSE)
