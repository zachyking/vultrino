# Installation

## Requirements

- Rust 1.75 or later (for building from source)
- OpenSSL development libraries (on Linux)

## From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/vultrino/vultrino.git
cd vultrino

# Build in release mode
cargo build --release

# The binary will be at target/release/vultrino
# Optionally, copy to your PATH
cp target/release/vultrino /usr/local/bin/
```

## Using Cargo

```bash
cargo install vultrino
```

## Pre-built Binaries

Download pre-built binaries from the [GitHub Releases](https://github.com/vultrino/vultrino/releases) page.

### macOS

```bash
# Intel
curl -L https://github.com/vultrino/vultrino/releases/latest/download/vultrino-x86_64-apple-darwin.tar.gz | tar xz
sudo mv vultrino /usr/local/bin/

# Apple Silicon
curl -L https://github.com/vultrino/vultrino/releases/latest/download/vultrino-aarch64-apple-darwin.tar.gz | tar xz
sudo mv vultrino /usr/local/bin/
```

### Linux

```bash
# x86_64
curl -L https://github.com/vultrino/vultrino/releases/latest/download/vultrino-x86_64-unknown-linux-gnu.tar.gz | tar xz
sudo mv vultrino /usr/local/bin/

# ARM64
curl -L https://github.com/vultrino/vultrino/releases/latest/download/vultrino-aarch64-unknown-linux-gnu.tar.gz | tar xz
sudo mv vultrino /usr/local/bin/
```

## Verify Installation

```bash
vultrino --version
# vultrino 0.1.0
```

## Next Steps

Continue to [Quick Start](./quickstart.md) to initialize Vultrino and add your first credential.
