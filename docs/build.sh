#!/bin/bash
# Cloudflare Pages build script for mdBook
set -e

MDBOOK_VERSION="0.4.40"
MDBOOK_URL="https://github.com/rust-lang/mdBook/releases/download/v${MDBOOK_VERSION}/mdbook-v${MDBOOK_VERSION}-x86_64-unknown-linux-gnu.tar.gz"

echo "Downloading mdBook v${MDBOOK_VERSION}..."
curl -sSL "$MDBOOK_URL" | tar -xz

echo "Building docs..."
./mdbook build

echo "Done!"
