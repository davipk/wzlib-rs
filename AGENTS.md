# CLAUDE.md

This file provides guidance to AI agents when working with code in this repository.

## Project Overview

MapleStory WZ file parser and writer in Rust, compiled to WebAssembly via wasm-pack, with a TypeScript wrapper for browser usage. Parses and saves encrypted binary WZ/MS archives (directory trees, image property trees, Canvas images, Sound extraction).

## Build Commands

```bash
# Rust tests
cargo test

# Build WASM (outputs to ts-wrapper/wasm-pkg/)
# --features wasm is required to include the WASM API exports
wasm-pack build --target web --out-dir ts-wrapper/wasm-pkg --features wasm

# TypeScript wrapper
cd ts-wrapper && npm install && npx tsc

# All-in-one build (from ts-wrapper/)
npm run build

# Run demo server at http://localhost:8080
node demo/serve.mjs
```

## Testing

Tests are inline (`#[cfg(test)]` modules) using synthetic byte arrays — no external test data files needed.

```bash
cargo test --lib              # Run all unit tests
cargo llvm-cov --lib          # Coverage report (requires cargo-llvm-cov)
cargo llvm-cov --lib --html   # HTML coverage report
```

## Validating Changes

When validating a change, run the unit tests together with formatting and lint/type checks:

```bash
cargo fmt --all -- --check    # Verify formatting (drop --check to auto-format)
cargo clippy --all-targets    # Lint and type-check
cargo test --lib              # Run all unit tests
```

All three should pass before considering a change complete.

## Architecture

**Three-layer stack:** Rust core → WASM (wasm-bindgen) → TypeScript wrapper.

- **Rust core** — parses and writes the encrypted binary archive formats: header/version detection, directory trees, image property trees, pixel formats, and the cryptographic primitives (key generation, stream ciphers, checksums). Reading and writing are implemented as symmetric, paired counterparts.
- **WASM boundary** — exposes parse, edit, and build operations. Structured data crosses as JSON; binary data (pixels, audio) crosses as raw bytes. All saving goes through the build APIs.
- **TypeScript wrapper** — loads the WASM module and provides an ergonomic API for parsing, tree navigation, and saving.
- **Demo** — a browser-based viewer/editor built on the wrapper.

### Data Flow

- **Parsing:** the file is loaded, its type is detected, then the directory and property trees are parsed to JSON. Binary data (pixels, audio) is fetched lazily on demand rather than embedded in the JSON.
- **Editing and saving:** parse-for-edit (JSON tree + binary blobs) → modify the JSON and/or blobs → build back to binary. This parse → modify → build path is the only way to save.

## Key Patterns

- **WASM ↔ TypeScript sync:** when adding or changing WASM exports, update the corresponding TypeScript types and wrapper methods, and wire it into the demo if used there.
- **Read ↔ Write symmetry:** readers and writers are paired. When you change how something is parsed, update its writer too. Roundtrip tests catch mismatches.
- **Blob-separated JSON:** edit APIs use a packed binary format so large binary data is not embedded in JSON; blobs are referenced by index from the JSON tree.
- **Three-phase save:** offset encryption depends on absolute file position (a chicken-and-egg problem). Saving serializes images, computes offsets, then writes at the correct positions — this ordering is inherited from the reference implementation and must be preserved.
- **String deduplication cache:** the writer's string cache must be cleared between images to prevent cross-image offset references.
- **Custom and hybrid IVs:** parsing and building accept an optional user-provided IV for region-specific files. Some files use different encryption for directory vs. image data; per-entry IV overrides are preserved across parse → build roundtrips.
- **Validation limits:** size/count limits guard against corrupt or malicious inputs during parsing.
- **Lazy key generation:** decryption keys are computed on first use and cached.
- **JSON for structured data, raw bytes for binary:** the WASM boundary uses JSON for trees and raw byte arrays for pixels/audio.
- **Build profile:** the crate builds both a WASM binary and a Rust library; the WASM build is optimized for size.

## Comment Conventions

Code should be self-explanatory. Minimize comments — only add them when the code alone cannot convey the intent.

### Keep
- **Module `//!` headers** (Rust) — one line: file purpose + port origin if applicable
- **Why comments** — explain *why*, never *what* (compatibility quirks, design decisions, non-obvious constraints)
- **Format specs** — bit-field layouts, encoding schemes, magic byte meanings, algorithm steps not expressible through naming
- **Section dividers** — `// ── Title ──────…` in large files for organization
- **Reference annotations** — constants whose meaning isn't obvious from the name

### Remove
- Doc comments (`///` / `/** */`) that restate the function/type name or signature
- Parameter docs that mirror the type signature
- Inline comments describing *what* the next line does when the code is clear
- Trivial getter/setter/accessor doc comments

### Rule of thumb
> If deleting the comment and reading just the code + names leaves you equally informed, delete the comment.
