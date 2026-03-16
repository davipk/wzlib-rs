# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MapleStory WZ file parser and writer in Rust, compiled to WebAssembly via wasm-pack, with a TypeScript wrapper for browser usage. Parses and saves encrypted binary WZ/MS archives (directory trees, image property trees, Canvas images with DXT decompression, Sound extraction).

## Build Commands

```bash
# Rust tests
cargo test

# Build WASM (outputs to ts-wrapper/wasm-pkg/)
wasm-pack build --target web --out-dir ts-wrapper/wasm-pkg

# TypeScript wrapper
cd ts-wrapper && npm install && npx tsc

# All-in-one build (from ts-wrapper/)
npm run build

# Run demo server at http://localhost:8080
node demo/serve.mjs
```

## Testing

tests across various source files. All tests are inline (`#[cfg(test)]` modules) using synthetic byte arrays — no external test data files needed.

```bash
cargo test --lib              # Run all unit tests
cargo llvm-cov --lib          # Coverage report (requires cargo-llvm-cov)
cargo llvm-cov --lib --html   # HTML coverage report
```

## Architecture

**Three-layer stack:** Rust core → WASM (wasm-bindgen) → TypeScript wrapper

### Rust Core (`src/`)

- **`wasm_api.rs`** — All wasm-bindgen exports (parse + save). WASM boundary; complex data crosses via JSON serialization, binary data (canvas pixels, audio) as raw bytes.
- **`crypto/`** — MapleStory encryption: AES-256-ECB WZ key generation (`aes_encryption.rs`), Snow 2.0 stream cipher (`snow2.rs`), byte-level custom cipher, CRC32 checksums. Four IV variants: GMS `[0x4D,0x23,0xC7,0x2B]`, EMS/MSEA `[0xB9,0x7D,0x63,0xE9]`, BMS/Classic `[0x00,0x00,0x00,0x00]`, plus user-provided custom IVs.
- **`wz/`** — Binary format parsing:
  - `file.rs` — Top-level WZ file: PKG1 header, 64-bit format detection (v770+), brute-force version detection (0–2000) with CRC32 validation. Also: `WzFileType` enum and `detect_file_type()` for distinguishing standard/hotfix/list formats, `parse_hotfix_data_wz()` for headerless Data.wz files. **Writing:** `WzFile::save()` (three-phase: serialize images → compute offsets → write), `save_hotfix_data_wz()`.
  - `binary_reader.rs` — Encrypted int/string/offset reading with lazy key generation.
  - `binary_writer.rs` — Encrypted int/string/offset writing with string deduplication cache. `write_string_value()` (cache-aware), `write_wz_object_value()` (directory entry names), `write_wz_offset()` (encrypted offsets).
  - `directory.rs` — Directory tree parsing (entry types 1–4: skip, string-ref, subdirectory, image). **Writing:** `generate_data()` (Phase 1: serialize images), `get_offsets()`/`get_img_offsets()` (Phase 2: offset calculation), `save_directory()` (Phase 3: write entry table).
  - `image.rs` — IMG property tree parsing, produces `WzProperty` enum (16 variants: Null, Short, Int, Long, Float, Double, String, SubProperty, Canvas, Convex, Sound, Vector, Uol, Lua, RawData, Video).
  - `image_writer.rs` — IMG property tree serialization (counterpart to `image.rs`). `write_image()` serializes a property tree to WZ binary. Handles all 16 property types including the 0x09 extended envelope for SubProperty, Canvas, Vector, Convex, Sound, UOL, RawData, Video.
  - `list_file.rs` — List.wz parser (pre-Big Bang path index). Different binary format: `[i32 len][u16 chars × len][u16 null]` entries, XOR-encrypted with WZ key (no incremental mask).
  - `ms_file.rs` — v220+ `.ms` archive parsing and saving. Snow2-encrypted entries with per-entry key derivation. **Writing:** `encrypt_entry_data()` (reverse of decrypt), `save_ms_file()` (full .ms file construction).
  - `properties/mod.rs` — `WzProperty` enum definition, serialization, and accessor helpers (`as_int`, `as_float`, `as_str`, `children`, `get`).
  - `test_utils.rs` — Shared test helpers: `dummy_header()`, `make_reader()`, WZ encoding helpers (`encode_wz_ascii()`, `encode_wz_offset()`), image data builders. Used across `binary_reader`, `binary_writer`, `directory`, `image`, and `image_writer` tests.
- **`image/`** — Pixel format decoders (BGRA4444, BGRA8888, ARGB1555, RGB565, DXT3, DXT5) all converting to RGBA8888. Handles zlib decompression and encrypted block formats.

### TypeScript Wrapper (`ts-wrapper/src/`)

- **`wz-parser.ts`** — `WzParser` class: loads WASM, exposes parse methods (`parseFile()`, `parseHotfixFile()`, etc.), save methods (`saveFile()`, `saveHotfixFile()`, `saveMsFile()`, `serializeImage()`, `encryptMsEntry()`), single-image extraction (`saveImage()`, `saveMsImage()`), and auto-detection (`detectMapleVersion()`). All parse/save methods accept optional `customIv` for user-provided encryption keys.
- **`wz-node.ts`** — `WzNode` class: tree navigation with `getChild()`, `resolve()`, `walk()`. Slash-separated paths (e.g., `"0/info/icon"`).
- **`types.ts`** — `WzMapleVersion` (includes `'custom'`), `WzFileType`, `WzPngFormat`, `WzPropertyNode`, `WasmExports` interface, `McvHeaderInfo`, `MsSaveEntry`, directory tree types.

### Demo (`demo/`)

Browser-based WZ file viewer/editor. Modular JS in `demo/js/`:
- **`app.js`** — Entry point, WASM initialization, imports all WASM functions
- **`file-handlers.js`** — File open/parse dispatching (standard, hotfix, list, MS)
- **`tree-view.js`** — Directory tree rendering
- **`property-view.js`** — Property panel rendering for selected nodes
- **`media.js`** — Canvas image display and sound/video playback
- **`save.js`** — Save operations: `saveCurrentFile()` (full file), `saveCurrentImage()` / `saveCurrentMsImage()` (single image extraction)
- **`state.js`** — Shared application state
- **`utils.js`** — DOM helpers, formatting utilities

### Data Flow

**Standard WZ files:**
1. Full `.wz` file loaded as `Uint8Array` in JS
2. `detectWzFileType()` → `"standard"`, `"hotfix"`, or `"list"`
3. `parseWzFile()` → returns JSON directory tree + version hash
4. `parseWzImage()` → returns JSON property tree (no binary data)
5. `decodeWzCanvas()` / `extractWzSound()` → returns raw bytes on demand (binary data fetched lazily, not included in JSON)

**Hotfix Data.wz:** No PKG1 header — first byte is `0x73`. Entire file is a single WzImage. `parseHotfixDataWz()` parses directly. `parseWzImage()`/`decodeWzCanvas()`/`extractWzSound()` auto-detect hotfix files.

**List.wz (pre-Big Bang):** Not PKG1 format. `parseWzListFile()` returns a JSON array of `.img` path strings.

**Saving WZ files (three-phase, ported from MapleLib's `SaveToDisk`):**
1. `generate_data()` — serialize each image's property tree to binary via `write_image()`, compute checksums
2. `get_offsets()` + `get_img_offsets()` — walk directory tree assigning byte positions
3. Write header → encrypted directory entries → image data blocks into a single buffer

**Saving MS files:** `save_ms_file()` constructs the full `.ms` format (random prefix, XOR-encoded salt, Snow2-encrypted header/entries, 1024-aligned double-encrypted data blocks). `encrypt_entry_data()` handles per-entry encryption.

## Key Patterns

- **WASM ↔ TypeScript sync:** When adding or changing `#[wasm_bindgen]` exports in `wasm_api.rs`, always update the `WasmExports` interface in `ts-wrapper/src/types.ts`, add a corresponding method to `WzParser` in `wz-parser.ts`, and import the new function in `demo/app.js` if the demo uses it.
- **Read ↔ Write symmetry:** `binary_reader.rs` / `binary_writer.rs`, `image.rs` / `image_writer.rs` are paired. When changing how a property type is parsed, update the corresponding write function too. Roundtrip tests in `image_writer.rs` catch mismatches.
- **Three-phase save:** WZ offset encryption depends on the writer's absolute file position, creating a chicken-and-egg problem. The three-phase approach (serialize images → compute offsets → write at correct positions) is inherited from MapleLib and must be preserved.
- **String deduplication cache:** `WzBinaryWriter.string_cache` must be cleared between writing different images (prevents cross-image offset references). Already handled by `write_image()` and `WzFile::save()`.
- **Custom IV support:** All parsing and saving functions accept an optional user-provided 4-byte IV (`custom_iv`), enabling decryption of region-specific files beyond the three built-in IV variants. The `WzMapleVersion::Custom` variant carries arbitrary IV bytes.
- **Hybrid IV preservation:** Some WZ files (JMS/KMS/CMS) use different encryption for directory vs. image data. `WzFile` stores the detected `iv`, and each `WzImageEntry` can store its own optional `iv` that overrides the directory-level one. This is preserved across parse → save roundtrips.
- **Validation limits:** `MAX_WZ_STRING_LEN`, `MAX_PROPERTY_COUNT`, `MAX_DIRECTORY_ENTRIES`, `MAX_CONVEX_POINTS` in `wz/mod.rs` guard against corrupt/malicious inputs during parsing.

- **Lazy key generation:** WZ decryption keys computed on first use, cached in `WzBinaryReader`.
- **JSON for structured data, raw bytes for binary:** WASM boundary uses JSON serialization for trees, `Uint8Array` for pixels/audio.
- **Canvas decode returns `[width_le32, height_le32, ...rgba_bytes]`** — first 8 bytes are little-endian dimensions.
- **Version detection is brute-force:** Iterates patch versions 0–2000, validates via CRC32 hash against header.
- **Crate type is `["cdylib", "rlib"]`:** builds both WASM binary and Rust library.
- **WASM optimized for size:** `opt-level = "s"`, LTO enabled.

## Comment Conventions

Code should be self-explanatory. Minimize comments — only add them when the code alone cannot convey the intent.

### Keep
- **Module `//!` headers** (Rust) — one line: file purpose + port origin if applicable
- **Why comments** — explain *why*, never *what* (C# compatibility quirks, design decisions, non-obvious constraints)
- **Format specs** — bit-field layouts, encoding schemes, magic byte meanings, algorithm steps not expressible through naming
- **Section dividers** — `// ── Title ──────…` in large files for organization
- **Reference annotations** — IV values, format IDs, constants whose meaning isn't obvious from the name

### Remove
- Doc comments (`///` / `/** */`) that restate the function/type name or signature
- Parameter docs that mirror the type signature
- Inline comments describing *what* the next line does when the code is clear
- Trivial getter/setter/accessor doc comments

### Rule of thumb
> If deleting the comment and reading just the code + names leaves you equally informed, delete the comment.