# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MapleStory WZ file parser and writer in Rust, compiled to WebAssembly via wasm-pack, with a TypeScript wrapper for browser usage. Parses and saves encrypted binary WZ/MS archives (directory trees, image property trees, Canvas images with DXT decompression, Sound extraction).

## Build Commands

```bash
# Rust tests
cargo test

# Build WASM (outputs to ts-wrapper/wasm-pkg/)
# --features wasm is required to include wasm_api.rs exports
wasm-pack build --target web --out-dir ts-wrapper/wasm-pkg --features wasm

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

- **`wasm_api.rs`** — All wasm-bindgen exports (parse, edit, build). WASM boundary; complex data crosses via JSON serialization, binary data (canvas pixels, audio) as raw bytes. **Edit/Build APIs** use a packed binary format: `[json_len:u32][json][blob_count:u32][blob_len:u32][blob_data]...` separating JSON property trees from binary blobs (Canvas png_data, Sound header+audio, etc.) referenced by `blobIndex` fields in the JSON. There are no separate "save" exports — all saving goes through the build APIs.
- **`crypto/`** — MapleStory encryption: AES-256-ECB WZ key generation (`aes_encryption.rs`), Snow 2.0 stream cipher (`snow2.rs`), ChaCha20 stream cipher (`chacha20.rs`, RFC 7539 — used by MS file v2), byte-level custom cipher, CRC32 checksums. Four IV variants: GMS `[0x4D,0x23,0xC7,0x2B]`, EMS/MSEA `[0xB9,0x7D,0x63,0xE9]`, BMS/Classic `[0x00,0x00,0x00,0x00]`, plus user-provided custom IVs.
- **`wz/`** — Binary format parsing:
  - `file.rs` — Top-level WZ file: PKG1 header, 64-bit format detection (v770+), brute-force version detection (0–2000) with CRC32 validation. Also: `WzFileType` enum and `detect_file_type()` for distinguishing standard/hotfix/list formats, `parse_hotfix_data_wz()` for headerless Data.wz files. **Writing:** `WzFile::save()` (three-phase: serialize images → compute offsets → write), `save_with_image_data()` (phases 2–3 with pre-serialized blobs), `save_hotfix_data_wz()`.
  - `binary_reader.rs` — Encrypted int/string/offset reading with lazy key generation.
  - `binary_writer.rs` — Encrypted int/string/offset writing with string deduplication cache. `write_string_value()` (cache-aware), `write_wz_object_value()` (directory entry names), `write_wz_offset()` (encrypted offsets).
  - `directory.rs` — Directory tree parsing (entry types 1–4: skip, string-ref, subdirectory, image). **Writing:** `generate_data()` (Phase 1: serialize images), `get_offsets()`/`get_img_offsets()` (Phase 2: offset calculation), `save_directory()` (Phase 3: write entry table), `attach_image_data()` (attach pre-serialized blobs for build-from-scratch flow).
  - `image.rs` — IMG property tree parsing, produces `WzProperty` enum (16 variants: Null, Short, Int, Long, Float, Double, String, SubProperty, Canvas, Convex, Sound, Vector, Uol, Lua, RawData, Video).
  - `image_writer.rs` — IMG property tree serialization (counterpart to `image.rs`). `write_image()` serializes a property tree to WZ binary. Handles all 16 property types including the 0x09 extended envelope for SubProperty, Canvas, Vector, Convex, Sound, UOL, RawData, Video.
  - `list_file.rs` — List.wz parser (pre-Big Bang path index). Different binary format: `[i32 len][u16 chars × len][u16 null]` entries, XOR-encrypted with WZ key (no incremental mask).
  - `ms_file.rs` — v220+ `.ms` archive parsing and saving. Two format versions: **v1** (Snow2 stream cipher, version byte 2) and **v2** (ChaCha20 stream cipher, version byte 4). `parse_ms_file()` auto-detects v1/v2. `decrypt_entry_data()` dispatches decryption by version. `encrypt_entry_data()` and `build_ms_file()` accept an `MsVersion` parameter to select v1 or v2. V2 uses `ChaCha20StreamReader`/`ChaCha20StreamWriter` for entry tables (counter-resetting per 64-byte block) and only encrypts the first 1024 bytes of each entry. V2 salt encoding uses a `((a|0x4B)<<1)-a-75` transform with sign-extended high bytes. V2 header hash formula: `hashed_salt_len + raw_version_byte + 4 + entry_count + salt_u16_sum`.
  - `properties/mod.rs` — `WzProperty` enum definition, serialization, and accessor helpers (`as_int`, `as_float`, `as_str`, `children`, `get`).
  - `test_utils.rs` — Shared test helpers: `dummy_header()`, `make_reader()`, WZ encoding helpers (`encode_wz_ascii()`, `encode_wz_offset()`), image data builders. Used across `binary_reader`, `binary_writer`, `directory`, `image`, and `image_writer` tests.
- **`image/`** — Pixel format decoders and encoders. `pixel.rs`/`dxt.rs` decode to RGBA8888; `encode.rs` encodes RGBA8888 back to WZ formats (BGRA4444, BGRA8888, ARGB1555, RGB565, R16, A8, RGBA1010102, RGBA32Float) and zlib-compresses raw data via `compress_png_data()`. DXT/BC encoding is not supported — use BGRA8888 for imported images.

### TypeScript Wrapper (`ts-wrapper/src/`)

- **`wz-parser.ts`** — `WzParser` class: loads WASM, exposes parse methods (`parseFile()`, `parseHotfixFile()`, etc.), auto-detection (`detectMapleVersion()`), **edit-friendly parsing** (`parseImageForEdit()`, `parseHotfixForEdit()`, `parseMsImageForEdit()`), **pixel encoding** (`encodePixels()`, `compressPng()`), **build APIs** (`buildImage()`, `buildFile()`, `buildMsFile(version)`), and `encryptMsEntry(version)` utility. `buildMsFile` and `encryptMsEntry` accept a `version` number (1 = Snow2, 2 = ChaCha20, default 1). Module-private `packBlobs`/`unpackEditResult` helpers handle the packed binary format. The build APIs are the single path for all saving — parse-for-edit → modify → build. All parse/build methods accept optional `customIv` for user-provided encryption keys.
- **`wz-node.ts`** — `WzNode` class: tree navigation with `getChild()`, `resolve()`, `walk()`. Slash-separated paths (e.g., `"0/info/icon"`).
- **`types.ts`** — `WzMapleVersion` (includes `'custom'`), `WzFileType`, `WzPngFormat`, `WzPropertyNode` (with optional `blobIndex`), `WasmExports` interface, `McvHeaderInfo`, `MsBuildEntry`, directory tree types.

### Demo (`demo/`)

Browser-based WZ file viewer/editor. Modular JS in `demo/js/`:
- **`app.js`** — Entry point, WASM initialization, imports all WASM functions
- **`file-handlers.js`** — File open/parse dispatching (standard, hotfix, list, MS)
- **`tree-view.js`** — Directory tree rendering
- **`property-view.js`** — Property panel rendering for selected nodes
- **`media.js`** — Canvas image display and sound/video playback
- **`save.js`** — Save operations via parse-for-edit + build APIs: `saveCurrentFile()` (full file), `saveCurrentImage()` / `saveCurrentMsImage()` (single image extraction). MS files are saved in their original format (v1 or v2) based on `state.msVersion`.
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

**Editing and saving (single workflow — parse-for-edit → modify → build):**
1. `parseWzImageForEdit()` → returns packed binary: JSON property tree (with `blobIndex` references) + binary blobs (Canvas png_data, Sound header+audio, etc.)
2. JS modifies JSON tree (edit values, reorder, add/remove nodes), manipulates blob array (or leaves unchanged for a pure re-save)
3. For new Canvas: `encodePixels()` (RGBA → format) + `compressPngData()` (zlib) → new blob
4. `buildWzImage()` → accepts modified JSON + blobs → serialized WZ image binary
5. `buildWzFile()` → accepts directory tree JSON + per-image serialized blobs + version/encryption params → complete `.wz` file
6. `buildMsFile(version)` → same pattern for `.ms` files; version 1 = Snow2, 2 = ChaCha20

**Internal three-phase save (inside Rust, ported from MapleLib's `SaveToDisk`):**
1. Serialize each image's property tree to binary via `write_image()`, compute checksums
2. `get_offsets()` + `get_img_offsets()` — walk directory tree assigning byte positions
3. Write header → encrypted directory entries → image data blocks into a single buffer

**MS file internals:** Two versions: **v1** uses Snow2 (double-encrypted first 1024 bytes per entry), **v2** uses ChaCha20 (only first 1024 bytes encrypted, with a `chacha20KeyObscure` XOR mask on all keys). All public APIs are unified: `parse_ms_file()` auto-detects version, `decrypt_entry_data()` dispatches by parsed version, `encrypt_entry_data(version)` and `build_ms_file(version)` accept `MsVersion::V1` or `V2`. WASM exports use a numeric `version` param (1 or 2). Internally, v1 uses `Snow2` directly for entry tables; v2 uses `ChaCha20StreamReader`/`ChaCha20StreamWriter` which process 64-byte blocks with counter resets on block boundaries.

## Key Patterns

- **WASM ↔ TypeScript sync:** When adding or changing `#[wasm_bindgen]` exports in `wasm_api.rs`, always update the `WasmExports` interface in `ts-wrapper/src/types.ts`, add a corresponding method to `WzParser` in `wz-parser.ts`, and import the new function in `demo/app.js` if the demo uses it.
- **Read ↔ Write symmetry:** `binary_reader.rs` / `binary_writer.rs`, `image.rs` / `image_writer.rs`, `pixel.rs` / `encode.rs` are paired. When changing how a property type is parsed, update the corresponding write function too. Roundtrip tests in `image_writer.rs` and `encode.rs` catch mismatches.
- **Blob-separated JSON:** Edit APIs (`parseWzImageForEdit`, `buildWzImage`, `buildWzFile`) use a packed binary format to avoid embedding large binary data in JSON. Canvas `png_data`, Sound `header+data`, Lua, RawData, and Video blobs are packed separately and referenced by `blobIndex` in the JSON. Sound blobs use a sub-format: `[header_len:u32 LE][header][audio_data]`.
- **Three-phase save:** WZ offset encryption depends on the writer's absolute file position, creating a chicken-and-egg problem. The three-phase approach (serialize images → compute offsets → write at correct positions) is inherited from MapleLib and must be preserved.
- **String deduplication cache:** `WzBinaryWriter.string_cache` must be cleared between writing different images (prevents cross-image offset references). Already handled by `write_image()` and `WzFile::save()`.
- **Custom IV support:** All parsing and building functions accept an optional user-provided 4-byte IV (`custom_iv`), enabling decryption of region-specific files beyond the three built-in IV variants. The `WzMapleVersion::Custom` variant carries arbitrary IV bytes.
- **Hybrid IV preservation:** Some WZ files (JMS/KMS/CMS) use different encryption for directory vs. image data. `WzFile` stores the detected `iv`, and each `WzImageEntry` can store its own optional `iv` that overrides the directory-level one. This is preserved across parse → build roundtrips.
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