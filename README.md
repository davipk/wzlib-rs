# wzlib-rs

MapleStory WZ file parser and writer — Rust core compiled to WebAssembly with a TypeScript wrapper.

Reads and writes `.wz` and `.ms` archives used by MapleStory — directory trees, property trees, canvas images, sound, and video — all in the browser via WASM.

## Features

- **Standard WZ** — parse and save directory trees, IMG properties, version auto-detection, 64-bit support
- **Hotfix & List WZ** — headerless Data.wz and pre-Big Bang List.wz path indices
- **MS archives** — v220+ `.ms` files: v1 (Snow2) and v2 (ChaCha20) with auto-detection, per-entry decryption/encryption
- **Canvas decoding** — 14 pixel formats (DXT1/3/5, BC7, BGRA4444/8888, RGB565, etc.) → RGBA8888
- **Sound extraction** — MP3/PCM for Web Audio playback
- **Video extraction** — MCV container parsing with frame metadata
- **Encryption** — GMS, EMS/MSEA, BMS/Classic with auto-detection
- **File saving** — full WZ file packaging (header + directory + images), hotfix Data.wz, and MS file construction
- **Small footprint** — ~100KB WASM binary (LTO, `opt-level = "s"`)

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) (stable)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/): `cargo install wasm-pack`
- [Node.js](https://nodejs.org/) 18+

### Build

```bash
# Build WASM package (--features wasm is required)
wasm-pack build --target web --out-dir ts-wrapper/wasm-pkg --features wasm

# Build TypeScript wrapper
cd ts-wrapper
npm install
npx tsc
```

### Test

```bash
cargo test
cargo llvm-cov --lib              # coverage (requires cargo-llvm-cov)
```

### Run Demo

```bash
node demo/serve.mjs
# Open http://localhost:8080
```

Drop a `.wz` or `.ms` file to explore directory trees, view images, play sounds, and inspect video metadata.

## Usage

```typescript
import { WzParser } from "wzlib";

const parser = await WzParser.create();

// Parse a .wz file
const wzData = new Uint8Array(await fetch("Map.wz").then(r => r.arrayBuffer()));
const root = parser.parseFile(wzData, "gms", 83);

// Navigate the tree
const mob = root.resolve("Mob/100100.img");
console.log(mob?.childNames);

// Decode a canvas
const rgba = parser.decodeCanvas(compressedPng, 64, 64, 2);
const imageData = parser.toImageData(rgba, 64, 64);
ctx.putImageData(imageData, 0, 0);

// Parse a .ms file (v220+)
const msData = new Uint8Array(await fetch("Data.ms").then(r => r.arrayBuffer()));
const entries = parser.parseMsFile(msData, "Data.ms");
const imgTree = parser.parseMsImage(msData, "Data.ms", 0);

// Edit and rebuild a hotfix Data.wz
const { properties, blobs } = parser.parseHotfixForEdit(wzData, "bms");
properties.find(p => p.name === "hp").value = 9999;
const saved = parser.buildImage(properties, blobs, "bms");

// Build a .ms file from entries
const msEntries = [{ name: "Mob/test.img", entryKey: [...key16] }];
const msSaved = parser.buildMsFile("output.ms", "salt", msEntries, [imageBlob]);
```

## Architecture

```
src/                  Rust WASM core
├── crypto/           AES, Snow2, ChaCha20, custom encryption, CRC32
├── wz/               WZ/MS/List file parsing + writing, MCV video, properties
├── image/            Pixel format decoders (DXT, BC7, etc.) → RGBA8888
└── wasm_api.rs       wasm-bindgen exports (parse + save)

ts-wrapper/src/       TypeScript wrapper
├── wz-parser.ts      High-level WzParser class
├── wz-node.ts        Tree navigation (resolve, walk)
└── types.ts          Shared type definitions

demo/                 Browser file explorer SPA
├── js/               Modular JS (state, tree, property, search, media…)
├── index.html        Entry page
└── styles.css        Styles
```

## Ported From

[Harepacker-resurrected](https://github.com/lastbattle/Harepacker-resurrected) — MapleLib
[WzComparerR2](https://github.com/Kagamia/WzComparerR2) - WzLib
