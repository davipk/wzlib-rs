# wzlib

TypeScript wrapper for the `wzlib-rs` WASM module. Provides a high-level API for parsing and saving MapleStory WZ and MS files in the browser.

## Setup

```bash
# Build the WASM package first (from project root)
wasm-pack build --target web --out-dir ts-wrapper/wasm-pkg

# Install dependencies and compile TypeScript
cd ts-wrapper
npm install
npx tsc
```

Or build everything in one step:

```bash
npm run build
```

## API

### `WzParser`

Main entry point. Wraps the WASM module with a typed interface.

```typescript
import { WzParser } from 'wzlib';

const parser = await WzParser.create();
```

#### File Detection & Parsing

| Method                                                                  | Description                                                          |
| ----------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `WzParser.create(wasmUrl?)`                                             | Load WASM and return a parser instance                               |
| `detectFileType(data)`                                                  | Detect whether data is `"standard"`, `"hotfix"`, or `"list"`         |
| `detectMapleVersion(data)`                                              | Auto-detect encryption variant (tries GMS/EMS/BMS, picks best match) |
| `parseFile(data, version, patchVersion?, customIv?)`                    | Parse a standard `.wz` file into a `WzNode` tree                     |
| `parseImage(data, version, imgOffset, imgSize, versionHash, customIv?)` | Parse a WZ image at a given offset into a property tree              |
| `parseListFile(data, version, customIv?)`                               | Parse a List.wz file, returning `.img` path strings                  |
| `parseHotfixFile(data, version, customIv?)`                             | Parse a hotfix Data.wz (single WzImage) into property nodes          |

#### MS File Support

| Method                                                 | Description                                                                       |
| ------------------------------------------------------ | --------------------------------------------------------------------------------- |
| `parseMsFile(data, fileName)`                          | Parse a `.ms` file, returning entry metadata (`MsEntryInfo[]`)                    |
| `parseMsImage(data, fileName, entryIndex)`             | Decrypt and parse a `.ms` entry as a WZ image property tree                       |
| `decodeMsCanvas(data, fileName, entryIndex, propPath)` | Decode a canvas from a `.ms` entry — returns `[width_le32, height_le32, ...rgba]` |
| `extractMsSound(data, fileName, entryIndex, propPath)` | Extract raw sound bytes from a `.ms` entry                                        |
| `extractMsVideo(data, fileName, entryIndex, propPath)` | Extract raw video bytes from a `.ms` entry                                        |

#### Image & Media Decoding

| Method                                                                       | Description                                                            |
| ---------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `decompressPng(compressed, wzKey?)`                                          | Zlib-decompress raw WZ PNG data (optional WZ key for encrypted blocks) |
| `decodePixels(raw, w, h, format)`                                            | Convert pixel format to RGBA8888                                       |
| `decodeWzCanvas(data, version, imgOffset, versionHash, propPath, customIv?)` | Decode a canvas directly from WZ data at offset + path                 |
| `extractSound(data, version, imgOffset, versionHash, propPath, customIv?)`   | Extract raw sound bytes from WZ data at offset + path                  |
| `extractVideo(data, version, imgOffset, versionHash, propPath, customIv?)`   | Extract raw video bytes from a standard WZ file                        |

#### Saving & Serialization

| Method                                                          | Description                                                          |
| --------------------------------------------------------------- | -------------------------------------------------------------------- |
| `serializeImage(properties, version, customIv?)`                | Serialize a property tree to WZ image binary format                  |
| `saveFile(data, version, customIv?)`                            | Parse a standard `.wz` file and re-save through the three-phase flow |
| `saveHotfixFile(data, version, customIv?)`                      | Parse a hotfix Data.wz from raw data and re-save                     |
| `saveMsFile(data, fileName)`                                    | Parse a `.ms` file from raw data and re-save                         |
| `saveImage(wzData, version, imgOffset, versionHash, customIv?)` | Save a single WZ image as standalone Data.wz                         |
| `saveMsImage(data, fileName, entryIndex, customIv?)`            | Save a single `.ms` entry as standalone Data.wz                      |
| `encryptMsEntry(data, salt, entryName, entryKey)`               | Encrypt a single `.ms` entry's image data                            |

#### Key & Version Utilities

| Method                        | Description                                   |
| ----------------------------- | --------------------------------------------- |
| `generateKey(iv, size)`       | Generate WZ decryption key material           |
| `getVersionIv(version)`       | Get the 4-byte IV for a MapleStory version    |
| `computeVersionHash(version)` | Compute hash from patch version number        |
| `mapleCustomEncrypt(data)`    | Apply MapleStory custom encryption (in-place) |
| `mapleCustomDecrypt(data)`    | Apply MapleStory custom decryption (in-place) |

### `WzNode`

Tree node returned by `parseFile()`. Represents directories, images, and properties.

```typescript
const root = parser.parseFile(wzData, 'gms');

// Navigate by path
const img = root.resolve('Mob/100100.img');

// Access children
console.log(img.childNames); // ["info", "move", "stand", ...]
console.log(img.childCount); // 12

// Get typed values
const speed = img.resolve('info/speed');
speed.intValue; // 5
speed.stringValue; // undefined

// Walk all descendants
root.walk((node, path) => {
  console.log(`${path}: ${node.type}`);
});
```

| Property / Method | Description                                     |
| ----------------- | ----------------------------------------------- |
| `name`            | Node name                                       |
| `type`            | `WzNodeType` string value                       |
| `value`           | Raw value (`unknown`)                           |
| `intValue`        | Value as `number` (Short/Int/Long/Float/Double) |
| `stringValue`     | Value as `string` (String/UOL)                  |
| `vectorValue`     | Value as `[x, y]` (Vector)                      |
| `pixelData`       | Decoded RGBA pixel data (Canvas)                |
| `width`           | Canvas width in pixels                          |
| `height`          | Canvas height in pixels                         |
| `audioData`       | Raw audio bytes (Sound)                         |
| `audioDurationMs` | Sound duration in milliseconds                  |
| `videoData`       | Raw video bytes (Video)                         |
| `videoType`       | Video type identifier                           |
| `children`        | Child nodes as array                            |
| `childNames`      | Child names as string array                     |
| `childCount`      | Number of children                              |
| `getChild(name)`  | Get child by name                               |
| `resolve(path)`   | Walk a `/`-separated path                       |
| `walk(callback)`  | Depth-first traversal                           |
| `toJSON()`        | Serializable representation                     |

### Types

```typescript
type WzMapleVersion = 'gms' | 'ems' | 'msea' | 'bms' | 'classic' | 'custom';

type WzFileType = 'standard' | 'hotfix' | 'list';

type WzPngFormat =
  | 1 // BGRA4444
  | 2 // BGRA8888
  | 3 // DXT3 Grayscale
  | 257 // ARGB1555
  | 513 // RGB565
  | 517 // RGB565 Block
  | 769 // R16
  | 1026 // DXT3
  | 2050 // DXT5
  | 2304 // A8
  | 2562 // RGBA1010102
  | 4097 // DXT1
  | 4098 // BC7
  | 4100; // RGBA32Float

enum WzNodeType {
  Null = 'Null',
  Short = 'Short',
  Int = 'Int',
  Long = 'Long',
  Float = 'Float',
  Double = 'Double',
  String = 'String',
  SubProperty = 'SubProperty',
  Canvas = 'Canvas',
  Vector = 'Vector',
  Convex = 'Convex',
  Sound = 'Sound',
  Uol = 'UOL',
  Lua = 'Lua',
  RawData = 'RawData',
  Video = 'Video',
  Directory = 'Directory',
  Image = 'Image',
}

interface WzPropertyNode {
  name: string;
  type: string;
  value?: unknown;
  children?: WzPropertyNode[];
  width?: number; // Canvas
  height?: number; // Canvas
  format?: number; // Canvas pixel format
  dataLength?: number; // Canvas compressed data length
  x?: number; // Vector
  y?: number; // Vector
  duration_ms?: number; // Sound
  videoType?: number; // Video
  mcv?: McvHeaderInfo; // Video (MCV container)
}

interface MsEntryInfo {
  name: string;
  size: number;
  index: number;
  entryKey: number[]; // 16-byte random key
}

interface MsSaveEntry {
  name: string;
  image_data: number[]; // serialized WZ image bytes
  entry_key: number[]; // 16-byte random key
}

interface McvHeaderInfo {
  fourcc: number;
  width: number;
  height: number;
  frameCount: number;
  dataFlags: number;
  frameDelayUnitNs: string; // i64 as string to avoid JS precision loss
  defaultDelay: number;
}
```

## Project Structure

```
ts-wrapper/
├── src/
│   ├── index.ts          # Package entry point (re-exports)
│   ├── wz-parser.ts      # WzParser class (WASM wrapper)
│   ├── wz-node.ts        # WzNode tree + WzNodeType enum
│   └── types.ts          # Shared TS types + WASM interface
├── wasm-pkg/             # Generated by wasm-pack (gitignored)
├── dist/                 # Compiled JS + declarations (gitignored)
├── package.json
└── tsconfig.json
```

## Example: Render a Sprite

```typescript
const parser = await WzParser.create();
const root = parser.parseFile(wzData, 'bms');

// Get a mob sprite
const img = root.resolve('8800000.img');
// In practice you'd use parseWzImage + decodeWzCanvas from the WASM API
// to decode the Canvas property's compressed PNG data to RGBA pixels.
```
