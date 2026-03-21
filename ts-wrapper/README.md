# wzlib

TypeScript wrapper for the `wzlib-rs` WASM module. Provides a high-level API for parsing, editing, and saving MapleStory WZ and MS files in the browser.

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

#### Pixel Encoding

| Method                              | Description                                                     |
| ----------------------------------- | --------------------------------------------------------------- |
| `encodePixels(rgba, w, h, format)`  | Convert RGBA8888 to a WZ pixel format (reverse of decodePixels) |
| `compressPng(raw)`                  | Zlib-compress raw pixel data for WZ Canvas storage              |

Supported encoding formats: BGRA4444, BGRA8888, ARGB1555, RGB565, R16, A8, RGBA1010102, RGBA32Float. DXT/BC formats are decode-only — use BGRA8888 (format `2`) for imported images.

#### Edit-Friendly Parsing

These methods return an `EditableImage` — a JSON property tree with binary data (Canvas pixels, Sound audio, etc.) separated into a `blobs[]` array. Each binary node has a `blobIndex` field referencing its blob.

| Method                                                                             | Description                                       |
| ---------------------------------------------------------------------------------- | ------------------------------------------------- |
| `parseImageForEdit(data, version, imgOffset, imgSize, versionHash, customIv?)`     | Parse a WZ image for editing                      |
| `parseHotfixForEdit(data, version, customIv?)`                                     | Parse a hotfix Data.wz for editing                |
| `parseMsImageForEdit(data, fileName, entryIndex)`                                  | Parse a `.ms` entry for editing                   |

```typescript
interface EditableImage {
  properties: WzPropertyNode[];  // JSON tree with blobIndex references
  blobs: Uint8Array[];           // Binary data (Canvas png_data, Sound audio, etc.)
}
```

#### Building from Modified State

After editing the JSON tree and blobs, use these methods to produce binary output.

| Method                                                                  | Description                                              |
| ----------------------------------------------------------------------- | -------------------------------------------------------- |
| `buildImage(properties, blobs, version, customIv?)`                     | Build a serialized WZ image from modified tree + blobs   |
| `buildFile(directory, imageBlobs, version, versionName, is64bit, customIv?)` | Build a complete `.wz` file from directory + image blobs |
| `buildMsFile(fileName, salt, entries, imageBlobs, version?)` | Build a complete `.ms` file (version: `1` = Snow2, `2` = ChaCha20; default `1`) |

#### MS Encryption Utilities

| Method                                                     | Description                                                                     |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `encryptMsEntry(data, salt, entryName, entryKey, version?)` | Encrypt a single `.ms` entry's image data (version: `1` = Snow2, `2` = ChaCha20; default `1`) |

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
  blobIndex?: number; // Edit mode: index into blobs array
  x?: number; // Vector
  y?: number; // Vector
  duration_ms?: number; // Sound
  videoType?: number; // Video
  mcv?: McvHeaderInfo; // Video (MCV container)
}

interface EditableImage {
  properties: WzPropertyNode[];
  blobs: Uint8Array[];
}

interface MsEntryInfo {
  name: string;
  size: number;
  index: number;
  entryKey: number[]; // 16-byte random key
}

interface MsBuildEntry {
  name: string;
  entryKey: number[]; // 16-byte random key
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

## Examples

### Render a Sprite

```typescript
const parser = await WzParser.create();
const wzData = new Uint8Array(await fetch('Mob.wz').then(r => r.arrayBuffer()));

const root = parser.parseFile(wzData, 'bms');
const img = root.resolve('8800000.img');

// Decode a canvas from the mob sprite
const rgba = parser.decodeWzCanvas(wzData, 'bms', img.value.offset, versionHash, '0/info/icon');
// First 8 bytes are [width_le32, height_le32], rest is RGBA pixels
```

### Edit Properties and Save

```typescript
const parser = await WzParser.create();
const wzData = new Uint8Array(/* ... */);
const fileInfo = JSON.parse(parser.detectMapleVersion(wzData));

// Parse an image for editing (JSON tree + binary blobs)
const img = fileInfo.directory.images[0];
const { properties, blobs } = parser.parseImageForEdit(
  wzData, fileInfo.versionName, img.offset, img.size, fileInfo.versionHash
);

// Modify a property value
const hpNode = properties.find(p => p.name === 'hp');
hpNode.value = 9999;

// Add a new string property
properties.push({ name: 'custom', type: 'String', value: 'hello' });

// Rebuild the image
const imageBytes = parser.buildImage(properties, blobs, fileInfo.versionName);
```

### Import a PNG as a New Canvas

```typescript
// Decode a PNG to RGBA pixels using a canvas element
const img = new Image();
img.src = URL.createObjectURL(pngFile);
await img.decode();
const canvas = new OffscreenCanvas(img.width, img.height);
canvas.getContext('2d').drawImage(img, 0, 0);
const rgba = new Uint8Array(canvas.getContext('2d').getImageData(0, 0, img.width, img.height).data);

// Encode to WZ format (BGRA8888) and compress
const raw = parser.encodePixels(rgba, img.width, img.height, 2);
const compressed = parser.compressPng(raw);

// Add as a new blob and create the Canvas node
blobs.push(compressed);
properties.push({
  name: 'newIcon',
  type: 'Canvas',
  width: img.width,
  height: img.height,
  format: 2,
  blobIndex: blobs.length - 1,
  children: [{ name: 'origin', type: 'Vector', x: 0, y: 0 }],
});
```

### Build a Complete WZ File

```typescript
// Start with a parsed directory tree
const fileInfo = JSON.parse(parser.detectMapleVersion(wzData));
const directory = fileInfo.directory;

// Modify directory structure
directory.images.push({ name: 'custom.img', size: 0, checksum: 0, offset: 0 });

// Serialize each image (one blob per image, depth-first order)
const imageBlobs = [];
for (const img of directory.images) {
  const { properties, blobs } = parser.parseImageForEdit(
    wzData, fileInfo.versionName, img.offset, img.size, fileInfo.versionHash
  );
  // ... modify properties/blobs as needed ...
  imageBlobs.push(parser.buildImage(properties, blobs, fileInfo.versionName));
}

// Build complete .wz file with desired version and encryption
const wzOutput = parser.buildFile(directory, imageBlobs, 83, 'gms', false);

// Download
const blob = new Blob([wzOutput], { type: 'application/octet-stream' });
const url = URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url;
a.download = 'Mob.wz';
a.click();
```

### Modify and Rebuild a .ms File

```typescript
const parser = await WzParser.create();
const msData = new Uint8Array(/* ... */);
const fileName = 'Mob_00000.ms';

// Parse and get entry list + salt + version
const parsed = parser.parseMsFile(msData, fileName);

// Decrypt an entry, modify it, then rebuild the whole file
const entries = [];
const imageBlobs = [];
for (const entry of parsed.entries) {
  const { properties, blobs } = parser.parseMsImageForEdit(msData, fileName, entry.index);

  // Modify mob HP in entry 0
  if (entry.index === 0) {
    const hp = properties.find(p => p.name === 'info')
      ?.children?.find(p => p.name === 'maxHP');
    if (hp) hp.value = 99999;
  }

  entries.push({ name: entry.name, entryKey: entry.entryKey });
  imageBlobs.push(parser.buildImage(properties, blobs, 'bms'));
}

// Rebuild as the same version (1 = Snow2, 2 = ChaCha20)
const output = parser.buildMsFile(fileName, parsed.salt, entries, imageBlobs, parsed.version);
```
