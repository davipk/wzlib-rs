/** MapleStory client encryption variant. */
export type WzMapleVersion = 'gms' | 'ems' | 'msea' | 'bms' | 'classic' | 'custom';

/** WZ PNG pixel format ID (matches the Rust `WzPngFormat` enum values). */
export type WzPngFormat =
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

/** A leaf node in the WZ directory tree (contains property data at `offset`). */
export interface WzImageEntry {
  name: string;
  size: number;
  checksum: number;
  offset: number;
}

/** Recursive directory tree as returned by the WASM `parseWzFile` call. */
export interface WzDirectoryTree {
  name: string;
  size: number;
  checksum: number;
  offset: number;
  entry_type: number;
  subdirectories: WzDirectoryTree[];
  images: WzImageEntry[];
}

/** File type as returned by `detectWzFileType`. */
export type WzFileType = 'standard' | 'hotfix' | 'list';

/** MCV video container header metadata. */
export interface McvHeaderInfo {
  fourcc: number;
  width: number;
  height: number;
  frameCount: number;
  dataFlags: number;
  frameDelayUnitNs: string; // i64 as string to avoid JS precision loss
  defaultDelay: number;
}

/** Property node as returned by `parseWzImage` / `parseHotfixDataWz`. */
export interface WzPropertyNode {
  name: string;
  type: string;
  value?: unknown;
  children?: WzPropertyNode[];
  // Canvas
  width?: number;
  height?: number;
  format?: number;
  dataLength?: number;
  // Vector
  x?: number;
  y?: number;
  // Sound
  duration_ms?: number;
  // Video
  videoType?: number;
  mcv?: McvHeaderInfo;
}

/** Entry metadata from a parsed .ms file. */
export interface MsEntryInfo {
  name: string;
  size: number;
  index: number;
  entryKey: number[]; // 16-byte random key
}

/** Result from parsing a .ms file (includes salt for save roundtrip). */
export interface MsParsedResult {
  entryCount: number;
  salt: string;
  entries: MsEntryInfo[];
}

/** Entry data for saving a .ms file. */
export interface MsSaveEntry {
  name: string;
  image_data: number[]; // serialized WZ image bytes
  entry_key: number[]; // 16-byte random key
}

/** Functions exported by the wasm-pack generated WASM module. */
export interface WasmExports {
  generateWzKey(iv: Uint8Array, size: number): Uint8Array;
  getVersionIv(version: string): Uint8Array;
  mapleCustomEncrypt(data: Uint8Array): void;
  mapleCustomDecrypt(data: Uint8Array): void;
  decompressPngData(compressed: Uint8Array, wzKey?: Uint8Array): Uint8Array;
  decodePixels(raw: Uint8Array, width: number, height: number, formatId: number): Uint8Array;
  parseWzFile(
    data: Uint8Array,
    versionName: string,
    patchVersion?: number,
    customIv?: Uint8Array,
  ): string;
  parseWzImage(
    data: Uint8Array,
    versionName: string,
    imgOffset: number,
    imgSize: number,
    versionHash: number,
    customIv?: Uint8Array,
  ): string;
  decodeWzCanvas(
    data: Uint8Array,
    versionName: string,
    imgOffset: number,
    versionHash: number,
    propPath: string,
    customIv?: Uint8Array,
  ): Uint8Array;
  extractWzSound(
    data: Uint8Array,
    versionName: string,
    imgOffset: number,
    versionHash: number,
    propPath: string,
    customIv?: Uint8Array,
  ): Uint8Array;
  detectWzMapleVersion(data: Uint8Array): string;
  detectWzFileType(data: Uint8Array): WzFileType;
  parseWzListFile(data: Uint8Array, versionName: string, customIv?: Uint8Array): string;
  parseHotfixDataWz(data: Uint8Array, versionName: string, customIv?: Uint8Array): string;
  computeVersionHash(version: number): number;
  parseMsFile(data: Uint8Array, fileName: string): string;
  parseMsImage(data: Uint8Array, fileName: string, entryIndex: number): string;
  decodeMsCanvas(
    data: Uint8Array,
    fileName: string,
    entryIndex: number,
    propPath: string,
  ): Uint8Array;
  extractMsSound(
    data: Uint8Array,
    fileName: string,
    entryIndex: number,
    propPath: string,
  ): Uint8Array;
  extractWzVideo(
    data: Uint8Array,
    versionName: string,
    imgOffset: number,
    versionHash: number,
    propPath: string,
    customIv?: Uint8Array,
  ): Uint8Array;
  extractMsVideo(
    data: Uint8Array,
    fileName: string,
    entryIndex: number,
    propPath: string,
  ): Uint8Array;
  serializeWzImage(propertiesJson: string, versionName: string, customIv?: Uint8Array): Uint8Array;
  encryptMsEntry(
    data: Uint8Array,
    salt: string,
    entryName: string,
    entryKey: Uint8Array,
  ): Uint8Array;
  saveWzFile(data: Uint8Array, versionName: string, customIv?: Uint8Array): Uint8Array;
  saveHotfixDataWz(data: Uint8Array, versionName: string, customIv?: Uint8Array): Uint8Array;
  saveMsFile(data: Uint8Array, fileName: string): Uint8Array;
  saveWzImage(
    wzData: Uint8Array,
    versionName: string,
    imgOffset: number,
    versionHash: number,
    customIv?: Uint8Array,
  ): Uint8Array;
  saveMsImage(
    data: Uint8Array,
    fileName: string,
    entryIndex: number,
    customIv?: Uint8Array,
  ): Uint8Array;
}
