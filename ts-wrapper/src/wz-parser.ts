import type {
  EditableImage,
  MsBuildEntry,
  MsParsedResult,
  WasmExports,
  WzDirectoryTree,
  WzFileType,
  WzMapleVersion,
  WzPngFormat,
  WzPropertyNode,
} from './types.js';
import { WzNode, WzNodeType } from './wz-node.js';

export type { EditableImage };

function unpackEditResult(packed: Uint8Array): EditableImage {
  if (packed.byteLength < 4) throw new Error('Edit result buffer too short');
  const view = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
  let offset = 0;

  const jsonLen = view.getUint32(offset, true);
  offset += 4;
  if (offset + jsonLen > packed.byteLength) throw new Error('Edit result JSON extends past buffer');
  const jsonBytes = packed.subarray(offset, offset + jsonLen);
  offset += jsonLen;
  const properties: WzPropertyNode[] = JSON.parse(new TextDecoder().decode(jsonBytes));

  if (offset + 4 > packed.byteLength) throw new Error('Edit result blob header truncated');
  const blobCount = view.getUint32(offset, true);
  offset += 4;
  const blobs: Uint8Array[] = [];
  for (let i = 0; i < blobCount; i++) {
    if (offset + 4 > packed.byteLength) throw new Error(`Blob ${i} header truncated`);
    const blobLen = view.getUint32(offset, true);
    offset += 4;
    if (offset + blobLen > packed.byteLength) throw new Error(`Blob ${i} data extends past buffer`);
    blobs.push(packed.slice(offset, offset + blobLen));
    offset += blobLen;
  }

  return { properties, blobs };
}

function packBlobs(blobs: Uint8Array[]): Uint8Array {
  let totalSize = 4;
  for (const b of blobs) totalSize += 4 + b.byteLength;

  const buf = new Uint8Array(totalSize);
  const view = new DataView(buf.buffer);
  let offset = 0;

  view.setUint32(offset, blobs.length, true);
  offset += 4;
  for (const b of blobs) {
    view.setUint32(offset, b.byteLength, true);
    offset += 4;
    buf.set(b, offset);
    offset += b.byteLength;
  }

  return buf;
}

/** High-level WZ file parser wrapping the WASM module. */
export class WzParser {
  private wasm: WasmExports;

  private constructor(wasm: WasmExports) {
    this.wasm = wasm;
  }

  static async create(wasmUrl?: string | URL): Promise<WzParser> {
    // @ts-ignore — wasm-pkg is generated at build time
    const wasmModule = await import('../wasm-pkg/wzlib_rs.js');
    await wasmModule.default(wasmUrl);
    return new WzParser(wasmModule as unknown as WasmExports);
  }

  // ── File type detection ───────────────────────────────────────────

  /** Detect whether `data` is a standard WZ, hotfix Data.wz, or List.wz. */
  detectFileType(data: Uint8Array): WzFileType {
    return this.wasm.detectWzFileType(data);
  }

  /** Auto-detect the MapleStory encryption variant by trying all candidates. */
  detectMapleVersion(data: Uint8Array): unknown {
    return JSON.parse(this.wasm.detectWzMapleVersion(data));
  }

  // ── Standard WZ ───────────────────────────────────────────────────

  parseFile(
    data: Uint8Array,
    version: WzMapleVersion,
    patchVersion?: number,
    customIv?: Uint8Array,
  ): WzNode {
    const json = this.wasm.parseWzFile(data, version, patchVersion, customIv);
    const tree: WzDirectoryTree = JSON.parse(json);
    return this.buildTree(tree);
  }

  // ── List.wz ───────────────────────────────────────────────────────

  /** Parse a List.wz file, returning the list of .img paths it indexes. */
  parseListFile(data: Uint8Array, version: WzMapleVersion, customIv?: Uint8Array): string[] {
    const json = this.wasm.parseWzListFile(data, version, customIv);
    return JSON.parse(json);
  }

  // ── Hotfix Data.wz ────────────────────────────────────────────────

  /** Parse a hotfix Data.wz file (entire file is a single WzImage). */
  parseHotfixFile(
    data: Uint8Array,
    version: WzMapleVersion,
    customIv?: Uint8Array,
  ): WzPropertyNode[] {
    const json = this.wasm.parseHotfixDataWz(data, version, customIv);
    return JSON.parse(json);
  }

  // ── Image parsing ────────────────────────────────────────────────

  /** Parse a WZ image at a given offset, returning its property tree. */
  parseImage(
    data: Uint8Array,
    version: WzMapleVersion,
    imgOffset: number,
    imgSize: number,
    versionHash: number,
    customIv?: Uint8Array,
  ): WzPropertyNode[] {
    const json = this.wasm.parseWzImage(data, version, imgOffset, imgSize, versionHash, customIv);
    return JSON.parse(json);
  }

  /** Decode a canvas directly from WZ data at a given image offset + property path. Returns `[width_le32, height_le32, ...rgba]`. */
  decodeWzCanvas(
    data: Uint8Array,
    version: WzMapleVersion,
    imgOffset: number,
    versionHash: number,
    propPath: string,
    customIv?: Uint8Array,
  ): Uint8Array {
    return this.wasm.decodeWzCanvas(data, version, imgOffset, versionHash, propPath, customIv);
  }

  /** Extract raw sound bytes from WZ data at a given image offset + property path. */
  extractSound(
    data: Uint8Array,
    version: WzMapleVersion,
    imgOffset: number,
    versionHash: number,
    propPath: string,
    customIv?: Uint8Array,
  ): Uint8Array {
    return this.wasm.extractWzSound(data, version, imgOffset, versionHash, propPath, customIv);
  }

  // ── Image / pixel decoding ────────────────────────────────────────

  decompressPng(compressed: Uint8Array, wzKey?: Uint8Array): Uint8Array {
    return this.wasm.decompressPngData(compressed, wzKey);
  }

  decodePixels(raw: Uint8Array, width: number, height: number, format: WzPngFormat): Uint8Array {
    return this.wasm.decodePixels(raw, width, height, format);
  }

  // ── Key / version utilities ───────────────────────────────────────

  generateKey(iv: Uint8Array, size: number): Uint8Array {
    return this.wasm.generateWzKey(iv, size);
  }

  getVersionIv(version: WzMapleVersion): Uint8Array {
    return this.wasm.getVersionIv(version);
  }

  computeVersionHash(version: number): number {
    return this.wasm.computeVersionHash(version);
  }

  // ── Crypto utilities ────────────────────────────────────────────

  /** Apply MapleStory custom encryption (in-place). */
  mapleCustomEncrypt(data: Uint8Array): void {
    this.wasm.mapleCustomEncrypt(data);
  }

  /** Apply MapleStory custom decryption (in-place). */
  mapleCustomDecrypt(data: Uint8Array): void {
    this.wasm.mapleCustomDecrypt(data);
  }

  // ── MS file (.ms) ──────────────────────────────────────────────────

  /** Parse a .ms file, returning entry metadata and salt. */
  parseMsFile(data: Uint8Array, fileName: string): MsParsedResult {
    const json = this.wasm.parseMsFile(data, fileName);
    return JSON.parse(json);
  }

  /** Decrypt and parse a single .ms entry as a WZ image property tree. */
  parseMsImage(data: Uint8Array, fileName: string, entryIndex: number): WzPropertyNode[] {
    const json = this.wasm.parseMsImage(data, fileName, entryIndex);
    return JSON.parse(json);
  }

  /** Decode a canvas from a .ms entry. Returns `[width_le32, height_le32, ...rgba]`. */
  decodeMsCanvas(
    data: Uint8Array,
    fileName: string,
    entryIndex: number,
    propPath: string,
  ): Uint8Array {
    return this.wasm.decodeMsCanvas(data, fileName, entryIndex, propPath);
  }

  /** Extract raw video bytes from a standard WZ file. */
  extractVideo(
    data: Uint8Array,
    versionName: WzMapleVersion,
    imgOffset: number,
    versionHash: number,
    propPath: string,
    customIv?: Uint8Array,
  ): Uint8Array {
    return this.wasm.extractWzVideo(data, versionName, imgOffset, versionHash, propPath, customIv);
  }

  /** Extract raw video bytes from a .ms entry. */
  extractMsVideo(
    data: Uint8Array,
    fileName: string,
    entryIndex: number,
    propPath: string,
  ): Uint8Array {
    return this.wasm.extractMsVideo(data, fileName, entryIndex, propPath);
  }

  /** Extract sound data from a .ms entry. */
  extractMsSound(
    data: Uint8Array,
    fileName: string,
    entryIndex: number,
    propPath: string,
  ): Uint8Array {
    return this.wasm.extractMsSound(data, fileName, entryIndex, propPath);
  }

  /** Decrypt a single .ms entry and return raw bytes (no WZ image parsing). */
  decryptMsEntry(
    data: Uint8Array,
    fileName: string,
    entryIndex: number,
  ): Uint8Array {
    return this.wasm.decryptMsEntry(data, fileName, entryIndex);
  }

  /** Encrypt a single .ms entry's image data (always v1/Snow2). */
  encryptMsEntry(
    data: Uint8Array,
    salt: string,
    entryName: string,
    entryKey: Uint8Array,
  ): Uint8Array {
    return this.wasm.encryptMsEntry(data, salt, entryName, entryKey);
  }

  // ── Encoding ──────────────────────────────────────────────────────

  // Reverse of decodePixels — does not support DXT/BC formats.
  encodePixels(rgba: Uint8Array, width: number, height: number, format: WzPngFormat): Uint8Array {
    return this.wasm.encodePixels(rgba, width, height, format);
  }

  compressPng(raw: Uint8Array): Uint8Array {
    return this.wasm.compressPngData(raw);
  }

  // ── Edit-friendly parsing ─────────────────────────────────────────
  //
  // These return a packed buffer: [json_len:u32 LE][json][blob_count:u32][blobs...]
  // Use `unpackEditResult()` to split into { json, blobs }.

  parseImageForEdit(
    data: Uint8Array,
    version: WzMapleVersion,
    imgOffset: number,
    imgSize: number,
    versionHash: number,
    customIv?: Uint8Array,
  ): EditableImage {
    const packed = this.wasm.parseWzImageForEdit(data, version, imgOffset, imgSize, versionHash, customIv);
    return unpackEditResult(packed);
  }

  parseHotfixForEdit(
    data: Uint8Array,
    version: WzMapleVersion,
    customIv?: Uint8Array,
  ): EditableImage {
    const packed = this.wasm.parseHotfixForEdit(data, version, customIv);
    return unpackEditResult(packed);
  }

  parseMsImageForEdit(
    data: Uint8Array,
    fileName: string,
    entryIndex: number,
  ): EditableImage {
    const packed = this.wasm.parseMsImageForEdit(data, fileName, entryIndex);
    return unpackEditResult(packed);
  }

  // ── Building from modified state ──────────────────────────────────

  buildImage(
    properties: WzPropertyNode[],
    blobs: Uint8Array[],
    version: WzMapleVersion,
    customIv?: Uint8Array,
  ): Uint8Array {
    const packedBlobs = packBlobs(blobs);
    return this.wasm.buildWzImage(JSON.stringify(properties), packedBlobs, version, customIv);
  }

  buildFile(
    directory: WzDirectoryTree,
    imageBlobs: Uint8Array[],
    version: number,
    versionName: WzMapleVersion,
    is64bit: boolean,
    customIv?: Uint8Array,
  ): Uint8Array {
    const packedBlobs = packBlobs(imageBlobs);
    return this.wasm.buildWzFile(JSON.stringify(directory), packedBlobs, version, versionName, is64bit, customIv);
  }

  buildMsFile(
    fileName: string,
    salt: string,
    entries: MsBuildEntry[],
    imageBlobs: Uint8Array[],
  ): Uint8Array {
    const packedBlobs = packBlobs(imageBlobs);
    return this.wasm.buildMsFile(fileName, salt, JSON.stringify(entries), packedBlobs);
  }

  // ── Internal ──────────────────────────────────────────────────────

  private buildTree(dir: WzDirectoryTree): WzNode {
    const node = new WzNode(dir.name || 'root', WzNodeType.Directory);

    for (const subdir of dir.subdirectories) {
      node.addChild(this.buildTree(subdir));
    }

    for (const img of dir.images) {
      const imgNode = new WzNode(img.name, WzNodeType.Image, {
        size: img.size,
        checksum: img.checksum,
        offset: img.offset,
      });
      node.addChild(imgNode);
    }

    return node;
  }
}
