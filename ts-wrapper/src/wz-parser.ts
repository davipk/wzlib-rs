import type {
  MsParsedResult,
  WasmExports,
  WzDirectoryTree,
  WzFileType,
  WzMapleVersion,
  WzPngFormat,
  WzPropertyNode,
} from './types.js';
import { WzNode, WzNodeType } from './wz-node.js';

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

  // ── Save / Serialize ─────────────────────────────────────────────

  /** Serialize a WZ image property tree to binary format. */
  serializeImage(
    properties: WzPropertyNode[],
    version: WzMapleVersion,
    customIv?: Uint8Array,
  ): Uint8Array {
    return this.wasm.serializeWzImage(JSON.stringify(properties), version, customIv);
  }

  /** Parse a standard WZ file from raw data and save through the regular flow. */
  saveFile(data: Uint8Array, version: WzMapleVersion, customIv?: Uint8Array): Uint8Array {
    return this.wasm.saveWzFile(data, version, customIv);
  }

  /** Parse a hotfix Data.wz from raw data and save through the regular flow. */
  saveHotfixFile(data: Uint8Array, version: WzMapleVersion, customIv?: Uint8Array): Uint8Array {
    return this.wasm.saveHotfixDataWz(data, version, customIv);
  }

  /** Parse a .ms file from raw data and save through the regular flow. */
  saveMsFile(data: Uint8Array, fileName: string): Uint8Array {
    return this.wasm.saveMsFile(data, fileName);
  }

  /** Encrypt a single .ms entry's image data. */
  encryptMsEntry(
    data: Uint8Array,
    salt: string,
    entryName: string,
    entryKey: Uint8Array,
  ): Uint8Array {
    return this.wasm.encryptMsEntry(data, salt, entryName, entryKey);
  }

  /** Save a single WZ image as a standalone Data.wz (hotfix format). */
  saveImage(
    wzData: Uint8Array,
    version: WzMapleVersion,
    imgOffset: number,
    versionHash: number,
    customIv?: Uint8Array,
  ): Uint8Array {
    return this.wasm.saveWzImage(wzData, version, imgOffset, versionHash, customIv);
  }

  /** Save a single .ms entry as a standalone Data.wz (hotfix format). */
  saveMsImage(
    data: Uint8Array,
    fileName: string,
    entryIndex: number,
    customIv?: Uint8Array,
  ): Uint8Array {
    return this.wasm.saveMsImage(data, fileName, entryIndex, customIv);
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
