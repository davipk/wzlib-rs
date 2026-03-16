// ── Packed binary helpers (shared between save.js and edit.js) ───────

export function unpackEditResult(packed) {
  const view = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
  let offset = 0;

  const jsonLen = view.getUint32(offset, true);
  offset += 4;
  const json = JSON.parse(new TextDecoder().decode(packed.subarray(offset, offset + jsonLen)));
  offset += jsonLen;

  const blobCount = view.getUint32(offset, true);
  offset += 4;
  const blobs = [];
  for (let i = 0; i < blobCount; i++) {
    const blobLen = view.getUint32(offset, true);
    offset += 4;
    blobs.push(packed.slice(offset, offset + blobLen));
    offset += blobLen;
  }

  return { properties: json, blobs };
}

export function packBlobs(blobs) {
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
