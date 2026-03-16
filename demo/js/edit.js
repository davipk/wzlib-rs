// ── Edit mode logic for WZ property tree editing ────────────────────

import {
  parseWzImageForEdit,
  parseHotfixForEdit,
  parseMsImageForEdit,
  encodePixels,
  compressPngData,
} from '../../ts-wrapper/wasm-pkg/wzlib_rs.js';
import { state } from './state.js';
import { unpackEditResult } from './packed.js';

// ── Edit key helpers ────────────────────────────────────────────────

export function getEditKey(viewKey) {
  if (state.fileMode === 'ms') return `ms:${viewKey}`;
  if (state.fileMode === 'hotfix') return 'hotfix';
  return String(viewKey);
}

export function isEditing(viewKey) {
  return state.editableImages.has(getEditKey(viewKey));
}

export function getEditData(viewKey) {
  return state.editableImages.get(getEditKey(viewKey));
}

// ── Enter edit mode ─────────────────────────────────────────────────

export function enterEditMode(viewKey) {
  const key = getEditKey(viewKey);
  if (state.editableImages.has(key)) return state.editableImages.get(key);

  let packed;
  if (state.fileMode === 'ms') {
    packed = parseMsImageForEdit(state.wzData, state.msFileName, viewKey);
  } else if (state.fileMode === 'hotfix') {
    packed = parseHotfixForEdit(state.wzData, state.wzVersionName);
  } else {
    packed = parseWzImageForEdit(
      state.wzData, state.wzVersionName, viewKey, 0, state.wzVersionHash,
    );
  }

  const data = unpackEditResult(packed);
  state.editableImages.set(key, data);
  return data;
}

// Create empty edit data for a new (synthetic) image
export function createEmptyEditData(editKey) {
  const data = { properties: [], blobs: [] };
  state.editableImages.set(editKey, data);
  return data;
}

// ── Property tree navigation ────────────────────────────────────────

export function findProperty(properties, path) {
  if (!path) return null;
  const parts = path.split('/');
  let current = properties;
  for (let i = 0; i < parts.length; i++) {
    const node = current.find(p => p.name === parts[i]);
    if (!node) return null;
    if (i === parts.length - 1) return node;
    current = node.children || [];
  }
  return null;
}

function findParentArray(properties, path) {
  const parts = path.split('/');
  if (parts.length === 1) return properties;
  const parentPath = parts.slice(0, -1).join('/');
  const parent = findProperty(properties, parentPath);
  return parent?.children || null;
}

// ── Property mutations ──────────────────────────────────────────────

export function markModified(viewKey) {
  if (state.fileMode === 'standard') {
    state.modifiedImages.add(viewKey);
  }
}

export function updateProperty(viewKey, path, updates) {
  const data = getEditData(viewKey);
  if (!data) return false;
  const node = findProperty(data.properties, path);
  if (!node) return false;
  Object.assign(node, updates);
  markModified(viewKey);
  return true;
}

export function deleteProperty(viewKey, path) {
  const data = getEditData(viewKey);
  if (!data) return false;
  const parts = path.split('/');
  const name = parts[parts.length - 1];
  const parent = findParentArray(data.properties, path);
  if (!parent) return false;
  const idx = parent.findIndex(p => p.name === name);
  if (idx < 0) return false;
  parent.splice(idx, 1);
  markModified(viewKey);
  return true;
}

export function addProperty(viewKey, parentPath, newProp) {
  const data = getEditData(viewKey);
  if (!data) return false;
  let target;
  if (!parentPath) {
    target = data.properties;
  } else {
    const parent = findProperty(data.properties, parentPath);
    if (!parent) return false;
    if (!parent.children) parent.children = [];
    target = parent.children;
  }
  if (target.some(p => p.name === newProp.name)) return false;
  target.push(newProp);
  markModified(viewKey);
  return true;
}

// ── Canvas replacement ──────────────────────────────────────────────

// Returns { width, height, rgba } so the caller can update the canvas preview
export async function replaceCanvasImage(viewKey, path, imageFile) {
  const data = getEditData(viewKey);
  if (!data) return null;
  const node = findProperty(data.properties, path);
  if (!node || node.type !== 'Canvas') return null;

  const img = await loadImageFromFile(imageFile);
  const { width, height, rgba } = getImageRGBA(img);

  // Encode as BGRA8888 (format 2) — safest, no DXT encoding needed
  const encoded = encodePixels(new Uint8Array(rgba), width, height, 2);
  const compressed = compressPngData(encoded);

  if (node.blobIndex != null && node.blobIndex < data.blobs.length) {
    data.blobs[node.blobIndex] = compressed;
  } else {
    node.blobIndex = data.blobs.length;
    data.blobs.push(compressed);
  }

  node.width = width;
  node.height = height;
  node.format = 2;
  node.dataLength = compressed.length;
  markModified(viewKey);
  return { width, height, rgba };
}

// ── Canvas/Sound blob creation (for "add new" flow) ─────────────────

export async function createCanvasBlob(viewKey, prop, imageFile) {
  const data = getEditData(viewKey);
  if (!data) return null;

  const img = await loadImageFromFile(imageFile);
  const { width, height, rgba } = getImageRGBA(img);

  const encoded = encodePixels(new Uint8Array(rgba), width, height, 2);
  const compressed = compressPngData(encoded);

  prop.width = width;
  prop.height = height;
  prop.format = 2;
  prop.dataLength = compressed.length;
  prop.blobIndex = data.blobs.length;
  data.blobs.push(compressed);

  markModified(viewKey);
  return { width, height, rgba };
}

export async function createSoundBlob(viewKey, prop, audioFile) {
  const data = getEditData(viewKey);
  if (!data) return null;

  const audioData = new Uint8Array(await audioFile.arrayBuffer());

  // Pack as sound blob: [header_len:u32 LE][header][audio_data]
  // Use empty header — audio data (MP3/WAV) is self-describing
  const blob = new Uint8Array(4 + audioData.length);
  const view = new DataView(blob.buffer);
  view.setUint32(0, 0, true);
  blob.set(audioData, 4);

  prop.dataLength = blob.length;
  prop.blobIndex = data.blobs.length;
  data.blobs.push(blob);

  // Try to read duration from the audio element
  prop.duration_ms = await getAudioDuration(audioFile).catch(() => 0);

  markModified(viewKey);
  return true;
}

function getAudioDuration(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const audio = new Audio(url);
    audio.addEventListener('loadedmetadata', () => {
      URL.revokeObjectURL(url);
      resolve(Math.round(audio.duration * 1000));
    });
    audio.addEventListener('error', () => {
      URL.revokeObjectURL(url);
      reject();
    });
  });
}

// ── File/image loading helpers ──────────────────────────────────────

function loadImageFromFile(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => { URL.revokeObjectURL(url); resolve(img); };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Failed to load image')); };
    img.src = url;
  });
}

function getImageRGBA(img) {
  const cvs = document.createElement('canvas');
  cvs.width = img.width;
  cvs.height = img.height;
  const ctx = cvs.getContext('2d');
  ctx.drawImage(img, 0, 0);
  const imageData = ctx.getImageData(0, 0, img.width, img.height);
  return { width: img.width, height: img.height, rgba: imageData.data };
}

// ── Default property values for "add" ───────────────────────────────

export const ADDABLE_TYPES = [
  'Null', 'Short', 'Int', 'Long', 'Float', 'Double',
  'String', 'SubProperty', 'Vector', 'UOL', 'Canvas', 'Sound',
];

export function createDefaultProperty(name, type) {
  const prop = { name, type };
  switch (type) {
    case 'Null': break;
    case 'Short': case 'Int': case 'Long': prop.value = 0; break;
    case 'Float': case 'Double': prop.value = 0.0; break;
    case 'String': prop.value = ''; break;
    case 'UOL': prop.value = ''; break;
    case 'Vector': prop.x = 0; prop.y = 0; break;
    case 'SubProperty': prop.children = []; break;
    case 'Canvas':
      prop.width = 0;
      prop.height = 0;
      prop.format = 2;
      prop.dataLength = 0;
      prop.children = [];
      break;
    case 'Sound':
      prop.duration_ms = 0;
      prop.dataLength = 0;
      break;
  }
  return prop;
}
