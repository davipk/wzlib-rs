//! WASM bindings — the public API exposed to JavaScript/TypeScript.

use wasm_bindgen::prelude::*;

use crate::crypto;
use crate::image;
use crate::wz::properties::WzProperty;
use crate::wz::types::{WzMapleVersion, WzPngFormat};

// ── Error conversion trait ──────────────────────────────────────────

trait ToJsErr<T> {
    fn to_js_err(self) -> Result<T, JsError>;
}

impl<T, E: std::fmt::Display> ToJsErr<T> for Result<T, E> {
    fn to_js_err(self) -> Result<T, JsError> {
        self.map_err(|e| JsError::new(&e.to_string()))
    }
}

// ── Shared helpers ──────────────────────────────────────────────────

fn parse_maple_version(name: &str) -> Result<WzMapleVersion, JsError> {
    match name.to_lowercase().as_str() {
        "gms" => Ok(WzMapleVersion::Gms),
        "ems" | "msea" => Ok(WzMapleVersion::Ems),
        "bms" | "classic" => Ok(WzMapleVersion::Bms),
        "custom" => Ok(WzMapleVersion::Custom),
        _ => Err(JsError::new(&format!("Unknown version: {}", name))),
    }
}

fn resolve_iv(version_name: &str, custom_iv: Option<Vec<u8>>) -> Result<[u8; 4], JsError> {
    if let Some(iv_bytes) = custom_iv {
        if iv_bytes.len() != 4 {
            return Err(JsError::new("custom_iv must be exactly 4 bytes"));
        }
        return Ok([iv_bytes[0], iv_bytes[1], iv_bytes[2], iv_bytes[3]]);
    }
    Ok(parse_maple_version(version_name)?.iv())
}

fn to_json_string(value: &impl serde::Serialize) -> Result<String, JsError> {
    serde_json::to_string(value).to_js_err()
}

// ── JSON serialization ──────────────────────────────────────────────

fn children_to_json(props: &[(String, WzProperty)]) -> Vec<serde_json::Value> {
    props.iter().map(|(n, p)| prop_to_json(n, p, None)).collect()
}

// When `blobs` is Some, binary data (Canvas png_data, Sound header+audio, etc.)
// is extracted into the blob vec and referenced by "blobIndex" in the JSON.
// When None, only metadata ("dataLength") is emitted (read-only mode).
fn prop_to_json(
    name: &str,
    prop: &WzProperty,
    mut blobs: Option<&mut Vec<Vec<u8>>>,
) -> serde_json::Value {
    use serde_json::json;

    match prop {
        WzProperty::Null => json!({ "name": name, "type": "Null" }),
        WzProperty::Short(v) => json!({ "name": name, "type": "Short", "value": v }),
        WzProperty::Int(v) => json!({ "name": name, "type": "Int", "value": v }),
        WzProperty::Long(v) => json!({ "name": name, "type": "Long", "value": v }),
        WzProperty::Float(v) => json!({ "name": name, "type": "Float", "value": v }),
        WzProperty::Double(v) => json!({ "name": name, "type": "Double", "value": v }),
        WzProperty::String(v) => json!({ "name": name, "type": "String", "value": v }),
        WzProperty::Uol(v) => json!({ "name": name, "type": "UOL", "value": v }),
        WzProperty::Vector { x, y } => json!({ "name": name, "type": "Vector", "x": x, "y": y }),
        WzProperty::SubProperty { properties, .. } => {
            let children = children_to_json_inner(properties, blobs);
            json!({ "name": name, "type": "SubProperty", "children": children })
        }
        WzProperty::Canvas { width, height, format, properties, png_data, .. } => {
            let children = children_to_json_inner(properties, blobs.as_deref_mut());
            let mut obj = json!({
                "name": name,
                "type": "Canvas",
                "width": width,
                "height": height,
                "format": format.format_id(),
                "children": children,
            });
            if let Some(blobs) = blobs {
                obj["blobIndex"] = json!(blobs.len());
                blobs.push(png_data.clone());
            } else {
                obj["dataLength"] = json!(png_data.len());
            }
            obj
        }
        WzProperty::Convex { points } => {
            let pts: Vec<serde_json::Value> = points
                .iter()
                .map(|(n, p)| prop_to_json(n, p, blobs.as_deref_mut()))
                .collect();
            json!({ "name": name, "type": "Convex", "children": pts })
        }
        WzProperty::Sound { duration_ms, data, header } => {
            let mut obj = json!({ "name": name, "type": "Sound", "duration_ms": duration_ms });
            if let Some(blobs) = blobs {
                obj["blobIndex"] = json!(blobs.len());
                blobs.push(pack_sound_blob(header, data));
            } else {
                obj["dataLength"] = json!(data.len());
            }
            obj
        }
        WzProperty::Lua(data) => {
            let mut obj = json!({ "name": name, "type": "Lua" });
            if let Some(blobs) = blobs {
                obj["blobIndex"] = json!(blobs.len());
                blobs.push(data.clone());
            } else {
                obj["dataLength"] = json!(data.len());
            }
            obj
        }
        WzProperty::RawData { raw_type, properties, data } => {
            let children = children_to_json_inner(properties, blobs.as_deref_mut());
            let mut obj = json!({ "name": name, "type": "RawData", "rawDataType": raw_type });
            if !children.is_empty() {
                obj["children"] = json!(children);
            }
            if let Some(blobs) = blobs {
                obj["blobIndex"] = json!(blobs.len());
                blobs.push(data.clone());
            } else {
                obj["dataLength"] = json!(data.len());
            }
            obj
        }
        WzProperty::Video { video_type, properties, data_length, mcv_header, video_data, .. } => {
            let children = children_to_json_inner(properties, blobs.as_deref_mut());
            let mut obj = json!({
                "name": name,
                "type": "Video",
                "videoType": video_type,
                "dataLength": data_length,
                "children": children,
            });
            if let Some(blobs) = blobs {
                if let Some(vdata) = video_data {
                    obj["blobIndex"] = json!(blobs.len());
                    blobs.push(vdata.clone());
                }
            }
            if let Some(header) = mcv_header {
                obj["mcv"] = json!({
                    "fourcc": header.fourcc,
                    "width": header.width,
                    "height": header.height,
                    "frameCount": header.frame_count,
                    "dataFlags": header.data_flags,
                    "frameDelayUnitNs": header.frame_delay_unit_ns.to_string(),
                    "defaultDelay": header.default_delay,
                });
            }
            obj
        }
    }
}

fn children_to_json_inner(
    props: &[(String, WzProperty)],
    mut blobs: Option<&mut Vec<Vec<u8>>>,
) -> Vec<serde_json::Value> {
    props.iter().map(|(n, p)| prop_to_json(n, p, blobs.as_deref_mut())).collect()
}

// ── Property tree traversal & extraction ────────────────────────────

fn find_property<'a>(
    properties: &'a [(String, WzProperty)],
    path: &str,
    predicate: &dyn Fn(&WzProperty) -> bool,
) -> Option<&'a WzProperty> {
    if path.is_empty() {
        for (_, prop) in properties {
            if predicate(prop) {
                return Some(prop);
            }
            if let Some(children) = prop.children() {
                if let Some(found) = find_property(children, "", predicate) {
                    return Some(found);
                }
            }
        }
        return None;
    }

    let parts: Vec<&str> = path.splitn(2, '/').collect();
    let name = parts[0];
    let rest = if parts.len() > 1 { parts[1] } else { "" };

    for (n, prop) in properties {
        if n == name {
            if rest.is_empty() {
                if predicate(prop) {
                    return Some(prop);
                }
                if let Some(children) = prop.children() {
                    return find_property(children, "", predicate);
                }
                return None;
            }
            if let Some(children) = prop.children() {
                return find_property(children, rest, predicate);
            }
        }
    }
    None
}

fn decode_canvas(prop: &WzProperty, iv: &[u8; 4]) -> Result<Vec<u8>, JsError> {
    match prop {
        WzProperty::Canvas { width, height, format, png_data, .. } => {
            let wz_key = crypto::aes_encryption::generate_wz_key(iv, 0x10000, None);
            let raw = image::decompress_png_data(png_data, Some(&wz_key))
                .map_err(|e| JsError::new(&format!("Decompress failed: {}", e)))?;
            let rgba = image::decode_pixels(&raw, *width as u32, *height as u32, *format)
                .map_err(|e| JsError::new(&format!("Pixel decode failed: {}", e)))?;
            let mut result = Vec::with_capacity(8 + rgba.len());
            result.extend_from_slice(&(*width as u32).to_le_bytes());
            result.extend_from_slice(&(*height as u32).to_le_bytes());
            result.extend_from_slice(&rgba);
            Ok(result)
        }
        _ => Err(JsError::new("Property at path is not a Canvas")),
    }
}

fn extract_sound(prop: &WzProperty, _iv: &[u8; 4]) -> Result<Vec<u8>, JsError> {
    match prop {
        WzProperty::Sound { data, .. } => Ok(data.clone()),
        _ => Err(JsError::new("Property at path is not a Sound")),
    }
}

fn extract_video(prop: &WzProperty, _iv: &[u8; 4]) -> Result<Vec<u8>, JsError> {
    match prop {
        WzProperty::Video { video_data: Some(data), .. } => Ok(data.clone()),
        WzProperty::Video { video_data: None, .. } => {
            Err(JsError::new("Video property has no video_data loaded"))
        }
        _ => Err(JsError::new("Property at path is not a Video")),
    }
}

fn extract_wz_prop(
    wz_data: &[u8],
    version_name: &str,
    img_offset: u32,
    version_hash: u32,
    prop_path: &str,
    custom_iv: Option<Vec<u8>>,
    type_name: &str,
    predicate: &dyn Fn(&WzProperty) -> bool,
    extract: &dyn Fn(&WzProperty, &[u8; 4]) -> Result<Vec<u8>, JsError>,
) -> Result<Vec<u8>, JsError> {
    let iv = resolve_iv(version_name, custom_iv)?;
    let (properties, detected_iv) = parse_image_props(wz_data, iv, img_offset, version_hash)?;
    let prop = find_property(&properties, prop_path, predicate)
        .ok_or_else(|| JsError::new(&format!("{} not found at path: {}", type_name, prop_path)))?;
    extract(prop, &detected_iv)
}

fn extract_ms_prop(
    data: &[u8],
    file_name: &str,
    entry_index: u32,
    prop_path: &str,
    type_name: &str,
    predicate: &dyn Fn(&WzProperty) -> bool,
    extract: &dyn Fn(&WzProperty, &[u8; 4]) -> Result<Vec<u8>, JsError>,
) -> Result<Vec<u8>, JsError> {
    let props = parse_ms_image_props(data, file_name, entry_index)?;
    let prop = find_property(&props, prop_path, predicate)
        .ok_or_else(|| JsError::new(&format!("{} not found at path: {}", type_name, prop_path)))?;
    extract(prop, &WzMapleVersion::Bms.iv())
}

// ── Crypto exports ──────────────────────────────────────────────────

#[wasm_bindgen(js_name = "generateWzKey")]
pub fn generate_wz_key(iv: &[u8], size: usize) -> Result<Vec<u8>, JsError> {
    if iv.len() != 4 {
        return Err(JsError::new("IV must be exactly 4 bytes"));
    }
    let iv_arr: [u8; 4] = [iv[0], iv[1], iv[2], iv[3]];
    Ok(crypto::aes_encryption::generate_wz_key(&iv_arr, size, None))
}

#[wasm_bindgen(js_name = "getVersionIv")]
pub fn get_version_iv(version: &str) -> Result<Vec<u8>, JsError> {
    Ok(parse_maple_version(version)?.iv().to_vec())
}

#[wasm_bindgen(js_name = "mapleCustomEncrypt")]
pub fn maple_custom_encrypt(data: &mut [u8]) {
    crypto::custom_encryption::maple_custom_encrypt(data);
}

#[wasm_bindgen(js_name = "mapleCustomDecrypt")]
pub fn maple_custom_decrypt(data: &mut [u8]) {
    crypto::custom_encryption::maple_custom_decrypt(data);
}

// ── Image decoding exports ──────────────────────────────────────────

#[wasm_bindgen(js_name = "decompressPngData")]
pub fn decompress_png_data(compressed: &[u8], wz_key: Option<Vec<u8>>) -> Result<Vec<u8>, JsError> {
    image::decompress_png_data(compressed, wz_key.as_deref())
        .to_js_err()
}

#[wasm_bindgen(js_name = "decodePixels")]
pub fn decode_pixels(
    raw: &[u8],
    width: u32,
    height: u32,
    format_id: u32,
) -> Result<Vec<u8>, JsError> {
    let format = WzPngFormat::from_combined(format_id);
    image::decode_pixels(raw, width, height, format).to_js_err()
}

// ── File type detection ─────────────────────────────────────────────

#[wasm_bindgen(js_name = "detectWzFileType")]
pub fn detect_wz_file_type(data: &[u8]) -> String {
    match crate::wz::file::detect_file_type(data) {
        crate::wz::file::WzFileType::Standard => "standard".to_string(),
        crate::wz::file::WzFileType::HotfixDataWz => "hotfix".to_string(),
        crate::wz::file::WzFileType::ListFile => "list".to_string(),
    }
}

// ── WZ file parsing exports ─────────────────────────────────────────

// IV may differ from input — some files (JMS/KMS/CMS) encrypt images with a different key than the directory.
fn parse_image_props(
    wz_data: &[u8],
    iv: [u8; 4],
    img_offset: u32,
    version_hash: u32,
) -> Result<(Vec<(String, WzProperty)>, [u8; 4]), JsError> {
    use std::io::Cursor;
    use crate::wz::binary_reader::WzBinaryReader;
    use crate::wz::file::{detect_file_type, WzFileType};
    use crate::wz::header::WzHeader;
    use crate::wz::image::parse_image;

    let is_hotfix = detect_file_type(wz_data) == WzFileType::HotfixDataWz;

    let mut cursor = Cursor::new(wz_data);
    let header = if is_hotfix {
        WzHeader::dummy(wz_data.len() as u64)
    } else {
        WzHeader::parse(&mut cursor).to_js_err()?
    };

    let actual_offset = if is_hotfix { 0u64 } else { img_offset as u64 };

    if !is_hotfix && (img_offset as usize) >= wz_data.len() {
        return Err(JsError::new(&format!(
            "Image offset 0x{:X} is past end of file (size 0x{:X})",
            img_offset, wz_data.len()
        )));
    }

    let mut reader = WzBinaryReader::new(cursor, iv, header, 0);
    if !is_hotfix {
        reader.hash = version_hash;
    }
    reader.seek(actual_offset)
        .to_js_err()?;

    let props = parse_image(&mut reader)
        .to_js_err()?;
    let detected_iv = reader.wz_key.iv();
    Ok((props, detected_iv))
}

#[wasm_bindgen(js_name = "parseWzFile")]
pub fn parse_wz_file(
    data: &[u8],
    version_name: &str,
    patch_version: Option<i16>,
    custom_iv: Option<Vec<u8>>,
) -> Result<String, JsError> {
    let maple_version = parse_maple_version(version_name)?;
    let iv = resolve_iv(version_name, custom_iv)?;

    let wz_file = crate::wz::file::WzFile::parse_with_iv(data, maple_version, iv, patch_version)
        .to_js_err()?;

    let result = serde_json::json!({
        "versionHash": wz_file.version_hash,
        "version": wz_file.version,
        "is64bit": wz_file.is_64bit,
        "iv": wz_file.iv,
        "directory": wz_file.directory,
    });

    to_json_string(&result)
}

#[wasm_bindgen(js_name = "parseWzImage")]
pub fn parse_wz_image(
    wz_data: &[u8],
    version_name: &str,
    img_offset: u32,
    img_size: u32,
    version_hash: u32,
    custom_iv: Option<Vec<u8>>,
) -> Result<String, JsError> {
    let _ = img_size; // reserved for future use; kept for WASM API stability
    let iv = resolve_iv(version_name, custom_iv)?;

    let (properties, _) = parse_image_props(wz_data, iv, img_offset, version_hash)?;
    to_json_string(&children_to_json(&properties))
}

#[wasm_bindgen(js_name = "parseWzListFile")]
pub fn parse_wz_list_file(data: &[u8], version_name: &str, custom_iv: Option<Vec<u8>>) -> Result<String, JsError> {
    let iv = resolve_iv(version_name, custom_iv)?;
    let entries = crate::wz::list_file::parse_list_file_with_iv(data, iv)
        .to_js_err()?;

    to_json_string(&entries)
}

#[wasm_bindgen(js_name = "parseHotfixDataWz")]
pub fn parse_hotfix_data_wz(data: &[u8], version_name: &str, custom_iv: Option<Vec<u8>>) -> Result<String, JsError> {
    let iv = resolve_iv(version_name, custom_iv)?;

    let properties = crate::wz::file::parse_hotfix_data_wz(data, iv)
        .to_js_err()?;
    to_json_string(&children_to_json(&properties))
}

#[wasm_bindgen(js_name = "decodeWzCanvas")]
pub fn decode_wz_canvas(
    wz_data: &[u8], version_name: &str, img_offset: u32, version_hash: u32,
    prop_path: &str, custom_iv: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    extract_wz_prop(wz_data, version_name, img_offset, version_hash, prop_path, custom_iv,
        "Canvas", &|p| matches!(p, WzProperty::Canvas { .. }), &decode_canvas)
}

#[wasm_bindgen(js_name = "extractWzSound")]
pub fn extract_wz_sound(
    wz_data: &[u8], version_name: &str, img_offset: u32, version_hash: u32,
    prop_path: &str, custom_iv: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    extract_wz_prop(wz_data, version_name, img_offset, version_hash, prop_path, custom_iv,
        "Sound", &|p| matches!(p, WzProperty::Sound { .. }), &extract_sound)
}

#[wasm_bindgen(js_name = "extractWzVideo")]
pub fn extract_wz_video(
    wz_data: &[u8], version_name: &str, img_offset: u32, version_hash: u32,
    prop_path: &str, custom_iv: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    extract_wz_prop(wz_data, version_name, img_offset, version_hash, prop_path, custom_iv,
        "Video", &|p| matches!(p, WzProperty::Video { .. }), &extract_video)
}

// ── MS file parsing exports ─────────────────────────────────────────

fn parse_ms_image_props(
    data: &[u8],
    file_name: &str,
    entry_index: u32,
) -> Result<Vec<(String, WzProperty)>, JsError> {
    use std::io::Cursor;
    use crate::wz::binary_reader::WzBinaryReader;
    use crate::wz::header::WzHeader;
    use crate::wz::image::parse_image;

    let parsed = crate::wz::ms_file::parse_ms_file(data, file_name)
        .to_js_err()?;

    let decrypted =
        crate::wz::ms_file::decrypt_entry_data(data, &parsed, entry_index as usize)
            .to_js_err()?;

    let iv = WzMapleVersion::Bms.iv();
    let cursor = Cursor::new(decrypted);
    let mut reader = WzBinaryReader::new(cursor, iv, WzHeader::dummy(0), 0);

    parse_image(&mut reader).to_js_err()
}

#[wasm_bindgen(js_name = "parseMsFile")]
pub fn parse_ms_file(data: &[u8], file_name: &str) -> Result<String, JsError> {
    let parsed = crate::wz::ms_file::parse_ms_file(data, file_name)
        .to_js_err()?;

    let entries: Vec<serde_json::Value> = parsed
        .entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            serde_json::json!({
                "name": e.name,
                "size": e.size,
                "index": i,
                "entryKey": e.entry_key,
            })
        })
        .collect();

    let version = match parsed.version {
        crate::wz::ms_file::MsVersion::V1 => 1,
        crate::wz::ms_file::MsVersion::V2 => 2,
    };

    to_json_string(&serde_json::json!({
        "entryCount": parsed.entries.len(),
        "salt": parsed.salt,
        "version": version,
        "entries": entries,
    }))
}

#[wasm_bindgen(js_name = "parseMsImage")]
pub fn parse_ms_image(
    data: &[u8],
    file_name: &str,
    entry_index: u32,
) -> Result<String, JsError> {
    let props = parse_ms_image_props(data, file_name, entry_index)?;
    to_json_string(&children_to_json(&props))
}

#[wasm_bindgen(js_name = "decodeMsCanvas")]
pub fn decode_ms_canvas(
    data: &[u8], file_name: &str, entry_index: u32, prop_path: &str,
) -> Result<Vec<u8>, JsError> {
    extract_ms_prop(data, file_name, entry_index, prop_path,
        "Canvas", &|p| matches!(p, WzProperty::Canvas { .. }), &decode_canvas)
}

#[wasm_bindgen(js_name = "extractMsSound")]
pub fn extract_ms_sound(
    data: &[u8], file_name: &str, entry_index: u32, prop_path: &str,
) -> Result<Vec<u8>, JsError> {
    extract_ms_prop(data, file_name, entry_index, prop_path,
        "Sound", &|p| matches!(p, WzProperty::Sound { .. }), &extract_sound)
}

#[wasm_bindgen(js_name = "extractMsVideo")]
pub fn extract_ms_video(
    data: &[u8], file_name: &str, entry_index: u32, prop_path: &str,
) -> Result<Vec<u8>, JsError> {
    extract_ms_prop(data, file_name, entry_index, prop_path,
        "Video", &|p| matches!(p, WzProperty::Video { .. }), &extract_video)
}

// ── Version detection ───────────────────────────────────────────────

const CANDIDATES: [(&str, WzMapleVersion); 3] = [
    ("gms", WzMapleVersion::Gms),
    ("ems", WzMapleVersion::Ems),
    ("bms", WzMapleVersion::Bms),
];

fn printable_rate(s: &str) -> (usize, usize) {
    let recognized = s.chars().filter(|&c| ('\x20'..='\x7E').contains(&c)).count();
    (recognized, s.len())
}

fn aggregate_printable_rate<'a>(names: impl Iterator<Item = &'a str>) -> f64 {
    let (mut recognized, mut total) = (0usize, 0usize);
    for name in names {
        let (r, t) = printable_rate(name);
        recognized += r;
        total += t;
    }
    if total == 0 { 0.0 } else { recognized as f64 / total as f64 }
}

fn detect_best_candidate<T>(
    data: &[u8],
    parse: impl Fn(&[u8], WzMapleVersion) -> Result<T, crate::wz::error::WzError>,
    rate: impl Fn(&T) -> f64,
    file_type: &str,
) -> Result<(&'static str, T), JsError> {
    let mut best: Option<(&str, T, f64)> = None;

    for (name, maple_version) in &CANDIDATES {
        if let Ok(parsed) = parse(data, *maple_version) {
            let r = rate(&parsed);
            if best.as_ref().is_none_or(|(_, _, br)| r > *br) {
                best = Some((name, parsed, r));
            }
        }
    }

    match best {
        Some((name, parsed, _)) => Ok((name, parsed)),
        None => Err(JsError::new(&format!(
            "Could not detect WZ encryption variant for {} file.",
            file_type
        ))),
    }
}

// Heuristic: tries all encryption variants, picks the one with the most printable ASCII names.
// Handles standard WZ, hotfix Data.wz, and List.wz files.
#[wasm_bindgen(js_name = "detectWzMapleVersion")]
pub fn detect_wz_maple_version(data: &[u8]) -> Result<String, JsError> {
    use crate::wz::file::{detect_file_type, WzFileType};

    match detect_file_type(data) {
        WzFileType::Standard => detect_standard_version(data),
        WzFileType::HotfixDataWz => detect_hotfix_version(data),
        WzFileType::ListFile => detect_list_version(data),
    }
}

fn detect_standard_version(data: &[u8]) -> Result<String, JsError> {
    let (name, wz_file) = detect_best_candidate(
        data,
        |d, v| crate::wz::file::WzFile::parse(d, v, None),
        |f| {
            let dir = &f.directory;
            aggregate_printable_rate(
                dir.subdirectories.iter().map(|s| s.name.as_str())
                    .chain(dir.images.iter().map(|i| i.name.as_str())),
            )
        },
        "standard",
    )?;
    to_json_string(&serde_json::json!({
        "fileType": "standard",
        "versionName": name,
        "version": wz_file.version,
        "versionHash": wz_file.version_hash,
        "is64bit": wz_file.is_64bit,
        "iv": wz_file.iv,
        "directory": wz_file.directory,
    }))
}

fn detect_hotfix_version(data: &[u8]) -> Result<String, JsError> {
    let (name, props) = detect_best_candidate(
        data,
        |d, v| crate::wz::file::parse_hotfix_data_wz(d, v.iv()),
        |p| aggregate_printable_rate(p.iter().map(|(n, _)| n.as_str())),
        "hotfix Data.wz",
    )?;
    to_json_string(&serde_json::json!({
        "fileType": "hotfix",
        "versionName": name,
        "properties": children_to_json(&props),
    }))
}

fn detect_list_version(data: &[u8]) -> Result<String, JsError> {
    let (name, entries) = detect_best_candidate(
        data,
        crate::wz::list_file::parse_list_file,
        |e| aggregate_printable_rate(e.iter().map(|s| s.as_str())),
        "List.wz",
    )?;
    to_json_string(&serde_json::json!({
        "fileType": "list",
        "versionName": name,
        "entries": entries,
    }))
}

// ── Utility exports ─────────────────────────────────────────────────

#[wasm_bindgen(js_name = "computeVersionHash")]
pub fn compute_version_hash(version: i16) -> u32 {
    crate::wz::file::compute_version_hash(version)
}

#[wasm_bindgen(js_name = "decryptMsEntry")]
pub fn decrypt_ms_entry(
    data: &[u8],
    file_name: &str,
    entry_index: u32,
) -> Result<Vec<u8>, JsError> {
    let parsed = crate::wz::ms_file::parse_ms_file(data, file_name).to_js_err()?;
    crate::wz::ms_file::decrypt_entry_data(data, &parsed, entry_index as usize).to_js_err()
}

#[wasm_bindgen(js_name = "encryptMsEntry")]
pub fn encrypt_ms_entry(
    data: &[u8],
    salt: &str,
    entry_name: &str,
    entry_key: &[u8],
) -> Result<Vec<u8>, JsError> {
    if entry_key.len() != 16 {
        return Err(JsError::new("entry_key must be exactly 16 bytes"));
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(entry_key);
    Ok(crate::wz::ms_file::encrypt_entry_data(data, salt, entry_name, &key))
}

// ── Image encoding exports ──────────────────────────────────────────

#[wasm_bindgen(js_name = "encodePixels")]
pub fn encode_pixels(
    rgba: &[u8],
    width: u32,
    height: u32,
    format_id: u32,
) -> Result<Vec<u8>, JsError> {
    let format = WzPngFormat::from_combined(format_id);
    image::encode::encode_pixels(rgba, width, height, format).to_js_err()
}

#[wasm_bindgen(js_name = "compressPngData")]
pub fn compress_png_data(raw: &[u8]) -> Result<Vec<u8>, JsError> {
    image::encode::compress_png_data(raw).to_js_err()
}

// ── Packed blob format ──────────────────────────────────────────────
//
// Binary data (Canvas png_data, Sound header+audio, Video data, Lua, RawData)
// is separated from JSON and packed into a binary buffer:
//
//   [blob_count: u32 LE]
//   [blob0_len: u32 LE][blob0_data: blob0_len bytes]
//   [blob1_len: u32 LE][blob1_data: blob1_len bytes]
//   ...
//
// The JSON property tree references blobs by index via "blobIndex" fields.
// For Sound nodes, the blob format is: [header_len: u32 LE][header][audio_data]

fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
}

fn pack_blobs(blobs: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = 4 + blobs.iter().map(|b| 4 + b.len()).sum::<usize>();
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&(blobs.len() as u32).to_le_bytes());
    for blob in blobs {
        buf.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        buf.extend_from_slice(blob);
    }
    buf
}

fn unpack_blobs(packed: &[u8]) -> Result<Vec<&[u8]>, JsError> {
    if packed.len() < 4 {
        return Err(JsError::new("Blob buffer too short"));
    }
    let count = read_u32_le(packed, 0) as usize;
    let mut offset = 4;
    let mut blobs = Vec::with_capacity(count);
    for _ in 0..count {
        if offset + 4 > packed.len() {
            return Err(JsError::new("Blob buffer truncated"));
        }
        let len = read_u32_le(packed, offset) as usize;
        offset += 4;
        if offset + len > packed.len() {
            return Err(JsError::new("Blob data extends past buffer end"));
        }
        blobs.push(&packed[offset..offset + len]);
        offset += len;
    }
    Ok(blobs)
}

fn pack_sound_blob(header: &[u8], data: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(4 + header.len() + data.len());
    blob.extend_from_slice(&(header.len() as u32).to_le_bytes());
    blob.extend_from_slice(header);
    blob.extend_from_slice(data);
    blob
}

fn unpack_sound_blob(blob: &[u8]) -> Result<(&[u8], &[u8]), JsError> {
    if blob.len() < 4 {
        return Err(JsError::new("Sound blob too short"));
    }
    let header_len = read_u32_le(blob, 0) as usize;
    let header_end = 4 + header_len;
    if header_end > blob.len() {
        return Err(JsError::new("Sound blob header extends past end"));
    }
    Ok((&blob[4..header_end], &blob[header_end..]))
}

// Format: [json_len:u32][json_utf8][packed_blobs]
fn pack_editable_result(json_str: &str, blobs: &[Vec<u8>]) -> Vec<u8> {
    let json_bytes = json_str.as_bytes();
    let packed_blobs = pack_blobs(blobs);
    let mut buf = Vec::with_capacity(4 + json_bytes.len() + packed_blobs.len());
    buf.extend_from_slice(&(json_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(json_bytes);
    buf.extend_from_slice(&packed_blobs);
    buf
}

fn props_to_packed_editable(
    props: &[(String, WzProperty)],
) -> Result<Vec<u8>, JsError> {
    let mut blobs = Vec::new();
    let json_nodes = children_to_json_inner(props, Some(&mut blobs));
    let json_str = to_json_string(&json_nodes)?;
    Ok(pack_editable_result(&json_str, &blobs))
}

// ── JSON → WzProperty conversion ────────────────────────────────────

fn json_array_to_properties(
    arr: &[serde_json::Value],
    blobs: &[&[u8]],
) -> Result<Vec<(String, WzProperty)>, JsError> {
    arr.iter()
        .map(|node| json_node_to_property(node, blobs))
        .collect()
}

fn get_blob<'a>(node: &serde_json::Value, blobs: &'a [&[u8]], type_name: &str) -> Result<&'a [u8], JsError> {
    let idx = node["blobIndex"].as_u64()
        .ok_or_else(|| JsError::new(&format!("{type_name} node missing 'blobIndex'")))? as usize;
    blobs.get(idx).copied()
        .ok_or_else(|| JsError::new(&format!("{type_name} blobIndex {idx} out of range (have {} blobs)", blobs.len())))
}

fn parse_children(node: &serde_json::Value, blobs: &[&[u8]]) -> Result<Vec<(String, WzProperty)>, JsError> {
    node["children"].as_array()
        .map(|arr| json_array_to_properties(arr, blobs))
        .transpose()
        .map(|opt| opt.unwrap_or_default())
}

fn json_node_to_property(
    node: &serde_json::Value,
    blobs: &[&[u8]],
) -> Result<(String, WzProperty), JsError> {
    let name = node["name"].as_str().unwrap_or("").to_string();
    let type_str = node["type"].as_str()
        .ok_or_else(|| JsError::new("Property node missing 'type' field"))?;

    let prop = match type_str {
        "Null" => WzProperty::Null,
        "Short" => WzProperty::Short(node["value"].as_i64().unwrap_or(0) as i16),
        "Int" => WzProperty::Int(node["value"].as_i64().unwrap_or(0) as i32),
        "Long" => WzProperty::Long(node["value"].as_i64().unwrap_or(0)),
        "Float" => WzProperty::Float(node["value"].as_f64().unwrap_or(0.0) as f32),
        "Double" => WzProperty::Double(node["value"].as_f64().unwrap_or(0.0)),
        "String" => WzProperty::String(node["value"].as_str().unwrap_or("").to_string()),
        "UOL" => WzProperty::Uol(node["value"].as_str().unwrap_or("").to_string()),
        "Vector" => WzProperty::Vector {
            x: node["x"].as_i64().unwrap_or(0) as i32,
            y: node["y"].as_i64().unwrap_or(0) as i32,
        },
        "SubProperty" => WzProperty::SubProperty { properties: parse_children(node, blobs)? },
        "Canvas" => WzProperty::Canvas {
            width: node["width"].as_i64().unwrap_or(0) as i32,
            height: node["height"].as_i64().unwrap_or(0) as i32,
            format: WzPngFormat::from_combined(node["format"].as_u64().unwrap_or(2) as u32),
            properties: parse_children(node, blobs)?,
            png_data: get_blob(node, blobs, "Canvas")?.to_vec(),
        },
        "Convex" => {
            let points = node["children"].as_array()
                .map(|arr| arr.iter()
                    .enumerate()
                    .map(|(i, n)| json_node_to_property(n, blobs).map(|(_, p)| (i.to_string(), p)))
                    .collect::<Result<Vec<_>, _>>())
                .transpose()?
                .unwrap_or_default();
            WzProperty::Convex { points }
        }
        "Sound" => {
            let (header, audio_data) = unpack_sound_blob(get_blob(node, blobs, "Sound")?)?;
            WzProperty::Sound {
                duration_ms: node["duration_ms"].as_i64().unwrap_or(0) as i32,
                header: header.to_vec(),
                data: audio_data.to_vec(),
            }
        }
        "Lua" => WzProperty::Lua(get_blob(node, blobs, "Lua")?.to_vec()),
        "RawData" => WzProperty::RawData {
            raw_type: node["rawDataType"].as_u64().unwrap_or(0) as u8,
            properties: parse_children(node, blobs)?,
            data: get_blob(node, blobs, "RawData")?.to_vec(),
        },
        "Video" => {
            let video_data = node["blobIndex"].as_u64()
                .map(|_| get_blob(node, blobs, "Video").map(|b| b.to_vec()))
                .transpose()?;
            let data_length = video_data.as_ref().map(|d| d.len() as u32)
                .unwrap_or(node["dataLength"].as_u64().unwrap_or(0) as u32);
            WzProperty::Video {
                video_type: node["videoType"].as_u64().unwrap_or(0) as u8,
                properties: parse_children(node, blobs)?,
                data_offset: 0,
                data_length,
                mcv_header: None,
                video_data,
            }
        }
        other => return Err(JsError::new(&format!("Unknown property type: {other}"))),
    };

    Ok((name, prop))
}

// ── Edit-friendly parse exports ─────────────────────────────────────

#[wasm_bindgen(js_name = "parseWzImageForEdit")]
pub fn parse_wz_image_for_edit(
    wz_data: &[u8],
    version_name: &str,
    img_offset: u32,
    img_size: u32,
    version_hash: u32,
    custom_iv: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    let _ = img_size;
    let iv = resolve_iv(version_name, custom_iv)?;
    let (properties, _) = parse_image_props(wz_data, iv, img_offset, version_hash)?;

    props_to_packed_editable(&properties)
}

#[wasm_bindgen(js_name = "parseHotfixForEdit")]
pub fn parse_hotfix_for_edit(
    data: &[u8],
    version_name: &str,
    custom_iv: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    let iv = resolve_iv(version_name, custom_iv)?;
    let properties = crate::wz::file::parse_hotfix_data_wz(data, iv).to_js_err()?;
    props_to_packed_editable(&properties)
}

#[wasm_bindgen(js_name = "parseMsImageForEdit")]
pub fn parse_ms_image_for_edit(
    data: &[u8],
    file_name: &str,
    entry_index: u32,
) -> Result<Vec<u8>, JsError> {
    let props = parse_ms_image_props(data, file_name, entry_index)?;
    props_to_packed_editable(&props)
}

// ── Build image from display JSON + blobs ───────────────────────────

#[wasm_bindgen(js_name = "buildWzImage")]
pub fn build_wz_image(
    properties_json: &str,
    blobs: &[u8],
    version_name: &str,
    custom_iv: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    let blob_slices = unpack_blobs(blobs)?;
    let json_arr: Vec<serde_json::Value> = serde_json::from_str(properties_json).to_js_err()?;
    let props = json_array_to_properties(&json_arr, &blob_slices)?;

    let iv = resolve_iv(version_name, custom_iv)?;
    crate::wz::file::save_hotfix_data_wz(&props, iv).to_js_err()
}

// ── Build complete WZ file from directory JSON + image blobs ────────

#[wasm_bindgen(js_name = "buildWzFile")]
pub fn build_wz_file(
    directory_json: &str,
    image_blobs: &[u8],
    version: i16,
    version_name: &str,
    is_64bit: bool,
    custom_iv: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    use crate::wz::directory::WzDirectoryEntry;
    use crate::wz::file::WzFile;
    use crate::wz::header::WzHeader;

    let iv = resolve_iv(version_name, custom_iv)?;
    let maple_version = parse_maple_version(version_name)?;

    let mut directory: WzDirectoryEntry = serde_json::from_str(directory_json).to_js_err()?;

    let blob_slices = unpack_blobs(image_blobs)?;
    let consumed = directory.attach_image_data(&blob_slices).to_js_err()?;
    if consumed != blob_slices.len() {
        return Err(JsError::new(&format!(
            "Directory has {} images but {} blobs were provided",
            consumed, blob_slices.len()
        )));
    }

    let hash = crate::wz::file::compute_version_hash(version);
    let mut wz_file = WzFile {
        header: WzHeader {
            ident: "PKG1".into(),
            file_size: 0,
            data_start: 60,
            copyright: String::new(),
        },
        version,
        version_hash: hash,
        maple_version,
        iv,
        user_key: None,
        is_64bit,
        directory,
    };

    wz_file.save_with_image_data(&blob_slices).to_js_err()
}

// ── Build MS file from entries + image blobs ────────────────────────

#[wasm_bindgen(js_name = "buildMsFile")]
pub fn build_ms_file(
    file_name: &str,
    salt: &str,
    entries_json: &str,
    image_blobs: &[u8],
) -> Result<Vec<u8>, JsError> {
    #[derive(serde::Deserialize)]
    struct EntryDef {
        name: String,
        #[serde(rename = "entryKey")]
        entry_key: Vec<u8>,
        #[serde(rename = "originalSize")]
        original_size: Option<usize>,
    }

    let entry_defs: Vec<EntryDef> = serde_json::from_str(entries_json).to_js_err()?;
    let blob_slices = unpack_blobs(image_blobs)?;

    if entry_defs.len() != blob_slices.len() {
        return Err(JsError::new(&format!(
            "entries_json has {} entries but {} blobs were provided",
            entry_defs.len(), blob_slices.len()
        )));
    }

    let mut entries = Vec::with_capacity(entry_defs.len());
    for (def, blob) in entry_defs.iter().zip(blob_slices.iter()) {
        if def.entry_key.len() != 16 {
            return Err(JsError::new(&format!(
                "Entry '{}' key must be 16 bytes, got {}",
                def.name, def.entry_key.len()
            )));
        }
        let mut key = [0u8; 16];
        key.copy_from_slice(&def.entry_key);
        entries.push(crate::wz::ms_file::MsSaveEntry {
            name: def.name.clone(),
            image_data: blob.to_vec(),
            entry_key: key,
            original_size: def.original_size,
        });
    }

    crate::wz::ms_file::save_ms_file(file_name, salt, &entries).to_js_err()
}
