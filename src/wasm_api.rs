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

fn children_to_json(props: &[(String, WzProperty)]) -> Vec<serde_json::Value> {
    props.iter().map(|(n, p)| prop_to_json(n, p)).collect()
}

// ── Crypto exports ───────────────────────────────────────────────────

#[wasm_bindgen(js_name = "generateWzKey")]
pub fn generate_wz_key(iv: &[u8], size: usize) -> Result<Vec<u8>, JsError> {
    if iv.len() != 4 {
        return Err(JsError::new("IV must be exactly 4 bytes"));
    }
    let iv_arr: [u8; 4] = [iv[0], iv[1], iv[2], iv[3]];
    Ok(crypto::aes_encryption::generate_wz_key(&iv_arr, size))
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

// ── Image decoding exports ───────────────────────────────────────────

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

// ── File type detection ──────────────────────────────────────────────

#[wasm_bindgen(js_name = "detectWzFileType")]
pub fn detect_wz_file_type(data: &[u8]) -> String {
    match crate::wz::file::detect_file_type(data) {
        crate::wz::file::WzFileType::Standard => "standard".to_string(),
        crate::wz::file::WzFileType::HotfixDataWz => "hotfix".to_string(),
        crate::wz::file::WzFileType::ListFile => "list".to_string(),
    }
}

// ── WZ file parsing exports ──────────────────────────────────────────

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

fn prop_to_json(name: &str, prop: &WzProperty) -> serde_json::Value {
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
            json!({ "name": name, "type": "SubProperty", "children": children_to_json(properties) })
        }
        WzProperty::Canvas { width, height, format, properties, png_data, .. } => {
            json!({
                "name": name,
                "type": "Canvas",
                "width": width,
                "height": height,
                "format": format.format_id(),
                "dataLength": png_data.len(),
                "children": children_to_json(properties),
            })
        }
        WzProperty::Convex { points } => {
            let pts: Vec<serde_json::Value> = points
                .iter()
                .enumerate()
                .map(|(i, p)| prop_to_json(&i.to_string(), p))
                .collect();
            json!({ "name": name, "type": "Convex", "children": pts })
        }
        WzProperty::Sound { duration_ms, data, .. } => {
            json!({ "name": name, "type": "Sound", "duration_ms": duration_ms, "dataLength": data.len() })
        }
        WzProperty::Lua(data) => {
            json!({ "name": name, "type": "Lua", "dataLength": data.len() })
        }
        WzProperty::RawData { data, .. } => {
            json!({ "name": name, "type": "RawData", "dataLength": data.len() })
        }
        WzProperty::Video { video_type, properties, data_length, mcv_header, .. } => {
            let mut obj = json!({
                "name": name,
                "type": "Video",
                "videoType": video_type,
                "dataLength": data_length,
                "children": children_to_json(properties),
            });
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

fn decode_canvas_prop(prop: &WzProperty, iv: &[u8; 4]) -> Result<Vec<u8>, JsError> {
    match prop {
        WzProperty::Canvas { width, height, format, png_data, .. } => {
            let wz_key = crypto::aes_encryption::generate_wz_key(iv, 0x10000);
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

fn extract_sound_prop(prop: &WzProperty) -> Result<Vec<u8>, JsError> {
    match prop {
        WzProperty::Sound { data, .. } => Ok(data.clone()),
        _ => Err(JsError::new("Property at path is not a Sound")),
    }
}

fn find_and_extract<'a>(
    properties: &'a [(String, WzProperty)],
    prop_path: &str,
    type_name: &str,
    predicate: &dyn Fn(&WzProperty) -> bool,
) -> Result<&'a WzProperty, JsError> {
    find_property(properties, prop_path, predicate)
        .ok_or_else(|| JsError::new(&format!("{} not found at path: {}", type_name, prop_path)))
}

#[wasm_bindgen(js_name = "decodeWzCanvas")]
pub fn decode_wz_canvas(
    wz_data: &[u8],
    version_name: &str,
    img_offset: u32,
    version_hash: u32,
    prop_path: &str,
    custom_iv: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    let iv = resolve_iv(version_name, custom_iv)?;
    let (properties, detected_iv) = parse_image_props(wz_data, iv, img_offset, version_hash)?;

    let canvas = find_and_extract(&properties, prop_path, "Canvas", &|p| matches!(p, WzProperty::Canvas { .. }))?;
    decode_canvas_prop(canvas, &detected_iv)
}

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

#[wasm_bindgen(js_name = "extractWzSound")]
pub fn extract_wz_sound(
    wz_data: &[u8],
    version_name: &str,
    img_offset: u32,
    version_hash: u32,
    prop_path: &str,
    custom_iv: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    let iv = resolve_iv(version_name, custom_iv)?;
    let (properties, _) = parse_image_props(wz_data, iv, img_offset, version_hash)?;

    let sound = find_and_extract(&properties, prop_path, "Sound", &|p| matches!(p, WzProperty::Sound { .. }))?;
    extract_sound_prop(sound)
}

fn extract_video_data(prop: &WzProperty) -> Result<Vec<u8>, JsError> {
    match prop {
        WzProperty::Video { video_data: Some(data), .. } => Ok(data.clone()),
        WzProperty::Video { video_data: None, .. } => {
            Err(JsError::new("Video property has no video_data loaded"))
        }
        _ => Err(JsError::new("Property at path is not a Video")),
    }
}

#[wasm_bindgen(js_name = "extractWzVideo")]
pub fn extract_wz_video(
    wz_data: &[u8],
    version_name: &str,
    img_offset: u32,
    version_hash: u32,
    prop_path: &str,
    custom_iv: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    let iv = resolve_iv(version_name, custom_iv)?;
    let (properties, _) = parse_image_props(wz_data, iv, img_offset, version_hash)?;

    let video = find_and_extract(&properties, prop_path, "Video", &|p| matches!(p, WzProperty::Video { .. }))?;
    extract_video_data(video)
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

// ── MS file parsing exports ─────────────────────────────────────────

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

    to_json_string(&serde_json::json!({
        "entryCount": parsed.entries.len(),
        "salt": parsed.salt,
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
    data: &[u8],
    file_name: &str,
    entry_index: u32,
    prop_path: &str,
) -> Result<Vec<u8>, JsError> {
    let props = parse_ms_image_props(data, file_name, entry_index)?;
    let canvas = find_and_extract(&props, prop_path, "Canvas", &|p| matches!(p, WzProperty::Canvas { .. }))?;
    decode_canvas_prop(canvas, &WzMapleVersion::Bms.iv())
}

#[wasm_bindgen(js_name = "extractMsSound")]
pub fn extract_ms_sound(
    data: &[u8],
    file_name: &str,
    entry_index: u32,
    prop_path: &str,
) -> Result<Vec<u8>, JsError> {
    let props = parse_ms_image_props(data, file_name, entry_index)?;
    let sound = find_and_extract(&props, prop_path, "Sound", &|p| matches!(p, WzProperty::Sound { .. }))?;
    extract_sound_prop(sound)
}

#[wasm_bindgen(js_name = "extractMsVideo")]
pub fn extract_ms_video(
    data: &[u8],
    file_name: &str,
    entry_index: u32,
    prop_path: &str,
) -> Result<Vec<u8>, JsError> {
    let props = parse_ms_image_props(data, file_name, entry_index)?;
    let video = find_and_extract(&props, prop_path, "Video", &|p| matches!(p, WzProperty::Video { .. }))?;
    extract_video_data(video)
}

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

#[wasm_bindgen(js_name = "computeVersionHash")]
pub fn compute_version_hash(version: i16) -> u32 {
    crate::wz::file::compute_version_hash(version)
}

// ── Save / Serialize exports ─────────────────────────────────────────

#[wasm_bindgen(js_name = "serializeWzImage")]
pub fn serialize_wz_image(
    properties_json: &str,
    version_name: &str,
    custom_iv: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    let props: Vec<(String, WzProperty)> =
        serde_json::from_str(properties_json).to_js_err()?;
    let iv = resolve_iv(version_name, custom_iv)?;
    crate::wz::file::save_hotfix_data_wz(&props, iv)
        .to_js_err()
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

#[wasm_bindgen(js_name = "saveWzFile")]
pub fn save_wz_file(data: &[u8], version_name: &str, custom_iv: Option<Vec<u8>>) -> Result<Vec<u8>, JsError> {
    let maple_version = parse_maple_version(version_name)?;
    let iv = resolve_iv(version_name, custom_iv)?;
    let mut wz_file = crate::wz::file::WzFile::parse_with_iv(data, maple_version, iv, None)
        .to_js_err()?;

    load_all_image_properties(data, &mut wz_file.directory, iv, wz_file.version_hash)?;
    wz_file.save().to_js_err()
}

#[wasm_bindgen(js_name = "saveHotfixDataWz")]
pub fn save_hotfix_data_wz(data: &[u8], version_name: &str, custom_iv: Option<Vec<u8>>) -> Result<Vec<u8>, JsError> {
    let iv = resolve_iv(version_name, custom_iv)?;
    let properties = crate::wz::file::parse_hotfix_data_wz(data, iv)
        .to_js_err()?;
    crate::wz::file::save_hotfix_data_wz(&properties, iv)
        .to_js_err()
}

#[wasm_bindgen(js_name = "saveMsFile")]
pub fn save_ms_file(data: &[u8], file_name: &str) -> Result<Vec<u8>, JsError> {
    let parsed = crate::wz::ms_file::parse_ms_file(data, file_name)
        .to_js_err()?;

    let mut entries = Vec::with_capacity(parsed.entries.len());
    for (i, entry) in parsed.entries.iter().enumerate() {
        let decrypted = crate::wz::ms_file::decrypt_entry_data(data, &parsed, i)
            .to_js_err()?;
        entries.push(crate::wz::ms_file::MsSaveEntry {
            name: entry.name.clone(),
            image_data: decrypted,
            entry_key: entry.entry_key,
        });
    }

    crate::wz::ms_file::save_ms_file(file_name, &parsed.salt, &entries)
        .to_js_err()
}

fn load_all_image_properties(
    data: &[u8],
    dir: &mut crate::wz::directory::WzDirectoryEntry,
    iv: [u8; 4],
    version_hash: u32,
) -> Result<(), JsError> {
    for img in &mut dir.images {
        let (props, detected_iv) = parse_image_props(data, iv, img.offset as u32, version_hash)?;
        img.properties = Some(props);
        if detected_iv != iv {
            img.iv = Some(detected_iv);
        }
    }
    for subdir in &mut dir.subdirectories {
        load_all_image_properties(data, subdir, iv, version_hash)?;
    }
    Ok(())
}

#[wasm_bindgen(js_name = "saveWzImage")]
pub fn save_wz_image(
    wz_data: &[u8],
    version_name: &str,
    img_offset: u32,
    version_hash: u32,
    custom_iv: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    let iv = resolve_iv(version_name, custom_iv)?;
    let (properties, _) = parse_image_props(wz_data, iv, img_offset, version_hash)?;
    crate::wz::file::save_hotfix_data_wz(&properties, iv)
        .to_js_err()
}

#[wasm_bindgen(js_name = "saveMsImage")]
pub fn save_ms_image(
    data: &[u8],
    file_name: &str,
    entry_index: u32,
    custom_iv: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    let props = parse_ms_image_props(data, file_name, entry_index)?;
    let iv = if let Some(ref iv_bytes) = custom_iv {
        if iv_bytes.len() != 4 {
            return Err(JsError::new("custom_iv must be exactly 4 bytes"));
        }
        [iv_bytes[0], iv_bytes[1], iv_bytes[2], iv_bytes[3]]
    } else {
        WzMapleVersion::Bms.iv()
    };
    crate::wz::file::save_hotfix_data_wz(&props, iv)
        .to_js_err()
}
