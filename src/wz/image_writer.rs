//! WZ image writing — serializes property trees to WZ binary format (counterpart to `image.rs`).

use std::io::{Seek, Write};

use super::binary_writer::WzBinaryWriter;
use super::error::{WzError, WzResult};
use super::properties::WzProperty;

pub fn write_image<W: Write + Seek>(
    writer: &mut WzBinaryWriter<W>,
    properties: &[(String, WzProperty)],
) -> WzResult<usize> {
    let start = writer.position()?;

    // Lua special case: single Lua property skips the "Property" header
    if properties.len() == 1 {
        if let WzProperty::Lua(data) = &properties[0].1 {
            writer.write_u8(0x01)?;
            writer.write_compressed_int(data.len() as i32)?;
            writer.write_bytes(data)?;
            writer.string_cache.clear();
            return Ok((writer.position()? - start) as usize);
        }
    }

    writer.write_string_value(super::WZ_TYPE_PROPERTY, 0x73, 0x1B)?;
    write_property_list(writer, properties)?;
    writer.string_cache.clear();

    Ok((writer.position()? - start) as usize)
}

fn write_property_list<W: Write + Seek>(
    writer: &mut WzBinaryWriter<W>,
    properties: &[(String, WzProperty)],
) -> WzResult<()> {
    writer.write_u16(0)?; // padding
    writer.write_compressed_int(properties.len() as i32)?;

    for (name, prop) in properties {
        writer.write_string_value(name, 0x00, 0x01)?;

        if is_extended(prop) {
            write_extended_value(writer, prop)?;
        } else {
            write_property_value(writer, prop)?;
        }
    }
    Ok(())
}

fn is_extended(prop: &WzProperty) -> bool {
    matches!(
        prop,
        WzProperty::SubProperty { .. }
            | WzProperty::Canvas { .. }
            | WzProperty::Vector { .. }
            | WzProperty::Convex { .. }
            | WzProperty::Sound { .. }
            | WzProperty::Uol(_)
            | WzProperty::RawData { .. }
            | WzProperty::Video { .. }
    )
}

fn write_property_value<W: Write + Seek>(
    writer: &mut WzBinaryWriter<W>,
    prop: &WzProperty,
) -> WzResult<()> {
    match prop {
        WzProperty::Null => writer.write_u8(0x00),

        WzProperty::Short(v) => {
            writer.write_u8(0x02)?;
            writer.write_i16(*v)
        }

        WzProperty::Int(v) => {
            writer.write_u8(0x03)?;
            writer.write_compressed_int(*v)
        }

        WzProperty::Long(v) => {
            writer.write_u8(0x14)?;
            writer.write_compressed_long(*v)
        }

        WzProperty::Float(v) => {
            writer.write_u8(0x04)?;
            if *v == 0.0 {
                writer.write_u8(0x00)
            } else {
                writer.write_u8(0x80)?;
                writer.write_f32(*v)
            }
        }

        WzProperty::Double(v) => {
            writer.write_u8(0x05)?;
            writer.write_f64(*v)
        }

        WzProperty::String(v) => {
            writer.write_u8(0x08)?;
            writer.write_string_value(v, 0x00, 0x01)
        }

        // Lua is handled at the write_image level, not here
        WzProperty::Lua(_) => Err(WzError::Custom(
            "Lua properties must be the sole property in an image".into(),
        )),

        // Extended types should not reach here
        _ => Err(WzError::Custom(format!(
            "Unexpected property type in write_property_value: {:?}",
            std::mem::discriminant(prop)
        ))),
    }
}

// 0x09 envelope: type byte + u32 size placeholder + content + seek-back patch
fn write_extended_value<W: Write + Seek>(
    writer: &mut WzBinaryWriter<W>,
    prop: &WzProperty,
) -> WzResult<()> {
    writer.write_u8(0x09)?;
    let size_pos = writer.position()?;
    writer.write_u32(0)?; // placeholder

    write_extended_content(writer, prop)?;

    let end_pos = writer.position()?;
    let block_size = (end_pos - size_pos - 4) as u32;
    writer.seek(size_pos)?;
    writer.write_u32(block_size)?;
    writer.seek(end_pos)?;
    Ok(())
}

fn write_extended_content<W: Write + Seek>(
    writer: &mut WzBinaryWriter<W>,
    prop: &WzProperty,
) -> WzResult<()> {
    use super::{WZ_TYPE_PROPERTY, WZ_TYPE_CANVAS, WZ_TYPE_VECTOR, WZ_TYPE_CONVEX, WZ_TYPE_SOUND, WZ_TYPE_UOL, WZ_TYPE_RAW_DATA, WZ_TYPE_VIDEO};
    match prop {
        WzProperty::SubProperty { properties } => {
            writer.write_string_value(WZ_TYPE_PROPERTY, 0x73, 0x1B)?;
            write_property_list(writer, properties)
        }

        WzProperty::Canvas {
            width,
            height,
            format,
            properties,
            png_data,
        } => {
            writer.write_string_value(WZ_TYPE_CANVAS, 0x73, 0x1B)?;
            writer.write_u8(0)?; // separator

            if properties.is_empty() {
                writer.write_u8(0)?;
            } else {
                writer.write_u8(1)?;
                write_property_list(writer, properties)?;
            }

            writer.write_compressed_int(*width)?;
            writer.write_compressed_int(*height)?;
            writer.write_compressed_int(format.format_low())?;
            writer.write_compressed_int(format.format_high())?;
            writer.write_i32(0)?; // padding
            writer.write_i32(png_data.len() as i32 + 1)?;
            writer.write_u8(0)?; // header byte
            writer.write_bytes(png_data)
        }

        WzProperty::Vector { x, y } => {
            writer.write_string_value(WZ_TYPE_VECTOR, 0x73, 0x1B)?;
            writer.write_compressed_int(*x)?;
            writer.write_compressed_int(*y)
        }

        WzProperty::Convex { points } => {
            writer.write_string_value(WZ_TYPE_CONVEX, 0x73, 0x1B)?;
            writer.write_compressed_int(points.len() as i32)?;
            for point in points {
                write_extended_content(writer, point)?;
            }
            Ok(())
        }

        WzProperty::Sound {
            duration_ms,
            data,
            header,
        } => {
            writer.write_string_value(WZ_TYPE_SOUND, 0x73, 0x1B)?;
            writer.write_u8(0)?; // padding
            writer.write_compressed_int(data.len() as i32)?;
            writer.write_compressed_int(*duration_ms)?;
            writer.write_bytes(header)?;
            writer.write_bytes(data)
        }

        WzProperty::Uol(path) => {
            writer.write_string_value(WZ_TYPE_UOL, 0x73, 0x1B)?;
            writer.write_u8(0)?; // separator
            writer.write_string_value(path, 0x00, 0x01)
        }

        WzProperty::RawData { data } => {
            writer.write_string_value(WZ_TYPE_RAW_DATA, 0x73, 0x1B)?;
            writer.write_compressed_int(data.len() as i32)?;
            writer.write_bytes(data)
        }

        WzProperty::Video {
            video_type,
            properties,
            video_data,
            ..
        } => {
            let data = video_data.as_ref().ok_or_else(|| {
                WzError::Custom("Video property requires video_data for writing".into())
            })?;
            writer.write_string_value(WZ_TYPE_VIDEO, 0x73, 0x1B)?;
            writer.write_u8(0)?; // separator

            if properties.is_empty() {
                writer.write_u8(0)?;
            } else {
                writer.write_u8(1)?;
                write_property_list(writer, properties)?;
            }

            writer.write_u8(*video_type)?;
            writer.write_compressed_int(data.len() as i32)?;
            writer.write_bytes(data)
        }

        _ => Err(WzError::Custom(format!(
            "Not an extended property: {:?}",
            std::mem::discriminant(prop)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wz::image::parse_image;
    use crate::wz::test_utils::{dummy_header, make_reader};
    use crate::wz::types::WzPngFormat;
    use std::io::Cursor;

    fn write_then_read(
        properties: Vec<(String, WzProperty)>,
    ) -> Vec<(String, WzProperty)> {
        let mut writer = WzBinaryWriter::new(Cursor::new(Vec::new()), [0; 4], dummy_header(0));
        write_image(&mut writer, &properties).unwrap();
        let data = writer.writer.into_inner();
        let mut reader = make_reader(data);
        parse_image(&mut reader).unwrap()
    }

    // ── Null ─────────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_null() {
        let props = write_then_read(vec![("n".into(), WzProperty::Null)]);
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].0, "n");
        assert!(matches!(props[0].1, WzProperty::Null));
    }

    // ── Short ────────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_short() {
        let props = write_then_read(vec![("s".into(), WzProperty::Short(42))]);
        assert_eq!(props[0].1.as_int(), Some(42));
    }

    #[test]
    fn test_roundtrip_short_negative() {
        let props = write_then_read(vec![("s".into(), WzProperty::Short(-1))]);
        assert_eq!(props[0].1.as_int(), Some(-1));
    }

    // ── Int ──────────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_int_small() {
        let props = write_then_read(vec![("i".into(), WzProperty::Int(50))]);
        assert_eq!(props[0].1.as_int(), Some(50));
    }

    #[test]
    fn test_roundtrip_int_large() {
        let props = write_then_read(vec![("i".into(), WzProperty::Int(100_000))]);
        assert_eq!(props[0].1.as_int(), Some(100_000));
    }

    // ── Long ─────────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_long() {
        let props = write_then_read(vec![("l".into(), WzProperty::Long(i64::MAX))]);
        assert_eq!(props[0].1.as_int(), Some(i64::MAX));
    }

    // ── Float ────────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_float_zero() {
        let props = write_then_read(vec![("f".into(), WzProperty::Float(0.0))]);
        assert_eq!(props[0].1.as_float(), Some(0.0));
    }

    #[test]
    fn test_roundtrip_float_nonzero() {
        let props = write_then_read(vec![("f".into(), WzProperty::Float(3.14))]);
        let v = props[0].1.as_float().unwrap();
        assert!((v - 3.14f32 as f64).abs() < 0.001);
    }

    // ── Double ───────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_double() {
        let props = write_then_read(vec![("d".into(), WzProperty::Double(2.718281828))]);
        let v = props[0].1.as_float().unwrap();
        assert!((v - 2.718281828).abs() < 1e-9);
    }

    // ── String ───────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_string() {
        let props = write_then_read(vec![("s".into(), WzProperty::String("hello".into()))]);
        assert_eq!(props[0].1.as_str(), Some("hello"));
    }

    #[test]
    fn test_roundtrip_string_empty() {
        let props = write_then_read(vec![("s".into(), WzProperty::String(String::new()))]);
        assert_eq!(props[0].1.as_str(), Some(""));
    }

    // ── SubProperty ──────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_sub_property() {
        let sub = WzProperty::SubProperty {
            properties: vec![
                ("a".into(), WzProperty::Int(1)),
                ("b".into(), WzProperty::String("two".into())),
            ],
        };
        let props = write_then_read(vec![("sub".into(), sub)]);
        let children = props[0].1.children().unwrap();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].0, "a");
        assert_eq!(children[0].1.as_int(), Some(1));
        assert_eq!(children[1].0, "b");
        assert_eq!(children[1].1.as_str(), Some("two"));
    }

    // ── Vector ───────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_vector() {
        let props = write_then_read(vec![("v".into(), WzProperty::Vector { x: -10, y: 20 })]);
        match &props[0].1 {
            WzProperty::Vector { x, y } => {
                assert_eq!(*x, -10);
                assert_eq!(*y, 20);
            }
            other => panic!("Expected Vector, got {:?}", other),
        }
    }

    // ── Canvas ───────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_canvas() {
        let canvas = WzProperty::Canvas {
            width: 4,
            height: 4,
            format: WzPngFormat::Bgra8888,
            properties: vec![("origin".into(), WzProperty::Vector { x: 0, y: 0 })],
            png_data: vec![0x78, 0x9C, 0x01, 0x00, 0x00], // minimal zlib
        };
        let props = write_then_read(vec![("c".into(), canvas)]);
        match &props[0].1 {
            WzProperty::Canvas {
                width,
                height,
                format,
                properties,
                png_data,
            } => {
                assert_eq!(*width, 4);
                assert_eq!(*height, 4);
                assert_eq!(format.format_id(), WzPngFormat::Bgra8888.format_id());
                assert_eq!(properties.len(), 1);
                assert_eq!(png_data, &[0x78, 0x9C, 0x01, 0x00, 0x00]);
            }
            other => panic!("Expected Canvas, got {:?}", other),
        }
    }

    // ── Convex ───────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_convex() {
        let convex = WzProperty::Convex {
            points: vec![
                WzProperty::Vector { x: 0, y: 0 },
                WzProperty::Vector { x: 10, y: 20 },
            ],
        };
        let props = write_then_read(vec![("cx".into(), convex)]);
        match &props[0].1 {
            WzProperty::Convex { points } => {
                assert_eq!(points.len(), 2);
                match &points[1] {
                    WzProperty::Vector { x, y } => {
                        assert_eq!(*x, 10);
                        assert_eq!(*y, 20);
                    }
                    _ => panic!("Expected Vector"),
                }
            }
            other => panic!("Expected Convex, got {:?}", other),
        }
    }

    // ── Sound ────────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_sound() {
        // Build a valid sound header: 51 bytes GUID data + 1 byte wav_format_len + wav_format
        let mut header = vec![0u8; 51]; // sound_header GUIDs
        header.push(18); // wav_format_len = 18 (WAVEFORMATEX base size)
        // WAVEFORMATEX: 18 bytes with cbSize=0 (extra_size at bytes[16..18])
        let mut wav = vec![0u8; 18];
        wav[16] = 0; // extra_size low
        wav[17] = 0; // extra_size high
        header.extend_from_slice(&wav);

        let sound = WzProperty::Sound {
            duration_ms: 1000,
            data: vec![0xFF, 0xFB, 0x90], // fake audio
            header: header.clone(),
        };
        let props = write_then_read(vec![("snd".into(), sound)]);
        match &props[0].1 {
            WzProperty::Sound {
                duration_ms, data, ..
            } => {
                assert_eq!(*duration_ms, 1000);
                assert_eq!(data, &[0xFF, 0xFB, 0x90]);
            }
            other => panic!("Expected Sound, got {:?}", other),
        }
    }

    // ── UOL ──────────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_uol() {
        let props = write_then_read(vec![("u".into(), WzProperty::Uol("../link".into()))]);
        assert_eq!(props[0].1.as_str(), Some("../link"));
    }

    // ── Lua ──────────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_lua() {
        let lua_data = vec![0x1B, 0x4C, 0x75, 0x61]; // fake lua bytecode
        let props =
            write_then_read(vec![("Script".into(), WzProperty::Lua(lua_data.clone()))]);
        assert_eq!(props.len(), 1);
        match &props[0].1 {
            WzProperty::Lua(data) => assert_eq!(data, &lua_data),
            other => panic!("Expected Lua, got {:?}", other),
        }
    }

    // ── Video ────────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_video() {
        let video_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];
        let video = WzProperty::Video {
            video_type: 2,
            properties: vec![("fps".into(), WzProperty::Int(30))],
            data_offset: 0,
            data_length: 0,
            mcv_header: None,
            video_data: Some(video_data.clone()),
        };
        let props = write_then_read(vec![("vid".into(), video)]);
        match &props[0].1 {
            WzProperty::Video {
                video_type,
                properties,
                video_data,
                ..
            } => {
                assert_eq!(*video_type, 2);
                assert_eq!(properties.len(), 1);
                assert_eq!(properties[0].1.as_int(), Some(30));
                assert_eq!(video_data.as_ref().unwrap(), &vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02]);
            }
            other => panic!("Expected Video, got {:?}", other),
        }
    }

    // ── Mixed property list ──────────────────────────────────────────

    #[test]
    fn test_roundtrip_mixed_properties() {
        let props = write_then_read(vec![
            ("null".into(), WzProperty::Null),
            ("short".into(), WzProperty::Short(7)),
            ("int".into(), WzProperty::Int(-200)),
            ("long".into(), WzProperty::Long(999_999_999)),
            ("float".into(), WzProperty::Float(1.5)),
            ("double".into(), WzProperty::Double(2.5)),
            ("str".into(), WzProperty::String("test".into())),
            ("vec".into(), WzProperty::Vector { x: 1, y: 2 }),
            ("uol".into(), WzProperty::Uol("path".into())),
        ]);
        assert_eq!(props.len(), 9);
        assert!(matches!(props[0].1, WzProperty::Null));
        assert_eq!(props[1].1.as_int(), Some(7));
        assert_eq!(props[2].1.as_int(), Some(-200));
        assert_eq!(props[3].1.as_int(), Some(999_999_999));
        assert!((props[4].1.as_float().unwrap() - 1.5).abs() < 0.01);
        assert_eq!(props[5].1.as_float(), Some(2.5));
        assert_eq!(props[6].1.as_str(), Some("test"));
    }

    // ── Empty property list ──────────────────────────────────────────

    #[test]
    fn test_roundtrip_empty() {
        let props = write_then_read(vec![]);
        assert!(props.is_empty());
    }

    // ── Nested SubProperty ───────────────────────────────────────────

    #[test]
    fn test_roundtrip_nested_sub() {
        let inner = WzProperty::SubProperty {
            properties: vec![("x".into(), WzProperty::Int(42))],
        };
        let outer = WzProperty::SubProperty {
            properties: vec![("inner".into(), inner)],
        };
        let props = write_then_read(vec![("outer".into(), outer)]);
        let outer_children = props[0].1.children().unwrap();
        assert_eq!(outer_children[0].0, "inner");
        let inner_children = outer_children[0].1.children().unwrap();
        assert_eq!(inner_children[0].0, "x");
        assert_eq!(inner_children[0].1.as_int(), Some(42));
    }
}
