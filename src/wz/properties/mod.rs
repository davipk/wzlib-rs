//! WZ property types — the value nodes in the WZ object tree.

use serde::{Deserialize, Serialize};

use crate::wz::mcv::McvHeader;
use crate::wz::types::WzPngFormat;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WzProperty {
    Null,           // 0x00
    Short(i16),     // 0x02
    Int(i32),       // 0x03
    Long(i64),      // 0x14
    Float(f32),     // 0x04
    Double(f64),    // 0x05
    String(String), // 0x08

    SubProperty {
        properties: Vec<(String, WzProperty)>,
    },

    Canvas {
        width: i32,
        height: i32,
        format: WzPngFormat,
        properties: Vec<(String, WzProperty)>,
        png_data: Vec<u8>, // raw compressed PNG, not yet decoded to pixels
    },

    Vector { x: i32, y: i32 },

    Convex {
        points: Vec<WzProperty>,
    },

    Sound {
        duration_ms: i32,
        data: Vec<u8>,
        header: Vec<u8>,
    },

    Uol(String),

    Lua(Vec<u8>),

    RawData {
        data: Vec<u8>,
    },

    Video {
        video_type: u8,
        properties: Vec<(String, WzProperty)>,
        data_offset: u64,
        data_length: u32,
        mcv_header: Option<McvHeader>,
    },
}

impl WzProperty {
    pub fn type_name(&self) -> &'static str {
        match self {
            WzProperty::Null => "Null",
            WzProperty::Short(_) => "Short",
            WzProperty::Int(_) => "Int",
            WzProperty::Long(_) => "Long",
            WzProperty::Float(_) => "Float",
            WzProperty::Double(_) => "Double",
            WzProperty::String(_) => "String",
            WzProperty::SubProperty { .. } => "SubProperty",
            WzProperty::Canvas { .. } => "Canvas",
            WzProperty::Vector { .. } => "Vector",
            WzProperty::Convex { .. } => "Convex",
            WzProperty::Sound { .. } => "Sound",
            WzProperty::Uol(_) => "UOL",
            WzProperty::Lua(_) => "Lua",
            WzProperty::RawData { .. } => "RawData",
            WzProperty::Video { .. } => "Video",
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            WzProperty::Short(v) => Some(*v as i64),
            WzProperty::Int(v) => Some(*v as i64),
            WzProperty::Long(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        match self {
            WzProperty::Float(v) => Some(*v as f64),
            WzProperty::Double(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            WzProperty::String(s) => Some(s),
            WzProperty::Uol(s) => Some(s),
            _ => None,
        }
    }

    pub fn children(&self) -> Option<&[(String, WzProperty)]> {
        match self {
            WzProperty::SubProperty { properties, .. } => Some(properties),
            WzProperty::Canvas { properties, .. } => Some(properties),
            WzProperty::Video { properties, .. } => Some(properties),
            _ => None,
        }
    }

    pub fn get(&self, name: &str) -> Option<&WzProperty> {
        self.children()?
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, p)| p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── type_name ──────────────────────────────────────────────────

    #[test]
    fn test_type_name_all_variants() {
        assert_eq!(WzProperty::Null.type_name(), "Null");
        assert_eq!(WzProperty::Short(0).type_name(), "Short");
        assert_eq!(WzProperty::Int(0).type_name(), "Int");
        assert_eq!(WzProperty::Long(0).type_name(), "Long");
        assert_eq!(WzProperty::Float(0.0).type_name(), "Float");
        assert_eq!(WzProperty::Double(0.0).type_name(), "Double");
        assert_eq!(WzProperty::String("".into()).type_name(), "String");
        assert_eq!(
            WzProperty::SubProperty {
                properties: vec![]
            }
            .type_name(),
            "SubProperty"
        );
        assert_eq!(
            WzProperty::Canvas {
                width: 0,
                height: 0,
                format: WzPngFormat::Bgra8888,
                properties: vec![],
                png_data: vec![]
            }
            .type_name(),
            "Canvas"
        );
        assert_eq!(WzProperty::Vector { x: 0, y: 0 }.type_name(), "Vector");
        assert_eq!(WzProperty::Convex { points: vec![] }.type_name(), "Convex");
        assert_eq!(
            WzProperty::Sound {
                duration_ms: 0,
                data: vec![],
                header: vec![]
            }
            .type_name(),
            "Sound"
        );
        assert_eq!(WzProperty::Uol("".into()).type_name(), "UOL");
        assert_eq!(WzProperty::Lua(vec![]).type_name(), "Lua");
        assert_eq!(
            WzProperty::RawData {
                data: vec![]
            }
            .type_name(),
            "RawData"
        );
        assert_eq!(
            WzProperty::Video {
                video_type: 0,
                properties: vec![],
                data_offset: 0,
                data_length: 0,
                mcv_header: None,
            }
            .type_name(),
            "Video"
        );
    }

    // ── as_int ─────────────────────────────────────────────────────

    #[test]
    fn test_as_int_short() {
        assert_eq!(WzProperty::Short(42).as_int(), Some(42));
        assert_eq!(WzProperty::Short(-1).as_int(), Some(-1));
    }

    #[test]
    fn test_as_int_int() {
        assert_eq!(WzProperty::Int(100_000).as_int(), Some(100_000));
        assert_eq!(WzProperty::Int(-1).as_int(), Some(-1));
    }

    #[test]
    fn test_as_int_long() {
        assert_eq!(WzProperty::Long(i64::MAX).as_int(), Some(i64::MAX));
        assert_eq!(WzProperty::Long(i64::MIN).as_int(), Some(i64::MIN));
    }

    #[test]
    fn test_as_int_returns_none_for_non_integers() {
        assert_eq!(WzProperty::Null.as_int(), None);
        assert_eq!(WzProperty::Float(1.0).as_int(), None);
        assert_eq!(WzProperty::String("42".into()).as_int(), None);
    }

    // ── as_float ───────────────────────────────────────────────────

    #[test]
    fn test_as_float_float() {
        let v = WzProperty::Float(1.5).as_float().unwrap();
        assert!((v - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_as_float_double() {
        assert_eq!(WzProperty::Double(2.5).as_float(), Some(2.5));
    }

    #[test]
    fn test_as_float_returns_none_for_non_floats() {
        assert_eq!(WzProperty::Int(1).as_float(), None);
        assert_eq!(WzProperty::Null.as_float(), None);
    }

    // ── as_str ─────────────────────────────────────────────────────

    #[test]
    fn test_as_str_string() {
        assert_eq!(WzProperty::String("hello".into()).as_str(), Some("hello"));
    }

    #[test]
    fn test_as_str_uol() {
        assert_eq!(WzProperty::Uol("../link".into()).as_str(), Some("../link"));
    }

    #[test]
    fn test_as_str_returns_none_for_non_strings() {
        assert_eq!(WzProperty::Int(1).as_str(), None);
        assert_eq!(WzProperty::Null.as_str(), None);
    }

    // ── children ───────────────────────────────────────────────────

    #[test]
    fn test_children_sub_property() {
        let prop = WzProperty::SubProperty {
            properties: vec![("a".into(), WzProperty::Int(1))],
        };
        let kids = prop.children().unwrap();
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].0, "a");
    }

    #[test]
    fn test_children_canvas() {
        let prop = WzProperty::Canvas {
            width: 1,
            height: 1,
            format: WzPngFormat::Bgra8888,
            properties: vec![("origin".into(), WzProperty::Vector { x: 0, y: 0 })],
            png_data: vec![],
        };
        assert_eq!(prop.children().unwrap().len(), 1);
    }

    #[test]
    fn test_children_video() {
        let prop = WzProperty::Video {
            video_type: 0,
            properties: vec![("fps".into(), WzProperty::Int(30))],
            data_offset: 0,
            data_length: 0,
            mcv_header: None,
        };
        assert_eq!(prop.children().unwrap().len(), 1);
    }

    #[test]
    fn test_children_returns_none_for_leaf() {
        assert!(WzProperty::Null.children().is_none());
        assert!(WzProperty::Int(1).children().is_none());
        assert!(WzProperty::String("x".into()).children().is_none());
        assert!(WzProperty::Vector { x: 0, y: 0 }.children().is_none());
    }

    // ── get ────────────────────────────────────────────────────────

    #[test]
    fn test_get_finds_child() {
        let prop = WzProperty::SubProperty {
            properties: vec![
                ("x".into(), WzProperty::Int(10)),
                ("y".into(), WzProperty::Int(20)),
            ],
        };
        assert_eq!(prop.get("x").unwrap().as_int(), Some(10));
        assert_eq!(prop.get("y").unwrap().as_int(), Some(20));
    }

    #[test]
    fn test_get_returns_none_for_missing() {
        let prop = WzProperty::SubProperty {
            properties: vec![("x".into(), WzProperty::Int(10))],
        };
        assert!(prop.get("z").is_none());
    }

    #[test]
    fn test_get_returns_none_on_leaf() {
        assert!(WzProperty::Int(1).get("anything").is_none());
    }
}
