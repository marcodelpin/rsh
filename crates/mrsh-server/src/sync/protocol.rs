//! Wire-protocol helpers shared by all server sync handlers:
//! type conversions between `protocol` and `delta`, and gzip codec.

use mrsh_core::protocol;
use mrsh_transfer::delta;

// ── Walk wire format ───────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct WalkEntry {
    #[serde(rename = "p")]
    pub(super) path: String,
    #[serde(rename = "s")]
    pub(super) size: i64,
    #[serde(rename = "m", default, skip_serializing_if = "is_zero_i64")]
    pub(super) mtime: i64,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

// ── Type conversion helpers ────────────────────────────────────

pub(super) fn convert_sigs_from_proto(sigs: &[protocol::BlockSig]) -> Vec<delta::BlockSig> {
    sigs.iter()
        .map(|s| delta::BlockSig {
            index: s.index as usize,
            weak: s.weak,
            strong: s.strong.clone(),
        })
        .collect()
}

pub(super) fn convert_sigs_to_proto(sigs: &[delta::BlockSig]) -> Vec<protocol::BlockSig> {
    sigs.iter()
        .map(|s| protocol::BlockSig {
            index: s.index as i32,
            weak: s.weak,
            strong: s.strong.clone(),
        })
        .collect()
}

pub(super) fn convert_delta_from_proto(ops: &[protocol::DeltaOp]) -> Vec<delta::DeltaOp> {
    ops.iter()
        .map(|op| delta::DeltaOp {
            op_type: op.op_type.clone(),
            index: op.index.unwrap_or(0) as usize,
            data: op.data.clone().unwrap_or_default(),
        })
        .collect()
}

pub(super) fn convert_delta_to_proto(ops: &[delta::DeltaOp]) -> Vec<protocol::DeltaOp> {
    ops.iter()
        .map(|op| protocol::DeltaOp {
            op_type: op.op_type.clone(),
            index: if op.op_type == "match" {
                Some(op.index as i32)
            } else {
                None
            },
            data: if op.data.is_empty() {
                None
            } else {
                Some(op.data.clone())
            },
        })
        .collect()
}

// ── Compression helpers ────────────────────────────────────────

pub(super) fn gzip_compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap_or_default();
    encoder.finish().unwrap_or_default()
}

pub(super) fn gzip_decompress(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    // Check for gzip magic bytes
    if data.len() < 2 || data[0] != 0x1f || data[1] != 0x8b {
        return None;
    }
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_roundtrip() {
        let data = b"test data for compression";
        let compressed = gzip_compress(data);
        let decompressed = gzip_decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn gzip_decompress_non_gzip() {
        assert!(gzip_decompress(b"not gzip").is_none());
    }
}
