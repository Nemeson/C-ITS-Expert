//! ESP32-C5 ITS5 / ITS6 Framing Parser & Host Time Anchor (Rust Core).

use std::time::{SystemTime, UNIX_EPOCH};

pub const ITS5_MAGIC: &[u8; 4] = b"ITS5";
pub const ITS6_MAGIC: &[u8; 4] = b"ITS6";
pub const RSSI_NONE: i8 = -128; // INT8_MIN sentinel

#[derive(Debug, Clone, PartialEq)]
pub struct Esp32V2xFrame {
    pub host_timestamp_secs: f64,
    pub fw_sec: u32,
    pub fw_usec: u32,
    pub rssi_dbm: Option<i8>,
    pub payload: Vec<u8>,
}

pub struct Esp32FramingEngine {
    anchor_wall: Option<f64>,
    anchor_fw: Option<f64>,
    last_fw: Option<f64>,
    pub discontinuities: usize,
}

impl Default for Esp32FramingEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Esp32FramingEngine {
    pub fn new() -> Self {
        Self {
            anchor_wall: None,
            anchor_fw: None,
            last_fw: None,
            discontinuities: 0,
        }
    }

    /// Attempts to parse an ITS5 or ITS6 frame from a stream buffer.
    /// Returns Ok(Some((frame, consumed_bytes))) if a frame is complete.
    pub fn parse_frame(&mut self, buffer: &[u8]) -> Option<(Esp32V2xFrame, usize)> {
        if buffer.len() < 14 {
            return None;
        }

        let is_its5 = &buffer[0..4] == ITS5_MAGIC;
        let is_its6 = &buffer[0..4] == ITS6_MAGIC;

        if !is_its5 && !is_its6 {
            return None;
        }

        let header_len = if is_its6 { 15 } else { 14 };
        if buffer.len() < header_len {
            return None;
        }

        let fw_sec = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        let fw_usec = u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);
        let payload_len = u16::from_le_bytes([buffer[12], buffer[13]]) as usize;

        let total_frame_len = header_len + payload_len;
        if buffer.len() < total_frame_len {
            return None; // Wait for more bytes
        }

        // Lookahead verification: if extra bytes exist, verify next magic or buffer boundary
        if buffer.len() >= total_frame_len + 4 {
            let next_magic = &buffer[total_frame_len..total_frame_len + 4];
            if next_magic != ITS5_MAGIC && next_magic != ITS6_MAGIC {
                // False magic collision or misaligned buffer
                return None;
            }
        }

        let rssi_dbm = if is_its6 {
            let raw_rssi = buffer[14] as i8;
            if raw_rssi == RSSI_NONE {
                None
            } else {
                Some(raw_rssi)
            }
        } else {
            None
        };

        let payload = buffer[header_len..total_frame_len].to_vec();
        let host_ts = self.compute_host_time(fw_sec, fw_usec);

        Some((
            Esp32V2xFrame {
                host_timestamp_secs: host_ts,
                fw_sec,
                fw_usec,
                rssi_dbm,
                payload,
            },
            total_frame_len,
        ))
    }

    fn compute_host_time(&mut self, fw_sec: u32, fw_usec: u32) -> f64 {
        let fw_time = (fw_sec as f64) + ((fw_usec as f64) / 1_000_000.0);
        let now_wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        if self.anchor_wall.is_none() || self.anchor_fw.is_none() {
            self.anchor_wall = Some(now_wall);
            self.anchor_fw = Some(fw_time);
            self.last_fw = Some(fw_time);
            return now_wall;
        }

        let last = self.last_fw.unwrap_or(fw_time);
        let delta = fw_time - last;

        // Discontinuity check: >2s backward (reset) or >60s forward
        if delta < -2.0 || delta > 60.0 {
            self.discontinuities += 1;
            self.anchor_wall = Some(now_wall);
            self.anchor_fw = Some(fw_time);
            self.last_fw = Some(fw_time);
            return now_wall;
        }

        self.last_fw = Some(fw_time);
        self.anchor_wall.unwrap() + (fw_time - self.anchor_fw.unwrap())
    }
}
