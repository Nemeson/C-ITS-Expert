//! High-Performance Zero-Copy Link-Layer Dissector for C-ITS / V2X (Rust Core).
//!
//! Strips DLT 127 Radiotap, IEEE 802.11 QoS Data, and LLC/SNAP headers to yield GeoNetworking.

pub const ETHERTYPE_GEONET: u16 = 0x8947;
pub const LLC_SNAP_GEONET: &[u8; 8] = b"\xaa\xaa\x03\x00\x00\x00\x89\x47";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DissectedPacket<'a> {
    pub link_type: u32,
    pub geonet_payload: &'a [u8],
    pub btp_port: Option<u16>,
    pub is_qos: bool,
}

pub struct ZeroCopyDissector;

impl ZeroCopyDissector {
    /// Dissects a packet record according to its PCAP Link-Layer Type (DLT).
    pub fn dissect(input: &[u8], link_type: u32) -> Option<DissectedPacket<'_>> {
        match link_type {
            1 => Self::dissect_dlt1(input),
            105 => Self::dissect_dlt105(input),
            127 => Self::dissect_dlt127(input),
            _ => None,
        }
    }

    fn dissect_dlt1(input: &[u8]) -> Option<DissectedPacket<'_>> {
        if input.len() < 14 {
            return None;
        }
        let ethertype = u16::from_be_bytes([input[12], input[13]]);
        if ethertype != ETHERTYPE_GEONET {
            return None;
        }
        let payload = &input[14..];
        let btp_port = Self::extract_btp_port(payload);
        Some(DissectedPacket {
            link_type: 1,
            geonet_payload: payload,
            btp_port,
            is_qos: false,
        })
    }

    fn dissect_dlt105(input: &[u8]) -> Option<DissectedPacket<'_>> {
        Self::strip_dot11_and_llc(input, 105)
    }

    fn dissect_dlt127(input: &[u8]) -> Option<DissectedPacket<'_>> {
        if input.len() < 4 {
            return None;
        }
        // Radiotap header length: 16-bit little-endian at bytes 2..4
        let rt_len = u16::from_le_bytes([input[2], input[3]]) as usize;
        if input.len() < rt_len {
            return None;
        }
        let dot11_bytes = &input[rt_len..];
        Self::strip_dot11_and_llc(dot11_bytes, 127)
    }

    fn strip_dot11_and_llc(dot11: &[u8], link_type: u32) -> Option<DissectedPacket<'_>> {
        if dot11.len() < 24 {
            return None;
        }
        let fc = u16::from_le_bytes([dot11[0], dot11[1]]);
        let frame_type = (fc >> 2) & 0x03;
        let frame_subtype = (fc >> 4) & 0x0F;

        if frame_type != 2 {
            return None; // Only Data frames
        }

        let is_qos = frame_subtype == 8;
        let mac_header_len = if is_qos { 26 } else { 24 };

        if dot11.len() < mac_header_len + 8 {
            return None;
        }

        let llc_snap = &dot11[mac_header_len..mac_header_len + 8];
        if llc_snap != LLC_SNAP_GEONET {
            return None;
        }

        let payload = &dot11[mac_header_len + 8..];
        let btp_port = Self::extract_btp_port(payload);

        Some(DissectedPacket {
            link_type,
            geonet_payload: payload,
            btp_port,
            is_qos,
        })
    }

    fn extract_btp_port(geonet: &[u8]) -> Option<u16> {
        if geonet.len() < 12 {
            return None;
        }
        let known_ports = [2001u16, 2002, 2003, 2004, 2006, 2007, 2008];
        let scan_limit = (geonet.len() - 1).min(64);

        for offset in 12..scan_limit {
            let port = u16::from_be_bytes([geonet[offset], geonet[offset + 1]]);
            if known_ports.contains(&port) {
                return Some(port);
            }
        }
        None
    }
}
