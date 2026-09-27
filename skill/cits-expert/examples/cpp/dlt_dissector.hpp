#pragma once

/**
 * Modern C++17 Zero-Copy Link-Layer Dissector for C-ITS / V2X Packets.
 * Handles DLT 1 (Ethernet II), DLT 105 (IEEE 802.11), and DLT 127 (IEEE 802.11 Radiotap).
 */

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string_view>
#include <array>
#include <algorithm>

namespace cits {

constexpr uint16_t ETHERTYPE_GEONET = 0x8947;
constexpr std::array<uint8_t, 8> LLC_SNAP_GEONET = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x89, 0x47};

struct DissectedPacket {
    uint32_t link_type{0};
    const uint8_t* geonet_data{nullptr};
    size_t geonet_len{0};
    std::optional<uint16_t> btp_port{std::nullopt};
    bool is_qos{false};
};

class DltDissector {
public:
    static std::optional<DissectedPacket> dissect(const uint8_t* data, size_t len, uint32_t link_type) {
        if (!data || len == 0) return std::nullopt;
        switch (link_type) {
            case 1:   return dissect_dlt1(data, len);
            case 105: return dissect_dlt105(data, len);
            case 127: return dissect_dlt127(data, len);
            default:  return std::nullopt;
        }
    }

private:
    static std::optional<DissectedPacket> dissect_dlt1(const uint8_t* data, size_t len) {
        if (len < 14) return std::nullopt;
        uint16_t ethertype = (static_cast<uint16_t>(data[12]) << 8) | data[13];
        if (ethertype != ETHERTYPE_GEONET) return std::nullopt;

        const uint8_t* payload = data + 14;
        size_t payload_len = len - 14;
        auto btp = extract_btp_port(payload, payload_len);

        return DissectedPacket{1, payload, payload_len, btp, false};
    }

    static std::optional<DissectedPacket> dissect_dlt105(const uint8_t* data, size_t len) {
        return strip_dot11_and_llc(data, len, 105);
    }

    static std::optional<DissectedPacket> dissect_dlt127(const uint8_t* data, size_t len) {
        if (len < 4) return std::nullopt;
        // Radiotap header length is a 16-bit little-endian value at bytes 2..3
        uint16_t rt_len = static_cast<uint16_t>(data[2]) | (static_cast<uint16_t>(data[3]) << 8);
        if (len < rt_len) return std::nullopt;

        return strip_dot11_and_llc(data + rt_len, len - rt_len, 127);
    }

    static std::optional<DissectedPacket> strip_dot11_and_llc(const uint8_t* dot11, size_t len, uint32_t link_type) {
        if (len < 24) return std::nullopt;

        uint16_t fc = static_cast<uint16_t>(dot11[0]) | (static_cast<uint16_t>(dot11[1]) << 8);
        uint8_t frame_type = (fc >> 2) & 0x03;
        uint8_t frame_subtype = (fc >> 4) & 0x0F;

        if (frame_type != 2) return std::nullopt; // Only Data frames

        bool is_qos = (frame_subtype == 8);
        size_t mac_header_len = is_qos ? 26 : 24;

        if (len < mac_header_len + 8) return std::nullopt;

        for (size_t i = 0; i < 8; ++i) {
            if (dot11[mac_header_len + i] != LLC_SNAP_GEONET[i]) return std::nullopt;
        }

        const uint8_t* payload = dot11 + mac_header_len + 8;
        size_t payload_len = len - (mac_header_len + 8);
        auto btp = extract_btp_port(payload, payload_len);

        return DissectedPacket{link_type, payload, payload_len, btp, is_qos};
    }

    static std::optional<uint16_t> extract_btp_port(const uint8_t* geonet, size_t len) {
        if (len < 14) return std::nullopt;
        constexpr std::array<uint16_t, 7> known_ports = {2001, 2002, 2003, 2004, 2006, 2007, 2008};
        size_t scan_limit = std::min(len - 1, static_cast<size_t>(64));

        for (size_t offset = 12; offset < scan_limit; ++offset) {
            uint16_t port = (static_cast<uint16_t>(geonet[offset]) << 8) | geonet[offset + 1];
            for (uint16_t kp : known_ports) {
                if (port == kp) return port;
            }
        }
        return std::nullopt;
    }
};

} // namespace cits
