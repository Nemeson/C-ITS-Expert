#pragma once

/**
 * Modern C++17 ESP32-C5 ITS5 / ITS6 Framing Parser & Host Time Anchor.
 */

#include <cstdint>
#include <cstddef>
#include <optional>
#include <vector>
#include <chrono>
#include <cstring>

namespace cits {

constexpr int8_t RSSI_NONE = -128; // INT8_MIN sentinel

struct Esp32V2xFrame {
    double host_timestamp_secs{0.0};
    uint32_t fw_sec{0};
    uint32_t fw_usec{0};
    std::optional<int8_t> rssi_dbm{std::nullopt};
    std::vector<uint8_t> payload;
};

class Esp32FramingEngine {
public:
    Esp32FramingEngine() = default;

    std::optional<std::pair<Esp32V2xFrame, size_t>> parse_frame(const uint8_t* buffer, size_t len) {
        if (!buffer || len < 14) return std::nullopt;

        bool is_its5 = (std::memcmp(buffer, "ITS5", 4) == 0);
        bool is_its6 = (std::memcmp(buffer, "ITS6", 4) == 0);

        if (!is_its5 && !is_its6) return std::nullopt;

        size_t header_len = is_its6 ? 15 : 14;
        if (len < header_len) return std::nullopt;

        uint32_t fw_sec = static_cast<uint32_t>(buffer[4]) |
                          (static_cast<uint32_t>(buffer[5]) << 8) |
                          (static_cast<uint32_t>(buffer[6]) << 16) |
                          (static_cast<uint32_t>(buffer[7]) << 24);

        uint32_t fw_usec = static_cast<uint32_t>(buffer[8]) |
                           (static_cast<uint32_t>(buffer[9]) << 8) |
                           (static_cast<uint32_t>(buffer[10]) << 16) |
                           (static_cast<uint32_t>(buffer[11]) << 24);

        uint16_t payload_len = static_cast<uint16_t>(buffer[12]) |
                               (static_cast<uint16_t>(buffer[13]) << 8);

        size_t total_frame_len = header_len + payload_len;
        if (len < total_frame_len) return std::nullopt;

        // Lookahead verification: if bytes follow, verify next magic
        if (len >= total_frame_len + 4) {
            bool next_its5 = (std::memcmp(buffer + total_frame_len, "ITS5", 4) == 0);
            bool next_its6 = (std::memcmp(buffer + total_frame_len, "ITS6", 4) == 0);
            if (!next_its5 && !next_its6) return std::nullopt;
        }

        std::optional<int8_t> rssi = std::nullopt;
        if (is_its6) {
            int8_t raw = static_cast<int8_t>(buffer[14]);
            if (raw != RSSI_NONE) {
                rssi = raw;
            }
        }

        std::vector<uint8_t> payload(buffer + header_len, buffer + total_frame_len);
        double host_ts = compute_host_time(fw_sec, fw_usec);

        return std::make_pair(
            Esp32V2xFrame{host_ts, fw_sec, fw_usec, rssi, std::move(payload)},
            total_frame_len
        );
    }

    size_t get_discontinuities() const { return discontinuities_; }

private:
    std::optional<double> anchor_wall_{std::nullopt};
    std::optional<double> anchor_fw_{std::nullopt};
    std::optional<double> last_fw_{std::nullopt};
    size_t discontinuities_{0};

    double compute_host_time(uint32_t fw_sec, uint32_t fw_usec) {
        double fw_time = static_cast<double>(fw_sec) + (static_cast<double>(fw_usec) / 1000000.0);
        auto now = std::chrono::system_clock::now().time_since_epoch();
        double now_wall = std::chrono::duration<double>(now).count();

        if (!anchor_wall_ || !anchor_fw_) {
            anchor_wall_ = now_wall;
            anchor_fw_ = fw_time;
            last_fw_ = fw_time;
            return now_wall;
        }

        double last = last_fw_.value_or(fw_time);
        double delta = fw_time - last;

        if (delta < -2.0 || delta > 60.0) {
            discontinuities_++;
            anchor_wall_ = now_wall;
            anchor_fw_ = fw_time;
            last_fw_ = fw_time;
            return now_wall;
        }

        last_fw_ = fw_time;
        return anchor_wall_.value() + (fw_time - anchor_fw_.value());
    }
};

} // namespace cits
