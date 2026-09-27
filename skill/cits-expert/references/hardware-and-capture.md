# Hardware Sniffing & Field Capture Reference

## 1. Waveshare ESP32-C5 5.9 GHz V2X Sniffer

The Waveshare ESP32-C5 development board features dual-band 2.4/5 GHz Wi-Fi 6 hardware capable of promiscuous packet capture on 5.9 GHz ITS-G5 (IEEE 802.11p) channel 180 (5900 MHz):

### 1.1 Dual USB Port Identification
The board provides two physical USB-C ports with distinct functions and chipsets:

| Port | Chipset / Endpoint | USB VID / PID | Purpose in Field Work |
| :--- | :--- | :--- | :--- |
| **Native USB** | ESP32-C5 USB-JTAG | `0x303A : 0x1001` | **Live V2X Sniffing Data Stream** (`ITS5`/`ITS6` binary frames) |
| **UART Port** | CH343 USB-Serial | `0x1A86 : 0x55D3` | **Firmware flashing & Serial Console / Debugging** |

> [!IMPORTANT]
> If a technician plugs into the CH343 port instead of the Native USB port, the application will receive console text logs rather than the binary packet stream. Detect VID/PID automatically and prompt the user to switch ports if needed.

### 1.2 Binary Framing: `ITS5` vs. `ITS6`
The receiver firmware sends captured frames prefixed with a binary header:

```
ITS5 (14 Bytes):
+--------------------+--------------------+--------------------+--------------------+
| Magic: "ITS5" (4B) | sec (4B uint32_le) | usec (4B uint32_le)| len (2B uint16_le) |
+--------------------+--------------------+--------------------+--------------------+
Followed by <len> bytes of raw 802.11 frame.

ITS6 (15 Bytes with RSSI):
+--------------------+--------------------+--------------------+--------------------+-----------+
| Magic: "ITS6" (4B) | sec (4B uint32_le) | usec (4B uint32_le)| len (2B uint16_le) | rssi (1B) |
+--------------------+--------------------+--------------------+--------------------+-----------+
Followed by <len> bytes of raw 802.11 frame.
```

- **RSSI Sentinel:** If `rssi == -128` (`INT8_MIN`), no signal strength was measured (`rssi_dbm = None`).
- **Lookahead Framing:** Always verify that offset `header_len + len` contains the next valid magic before accepting an unverified frame length.

### 1.3 Host Wall-Clock Anchoring
- The ESP32-C5 firmware maintains an internal boot timer (`rx_ctrl.timestamp`). It does NOT run an SNTP client.
- `sec` and `usec` represent **uptime since boot**, NOT Unix epoch time.
- **Rule:** The host must anchor `SystemTime::now()` on the first received frame:
  $$\text{host\_time} = \text{anchor\_wall\_time} + (\text{fw\_time} - \text{anchor\_fw\_time})$$
- Reset the anchor if $\Delta t < -2.0$ s (reboot/counter reset) or $\Delta t > 60.0$ s.

---

## 2. Linux-based RSU Live Capture via SSH

Roadside Units (RSUs) operating in the field can be tapped live over SSH:
- Command: `sudo tcpdump -i <interface> -nn -s 4096 -U ether proto 0x8947 -w -`
- **Critical Flag `-U`:** The `-U` (packet-buffered) flag is strictly required. Without it, `tcpdump` buffers data into 4 KB chunks, causing the real-time live stream to stall.
- **3-Mechanism Capture Integrity:**
  1. **Graceful SIGINT:** Send SIGINT to remote tcpdump before terminating SSH to ensure buffers flush cleanly.
  2. **Post-Capture Repair:** If a stream is interrupted abruptly, truncate the PCAP at the boundary of the last complete record header.
  3. **Atomic Write:** Record to `<filename>.pcap.tmp` and rename to `.pcap` only upon clean completion.
