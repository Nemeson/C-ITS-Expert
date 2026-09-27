/**
 * Vanilla JavaScript DLT Unwrapper & Link-Layer Dissector for Node.js and Browser environments.
 * Handles DLT 1 (Ethernet II), DLT 105 (IEEE 802.11), and DLT 127 (IEEE 802.11 Radiotap).
 */

class DltReader {
  /**
   * Unwraps packet bytes according to its PCAP Data Link Type.
   * @param {Uint8Array} rawBytes
   * @param {number} linkType
   * @returns {{linkType: number, geonetPayload: Uint8Array, btpPort: number | null, isQos: boolean} | null}
   */
  static unwrap(rawBytes, linkType) {
    if (linkType === 1) {
      return this._unwrapDlt1(rawBytes);
    } else if (linkType === 105) {
      return this._unwrapDlt105(rawBytes);
    } else if (linkType === 127) {
      return this._unwrapDlt127(rawBytes);
    }
    return null;
  }

  static _unwrapDlt1(bytes) {
    if (bytes.length < 14) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const ethertype = view.getUint16(12, false); // Big-Endian
    if (ethertype !== 0x8947) return null;

    const payload = bytes.subarray(14);
    const btpPort = this._extractBtpPort(payload);
    return { linkType: 1, geonetPayload: payload, btpPort, isQos: false };
  }

  static _unwrapDlt105(bytes) {
    return this._stripDot11AndLlc(bytes, 105);
  }

  static _unwrapDlt127(bytes) {
    if (bytes.length < 4) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    // Radiotap header length at bytes 2..4 (Little-Endian uint16)
    const rtLen = view.getUint16(2, true);
    if (bytes.length < rtLen) return null;

    const dot11 = bytes.subarray(rtLen);
    return this._stripDot11AndLlc(dot11, 127);
  }

  static _stripDot11AndLlc(dot11, linkType) {
    if (dot11.length < 24) return null;
    const view = new DataView(dot11.buffer, dot11.byteOffset, dot11.byteLength);

    const fc = view.getUint16(0, true);
    const frameType = (fc >> 2) & 0x03;
    const frameSubtype = (fc >> 4) & 0x0f;

    if (frameType !== 2) return null; // Must be Data Frame

    const isQos = frameSubtype === 8;
    const macLen = isQos ? 26 : 24;

    if (dot11.length < macLen + 8) return null;

    // Verify LLC/SNAP: aa aa 03 00 00 00 89 47
    const llcExpected = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x89, 0x47];
    for (let i = 0; i < 8; i++) {
      if (dot11[macLen + i] !== llcExpected[i]) return null;
    }

    const payload = dot11.subarray(macLen + 8);
    const btpPort = this._extractBtpPort(payload);

    return { linkType, geonetPayload: payload, btpPort, isQos };
  }

  static _extractBtpPort(geonet) {
    if (geonet.length < 14) return null;
    const view = new DataView(geonet.buffer, geonet.byteOffset, geonet.byteLength);
    const knownPorts = new Set([2001, 2002, 2003, 2004, 2006, 2007, 2008]);

    const limit = Math.min(geonet.length - 2, 64);
    for (let offset = 12; offset < limit; offset++) {
      const port = view.getUint16(offset, false);
      if (knownPorts.has(port)) return port;
    }
    return null;
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { DltReader };
}
