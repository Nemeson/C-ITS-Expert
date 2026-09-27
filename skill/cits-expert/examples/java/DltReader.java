package cits;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Android & Java SE Link-Layer Dissector for C-ITS / V2X PCAP records.
 * Unwraps DLT 1 (Ethernet II), DLT 105 (IEEE 802.11), and DLT 127 (IEEE 802.11 Radiotap).
 */
public class DltReader {

    public static final int ETHERTYPE_GEONET = 0x8947;
    public static final byte[] LLC_SNAP_GEONET = new byte[] {
        (byte) 0xaa, (byte) 0xaa, (byte) 0x03, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x89, (byte) 0x47
    };

    private static final Set<Integer> KNOWN_BTP_PORTS = new HashSet<>(
        Arrays.asList(2001, 2002, 2003, 2004, 2006, 2007, 2008)
    );

    public static class UnwrappedFrame {
        public final int linkType;
        public final byte[] geonetPayload;
        public final Integer btpPort;
        public final boolean isQos;

        public UnwrappedFrame(int linkType, byte[] geonetPayload, Integer btpPort, boolean isQos) {
            this.linkType = linkType;
            this.geonetPayload = geonetPayload;
            this.btpPort = btpPort;
            this.isQos = isQos;
        }
    }

    public static UnwrappedFrame unwrap(byte[] rawBytes, int linkType) {
        if (rawBytes == null || rawBytes.length == 0) return null;

        if (linkType == 1) {
            return unwrapDlt1(rawBytes);
        } else if (linkType == 105) {
            return unwrapDlt105(rawBytes);
        } else if (linkType == 127) {
            return unwrapDlt127(rawBytes);
        }
        return null;
    }

    private static UnwrappedFrame unwrapDlt1(byte[] bytes) {
        if (bytes.length < 14) return null;
        ByteBuffer bb = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
        int ethertype = bb.getShort(12) & 0xFFFF;
        if (ethertype != ETHERTYPE_GEONET) return null;

        byte[] payload = Arrays.copyOfRange(bytes, 14, bytes.length);
        Integer btp = extractBtpPort(payload);
        return new UnwrappedFrame(1, payload, btp, false);
    }

    private static UnwrappedFrame unwrapDlt105(byte[] bytes) {
        return stripDot11AndLlc(bytes, 105);
    }

    private static UnwrappedFrame unwrapDlt127(byte[] bytes) {
        if (bytes.length < 4) return null;
        ByteBuffer bb = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        // Radiotap header length at bytes 2..3
        int rtLen = bb.getShort(2) & 0xFFFF;
        if (bytes.length < rtLen) return null;

        byte[] dot11 = Arrays.copyOfRange(bytes, rtLen, bytes.length);
        return stripDot11AndLlc(dot11, 127);
    }

    private static UnwrappedFrame stripDot11AndLlc(byte[] dot11, int linkType) {
        if (dot11.length < 24) return null;
        ByteBuffer bb = ByteBuffer.wrap(dot11).order(ByteOrder.LITTLE_ENDIAN);

        int fc = bb.getShort(0) & 0xFFFF;
        int frameType = (fc >> 2) & 0x03;
        int frameSubtype = (fc >> 4) & 0x0F;

        if (frameType != 2) return null; // Must be Data frame

        boolean isQos = (frameSubtype == 8);
        int macLen = isQos ? 26 : 24;

        if (dot11.length < macLen + 8) return null;

        // Verify LLC/SNAP: aa aa 03 00 00 00 89 47
        for (int i = 0; i < 8; i++) {
            if (dot11[macLen + i] != LLC_SNAP_GEONET[i]) return null;
        }

        byte[] payload = Arrays.copyOfRange(dot11, macLen + 8, dot11.length);
        Integer btp = extractBtpPort(payload);
        return new UnwrappedFrame(linkType, payload, btp, isQos);
    }

    private static Integer extractBtpPort(byte[] geonet) {
        if (geonet.length < 14) return null;
        ByteBuffer bb = ByteBuffer.wrap(geonet).order(ByteOrder.BIG_ENDIAN);

        int scanLimit = Math.min(geonet.length - 1, 64);
        for (int offset = 12; offset < scanLimit; offset++) {
            int port = bb.getShort(offset) & 0xFFFF;
            if (KNOWN_BTP_PORTS.contains(port)) {
                return port;
            }
        }
        return null;
    }
}
