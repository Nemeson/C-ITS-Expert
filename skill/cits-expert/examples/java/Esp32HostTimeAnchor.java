package cits;

/**
 * Android & Java SE Host Time Anchor for ESP32-C5 V2X Receiver.
 * Translates firmware boot-relative uptime into wall-clock Unix time and detects timer resets.
 */
public class Esp32HostTimeAnchor {

    public static final byte RSSI_NONE = -128; // INT8_MIN sentinel

    private Double anchorWall = null;
    private Double anchorFw = null;
    private Double lastFw = null;
    private int discontinuities = 0;

    public synchronized double computeHostTime(long fwSec, long fwUsec) {
        return computeHostTime(fwSec, fwUsec, System.currentTimeMillis() / 1000.0);
    }

    public synchronized double computeHostTime(long fwSec, long fwUsec, double currentWallTime) {
        double fwTime = ((double) fwSec) + (((double) fwUsec) / 1_000_000.0);

        if (anchorWall == null || anchorFw == null) {
            anchorWall = currentWallTime;
            anchorFw = fwTime;
            lastFw = fwTime;
            return currentWallTime;
        }

        double last = (lastFw != null) ? lastFw : fwTime;
        double delta = fwTime - last;

        // Discontinuity check: backward jump > 2s (reboot) or forward jump > 60s
        if (delta < -2.0 || delta > 60.0) {
            discontinuities++;
            anchorWall = currentWallTime;
            anchorFw = fwTime;
            lastFw = fwTime;
            return currentWallTime;
        }

        lastFw = fwTime;
        return anchorWall + (fwTime - anchorFw);
    }

    public static Integer parseRssi(byte rawRssi) {
        if (rawRssi == RSSI_NONE) {
            return null;
        }
        return (int) rawRssi;
    }

    public int getDiscontinuities() {
        return discontinuities;
    }
}
