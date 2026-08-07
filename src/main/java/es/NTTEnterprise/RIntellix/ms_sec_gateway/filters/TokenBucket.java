package es.NTTEnterprise.RIntellix.ms_sec_gateway.filters;

/**
 * Classic token bucket: {@code capacity} tokens refilled at
 * {@code requestsPerMinute / 60} tokens per second.
 * 
 * @author Lucía Fernández Mancebo
 * @date 28/07/2026
 */
class TokenBucket {

    private final double capacity;
    private final double refillPerSecond;
    private double tokens;
    private long lastRefillNanos;

    TokenBucket(final int requestsPerMinute, final int burstCapacity) {
        this.capacity = (double) requestsPerMinute + burstCapacity;
        this.refillPerSecond = requestsPerMinute / 60.0;
        this.tokens = this.capacity;
        this.lastRefillNanos = System.nanoTime();
    }

    synchronized boolean tryConsume() {
        refill();
        if (tokens >= 1.0) {
            tokens -= 1.0;
            return true;
        }
        return false;
    }

    private void refill() {
        final long now = System.nanoTime();
        final double elapsedSeconds = (now - lastRefillNanos) / 1_000_000_000.0;
        if (elapsedSeconds <= 0) {
            return;
        }
        tokens = Math.min(capacity, tokens + elapsedSeconds * refillPerSecond);
        lastRefillNanos = now;
    }
}
