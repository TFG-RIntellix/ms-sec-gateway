package es.NTTEnterprise.RIntellix.ms_sec_gateway.filters;

import java.util.concurrent.ConcurrentHashMap;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import es.NTTEnterprise.RIntellix.ms_sec_gateway.config.GatewaySecurityProperties;
import es.NTTEnterprise.RIntellix.ms_sec_gateway.error.GatewayErrorWriter;
import es.NTTEnterprise.RIntellix.ms_sec_gateway.utils.LogMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Lightweight in-memory (per-instance) token-bucket rate limiter.
 *
 * <p>
 * Keys buckets by the authenticated JWT subject, falling back to the client IP
 * for unauthenticated traffic. Suitable for a single-instance local TFG setup;
 * a Redis-backed {@code RequestRateLimiter} is the horizontal-scaling upgrade.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RateLimitFilter implements GlobalFilter, Ordered {

    public static final int ORDER = -150;

    private final GatewaySecurityProperties properties;
    private final GatewayErrorWriter errorWriter;

    private final ConcurrentHashMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();

    @Override
    public Mono<Void> filter(final ServerWebExchange exchange, final GatewayFilterChain chain) {
        final GatewaySecurityProperties.RateLimit config = properties.getRateLimit();
        if (!config.isEnabled()) {
            return chain.filter(exchange);
        }

        return exchange.getPrincipal()
                .map(java.security.Principal::getName)
                .defaultIfEmpty(clientKey(exchange))
                .flatMap(key -> {
                    final TokenBucket bucket = buckets.computeIfAbsent(key,
                            unused -> new TokenBucket(config.getRequestsPerMinute(), config.getBurstCapacity()));
                    if (bucket.tryConsume()) {
                        return chain.filter(exchange);
                    }
                    log.warn(LogMessage.FILTER_RATE_LIMITED, key);
                    return errorWriter.write(exchange, HttpStatus.TOO_MANY_REQUESTS, "RATE_LIMITED",
                            "Too many requests. Please slow down and try again shortly.");
                });
    }

    private String clientKey(final ServerWebExchange exchange) {
        if (exchange.getRequest().getRemoteAddress() != null
                && exchange.getRequest().getRemoteAddress().getAddress() != null) {
            return "ip:" + exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();
        }
        return "anonymous";
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    /**
     * Classic token bucket: {@code capacity} tokens refilled at
     * {@code requestsPerMinute / 60} tokens per second.
     */
    private static final class TokenBucket {

        private final double capacity;
        private final double refillPerSecond;
        private double tokens;
        private long lastRefillNanos;

        private TokenBucket(final int requestsPerMinute, final int burstCapacity) {
            this.capacity = (double) requestsPerMinute + burstCapacity;
            this.refillPerSecond = requestsPerMinute / 60.0;
            this.tokens = this.capacity;
            this.lastRefillNanos = System.nanoTime();
        }

        private synchronized boolean tryConsume() {
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
}
