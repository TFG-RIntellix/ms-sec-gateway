package es.NTTEnterprise.RIntellix.ms_sec_gateway.filters;

import java.security.Principal;

import java.util.concurrent.ConcurrentHashMap;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import es.NTTEnterprise.RIntellix.ms_sec_gateway.config.GatewaySecurityProperties;
import es.NTTEnterprise.RIntellix.ms_sec_gateway.config.RateLimit;
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
/**
 * Core component: RateLimitFilter.
 * Encapsulates the logic and responsibilities assigned to this element
 * within the Hexagonal Architecture, ensuring separation of concerns.
 *
 * @author Lucía Fernández Mancebo
 * @date 28/07/2026
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
        final RateLimit config = properties.getRateLimit();
        if (!config.isEnabled()) {
            return chain.filter(exchange);
        }

        return exchange.getPrincipal()
                .map(Principal::getName)
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
}
