package es.NTTEnterprise.RIntellix.ms_sec_gateway.filters;

import java.util.List;
import java.util.Map;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import es.NTTEnterprise.RIntellix.ms_sec_gateway.config.GatewaySecurityProperties;
import es.NTTEnterprise.RIntellix.ms_sec_gateway.config.Limits;
import es.NTTEnterprise.RIntellix.ms_sec_gateway.error.GatewayErrorWriter;
import es.NTTEnterprise.RIntellix.ms_sec_gateway.security.AttackDetector;
import es.NTTEnterprise.RIntellix.ms_sec_gateway.utils.LogMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Cheap, synchronous request-hardening checks performed before the body is read:
 * URL length, header count, path traversal, declared payload size, and NoSQL/XSS
 * scanning of the query string and path.
 */
/**
 * Core component: RequestGuardFilter.
 * Encapsulates the logic and responsibilities assigned to this element
 * within the Hexagonal Architecture, ensuring separation of concerns.
 *
 * @author Lucía Fernández Mancebo
 * @date 28/07/2026
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RequestGuardFilter implements GlobalFilter, Ordered {

    public static final int ORDER = -120;

    private static final List<String> TRAVERSAL_MARKERS = List.of("..", "%2e%2e", "%252e", "\0", "%00");

    private final GatewaySecurityProperties properties;
    private final AttackDetector attackDetector;
    private final GatewayErrorWriter errorWriter;

    @Override
    public Mono<Void> filter(final ServerWebExchange exchange, final GatewayFilterChain chain) {
        final ServerHttpRequest request = exchange.getRequest();
        final Limits limits = properties.getLimits();

        // 1. URL length
        final String uri = request.getURI().toString();
        if (uri.length() > limits.getMaxUrlLength()) {
            log.warn(LogMessage.FILTER_URL_TOO_LONG, uri.length(), limits.getMaxUrlLength());
            return errorWriter.write(exchange, HttpStatus.URI_TOO_LONG, "URL_TOO_LONG",
                    "Request URL exceeds the maximum allowed length.");
        }

        // 2. Header count
        final int headerCount = request.getHeaders().size();
        if (headerCount > limits.getMaxHeaderCount()) {
            log.warn(LogMessage.FILTER_TOO_MANY_HEADERS, headerCount, limits.getMaxHeaderCount());
            return errorWriter.write(exchange, HttpStatus.BAD_REQUEST, "TOO_MANY_HEADERS",
                    "Request carries too many headers.");
        }

        // 3. Path traversal
        final String rawPath = request.getURI().getRawPath().toLowerCase();
        for (final String marker : TRAVERSAL_MARKERS) {
            if (rawPath.contains(marker)) {
                log.warn(LogMessage.FILTER_PATH_TRAVERSAL_BLOCKED, rawPath);
                return errorWriter.write(exchange, HttpStatus.BAD_REQUEST, "PATH_TRAVERSAL_BLOCKED",
                        "The request path contains an illegal sequence.");
            }
        }

        // 4. Declared payload size (fast pre-check; the body filter enforces the actual
        // size)
        final long contentLength = request.getHeaders().getContentLength();
        if (contentLength > limits.getMaxBodyBytes()) {
            log.warn(LogMessage.FILTER_PAYLOAD_TOO_LARGE, request.getMethod(), request.getPath().value(),
                    contentLength, limits.getMaxBodyBytes());
            return errorWriter.write(exchange, HttpStatus.PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE",
                    "Request body exceeds the maximum allowed size.");
        }

        // 5. NoSQL / XSS scan of the query string and path (if enabled)
        if (properties.getInjection().isEnabled()) {
            final String reason = scanQueryAndPath(exchange);
            if (reason != null) {
                log.warn(LogMessage.FILTER_NOSQL_BLOCKED, request.getMethod(), request.getPath().value(),
                        "query/path", reason);
                return errorWriter.write(exchange, HttpStatus.BAD_REQUEST, "INJECTION_BLOCKED",
                        "The request contains a potentially malicious query or path.");
            }
        }

        return chain.filter(exchange);
    }

    private String scanQueryAndPath(final ServerWebExchange exchange) {
        for (final Map.Entry<String, List<String>> param : exchange.getRequest().getQueryParams().entrySet()) {
            final String keyReason = attackDetector.scanKey(param.getKey());
            if (keyReason != null) {
                return keyReason;
            }
            for (final String value : param.getValue()) {
                final String valueReason = attackDetector.scanValue(value);
                if (valueReason != null) {
                    return valueReason;
                }
            }
        }
        return attackDetector.scanValue(exchange.getRequest().getURI().getRawPath());
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
