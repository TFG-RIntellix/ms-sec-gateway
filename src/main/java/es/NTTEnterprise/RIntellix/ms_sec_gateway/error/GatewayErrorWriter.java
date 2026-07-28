package es.NTTEnterprise.RIntellix.ms_sec_gateway.error;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import es.NTTEnterprise.RIntellix.ms_sec_gateway.utils.LogMessage;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Writes a uniform JSON error body directly onto the reactive response.
 *
 * <p>
 * Used by the security entry point / access-denied handler and by the attack
 * filters so every rejection ({@code 400/401/403/413/429}) shares the same
 * shape and carries the {@code X-Request-ID} for cross-service correlation.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class GatewayErrorWriter {

    private static final String REQUEST_ID_HEADER = "X-Request-ID";

    private final ObjectMapper objectMapper;

    public Mono<Void> write(final ServerWebExchange exchange, final HttpStatus status,
            final String error, final String message) {

        final ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        final String requestId = exchange.getRequest().getHeaders().getFirst(REQUEST_ID_HEADER);

        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", status.value());
        body.put("error", error);
        body.put("message", message);
        body.put("path", exchange.getRequest().getPath().value());
        if (requestId != null) {
            body.put("requestId", requestId);
        }

        final byte[] bytes;
        try {
            bytes = objectMapper.writeValueAsBytes(body);
        } catch (final JacksonException ex) {
            log.error(LogMessage.EXCEPTION_UNEXPECTED, ex);
            return response.setComplete();
        }

        final DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }

    /** Convenience overload using the status' default reason phrase as the message. */
    public Mono<Void> write(final ServerWebExchange exchange, final HttpStatus status, final String error) {
        return write(exchange, status, error, status.getReasonPhrase());
    }
}
