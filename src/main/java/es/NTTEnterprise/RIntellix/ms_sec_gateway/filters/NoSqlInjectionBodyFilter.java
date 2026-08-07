package es.NTTEnterprise.RIntellix.ms_sec_gateway.filters;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import es.NTTEnterprise.RIntellix.ms_sec_gateway.config.GatewaySecurityProperties;
import es.NTTEnterprise.RIntellix.ms_sec_gateway.error.GatewayErrorWriter;
import es.NTTEnterprise.RIntellix.ms_sec_gateway.security.AttackDetector;
import es.NTTEnterprise.RIntellix.ms_sec_gateway.utils.LogMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Buffers the JSON request body, scans it for NoSQL (MongoDB) injection / XSS
 * payloads, and re-emits the cached body downstream when it is clean.
 *
 * <p>
 * Only bodies of write methods ({@code POST/PUT/PATCH}) with a JSON content type
 * are inspected; everything else passes straight through untouched.
 */
/**
 * Core component: NoSqlInjectionBodyFilter.
 * Encapsulates the logic and responsibilities assigned to this element
 * within the Hexagonal Architecture, ensuring separation of concerns.
 *
 * @author Lucía Fernández Mancebo
 * @date 28/07/2026
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class NoSqlInjectionBodyFilter implements GlobalFilter, Ordered {

    public static final int ORDER = -100;

    private final GatewaySecurityProperties properties;
    private final AttackDetector attackDetector;
    private final GatewayErrorWriter errorWriter;

    @Override
    public Mono<Void> filter(final ServerWebExchange exchange, final GatewayFilterChain chain) {
        if (!properties.getInjection().isEnabled() || !shouldInspect(exchange.getRequest())) {
            return chain.filter(exchange);
        }

        return DataBufferUtils.join(exchange.getRequest().getBody())
                .flatMap(dataBuffer -> {
                    final byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);

                    if (bytes.length > properties.getLimits().getMaxBodyBytes()) {
                        log.warn(LogMessage.FILTER_PAYLOAD_TOO_LARGE, exchange.getRequest().getMethod(),
                                exchange.getRequest().getPath().value(), bytes.length,
                                properties.getLimits().getMaxBodyBytes());
                        return errorWriter.write(exchange, HttpStatus.PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE",
                                "Request body exceeds the maximum allowed size.");
                    }

                    final String reason = attackDetector.scanJsonBody(bytes, properties.getInjection().getMaxJsonDepth());
                    if (reason != null) {
                        log.warn(LogMessage.FILTER_NOSQL_BLOCKED, exchange.getRequest().getMethod(),
                                exchange.getRequest().getPath().value(), "body", reason);
                        return errorWriter.write(exchange, HttpStatus.BAD_REQUEST, "INJECTION_BLOCKED",
                                "The request body contains a potentially malicious payload.");
                    }

                    final ServerHttpRequestDecorator decorated =
                            decorate(exchange, bytes);
                    return chain.filter(exchange.mutate().request(decorated).build());
                })
                .switchIfEmpty(Mono.defer(() -> chain.filter(exchange)));
    }

    private boolean shouldInspect(final ServerHttpRequest request) {
        final HttpMethod method = request.getMethod();
        final boolean writeMethod = HttpMethod.POST.equals(method)
                || HttpMethod.PUT.equals(method)
                || HttpMethod.PATCH.equals(method);
        if (!writeMethod) {
            return false;
        }
        final MediaType contentType = request.getHeaders().getContentType();
        return contentType != null && contentType.isCompatibleWith(MediaType.APPLICATION_JSON);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    private ServerHttpRequestDecorator decorate(final ServerWebExchange exchange, final byte[] bytes) {
        final DataBufferFactory bufferFactory = exchange.getResponse().bufferFactory();
        return new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public Flux<DataBuffer> getBody() {
                return Flux.just(bufferFactory.wrap(bytes));
            }
        };
    }
}
