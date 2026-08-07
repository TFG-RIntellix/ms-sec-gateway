package es.NTTEnterprise.RIntellix.ms_sec_gateway.filters;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import es.NTTEnterprise.RIntellix.ms_sec_gateway.config.GatewaySecurityProperties;
import es.NTTEnterprise.RIntellix.ms_sec_gateway.utils.LogMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Strips spoofable, client-supplied identity headers before routing so that
 * downstream services can only ever trust what the gateway itself sets.
 *
 * <p>
 * Runs first among the gateway's global filters.
 */
/**
 * Core component: HeaderSanitizationFilter.
 * Encapsulates the logic and responsibilities assigned to this element
 * within the Hexagonal Architecture, ensuring separation of concerns.
 *
 * @author Lucía Fernández Mancebo
 * @date 28/07/2026
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class HeaderSanitizationFilter implements GlobalFilter, Ordered {

    public static final int ORDER = -200;

    private final GatewaySecurityProperties properties;

    @Override
    public Mono<Void> filter(final ServerWebExchange exchange, final GatewayFilterChain chain) {
        final ServerHttpRequest original = exchange.getRequest();

        final boolean anyPresent = properties.getStrippedHeaders().stream()
                .anyMatch(header -> original.getHeaders().containsHeader(header));

        if (!anyPresent) {
            return chain.filter(exchange);
        }

        final ServerHttpRequest mutated = original.mutate()
                .headers(headers -> properties.getStrippedHeaders().forEach(header -> {
                    if (headers.remove(header) != null) {
                        log.debug(LogMessage.FILTER_HEADER_STRIPPED, header);
                    }
                }))
                .build();

        return chain.filter(exchange.mutate().request(mutated).build());
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
