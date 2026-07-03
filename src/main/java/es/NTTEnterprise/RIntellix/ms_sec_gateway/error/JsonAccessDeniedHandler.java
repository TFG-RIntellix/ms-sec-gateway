package es.NTTEnterprise.RIntellix.ms_sec_gateway.error;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import es.NTTEnterprise.RIntellix.ms_sec_gateway.utils.LogMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Returns a JSON {@code 403 Forbidden} when an authenticated caller lacks the
 * required {@code ANALISTA} role.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JsonAccessDeniedHandler implements ServerAccessDeniedHandler {

    private final GatewayErrorWriter errorWriter;

    @Override
    public Mono<Void> handle(final ServerWebExchange exchange, final AccessDeniedException ex) {
        return exchange.getPrincipal()
                .map(java.security.Principal::getName)
                .defaultIfEmpty("anonymous")
                .flatMap(subject -> {
                    log.warn(LogMessage.AUTH_FORBIDDEN, subject,
                            exchange.getRequest().getMethod(),
                            exchange.getRequest().getPath().value());
                    return errorWriter.write(exchange, HttpStatus.FORBIDDEN, "FORBIDDEN",
                            "The 'ANALISTA' role is required to execute this operation.");
                });
    }
}
