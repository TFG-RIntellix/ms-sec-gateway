package es.NTTEnterprise.RIntellix.ms_sec_gateway.error;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import es.NTTEnterprise.RIntellix.ms_sec_gateway.utils.LogMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Returns a JSON {@code 401 Unauthorized} when no/invalid credentials are
 * presented, instead of Spring Security's default empty {@code WWW-Authenticate}
 * response.
 */
/**
 * Core component: JsonAuthenticationEntryPoint.
 * Encapsulates the logic and responsibilities assigned to this element
 * within the Hexagonal Architecture, ensuring separation of concerns.
 *
 * @author Lucía Fernández Mancebo
 * @date 28/07/2026
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JsonAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private final GatewayErrorWriter errorWriter;

    @Override
    public Mono<Void> commence(final ServerWebExchange exchange, final AuthenticationException ex) {
        log.warn(LogMessage.AUTH_UNAUTHENTICATED,
                exchange.getRequest().getMethod(),
                exchange.getRequest().getPath().value(),
                ex.getMessage());
        return errorWriter.write(exchange, HttpStatus.UNAUTHORIZED, "UNAUTHORIZED",
                "Authentication is required to access this resource.");
    }
}
