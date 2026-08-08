package es.NTTEnterprise.RIntellix.ms_sec_gateway.config;

import java.time.Duration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter.Mode;
import org.springframework.web.cors.reactive.CorsConfigurationSource;

import es.NTTEnterprise.RIntellix.ms_sec_gateway.error.JsonAccessDeniedHandler;
import es.NTTEnterprise.RIntellix.ms_sec_gateway.error.JsonAuthenticationEntryPoint;
import es.NTTEnterprise.RIntellix.ms_sec_gateway.security.KeycloakRealmRoleConverter;
import reactor.core.publisher.Mono;

/**
 * Reactive security configuration.
 *
 * <p>
 * The gateway is a stateless OAuth2 <em>resource server</em>: it validates the
 * Keycloak-issued JWT on every request (signature, issuer, expiry via the realm
 * JWKS configured through {@code spring.security.oauth2.resourceserver.jwt}),
 * then authorises only the {@code ANALISTA} realm role to reach any routed REST
 * method. Health/info probes and CORS preflight are the only public endpoints.
 */
/**
 * Core component: SecurityConfig.
 * Encapsulates the logic and responsibilities assigned to this element
 * within the Hexagonal Architecture, ensuring separation of concerns.
 *
 * @author Lucía Fernández Mancebo
 * @date 28/07/2026
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private static final String REQUIRED_ROLE = "ANALISTA";

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            final ServerHttpSecurity http,
            final CorsConfigurationSource corsConfigurationSource,
            final Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter,
            final JsonAuthenticationEntryPoint authenticationEntryPoint,
            final JsonAccessDeniedHandler accessDeniedHandler) {

        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(HttpMethod.OPTIONS).permitAll()
                        .pathMatchers("/actuator/health/**", "/actuator/info").permitAll()
                        .pathMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/**").permitAll()
                        .anyExchange().hasRole(REQUIRED_ROLE))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter)))
                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .headers(headers -> headers
                        .frameOptions(frame -> frame.mode(Mode.DENY))
                        .referrerPolicy(referrer -> referrer.policy(ReferrerPolicy.NO_REFERRER))
                        .hsts(hsts -> hsts.includeSubdomains(true).maxAge(Duration.ofDays(365)))
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' http://localhost:8180; frame-ancestors 'none'")));

        return http.build();
    }

    /**
     * Adapts the servlet-style {@link JwtAuthenticationConverter} (configured with
     * the Keycloak realm-role mapping) to the reactive converter the resource
     * server expects.
     */
    @Bean
    public Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter() {
        final JwtAuthenticationConverter delegate = new JwtAuthenticationConverter();
        delegate.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
        return new ReactiveJwtAuthenticationConverterAdapter(delegate);
    }
}
