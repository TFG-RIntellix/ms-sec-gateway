package es.NTTEnterprise.RIntellix.ms_sec_gateway.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

/**
 * Tunable configuration for the gateway's security / attack-mitigation filters.
 *
 * <p>
 * Bound from the {@code gateway.security} prefix in {@code application.yaml}.
 * Every value has a safe default so the gateway is protected out of the box.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "gateway.security")
/**
 * Core component: GatewaySecurityProperties.
 * Encapsulates the logic and responsibilities assigned to this element
 * within the Hexagonal Architecture, ensuring separation of concerns.
 *
 * @author Lucía Fernández Mancebo
 * @date 28/07/2026
 */
public class GatewaySecurityProperties {

    /** CORS configuration for the (future) frontend. */
    @NotNull
    private Cors cors = new Cors();

    /** Request-hardening limits (size, URL length, header count). */
    @NotNull
    private Limits limits = new Limits();

    /** NoSQL-injection / XSS payload filtering. */
    @NotNull
    private Injection injection = new Injection();

    /** In-memory rate limiting. */
    @NotNull
    private RateLimit rateLimit = new RateLimit();

    /**
     * Inbound headers that clients must never be able to set (identity spoofing).
     * They are stripped before the request is routed downstream.
     */
    @NotNull
    private List<String> strippedHeaders;

}
