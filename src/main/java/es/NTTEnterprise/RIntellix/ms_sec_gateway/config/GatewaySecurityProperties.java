package es.NTTEnterprise.RIntellix.ms_sec_gateway.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
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
    private List<String> strippedHeaders = List.of(
            "X-User-Role", "X-User-Id", "X-User-Name", "X-Authenticated-User",
            "X-Roles", "X-Auth-Roles", "X-Forwarded-User");

    @Getter
    @Setter
    public static class Cors {
        /** Allowed origins for browser calls. Empty means CORS is effectively disabled. */
        private List<String> allowedOrigins = List.of("http://localhost:4200", "http://localhost:3000");
        private List<String> allowedMethods = List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS");
        private List<String> allowedHeaders = List.of("Authorization", "Content-Type", "X-Request-ID");
        private boolean allowCredentials = true;
        @Positive
        private long maxAgeSeconds = 3600;
    }

    @Getter
    @Setter
    public static class Limits {
        /** Maximum accepted request body size in bytes (default 1 MiB). */
        @Positive
        private long maxBodyBytes = 1_048_576;
        /** Maximum accepted request URL length. */
        @Positive
        private int maxUrlLength = 4_096;
        /** Maximum number of inbound headers. */
        @Positive
        private int maxHeaderCount = 64;
    }

    @Getter
    @Setter
    public static class Injection {
        /** Master switch for the NoSQL / XSS payload filters. */
        private boolean enabled = true;
        /** Reject JSON bodies nested deeper than this (bounds scan cost). */
        @Min(1)
        private int maxJsonDepth = 32;
    }

    @Getter
    @Setter
    public static class RateLimit {
        private boolean enabled = true;
        /** Sustained requests allowed per minute, per caller. */
        @Positive
        private int requestsPerMinute = 120;
        /** Additional burst capacity on top of the sustained rate. */
        @Positive
        private int burstCapacity = 40;
    }
}
