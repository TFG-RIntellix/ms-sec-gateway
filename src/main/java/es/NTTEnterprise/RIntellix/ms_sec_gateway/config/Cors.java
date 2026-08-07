package es.NTTEnterprise.RIntellix.ms_sec_gateway.config;

import java.util.List;

import jakarta.validation.constraints.Positive;
import lombok.Getter;
import lombok.Setter;

/**
 * Cors properties.
 *
 * @author Lucía Fernández Mancebo
 * @date 28/07/2026
 */
@Getter
@Setter
public class Cors {
    /** Allowed origins for browser calls. Empty means CORS is effectively disabled. */
    private List<String> allowedOrigins;
    private List<String> allowedMethods;
    private List<String> allowedHeaders;
    private boolean allowCredentials;
    @Positive
    private long maxAgeSeconds;
}
