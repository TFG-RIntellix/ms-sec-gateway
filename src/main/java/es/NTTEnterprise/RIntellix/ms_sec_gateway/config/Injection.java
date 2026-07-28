package es.NTTEnterprise.RIntellix.ms_sec_gateway.config;

import jakarta.validation.constraints.Min;
import lombok.Getter;
import lombok.Setter;

/**
 * Injection properties.
 *
 * @author Lucía Fernández Mancebo
 * @date 28/07/2026
 */
@Getter
@Setter
public class Injection {
    /** Master switch for the NoSQL / XSS payload filters. */
    private boolean enabled;
    /** Reject JSON bodies nested deeper than this (bounds scan cost). */
    @Min(1)
    private int maxJsonDepth;
}
