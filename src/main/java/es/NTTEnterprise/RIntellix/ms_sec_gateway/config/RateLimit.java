package es.NTTEnterprise.RIntellix.ms_sec_gateway.config;

import jakarta.validation.constraints.Positive;
import lombok.Getter;
import lombok.Setter;

/**
 * Rate limit properties.
 *
 * @author Lucía Fernández Mancebo
 * @date 28/07/2026
 */
@Getter
@Setter
public class RateLimit {
    private boolean enabled;
    /** Sustained requests allowed per minute, per caller. */
    @Positive
    private int requestsPerMinute;
    /** Additional burst capacity on top of the sustained rate. */
    @Positive
    private int burstCapacity;
}
