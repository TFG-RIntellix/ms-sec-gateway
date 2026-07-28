package es.NTTEnterprise.RIntellix.ms_sec_gateway.config;

import jakarta.validation.constraints.Positive;
import lombok.Getter;
import lombok.Setter;

/**
 * Limits properties for GatewaySecurityProperties.
 *
 * @author Lucía Fernández Mancebo
 * @date 28/07/2026
 */
@Getter
@Setter
public class Limits {
    /** Maximum accepted request body size in bytes. */
    @Positive
    private long maxBodyBytes;
    
    /** Maximum accepted request URL length. */
    @Positive
    private int maxUrlLength;
    
    /** Maximum number of inbound headers. */
    @Positive
    private int maxHeaderCount;
}
