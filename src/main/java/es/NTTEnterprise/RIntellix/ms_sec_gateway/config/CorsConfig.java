package es.NTTEnterprise.RIntellix.ms_sec_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import lombok.RequiredArgsConstructor;

/**
 * CORS policy for the gateway, restricted to the configured frontend origins.
 */
@Configuration
@RequiredArgsConstructor
public class CorsConfig {

    private final GatewaySecurityProperties properties;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        final GatewaySecurityProperties.Cors cors = properties.getCors();

        final CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(cors.getAllowedOrigins());
        config.setAllowedMethods(cors.getAllowedMethods());
        config.setAllowedHeaders(cors.getAllowedHeaders());
        config.setAllowCredentials(cors.isAllowCredentials());
        config.setMaxAge(cors.getMaxAgeSeconds());

        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
