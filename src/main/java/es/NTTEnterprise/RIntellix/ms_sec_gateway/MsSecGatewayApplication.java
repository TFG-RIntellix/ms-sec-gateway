package es.NTTEnterprise.RIntellix.ms_sec_gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Entry point for the RIntellix security gateway.
 *
 * <p>
 * Single public entry point for the platform. It authenticates callers against
 * Keycloak (OAuth2 resource server / JWT), authorises only the {@code ANALISTA}
 * role to reach the downstream REST methods, filters out NoSQL (MongoDB)
 * injection and other common web attacks, and routes the surviving traffic to
 * the backing microservices.
 *
 * @author Lucía Fernández Mancebo
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class MsSecGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(MsSecGatewayApplication.class, args);
    }
}
