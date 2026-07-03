package es.NTTEnterprise.RIntellix.ms_sec_gateway.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

class KeycloakRealmRoleConverterTest {

    private final KeycloakRealmRoleConverter converter = new KeycloakRealmRoleConverter();

    @Test
    void mapsRealmRolesToPrefixedAuthorities() {
        final Jwt jwt = jwtWithRealmRoles(List.of("ANALISTA", "offline_access"));

        assertThat(converter.convert(jwt))
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_ANALISTA", "ROLE_offline_access");
    }

    @Test
    void returnsEmptyWhenRealmAccessMissing() {
        final Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .subject("user")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();

        assertThat(converter.convert(jwt)).isEmpty();
    }

    @Test
    void returnsEmptyWhenRolesNotACollection() {
        final Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "none")
                .subject("user")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .claim("realm_access", Map.of("roles", "ANALISTA"))
                .build();

        assertThat(converter.convert(jwt)).isEmpty();
    }

    private Jwt jwtWithRealmRoles(final List<String> roles) {
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("analista-user")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .claim("realm_access", Map.of("roles", roles))
                .build();
    }
}
