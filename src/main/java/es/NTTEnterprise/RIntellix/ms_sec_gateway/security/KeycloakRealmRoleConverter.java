package es.NTTEnterprise.RIntellix.ms_sec_gateway.security;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Maps Keycloak realm roles carried in a JWT to Spring Security authorities.
 *
 * <p>
 * Keycloak places realm roles under the {@code realm_access.roles} claim. Each
 * role {@code X} becomes a {@code ROLE_X} authority so that
 * {@code hasRole("ANALISTA")} matches the Keycloak realm role {@code ANALISTA}.
 */
public class KeycloakRealmRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final String REALM_ACCESS_CLAIM = "realm_access";
    private static final String ROLES_CLAIM = "roles";
    private static final String ROLE_PREFIX = "ROLE_";

    @Override
    public Collection<GrantedAuthority> convert(final Jwt jwt) {
        final Map<String, Object> realmAccess = jwt.getClaimAsMap(REALM_ACCESS_CLAIM);
        if (realmAccess == null) {
            return List.of();
        }

        final Object roles = realmAccess.get(ROLES_CLAIM);
        if (!(roles instanceof Collection<?> roleCollection)) {
            return List.of();
        }

        return roleCollection.stream()
                .filter(java.util.Objects::nonNull)
                .map(Object::toString)
                .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role))
                .collect(Collectors.toUnmodifiableList());
    }
}
