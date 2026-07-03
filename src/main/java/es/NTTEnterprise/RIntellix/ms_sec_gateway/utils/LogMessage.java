package es.NTTEnterprise.RIntellix.ms_sec_gateway.utils;

/**
 * Centralized log messages for the ms-sec-gateway microservice.
 *
 * <p>
 * Provides consistent, reusable log message templates so logging stays uniform
 * across the gateway's security filters and configuration.
 *
 * @author Lucía Fernández Mancebo
 */
public final class LogMessage {

    private LogMessage() {
        // Prevent instantiation
    }

    // ============================================================
    // AUTHENTICATION / AUTHORIZATION
    // ============================================================

    public static final String AUTH_UNAUTHENTICATED = "Rejected unauthenticated request - {} {} - reason: {}";
    public static final String AUTH_FORBIDDEN = "Rejected request without required role - subject: [{}], {} {}";

    // ============================================================
    // ATTACK FILTERS
    // ============================================================

    public static final String FILTER_HEADER_STRIPPED = "Stripped spoofable inbound header: [{}]";
    public static final String FILTER_NOSQL_BLOCKED = "Blocked possible NoSQL injection - {} {} - location: {} - reason: {}";
    public static final String FILTER_XSS_BLOCKED = "Blocked possible script/XSS payload - {} {} - location: {}";
    public static final String FILTER_PATH_TRAVERSAL_BLOCKED = "Blocked path-traversal attempt - path: [{}]";
    public static final String FILTER_PAYLOAD_TOO_LARGE = "Blocked oversized request - {} {} - size: {} bytes (max {})";
    public static final String FILTER_URL_TOO_LONG = "Blocked overly long URL - length: {} (max {})";
    public static final String FILTER_TOO_MANY_HEADERS = "Blocked request with too many headers - count: {} (max {})";
    public static final String FILTER_RATE_LIMITED = "Rate limit exceeded - key: [{}]";
}
