package es.NTTEnterprise.RIntellix.ms_sec_gateway.security;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Detects NoSQL (MongoDB) injection and script/XSS payloads in request data.
 *
 * <p>
 * The gateway is the single entry point, so this is defence-in-depth for the
 * downstream Spring Data MongoDB services: it rejects the operator-injection
 * vectors ({@code $where}, {@code $ne}, {@code $regex}, dotted keys, embedded
 * JavaScript, …) before the payload can reach a Mongo query, plus obvious
 * reflected-XSS markers.
 *
 * <p>
 * All checks are read-only and allocation-light; each returns a human-readable
 * reason {@code String} when something is blocked, or {@code null} when clean.
 */
@Component
@RequiredArgsConstructor
public class AttackDetector {

    /** Mongo query operators / server-side JS that must never appear in user input. */
    private static final Set<String> NOSQL_TOKENS = Set.of(
            "$where", "$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin",
            "$regex", "$expr", "$function", "$or", "$and", "$nor", "$not",
            "$exists", "$elemmatch", "$mod", "$text", "$search", "$jsonschema",
            "mapreduce", "function(", "this.", "sleep(", ";return", ";sleep");

    /** Reflected-XSS / HTML-injection markers. */
    private static final Set<String> XSS_TOKENS = Set.of(
            "<script", "</script", "javascript:", "onerror=", "onload=",
            "onclick=", "onmouseover=", "<iframe", "<svg", "<img",
            "document.cookie", "eval(", "<body");

    private final ObjectMapper objectMapper;

    // ------------------------------------------------------------------
    // Query params / path segments (synchronous, no body)
    // ------------------------------------------------------------------

    /**
     * Scans a single query-parameter (or path) key. Mongo operator injection via
     * URL parameters typically arrives as {@code ?field[$ne]=} or a key literally
     * starting with {@code $}.
     */
    public String scanKey(final String key) {
        if (key == null || key.isEmpty()) {
            return null;
        }
        final String lower = key.toLowerCase();
        if (key.startsWith("$") || lower.contains("[$")) {
            return "operator-like key: '" + key + "'";
        }
        if (containsToken(lower, NOSQL_TOKENS)) {
            return "operator token in key: '" + key + "'";
        }
        return null;
    }

    /** Scans a query-parameter or path value for NoSQL / XSS payloads. */
    public String scanValue(final String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        final String lower = value.toLowerCase();
        if (containsToken(lower, NOSQL_TOKENS)) {
            return "NoSQL operator in value";
        }
        if (containsToken(lower, XSS_TOKENS)) {
            return "script/XSS marker in value";
        }
        return null;
    }

    // ------------------------------------------------------------------
    // JSON request body
    // ------------------------------------------------------------------

    /**
     * Parses and walks a JSON body. Rejects object field names that begin with
     * {@code $} or contain {@code .} (Mongo operator / dotted-path injection) and
     * string values carrying NoSQL/XSS markers. Falls back to a raw substring
     * scan when the payload is not valid JSON.
     *
     * @return a reason when blocked, otherwise {@code null}
     */
    public String scanJsonBody(final byte[] body, final int maxDepth) {
        if (body == null || body.length == 0) {
            return null;
        }
        final JsonNode root;
        try {
            root = objectMapper.readTree(body);
        } catch (final RuntimeException ex) {
            return scanRaw(new String(body, StandardCharsets.UTF_8));
        }
        return walk(root, 0, maxDepth);
    }

    private String walk(final JsonNode node, final int depth, final int maxDepth) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (depth > maxDepth) {
            return "JSON nesting exceeds maximum depth of " + maxDepth;
        }
        if (node.isObject()) {
            for (final Map.Entry<String, JsonNode> field : node.properties()) {
                final String keyReason = scanJsonKey(field.getKey());
                if (keyReason != null) {
                    return keyReason;
                }
                final String childReason = walk(field.getValue(), depth + 1, maxDepth);
                if (childReason != null) {
                    return childReason;
                }
            }
            return null;
        }
        if (node.isArray()) {
            for (final JsonNode child : node) {
                final String childReason = walk(child, depth + 1, maxDepth);
                if (childReason != null) {
                    return childReason;
                }
            }
            return null;
        }
        if (node.isString()) {
            return scanValue(node.asString());
        }
        return null;
    }

    private String scanJsonKey(final String key) {
        if (key == null || key.isEmpty()) {
            return null;
        }
        if (key.startsWith("$")) {
            return "JSON key starts with '$': '" + key + "'";
        }
        if (key.contains(".")) {
            return "JSON key contains dotted path: '" + key + "'";
        }
        if (containsToken(key.toLowerCase(), NOSQL_TOKENS)) {
            return "operator token in JSON key: '" + key + "'";
        }
        return null;
    }

    private String scanRaw(final String raw) {
        final String lower = raw.toLowerCase();
        for (final String token : List.of("$where", "$ne", "$gt", "$regex", "$function", "mapreduce")) {
            if (lower.contains(token)) {
                return "NoSQL operator in body: '" + token + "'";
            }
        }
        if (containsToken(lower, XSS_TOKENS)) {
            return "script/XSS marker in body";
        }
        return null;
    }

    private boolean containsToken(final String haystackLower, final Set<String> tokens) {
        for (final String token : tokens) {
            if (haystackLower.contains(token)) {
                return true;
            }
        }
        return false;
    }
}
