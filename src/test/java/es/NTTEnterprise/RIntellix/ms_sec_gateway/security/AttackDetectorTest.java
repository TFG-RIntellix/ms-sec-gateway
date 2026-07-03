package es.NTTEnterprise.RIntellix.ms_sec_gateway.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import tools.jackson.databind.json.JsonMapper;

class AttackDetectorTest {

    private static final int MAX_DEPTH = 32;

    private AttackDetector detector;

    @BeforeEach
    void setUp() {
        detector = new AttackDetector(new JsonMapper());
    }

    // ------------------------------------------------------------------
    // JSON body scanning
    // ------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"partyName\": {\"$ne\": null}}",
            "{\"amount\": {\"$gt\": 0}}",
            "{\"$where\": \"this.balance > 0\"}",
            "{\"filter\": {\"$regex\": \".*\"}}",
            "{\"user.role\": \"admin\"}",
            "{\"nested\": {\"inner\": {\"$in\": [1, 2]}}}",
            "{\"note\": \"<script>alert(1)</script>\"}"
    })
    void blocksMaliciousJsonBodies(final String json) {
        final String reason = detector.scanJsonBody(json.getBytes(StandardCharsets.UTF_8), MAX_DEPTH);
        assertThat(reason).as("payload should be blocked: %s", json).isNotNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"partyName\": \"John Doe\"}",
            "{\"amount\": 1500.50, \"currency\": \"EUR\"}",
            "{\"requestId\": \"abc-123\", \"formChanges\": {\"income\": 4200}}",
            "{\"items\": [{\"id\": 1}, {\"id\": 2}]}"
    })
    void allowsLegitimateJsonBodies(final String json) {
        final String reason = detector.scanJsonBody(json.getBytes(StandardCharsets.UTF_8), MAX_DEPTH);
        assertThat(reason).as("payload should be allowed: %s", json).isNull();
    }

    @Test
    void allowsEmptyBody() {
        assertThat(detector.scanJsonBody(new byte[0], MAX_DEPTH)).isNull();
        assertThat(detector.scanJsonBody(null, MAX_DEPTH)).isNull();
    }

    @Test
    void blocksMaliciousPayloadInMalformedJsonViaRawScan() {
        final byte[] body = "not-json but has $where inside".getBytes(StandardCharsets.UTF_8);
        assertThat(detector.scanJsonBody(body, MAX_DEPTH)).isNotNull();
    }

    @Test
    void blocksExcessiveNesting() {
        final StringBuilder open = new StringBuilder();
        final StringBuilder close = new StringBuilder();
        for (int i = 0; i < 40; i++) {
            open.append("{\"a\":");
            close.append("}");
        }
        final String json = open + "1" + close;
        assertThat(detector.scanJsonBody(json.getBytes(StandardCharsets.UTF_8), MAX_DEPTH)).isNotNull();
    }

    // ------------------------------------------------------------------
    // Query params / keys
    // ------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"$ne", "partyName[$ne]", "$where"})
    void blocksMaliciousKeys(final String key) {
        assertThat(detector.scanKey(key)).isNotNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"partyName", "requestId", "archived"})
    void allowsLegitimateKeys(final String key) {
        assertThat(detector.scanKey(key)).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"$gt\": \"\"}", "<script>alert(1)</script>", "javascript:alert(1)"})
    void blocksMaliciousValues(final String value) {
        assertThat(detector.scanValue(value)).isNotNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"John Doe", "abc-123", "2026-01-01"})
    void allowsLegitimateValues(final String value) {
        assertThat(detector.scanValue(value)).isNull();
    }
}
