package io.github.aarmam.tsl;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdentifierListTest extends BaseTest {

    private static final byte[] TEST_ID_1 = "test-identifier-1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TEST_ID_2 = "test-identifier-2".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TEST_ID_3 = "test-identifier-3".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TEST_ID_4 = "test-identifier-4".getBytes(StandardCharsets.UTF_8);

    private IdentifierList exampleIdentifierList() {
        IdentifierList identifierList = new IdentifierList("https://example.com/aggregation");
        identifierList.addIdentifier(TEST_ID_1);
        identifierList.addIdentifier(TEST_ID_2);
        identifierList.addIdentifier(TEST_ID_3);
        return identifierList;
    }

    private IdentifierList exampleIdentifierListNoAggregation() {
        IdentifierList identifierList = new IdentifierList();
        identifierList.addIdentifier(TEST_ID_1);
        identifierList.addIdentifier(TEST_ID_2);
        return identifierList;
    }

    @Test
    void testCreateEmptyIdentifierList() {
        IdentifierList identifierList = new IdentifierList();
        assertThat(identifierList.getIdentifiers(), is(notNullValue()));
        assertThat(identifierList.size(), equalTo(0));
        assertThat(identifierList.getAggregationUri(), is(nullValue()));
    }

    @Test
    void testCreateIdentifierListWithAggregationUri() {
        String aggregationUri = "https://example.com/aggregation";
        IdentifierList identifierList = new IdentifierList(aggregationUri);
        assertThat(identifierList.getAggregationUri(), equalTo(aggregationUri));
    }

    @Test
    void testAddIdentifier() {
        IdentifierList identifierList = new IdentifierList();
        identifierList.addIdentifier(TEST_ID_1);
        assertThat(identifierList.size(), equalTo(1));
        assertTrue(identifierList.isRevoked(TEST_ID_1));
    }

    @Test
    void testAddMultipleIdentifiers() {
        IdentifierList identifierList = exampleIdentifierList();
        assertThat(identifierList.size(), equalTo(3));
        assertTrue(identifierList.isRevoked(TEST_ID_1));
        assertTrue(identifierList.isRevoked(TEST_ID_2));
        assertTrue(identifierList.isRevoked(TEST_ID_3));
        assertFalse(identifierList.isRevoked(TEST_ID_4));
    }

    @Test
    void testRemoveIdentifier() {
        IdentifierList identifierList = exampleIdentifierList();
        assertTrue(identifierList.isRevoked(TEST_ID_2));
        identifierList.removeIdentifier(TEST_ID_2);
        assertFalse(identifierList.isRevoked(TEST_ID_2));
        assertThat(identifierList.size(), equalTo(2));
    }

    @Test
    void testIsRevoked() {
        IdentifierList identifierList = new IdentifierList();
        assertFalse(identifierList.isRevoked(TEST_ID_1));
        identifierList.addIdentifier(TEST_ID_1);
        assertTrue(identifierList.isRevoked(TEST_ID_1));
    }

    @Test
    void testEncodeAsMap() {
        IdentifierList identifierList = exampleIdentifierList();
        Map<String, Object> map = identifierList.encodeAsMap();
        assertThat(map, is(notNullValue()));
        assertThat(map, hasKey("identifiers"));
        assertThat(map, hasEntry("aggregation_uri", "https://example.com/aggregation"));
        assertThat(map, aMapWithSize(2));

        @SuppressWarnings("unchecked")
        Map<String, Object> identifiers = (Map<String, Object>) map.get("identifiers");
        assertThat(identifiers, is(notNullValue()));
        assertThat(identifiers.size(), equalTo(3));
    }

    @Test
    void testEncodeAsMapWithoutAggregation() {
        IdentifierList identifierList = exampleIdentifierListNoAggregation();
        Map<String, Object> map = identifierList.encodeAsMap();
        assertThat(map, is(notNullValue()));
        assertThat(map, hasKey("identifiers"));
        assertThat(map, aMapWithSize(1));

        @SuppressWarnings("unchecked")
        Map<String, Object> identifiers = (Map<String, Object>) map.get("identifiers");
        assertThat(identifiers, is(notNullValue()));
        assertThat(identifiers.size(), equalTo(2));
    }

    @Test
    void testEncodeAsCBOR() throws IOException {
        IdentifierList identifierList = exampleIdentifierList();
        byte[] cbor = identifierList.encodeAsCBOR();
        assertThat(cbor, is(notNullValue()));
        assertThat(cbor.length > 0, is(true));
    }

    @Test
    void testBuildFromCbor() throws IOException {
        IdentifierList original = exampleIdentifierList();
        byte[] cbor = original.encodeAsCBOR();

        IdentifierList decoded = IdentifierList.buildFromCbor()
                .cbor(cbor)
                .build();

        assertThat(decoded, is(notNullValue()));
        assertThat(decoded.size(), equalTo(3));
        assertTrue(decoded.isRevoked(TEST_ID_1));
        assertTrue(decoded.isRevoked(TEST_ID_2));
        assertTrue(decoded.isRevoked(TEST_ID_3));
        assertFalse(decoded.isRevoked(TEST_ID_4));
        assertThat(decoded.getAggregationUri(), equalTo("https://example.com/aggregation"));
    }

    @Test
    void testBuildFromJson() throws IOException {
        String json = "{\"identifiers\":{\"dGVzdC1pZGVudGlmaWVyLTE\":{},\"dGVzdC1pZGVudGlmaWVyLTI\":{}},\"aggregation_uri\":\"https://example.com/aggregation\"}";
        IdentifierList identifierList = IdentifierList.buildFromJson()
                .json(json)
                .build();

        assertThat(identifierList, is(notNullValue()));
        assertThat(identifierList.size(), equalTo(2));
        assertTrue(identifierList.isRevoked(TEST_ID_1));
        assertTrue(identifierList.isRevoked(TEST_ID_2));
        assertThat(identifierList.getAggregationUri(), equalTo("https://example.com/aggregation"));
    }

    @Test
    void testRoundTripJson() throws IOException {
        IdentifierList original = exampleIdentifierList();
        Map<String, Object> map = original.encodeAsMap();

        com.fasterxml.jackson.databind.ObjectMapper objectMapper = new com.fasterxml.jackson.databind.ObjectMapper();
        String json = objectMapper.writeValueAsString(map);

        IdentifierList decoded = IdentifierList.buildFromJson()
                .json(json)
                .build();

        assertThat(decoded.size(), equalTo(original.size()));
        assertTrue(decoded.isRevoked(TEST_ID_1));
        assertTrue(decoded.isRevoked(TEST_ID_2));
        assertTrue(decoded.isRevoked(TEST_ID_3));
        assertThat(decoded.getAggregationUri(), equalTo(original.getAggregationUri()));
    }

    @Test
    void testRoundTripCbor() throws IOException {
        IdentifierList original = exampleIdentifierList();
        byte[] cbor = original.encodeAsCBOR();

        IdentifierList decoded = IdentifierList.buildFromCbor()
                .cbor(cbor)
                .build();

        assertThat(decoded.size(), equalTo(original.size()));
        assertTrue(decoded.isRevoked(TEST_ID_1));
        assertTrue(decoded.isRevoked(TEST_ID_2));
        assertTrue(decoded.isRevoked(TEST_ID_3));
        assertThat(decoded.getAggregationUri(), equalTo(original.getAggregationUri()));
    }

    @Test
    void testEmptyIdentifierList() throws IOException {
        IdentifierList identifierList = new IdentifierList();
        Map<String, Object> map = identifierList.encodeAsMap();
        assertThat(map, hasKey("identifiers"));

        @SuppressWarnings("unchecked")
        Map<String, Object> identifiers = (Map<String, Object>) map.get("identifiers");
        assertThat(identifiers.size(), equalTo(0));
    }
}
