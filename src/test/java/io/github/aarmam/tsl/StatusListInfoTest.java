package io.github.aarmam.tsl;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.HexFormat;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StatusListInfoTest {

    private static final String URI = "https://example.com/statuslists/1";

    @Test
    void testEncodesTheSection62Example() {
        StatusListInfo info = StatusListInfo.of(0, URI);

        assertThat(info.encodeAsStatusClaim(), equalTo(Map.of(
                "status_list", Map.of("idx", 0, "uri", URI))));
    }

    @Test
    void testParsesTheSection62Example() throws IOException {
        StatusListInfo info = StatusListInfo.buildFromJson()
                .json("{\"idx\": 0, \"uri\": \"" + URI + "\"}")
                .build();

        assertThat(info.getIdx(), equalTo(0));
        assertThat(info.getUri(), equalTo(URI));
    }

    @Test
    void testParsesFromStatusClaim() {
        StatusListInfo info = StatusListInfo.fromStatusClaim(
                Map.of("status_list", Map.of("idx", 42, "uri", URI)));

        assertThat(info.getIdx(), equalTo(42));
        assertThat(info.getUri(), equalTo(URI));
    }

    @Test
    void testCborStatusStructureMatchesTheSection63Example() throws IOException {
        // the status claim value from the Section 6.3 Referenced Token example
        StatusListInfo info = StatusListInfo.of(0, URI);
        String expected = "a16b7374617475735f6c697374a2636964780063757269782168747470733a2f2f6578"
                + "616d706c652e636f6d2f7374617475736c697374732f31";

        assertThat(HexFormat.of().formatHex(info.encodeAsStatusClaimCBOR()), equalTo(expected));
    }

    @Test
    void testCborRoundTrip() throws IOException {
        StatusListInfo info = StatusListInfo.of(7, URI);
        StatusListInfo decoded = StatusListInfo.buildFromCbor()
                .cbor(info.encodeAsCBOR())
                .build();

        assertThat(decoded.getIdx(), equalTo(7));
        assertThat(decoded.getUri(), equalTo(URI));
    }

    @Test
    void testRejectsNegativeIndex() {
        // Section 6.2: idx MUST be a non-negative Integer
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> StatusListInfo.of(-1, URI));
        assertThat(thrown.getMessage(), equalTo("idx must be a non-negative integer"));
    }

    @Test
    void testRejectsMissingMembers() {
        IllegalArgumentException missingUri = assertThrows(IllegalArgumentException.class,
                () -> StatusListInfo.buildFromMap().map(Map.of("idx", 0)).build());
        assertThat(missingUri.getMessage(), equalTo("Missing or malformed status_list member: uri"));

        IllegalArgumentException missingIdx = assertThrows(IllegalArgumentException.class,
                () -> StatusListInfo.buildFromMap().map(Map.of("uri", URI)).build());
        assertThat(missingIdx.getMessage(), equalTo("Missing or malformed status_list member: idx"));
    }

    @Test
    void testRejectsStatusClaimWithoutStatusList() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> StatusListInfo.fromStatusClaim(Map.of("other_mechanism", Map.of())));
        assertThat(thrown.getMessage(), equalTo("Missing status mechanism: status_list"));
    }
}
