package io.github.aarmam.tsl;

import io.github.aarmam.tsl.status.AppSpecificStatus;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StatusListTest extends BaseTest {

    private static void assertStatusList(StatusList decodedStatusList) {
        assertThat(decodedStatusList, is(notNullValue()));
        assertThat(decodedStatusList.get(0), equalTo(1));
        assertThat(decodedStatusList.get(1), equalTo(0));
        assertThat(decodedStatusList.get(2), equalTo(0));
        assertThat(decodedStatusList.get(3), equalTo(1));
        assertThat(decodedStatusList.get(4), equalTo(1));
        assertThat(decodedStatusList.get(5), equalTo(1));
        assertThat(decodedStatusList.get(6), equalTo(0));
        assertThat(decodedStatusList.get(7), equalTo(1));
        assertThat(decodedStatusList.get(8), equalTo(1));
        assertThat(decodedStatusList.get(9), equalTo(1));
        assertThat(decodedStatusList.get(10), equalTo(0));
        assertThat(decodedStatusList.get(11), equalTo(0));
        assertThat(decodedStatusList.get(12), equalTo(0));
        assertThat(decodedStatusList.get(13), equalTo(1));
        assertThat(decodedStatusList.get(14), equalTo(0));
        assertThat(decodedStatusList.get(15), equalTo(1));
    }

    @Test
    void testStatusListEncoding1Bit() throws IOException {
        StatusList statusList = exampleStatusList1Bit();
        Map<String, Object> map = statusList.encodeAsMap(true);
        assertThat(map, is(notNullValue()));
        assertThat(map, hasEntry("bits", 1));
        assertThat(map, hasEntry("lst", "eNrbuRgAAhcBXQ"));
        assertThat(map, aMapWithSize(2));
    }

    @Test
    void testStatusListEncoding1BitCBOR() throws IOException {
        StatusList statusList = exampleStatusList1Bit();
        String hexEncoded = statusList.encodeAsCBORHex();
        assertThat(hexEncoded, equalTo("a2646269747301636c73744a78dadbb918000217015d"));
    }

    @Test
    void testStatusListEncoding2Bit() throws IOException {
        StatusList statusList = exampleStatusList2Bit();
        Map<String, Object> map = statusList.encodeAsMap(true);
        assertThat(map, is(notNullValue()));
        assertThat(map, hasEntry("bits", 2));
        assertThat(map, hasEntry("lst", "eNo76fITAAPfAgc"));
        assertThat(map, aMapWithSize(2));
    }

    @Test
    void testStatusListEncoding2BitCBOR() throws IOException {
        StatusList statusList = exampleStatusList2Bit();
        String hexEncoded = statusList.encodeAsCBORHex();
        assertThat(hexEncoded, equalTo("a2646269747302636c73744b78da3be9f2130003df0207"));
    }

    @Test
    void testBuildFromBytes() throws IOException {
        StatusList statusList = exampleStatusList1Bit();
        byte[] encoded = statusList.encodeAsBytes();
        StatusList decodedStatusList = StatusList.buildFromBytes()
                .bits(1)
                .list(encoded)
                .build();
        assertStatusList(decodedStatusList);
    }

    @Test
    void testBuildFromBytesDerivesSizeFromDecompressedList() throws IOException {
        StatusList statusList = exampleStatusList1Bit();
        byte[] encoded = statusList.encodeAsBytes();
        // the 16-entry list compresses to 10 bytes; size must follow the decompressed 2 bytes
        assertThat(encoded.length, equalTo(10));

        StatusList decodedStatusList = StatusList.buildFromBytes()
                .bits(1)
                .list(encoded)
                .build();

        assertThat(decodedStatusList.size(), equalTo(16));
        assertThrows(IndexOutOfBoundsException.class, () -> decodedStatusList.get(16));
        assertThrows(IndexOutOfBoundsException.class, () -> decodedStatusList.get(40));
    }

    @Test
    void testBuildFromJson() throws IOException {
        String json = "{\"bits\":1,\"lst\":\"eNrbuRgAAhcBXQ\"}";
        StatusList statusList = StatusList.buildFromJson()
                .json(json)
                .build();
        assertStatusList(statusList);
    }

    @Test
    void testBuildFromCbor() throws IOException {
        String cbor = "a2646269747301636c73744a78dadbb918000217015d";
        StatusList statusList = StatusList.buildFromCbor()
                .cborHex(cbor)
                .build();
        assertStatusList(statusList);
    }

    @Test
    void testBuildFromCborIgnoresEntryOrder() throws IOException {
        // same map as testBuildFromCbor, with "lst" written before "bits"
        String cbor = "a2636c73744a78dadbb918000217015d646269747301";
        StatusList statusList = StatusList.buildFromCbor()
                .cborHex(cbor)
                .build();
        assertStatusList(statusList);
    }

    @Test
    void testBuildFromCborWithAdditionalEntries() throws IOException {
        // {"bits": 1, "lst": h'...', "aggregation_uri": "https://example.com/aggregation"}
        String cbor = "a3646269747301636c73744a78dadbb918000217015d6f6167677265676174696f6e5f757269"
                + "781f68747470733a2f2f6578616d706c652e636f6d2f6167677265676174696f6e";
        StatusList statusList = StatusList.buildFromCbor()
                .cborHex(cbor)
                .build();
        assertStatusList(statusList);
    }

    @Test
    void testBuildFromCborRejectsMissingEntries() {
        // {"bits": 1} with no "lst"
        String cbor = "a1646269747301";
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> StatusList.buildFromCbor().cborHex(cbor).build());
        assertThat(thrown.getMessage(), equalTo("Missing required Status List entry: lst"));
    }

    @Test
    void testApplicationSpecificStatus() {
        ExceptionInInitializerError thrown = assertThrows(
                ExceptionInInitializerError.class,
                () -> {
                    StatusType noop = AppSpecificStatus.INVALID_STATUS;
                }
        );
        assertThat(thrown.getException().getMessage(), equalTo("Not a valid application specific status"));
    }

    @Test
    void testApplicationSpecificStatusRange() {
        // Section 7.1: 0x03 and 0x0C..0x0F are application specific, nothing else
        assertThat(ApplicationSpecificStatusType.isApplicationSpecific(0x03), is(true));
        assertThat(ApplicationSpecificStatusType.isApplicationSpecific(0x0C), is(true));
        assertThat(ApplicationSpecificStatusType.isApplicationSpecific(0x0D), is(true));
        assertThat(ApplicationSpecificStatusType.isApplicationSpecific(0x0E), is(true));
        assertThat(ApplicationSpecificStatusType.isApplicationSpecific(0x0F), is(true));

        // 0x0B was dropped from the range in draft-14 and is reserved for registration
        assertThat(ApplicationSpecificStatusType.isApplicationSpecific(0x0B), is(false));
        assertThat(ApplicationSpecificStatusType.isApplicationSpecific(0x00), is(false));
        assertThat(ApplicationSpecificStatusType.isApplicationSpecific(0x02), is(false));
        assertThat(ApplicationSpecificStatusType.isApplicationSpecific(0x10), is(false));
    }
}