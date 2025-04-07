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
    void testApplicationSpecificStatus() {
        ExceptionInInitializerError thrown = assertThrows(
                ExceptionInInitializerError.class,
                () -> {
                    StatusType noop = AppSpecificStatus.INVALID_STATUS;
                }
        );
        assertThat(thrown.getException().getMessage(), equalTo("Not a valid application specific status"));
    }
}