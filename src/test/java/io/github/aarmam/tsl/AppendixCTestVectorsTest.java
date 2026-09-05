package io.github.aarmam.tsl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

/**
 * Checks the implementation against the test vectors in Appendix C of the specification.
 * <p>
 * Section 11.1 warns that an incorrect implementation may check the index against the wrong
 * data or miscalculate the bit and byte index, and says implementations SHOULD verify
 * correctness using these vectors. Each vector is a 2^20 entry Status List; every index not
 * listed in the specification is VALID (0).
 * <p>
 * Only the decode direction is asserted byte-exactly. DEFLATE does not mandate a particular
 * encoder, so a conformant implementation need not reproduce the specification's compressed
 * bytes - it must reproduce the statuses they decode to.
 */
class AppendixCTestVectorsTest {

    private static final int SIZE = 1 << 20;

    private static Map<String, Map<String, Object>> vectors() throws IOException {
        try (InputStream in = AppendixCTestVectorsTest.class
                .getResourceAsStream("/appendix-c-vectors.json")) {
            return new ObjectMapper().readValue(in, new TypeReference<>() {
            });
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Integer> statuses(Map<String, Object> vector) {
        return (Map<String, Integer>) vector.get("statuses");
    }

    private static void assertMatchesVector(StatusList statusList, Map<String, Integer> statuses) {
        assertThat(statusList.size(), equalTo(SIZE));

        for (Map.Entry<String, Integer> entry : statuses.entrySet()) {
            int index = Integer.parseInt(entry.getKey());
            assertThat("status[" + index + "]", statusList.get(index), equalTo(entry.getValue()));
        }

        // every other index is VALID; walking the whole list also catches an encoder that
        // wrote the right values into the wrong bit positions
        int nonZero = 0;
        for (int i = 0; i < SIZE; i++) {
            if (statusList.get(i) != 0) {
                nonZero++;
            }
        }
        long expectedNonZero = statuses.values().stream().filter(value -> value != 0).count();
        assertThat((long) nonZero, equalTo(expectedNonZero));
    }

    @ParameterizedTest
    @ValueSource(strings = {"1", "2", "4", "8"})
    void testJsonVector(String bits) throws IOException {
        Map<String, Object> vector = vectors().get(bits);
        String json = "{\"bits\":" + bits + ",\"lst\":\"" + vector.get("lst") + "\"}";

        assertMatchesVector(StatusList.buildFromJson().json(json).build(), statuses(vector));
    }

    @ParameterizedTest
    @ValueSource(strings = {"1", "2", "4", "8"})
    void testCborVector(String bits) throws IOException {
        Map<String, Object> vector = vectors().get(bits);

        StatusList statusList = StatusList.buildFromCbor()
                .cborHex((String) vector.get("cbor"))
                .build();

        assertMatchesVector(statusList, statuses(vector));
    }

    @ParameterizedTest
    @ValueSource(strings = {"1", "2", "4", "8"})
    void testReEncodedVectorRoundTrips(String bits) throws IOException {
        Map<String, Object> vector = vectors().get(bits);
        Map<String, Integer> statuses = statuses(vector);

        StatusList built = new StatusList(SIZE, Integer.parseInt(bits));
        for (Map.Entry<String, Integer> entry : statuses.entrySet()) {
            built.set(Integer.parseInt(entry.getKey()), entry.getValue());
        }

        // our own compressed output need not match the specification's byte for byte, but it
        // must decode back to the same statuses through both representations
        assertMatchesVector(StatusList.buildFromCbor().cborHex(built.encodeAsCBORHex()).build(), statuses);
        assertMatchesVector(StatusList.buildFromJson()
                .json(new ObjectMapper().writeValueAsString(built.encodeAsMap(true)))
                .build(), statuses);
    }
}
