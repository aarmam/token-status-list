package io.github.aarmam.tsl;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StatusListAggregationTest {

    // the Section 9.3 example
    private static final String EXAMPLE_JSON = """
            {
               "status_lists" : [
                  "https://example.com/statuslists/1",
                  "https://example.com/statuslists/2",
                  "https://example.com/statuslists/3"
               ]
            }""";

    @Test
    void testParsesSpecificationExample() throws IOException {
        StatusListAggregation aggregation = StatusListAggregation.buildFromJson()
                .json(EXAMPLE_JSON)
                .build();

        assertThat(aggregation.getStatusLists(), contains(
                "https://example.com/statuslists/1",
                "https://example.com/statuslists/2",
                "https://example.com/statuslists/3"));
    }

    @Test
    void testEncodesToSpecificationExample() throws IOException {
        StatusListAggregation aggregation = StatusListAggregation.builder()
                .statusLists(List.of(
                        "https://example.com/statuslists/1",
                        "https://example.com/statuslists/2",
                        "https://example.com/statuslists/3"))
                .build();

        assertThat(aggregation.encodeAsJson(), equalTo(
                "{\"status_lists\":[\"https://example.com/statuslists/1\","
                        + "\"https://example.com/statuslists/2\","
                        + "\"https://example.com/statuslists/3\"]}"));
        assertThat(StatusListAggregation.MEDIA_TYPE, equalTo("application/json"));
    }

    @Test
    void testRejectsMissingStatusLists() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> StatusListAggregation.buildFromJson().json("{}").build());
        assertThat(thrown.getMessage(), equalTo("Missing required member: status_lists"));
    }

    @Test
    void testRejectsNonStringEntries() {
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> StatusListAggregation.buildFromJson().json("{\"status_lists\":[1]}").build());
        assertThat(thrown.getMessage(), equalTo("status_lists must contain only strings"));
    }
}
