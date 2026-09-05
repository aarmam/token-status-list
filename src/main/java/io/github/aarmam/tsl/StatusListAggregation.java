package io.github.aarmam.tsl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Implements the Status List Aggregation data structure defined in Section 9.3 of the
 * IETF OAuth Token Status List specification.
 * <p>
 * A Status List Aggregation publishes the URIs of one or more Status List Tokens issued by
 * the same Issuer, so that a Relying Party can fetch and cache them ahead of encountering a
 * specific URI in a Referenced Token. It is a JSON object with a single required member:
 * <ul>
 *   <li>{@code status_lists}: JSON array of strings containing URIs linking to Status List Tokens</li>
 * </ul>
 * The aggregation is served as {@code application/json}; see {@link #MEDIA_TYPE}.
 * <p>
 * A Relying Party iterating this list SHOULD continue processing the remaining URIs when one
 * of the Status List Tokens fails validation.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/">IETF OAuth Token Status List specification</a>
 */
@Getter
public class StatusListAggregation {
    static final String STATUS_LISTS_KEY = "status_lists";

    /**
     * The media type a Status List Aggregation MUST be returned with, per Section 9.3.
     */
    public static final String MEDIA_TYPE = "application/json";

    /**
     * The URIs of the Status List Tokens covered by this aggregation.
     */
    private final List<String> statusLists;

    /**
     * Creates a Status List Aggregation over the given Status List Token URIs.
     *
     * @param statusLists URIs linking to Status List Tokens
     */
    @Builder
    public StatusListAggregation(@NonNull Collection<String> statusLists) {
        this.statusLists = List.copyOf(statusLists);
    }

    /**
     * Parses a Status List Aggregation from its JSON representation.
     *
     * @param json JSON string containing the aggregation
     * @return A new StatusListAggregation instance
     * @throws IOException              If the JSON cannot be parsed
     * @throws IllegalArgumentException If the required status_lists member is missing
     */
    @Builder(builderMethodName = "buildFromJson", builderClassName = "BuildFromJson")
    public static StatusListAggregation fromJson(@NonNull String json) throws IOException {
        Map<String, Object> result = new ObjectMapper().readValue(json, new TypeReference<>() {
        });

        Object statusLists = result.get(STATUS_LISTS_KEY);
        if (!(statusLists instanceof List<?> uris)) {
            throw new IllegalArgumentException("Missing required member: " + STATUS_LISTS_KEY);
        }

        List<String> uriStrings = new ArrayList<>(uris.size());
        for (Object uri : uris) {
            if (!(uri instanceof String uriString)) {
                throw new IllegalArgumentException(STATUS_LISTS_KEY + " must contain only strings");
            }
            uriStrings.add(uriString);
        }
        return new StatusListAggregation(uriStrings);
    }

    /**
     * Encodes this Status List Aggregation as a Map suitable for JSON serialization.
     *
     * @return A Map containing the status_lists member
     */
    public Map<String, Object> encodeAsMap() {
        Map<String, Object> encoded = new LinkedHashMap<>();
        encoded.put(STATUS_LISTS_KEY, statusLists);
        return encoded;
    }

    /**
     * Encodes this Status List Aggregation as a JSON string.
     *
     * @return The JSON representation of this aggregation
     * @throws IOException If serialization fails
     */
    public String encodeAsJson() throws IOException {
        return new ObjectMapper().writeValueAsString(encodeAsMap());
    }
}
