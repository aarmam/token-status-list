package io.github.aarmam.tsl;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORizer;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Represents the {@code status_list} reference a Referenced Token carries in its
 * {@code status} claim, as defined in Section 6.2 (JOSE) and Section 6.3 (COSE) of the
 * IETF OAuth Token Status List specification.
 * <p>
 * The structure has two required members:
 * <ul>
 *   <li>{@code idx}: the index to check for status information in the Status List</li>
 *   <li>{@code uri}: the URI identifying the Status List Token</li>
 * </ul>
 * In a JWT this sits at {@code status.status_list}; in a CWT the Status structure is
 * carried in claim {@value #CWT_STATUS_CLAIM}, keyed by the status mechanism identifier.
 * <p>
 * The {@code status} claim is an extension point: it MUST contain at least one status
 * mechanism, and {@code status_list} is the one this specification defines. Use
 * {@link #encodeAsStatusClaim()} to wrap this reference in that claim.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/">IETF OAuth Token Status List specification</a>
 */
@Builder
@AllArgsConstructor
@Getter
public class StatusListInfo {
    /**
     * The CWT claim carrying the Status structure of a Referenced Token (Section 6.3).
     */
    public static final int CWT_STATUS_CLAIM = 65535;
    /**
     * The name of the {@code status} claim in a JOSE-based Referenced Token (Section 6.2).
     */
    public static final String STATUS_CLAIM = "status";
    /**
     * The status mechanism identifier defined by this specification.
     */
    public static final String STATUS_LIST_MECHANISM = "status_list";

    static final String IDX_KEY = "idx";
    static final String URI_KEY = "uri";

    /**
     * The index of this Referenced Token within the Status List. Non-negative.
     */
    private final int idx;

    /**
     * The URI identifying the Status List Token that holds this token's status.
     */
    @NonNull
    private final String uri;

    /**
     * Creates a StatusListInfo, rejecting a negative index.
     *
     * @param idx The index within the Status List
     * @param uri The URI of the Status List Token
     * @return A new StatusListInfo instance
     */
    public static StatusListInfo of(int idx, @NonNull String uri) {
        if (idx < 0) {
            throw new IllegalArgumentException("idx must be a non-negative integer");
        }
        return new StatusListInfo(idx, uri);
    }

    /**
     * Parses a StatusListInfo from the {@code status_list} object of a Referenced Token.
     *
     * @param map The decoded status_list object
     * @return A new StatusListInfo instance
     * @throws IllegalArgumentException If a required member is missing or malformed
     */
    @Builder(builderMethodName = "buildFromMap", builderClassName = "BuildFromMap")
    public static StatusListInfo fromMap(@NonNull Map<String, Object> map) {
        if (!(map.get(IDX_KEY) instanceof Number idx)) {
            throw new IllegalArgumentException("Missing or malformed status_list member: " + IDX_KEY);
        }
        if (!(map.get(URI_KEY) instanceof String uri)) {
            throw new IllegalArgumentException("Missing or malformed status_list member: " + URI_KEY);
        }
        return of(idx.intValue(), uri);
    }

    /**
     * Parses a StatusListInfo from the {@code status} claim of a JOSE-based Referenced Token.
     *
     * @param statusClaim The decoded status claim
     * @return A new StatusListInfo instance
     * @throws IllegalArgumentException If the claim carries no status_list mechanism
     */
    @SuppressWarnings("unchecked")
    public static StatusListInfo fromStatusClaim(@NonNull Map<String, Object> statusClaim) {
        Object statusList = statusClaim.get(STATUS_LIST_MECHANISM);
        if (!(statusList instanceof Map<?, ?>)) {
            throw new IllegalArgumentException("Missing status mechanism: " + STATUS_LIST_MECHANISM);
        }
        return fromMap((Map<String, Object>) statusList);
    }

    /**
     * Parses a StatusListInfo from the JSON representation of a {@code status_list} object.
     *
     * @param json JSON string containing the status_list object
     * @return A new StatusListInfo instance
     * @throws IOException If the JSON cannot be parsed
     */
    @Builder(builderMethodName = "buildFromJson", builderClassName = "BuildFromJson")
    public static StatusListInfo fromJson(@NonNull String json) throws IOException {
        return fromMap(new ObjectMapper().readValue(json, new TypeReference<>() {
        }));
    }

    /**
     * Parses a StatusListInfo from the CBOR StatusListInfo structure of Section 6.3.
     *
     * @param cbor CBOR-encoded status_list structure
     * @return A new StatusListInfo instance
     * @throws IOException If the CBOR cannot be parsed
     */
    @Builder(builderMethodName = "buildFromCbor", builderClassName = "BuildFromCbor")
    public static StatusListInfo fromCbor(byte @NonNull [] cbor) throws IOException {
        CBORDecoder decoder = new CBORDecoder(new ByteArrayInputStream(cbor));
        CBORPairList pairList = (CBORPairList) decoder.next();

        Map<String, Object> members = new LinkedHashMap<>();
        for (CBORPair pair : pairList.getPairs()) {
            Object key = pair.getKey().parse();
            if (key instanceof String name) {
                members.put(name, pair.getValue().parse());
            }
        }
        return fromMap(members);
    }

    /**
     * Encodes this reference as the {@code status_list} object of a Referenced Token.
     *
     * @return A Map with the idx and uri members
     */
    public Map<String, Object> encodeAsMap() {
        Map<String, Object> encoded = new LinkedHashMap<>();
        encoded.put(IDX_KEY, idx);
        encoded.put(URI_KEY, uri);
        return encoded;
    }

    /**
     * Encodes this reference as the full {@code status} claim of a Referenced Token, that is
     * {@code {"status_list": {"idx": ..., "uri": ...}}}.
     *
     * @return A Map suitable for use as the value of the status claim
     */
    public Map<String, Object> encodeAsStatusClaim() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put(STATUS_LIST_MECHANISM, encodeAsMap());
        return status;
    }

    /**
     * Encodes this reference as the CBOR StatusListInfo structure of Section 6.3.
     *
     * @return A byte array containing the CBOR-encoded structure
     * @throws IOException If CBOR encoding fails
     */
    public byte[] encodeAsCBOR() throws IOException {
        Map<Object, Object> encoded = new LinkedHashMap<>();
        encoded.put(IDX_KEY, idx);
        encoded.put(URI_KEY, uri);
        return new CBORizer().cborizeMap(encoded).encode();
    }

    /**
     * Encodes this reference as the CBOR Status structure carried in CWT claim
     * {@value #CWT_STATUS_CLAIM}, that is a map keyed by the status mechanism identifier.
     *
     * @return A byte array containing the CBOR-encoded Status structure
     * @throws IOException If CBOR encoding fails
     */
    public byte[] encodeAsStatusClaimCBOR() throws IOException {
        Map<Object, Object> status = new LinkedHashMap<>();
        Map<Object, Object> statusList = new LinkedHashMap<>();
        statusList.put(IDX_KEY, idx);
        statusList.put(URI_KEY, uri);
        status.put(STATUS_LIST_MECHANISM, statusList);
        return new CBORizer().cborizeMap(status).encode();
    }
}
