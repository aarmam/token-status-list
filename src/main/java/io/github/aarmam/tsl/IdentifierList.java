package io.github.aarmam.tsl;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORizer;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Implements an Identifier List as defined in ISO/IEC 18013-5:2021.
 * <p>
 * An Identifier List is a mechanism to revoke MSOs (Mobile Security Objects) based on whether
 * an issuer-defined identifier in the MSO is present on the identifier list. Unlike the Status List
 * mechanism which uses bit positions, the Identifier List mechanism revokes based on the presence
 * of specific identifiers in a map structure.
 * <p>
 * The Identifier List is encoded as a CBOR structure containing:
 * <ul>
 *   <li>"identifiers": A map of byte string identifiers to IdentifierInfo structures</li>
 *   <li>"aggregation_uri" (optional): URI for aggregation mechanism</li>
 * </ul>
 * <p>
 * The presence of an identifier in the list indicates that the MSO containing that identifier
 * in its status element is revoked.
 *
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021</a>
 */
public class IdentifierList {
    @Getter
    private final Map<ByteArrayWrapper, IdentifierInfo> identifiers;
    @Getter
    private final String aggregationUri;

    /**
     * Creates a new empty Identifier List without an aggregation URI.
     */
    public IdentifierList() {
        this(null);
    }

    /**
     * Creates a new empty Identifier List with an optional aggregation URI.
     *
     * @param aggregationUri Optional URI for the aggregation mechanism as defined in the Token Status List specification
     */
    public IdentifierList(String aggregationUri) {
        this.identifiers = new HashMap<>();
        this.aggregationUri = aggregationUri;
    }

    @Builder(access = AccessLevel.PRIVATE)
    private IdentifierList(Map<ByteArrayWrapper, IdentifierInfo> identifiers, String aggregationUri) {
        this.identifiers = identifiers != null ? identifiers : new HashMap<>();
        this.aggregationUri = aggregationUri;
    }

    /**
     * Creates an Identifier List from a JSON string.
     *
     * @param json JSON string containing the identifier list data
     * @return A new IdentifierList instance
     * @throws IOException If the JSON cannot be parsed
     */
    @Builder(builderMethodName = "buildFromJson", builderClassName = "BuildFromJson")
    public static IdentifierList fromJson(@NonNull String json) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> result = objectMapper.readValue(json, new TypeReference<>() {
        });

        Map<ByteArrayWrapper, IdentifierInfo> identifiers = new HashMap<>();
        @SuppressWarnings("unchecked")
        Map<String, Object> identifiersMap = (Map<String, Object>) result.get("identifiers");

        if (identifiersMap != null) {
            for (Map.Entry<String, Object> entry : identifiersMap.entrySet()) {
                byte[] identifier = Base64.getUrlDecoder().decode(entry.getKey());
                identifiers.put(new ByteArrayWrapper(identifier), new IdentifierInfo());
            }
        }

        String aggregationUri = (String) result.get("aggregation_uri");

        return IdentifierList.builder()
                .identifiers(identifiers)
                .aggregationUri(aggregationUri)
                .build();
    }

    /**
     * Creates an Identifier List from CBOR-encoded bytes.
     *
     * @param cbor CBOR-encoded byte array containing the identifier list
     * @return A new IdentifierList instance
     * @throws IOException If the CBOR cannot be parsed
     */
    @Builder(builderMethodName = "buildFromCbor", builderClassName = "BuildFromCbor")
    public static IdentifierList fromCbor(byte @NonNull [] cbor) throws IOException {
        CBORDecoder decoder = new CBORDecoder(new ByteArrayInputStream(cbor));
        CBORPairList pairList = (CBORPairList) decoder.next();
        List<? extends CBORPair> pairs = pairList.getPairs();

        Map<ByteArrayWrapper, IdentifierInfo> identifiers = new HashMap<>();
        String aggregationUri = null;

        for (CBORPair pair : pairs) {
            String key = (String) pair.getKey().parse();
            if ("identifiers".equals(key)) {
                CBORPairList identifiersPairList = (CBORPairList) pair.getValue();
                for (CBORPair identifierPair : identifiersPairList.getPairs()) {
                    byte[] identifier = (byte[]) identifierPair.getKey().parse();
                    identifiers.put(new ByteArrayWrapper(identifier), new IdentifierInfo());
                }
            } else if ("aggregation_uri".equals(key)) {
                aggregationUri = (String) pair.getValue().parse();
            }
        }

        return IdentifierList.builder()
                .identifiers(identifiers)
                .aggregationUri(aggregationUri)
                .build();
    }

    /**
     * Adds an identifier to the revocation list.
     * <p>
     * Adding an identifier indicates that any MSO containing this identifier should be considered revoked.
     *
     * @param identifier The identifier to add (byte string)
     */
    public void addIdentifier(byte @NonNull [] identifier) {
        identifiers.put(new ByteArrayWrapper(identifier), new IdentifierInfo());
    }

    /**
     * Removes an identifier from the revocation list.
     * <p>
     * Removing an identifier indicates that any MSO containing this identifier should no longer be considered revoked
     * (assuming it was previously revoked via this list).
     *
     * @param identifier The identifier to remove (byte string)
     */
    public void removeIdentifier(byte @NonNull [] identifier) {
        identifiers.remove(new ByteArrayWrapper(identifier));
    }

    /**
     * Checks if an identifier is present in the revocation list.
     * <p>
     * The presence of an identifier in the list indicates that the MSO containing that identifier is revoked.
     *
     * @param identifier The identifier to check (byte string)
     * @return true if the identifier is revoked (present in the list), false otherwise
     */
    public boolean isRevoked(byte @NonNull [] identifier) {
        return identifiers.containsKey(new ByteArrayWrapper(identifier));
    }

    /**
     * Returns the number of identifiers in the revocation list.
     *
     * @return The count of revoked identifiers
     */
    public int size() {
        return identifiers.size();
    }

    /**
     * Encodes this Identifier List as a Map that can be used in JSON format.
     * <p>
     * The returned Map contains:
     * <ul>
     *   <li>"identifiers": A map of base64url-encoded identifiers to empty objects</li>
     *   <li>"aggregation_uri" (optional): The aggregation URI if present</li>
     * </ul>
     *
     * @return A Map representing this Identifier List
     */
    public Map<String, Object> encodeAsMap() {
        Map<String, Object> result = new LinkedHashMap<>();

        Map<String, Object> identifiersMap = new LinkedHashMap<>();
        for (ByteArrayWrapper wrapper : identifiers.keySet()) {
            String encodedId = Base64.getUrlEncoder().withoutPadding().encodeToString(wrapper.data);
            identifiersMap.put(encodedId, new LinkedHashMap<>());
        }
        result.put("identifiers", identifiersMap);

        if (aggregationUri != null) {
            result.put("aggregation_uri", aggregationUri);
        }

        return result;
    }

    /**
     * Encodes this Identifier List as a CBOR byte array according to ISO/IEC 18013-5:2021.
     * <p>
     * The CBOR structure contains:
     * <ul>
     *   <li>"identifiers": A map of byte string identifiers to empty maps (IdentifierInfo)</li>
     *   <li>"aggregation_uri" (optional): The aggregation URI if present</li>
     * </ul>
     *
     * @return A byte array containing the CBOR-encoded Identifier List
     * @throws IOException If CBOR encoding fails
     */
    public byte[] encodeAsCBOR() throws IOException {
        Map<Object, Object> cborMap = new LinkedHashMap<>();

        // Build identifiers map
        Map<Object, Object> identifiersMap = new LinkedHashMap<>();
        for (ByteArrayWrapper wrapper : identifiers.keySet()) {
            // Key is byte array, value is empty map (IdentifierInfo)
            identifiersMap.put(wrapper.data, new LinkedHashMap<>());
        }
        cborMap.put("identifiers", identifiersMap);

        if (aggregationUri != null) {
            cborMap.put("aggregation_uri", aggregationUri);
        }

        return new CBORizer().cborizeMap(cborMap).encode();
    }

    /**
     * Wrapper class for byte arrays to enable proper equality and hashing in HashMap.
     * <p>
     * This is necessary because byte[] does not override equals() and hashCode() properly.
     */
    static class ByteArrayWrapper {
        private final byte[] data;
        private final int hashCode;

        ByteArrayWrapper(byte[] data) {
            this.data = data;
            this.hashCode = Arrays.hashCode(data);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;
            ByteArrayWrapper that = (ByteArrayWrapper) obj;
            return Arrays.equals(data, that.data);
        }

        @Override
        public int hashCode() {
            return hashCode;
        }
    }

    /**
     * Represents the IdentifierInfo structure as defined in ISO/IEC 18013-5:2021.
     * <p>
     * Per the specification, this is an empty CBOR map structure.
     */
    public static class IdentifierInfo {
        /**
         * Converts this IdentifierInfo to a CBOR-compatible map.
         * Per the specification, this returns an empty map.
         *
         * @return An empty map
         */
        public Map<Object, Object> toCBOR() {
            return new LinkedHashMap<>();
        }
    }
}
