package io.github.aarmam.tsl;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORizer;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

/**
 * Implements a Status List as defined in the IETF OAuth Token Status List specification.
 * <p>
 * A Status List is a byte array that contains the statuses of many Referenced Tokens represented by one or multiple bits.
 * Each status of a Referenced Token is represented with a bit-size of 1, 2, 4, or 8, allowing for up to 2, 4, 16, or 256
 * different status values respectively.
 * <p>
 * The Status List is encoded as a byte array where each byte corresponds to 8/(bit-size) statuses.
 * The status of each Referenced Token is identified using an index that maps to specific bits within the byte array.
 * For transmission and storage efficiency, the byte array is compressed using DEFLATE with the ZLIB data format.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/">IETF OAuth Token Status List specification</a>
 */
public class StatusList {
    private final int bits;
    private final byte[] list;
    private final int divisor;
    private final int size;
    private final int valueMask;

    /**
     * Creates a new Status List with the specified size and bits per status.
     * <p>
     * The size parameter determines how many tokens can be represented in this Status List.
     * The bits parameter determines how many bits are used to represent each token's status,
     * which affects how many different status values can be represented:
     * <ul>
     *   <li>1 bit: 2 possible status values (0-1)</li>
     *   <li>2 bits: 4 possible status values (0-3)</li>
     *   <li>4 bits: 16 possible status values (0-15)</li>
     *   <li>8 bits: 256 possible status values (0-255)</li>
     * </ul>
     *
     * @param size The number of tokens that can be represented in this Status List
     * @param bits The number of bits used to represent each token's status (1, 2, 4, or 8)
     * @throws IllegalArgumentException if size is not positive, bits is not 1, 2, 4, or 8,
     *                                  or size is not a multiple of 8/bits
     */
    public StatusList(int size, int bits) {
        if (size <= 0) {
            throw new IllegalArgumentException("Size must be positive");
        }
        validateBits(bits);
        this.divisor = 8 / bits;
        if (size % this.divisor != 0) {
            throw new IllegalArgumentException("Size must be a multiple of " + this.divisor +
                    " for " + bits + "-bit value");
        }
        this.bits = bits;
        this.size = size;
        this.valueMask = (1 << bits) - 1;
        this.list = new byte[size / this.divisor];
    }

    @Builder(access = AccessLevel.PRIVATE)
    private StatusList(int bits, byte[] list, int divisor, int size, int valueMask) {
        validateBits(bits);
        this.bits = bits;
        this.list = list;
        this.divisor = divisor;
        this.size = size;
        this.valueMask = valueMask;
    }

    @Builder(builderMethodName = "buildFromBytes", builderClassName = "BuildFromEncoded")
    public static StatusList fromBytes(int bits, byte[] list) throws IOException {
        return StatusList.builder()
                .bits(bits)
                .divisor(8 / bits)
                .valueMask((1 << bits) - 1)
                .size(list.length * 8 / bits)
                .list(decompress(list))
                .build();
    }

    @Builder(builderMethodName = "buildFromJson", builderClassName = "BuildFromJson")
    public static StatusList fromJson(String json) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> result = objectMapper.readValue(json, new TypeReference<>() {
        });
        int bits = (Integer) result.get("bits");
        byte[] list = decompress(Base64.getUrlDecoder().decode((String) result.get("lst")));
        return StatusList.builder()
                .bits(bits)
                .divisor(8 / bits)
                .valueMask((1 << bits) - 1)
                .size(list.length * 8 / bits)
                .list(list)
                .build();
    }

    @Builder(builderMethodName = "buildFromCbor", builderClassName = "BuildFromCbor")
    public static StatusList fromCbor(String cborHex) throws IOException {
        byte[] cbor = HexFormat.of().parseHex(cborHex);
        CBORDecoder decoder = new CBORDecoder(new ByteArrayInputStream(cbor));
        CBORPairList pairList = (CBORPairList) decoder.next();
        List<? extends CBORPair> pairs = pairList.getPairs();
        int bits = (int) pairs.getFirst().getValue().parse();
        byte[] list = decompress((byte[]) pairs.getLast().getValue().parse());
        return StatusList.builder()
                .bits(bits)
                .divisor(8 / bits)
                .valueMask((1 << bits) - 1)
                .size(list.length * 8 / bits)
                .list(list)
                .build();
    }

    private static void validateBits(int bits) {
        if (bits != 1 && bits != 2 && bits != 4 && bits != 8) {
            throw new IllegalArgumentException("Bits must be 1, 2, 4, or 8");
        }
    }

    private static byte[] compress(byte @NonNull [] input) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        DeflaterOutputStream dos = new DeflaterOutputStream(baos, deflater, false);
        try {
            dos.write(input);
        } finally {
            dos.flush();
            dos.close();
            deflater.end();
        }
        return baos.toByteArray();
    }

    private static byte[] decompress(byte @NonNull [] input) throws IOException {
        try (InflaterInputStream iis = new InflaterInputStream(new ByteArrayInputStream(input))) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            iis.transferTo(baos);
            return baos.toByteArray();
        }
    }

    /**
     * Sets the status value for a token at the specified index using a StatusType enum.
     * <p>
     * This is a convenience method that calls {@link #set(int, int)} with the numeric value
     * of the provided StatusType.
     *
     * @param index  The index of the token in the Status List
     * @param status The StatusType value to set
     * @throws IndexOutOfBoundsException if the index is out of range
     */
    public void set(int index, StatusType status) {
        set(index, status.getValue());
    }

    /**
     * Sets the status value for a token at the specified index.
     * <p>
     * The status value must be within the valid range for the bit size of this Status List:
     * <ul>
     *   <li>1 bit: 0-1</li>
     *   <li>2 bits: 0-3</li>
     *   <li>4 bits: 0-15</li>
     *   <li>8 bits: 0-255</li>
     * </ul>
     *
     * @param index  The index of the token in the Status List
     * @param status The status value to set
     * @throws IndexOutOfBoundsException if the index is out of range
     * @throws IllegalArgumentException  if the status value is outside the valid range for the bit size
     */
    public void set(int index, int status) {
        Objects.checkIndex(index, size);
        if (status < 0 || status > valueMask) {
            throw new IllegalArgumentException("Status value " + status +
                    " is outside valid range [0, " + valueMask + "] for " + bits + "-bit value");
        }
        final int bytePos = index / divisor;
        final int shift = (index % divisor) * bits;
        list[bytePos] = (byte) ((list[bytePos] & ~(valueMask << shift)) | (status << shift));
    }

    /**
     * Gets the status value for a token at the specified index.
     * <p>
     * The returned value will be within the range determined by the bit size of this Status List:
     * <ul>
     *   <li>1 bit: 0-1</li>
     *   <li>2 bits: 0-3</li>
     *   <li>4 bits: 0-15</li>
     *   <li>8 bits: 0-255</li>
     * </ul>
     *
     * @param index The index of the token in the Status List
     * @return The status value at the specified index
     * @throws IndexOutOfBoundsException if the index is out of range
     */
    public int get(int index) {
        Objects.checkIndex(index, size);
        final int bytePos = index / divisor;
        final int shift = (index % divisor) * bits;
        return (list[bytePos] >> shift) & valueMask;
    }

    /**
     * Encodes this Status List as a Map that can be used in JSON or similar formats.
     * <p>
     * The returned Map contains:
     * <ul>
     *   <li>"bits": The number of bits per status (1, 2, 4, or 8)</li>
     *   <li>"lst": The compressed Status List, either as a byte array or base64url-encoded string</li>
     * </ul>
     *
     * @param base64EncodeList If true, the "lst" value will be base64url-encoded; otherwise, it will be a byte array
     * @return A Map representing this Status List
     * @throws IOException If compression fails
     */
    public Map<String, Object> encodeAsMap(boolean base64EncodeList) throws IOException {
        return new LinkedHashMap<>() {{
            put("bits", bits);
            put("lst", base64EncodeList ? Base64.getUrlEncoder().withoutPadding().encodeToString(compress(list)) : compress(list));
        }};
    }

    /**
     * Encodes this Status List as a CBOR byte array.
     * <p>
     * The CBOR structure contains:
     * <ul>
     *   <li>"bits": The number of bits per status (1, 2, 4, or 8)</li>
     *   <li>"lst": The compressed Status List as a byte string</li>
     * </ul>
     *
     * @return A byte array containing the CBOR-encoded Status List
     * @throws IOException If compression or CBOR encoding fails
     */
    public byte[] encodeAsCBOR() throws IOException {
        return new CBORizer().cborizeMap(
                new LinkedHashMap<>() {{
                    put("bits", bits);
                    put("lst", compress(list));
                }}).encode();
    }

    /**
     * Encodes this Status List as a hexadecimal string representation of the CBOR encoding.
     * <p>
     * This is a convenience method that calls {@link #encodeAsCBOR()} and converts the result to a hex string.
     *
     * @return A hexadecimal string representation of the CBOR-encoded Status List
     * @throws IOException If compression or CBOR encoding fails
     */
    public String encodeAsCBORHex() throws IOException {
        return HexFormat.of().formatHex(encodeAsCBOR());
    }

    /**
     * Encodes this Status List as a compressed byte array.
     * <p>
     * This method returns just the compressed list without any additional metadata.
     *
     * @return A byte array containing the compressed Status List
     * @throws IOException If compression fails
     */
    public byte[] encodeAsBytes() throws IOException {
        return compress(list);
    }
}
