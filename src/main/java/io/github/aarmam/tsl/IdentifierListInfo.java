package io.github.aarmam.tsl;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORizer;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents the identifier_list element in an MSO's Status structure as defined in ISO/IEC 18013-5:2021.
 * <p>
 * The IdentifierListInfo structure is a CBOR structure with the following CDDL:
 * <pre>
 * IdentifierListInfo = {
 *     "id": Identifier,
 *     "uri": URI,
 *     ? "certificate": Certificate
 * }
 * </pre>
 * <p>
 * This structure is used in the MSO (Mobile Security Object) to reference an identifier list
 * for revocation checking. The identifier must be unique per MSO, and its presence in the
 * identifier list indicates that the MSO is revoked.
 *
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021</a>
 */
@Builder
@AllArgsConstructor
@Getter
public class IdentifierListInfo {
    /**
     * The identifier (byte string) that uniquely identifies this MSO.
     * The value of this identifier shall be unique per MSO.
     */
    @NonNull
    private final byte[] id;

    /**
     * The URI where the identifier list can be retrieved.
     * This URI points to an Identifier List Token.
     */
    @NonNull
    private final String uri;

    /**
     * Optional certificate containing the public key that signed the top-level certificate
     * in the x5chain element in the MSO revocation list structure.
     * <p>
     * If present, the mdoc reader shall use this certificate as trust point for verification
     * of the x5chain element in the MSO revocation list structure. If not present, the top-level
     * certificate in the x5chain element shall be signed by the certificate used to sign the
     * certificate in the x5chain element of the MSO (i.e., the IACA certificate in the context of an mDL).
     */
    private final Certificate certificate;

    /**
     * Creates an IdentifierListInfo from a CBOR-encoded byte array.
     *
     * @param cbor The CBOR-encoded identifier list info
     * @return A new IdentifierListInfo instance
     * @throws IOException              If the CBOR cannot be parsed
     * @throws CertificateException     If the certificate cannot be parsed
     */
    @Builder(builderMethodName = "buildFromCbor", builderClassName = "BuildFromCbor")
    public static IdentifierListInfo fromCbor(byte @NonNull [] cbor) throws IOException, CertificateException {
        CBORDecoder decoder = new CBORDecoder(new ByteArrayInputStream(cbor));
        CBORPairList pairList = (CBORPairList) decoder.next();
        List<? extends CBORPair> pairs = pairList.getPairs();

        byte[] id = null;
        String uri = null;
        Certificate certificate = null;

        for (CBORPair pair : pairs) {
            String key = (String) pair.getKey().parse();
            switch (key) {
                case "id":
                    id = (byte[]) pair.getValue().parse();
                    break;
                case "uri":
                    uri = (String) pair.getValue().parse();
                    break;
                case "certificate":
                    byte[] certBytes = (byte[]) pair.getValue().parse();
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    certificate = cf.generateCertificate(new ByteArrayInputStream(certBytes));
                    break;
            }
        }

        if (id == null || uri == null) {
            throw new IllegalArgumentException("Missing required fields: id and uri must be present");
        }

        return new IdentifierListInfo(id, uri, certificate);
    }

    /**
     * Creates an IdentifierListInfo from a Map (typically from JSON parsing).
     *
     * @param map The map containing identifier list info data
     * @return A new IdentifierListInfo instance
     * @throws CertificateException If the certificate cannot be parsed
     */
    @Builder(builderMethodName = "buildFromMap", builderClassName = "BuildFromMap")
    public static IdentifierListInfo fromMap(@NonNull Map<String, Object> map) throws CertificateException {
        String idString = (String) map.get("id");
        if (idString == null) {
            throw new IllegalArgumentException("Missing required field: id");
        }
        byte[] id = Base64.getUrlDecoder().decode(idString);

        String uri = (String) map.get("uri");
        if (uri == null) {
            throw new IllegalArgumentException("Missing required field: uri");
        }

        Certificate certificate = null;
        String certString = (String) map.get("certificate");
        if (certString != null) {
            byte[] certBytes = Base64.getUrlDecoder().decode(certString);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certificate = cf.generateCertificate(new ByteArrayInputStream(certBytes));
        }

        return new IdentifierListInfo(id, uri, certificate);
    }

    /**
     * Encodes this IdentifierListInfo as a CBOR byte array according to ISO/IEC 18013-5:2021.
     *
     * @return A byte array containing the CBOR-encoded IdentifierListInfo
     * @throws IOException                  If CBOR encoding fails
     * @throws CertificateEncodingException If the certificate encoding fails
     */
    public byte[] encodeAsCBOR() throws IOException, CertificateEncodingException {
        Map<Object, Object> cborMap = new LinkedHashMap<>();
        cborMap.put("id", id);
        cborMap.put("uri", uri);
        if (certificate != null) {
            cborMap.put("certificate", certificate.getEncoded());
        }
        return new CBORizer().cborizeMap(cborMap).encode();
    }

    /**
     * Encodes this IdentifierListInfo as a Map suitable for JSON encoding.
     *
     * @return A Map containing the identifier list info data
     * @throws CertificateEncodingException If the certificate encoding fails
     */
    public Map<String, Object> encodeAsMap() throws CertificateEncodingException {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", Base64.getUrlEncoder().withoutPadding().encodeToString(id));
        map.put("uri", uri);
        if (certificate != null) {
            map.put("certificate", Base64.getUrlEncoder().withoutPadding().encodeToString(certificate.getEncoded()));
        }
        return map;
    }
}
