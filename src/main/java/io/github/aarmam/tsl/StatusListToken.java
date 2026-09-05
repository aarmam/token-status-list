package io.github.aarmam.tsl;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSEException;
import com.authlete.cose.COSEProtectedHeader;
import com.authlete.cose.COSEProtectedHeaderBuilder;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSESign1Builder;
import com.authlete.cose.COSESigner;
import com.authlete.cose.COSEUnprotectedHeader;
import com.authlete.cose.COSEUnprotectedHeaderBuilder;
import com.authlete.cose.SigStructure;
import com.authlete.cose.SigStructureBuilder;
import com.authlete.cose.COSEVerifier;
import com.authlete.cwt.CWTClaimsSet;
import com.authlete.cwt.CWTClaimsSetBuilder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.PublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.Map;

/**
 * Represents a Status List Token that embeds a Status List into a cryptographically secured token.
 * <p>
 * A Status List Token contains a Status List which describes the statuses of multiple Referenced Tokens.
 * The Status List is a byte array that contains the statuses of many Referenced Tokens represented by one or multiple bits.
 * Each Referenced Token is allocated an index during issuance that represents its position within this bit array.
 * The value of the bit(s) at this index corresponds to the Referenced Token's status.
 * <p>
 * This class supports both JWT and CWT formats for the Status List Token as defined in the Token Status List specification.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/">IETF OAuth Token Status List specification</a>
 */
@Builder
@AllArgsConstructor
public class StatusListToken {
    static final int CWT_TTL_CLAIM = 65534;
    static final int CWT_STATUS_LIST_CLAIM = 65533;
    static final String STATUS_LIST_CLAIM = "status_list";
    static final int COSE_TYPE_HEADER = 16;
    static final String TTL_CLAIM = "ttl";
    /**
     * The JWT {@code typ} header value, as required by Section 5.1. Unlike the CWT type
     * header this is the bare subtype, without an {@code application/} prefix.
     */
    public static final String STATUS_LIST_TYP_JWT = "statuslist+jwt";
    /**
     * The CWT type (protected header 16) value, as required by Section 5.2. RFC 9596
     * carries a full media type here, so this is {@code application/statuslist+cwt} and
     * not the bare subtype.
     */
    public static final String STATUS_LIST_TYP_CWT = "application/statuslist+cwt";
    /**
     * The media type used for HTTP content negotiation of a Status List Token in JWT
     * format, as defined in Section 8.1 and registered in Section 14.7.
     */
    public static final String STATUS_LIST_MEDIA_TYPE_JWT = "application/statuslist+jwt";
    /**
     * The media type used for HTTP content negotiation of a Status List Token in CWT
     * format, as defined in Section 8.1 and registered in Section 14.7.
     */
    public static final String STATUS_LIST_MEDIA_TYPE_CWT = STATUS_LIST_TYP_CWT;
    private static final JOSEObjectType JOSE_STATUS_LIST_TYP_JWT = new JOSEObjectType(STATUS_LIST_TYP_JWT);

    private String subject;
    private Instant issuedAt;
    private Instant expiresAt;
    private Duration timeToLive;
    private StatusList statusList;
    private Key signingKey;
    private String keyId;

    /**
     * Verifies the signature of a Status List JWT and extracts the Status List.
     * <p>
     * This method parses the provided JWT string, verifies its signature using the provided public key,
     * and extracts the Status List from the JWT claims.
     *
     * @param statusListJwt        The Status List JWT string to verify and extract from
     * @param statusListSigningKey The public key used to verify the JWT signature
     * @return The extracted Status List if the signature verification is successful
     * @throws ParseException If the JWT string cannot be parsed
     * @throws JOSEException  If the JWT signature is invalid or if there's an error during verification
     * @throws IOException    If there's an error processing the Status List data
     */
    public static StatusList verifySignatureAndGetStatusList(@NonNull String statusListJwt, @NonNull PublicKey statusListSigningKey) throws ParseException, JOSEException, IOException {
        return verifySignatureAndGetStatusList(SignedJWT.parse(statusListJwt), statusListSigningKey, null);
    }

    /**
     * Verifies a Status List JWT against the URI the Referenced Token pointed at, and
     * extracts the Status List.
     * <p>
     * In addition to the signature, this applies the validation rules of Section 8.3: the
     * token type, the presence of the required claims, expiry, and step 4a - the subject
     * claim MUST equal the uri claim in the status_list object of the Referenced Token.
     *
     * @param statusListJwt        The Status List JWT string to verify and extract from
     * @param statusListSigningKey The public key used to verify the JWT signature
     * @param expectedUri          The uri from the Referenced Token's status_list claim, or null to skip step 4a
     * @return The extracted Status List if verification and validation succeed
     * @throws ParseException                  If the JWT string cannot be parsed
     * @throws JOSEException                   If the JWT signature is invalid
     * @throws IOException                     If there's an error processing the Status List data
     * @throws StatusListValidationException   If the token fails a Section 8.3 validation rule
     */
    public static StatusList verifySignatureAndGetStatusList(@NonNull String statusListJwt, @NonNull PublicKey statusListSigningKey, String expectedUri) throws ParseException, JOSEException, IOException {
        return verifySignatureAndGetStatusList(SignedJWT.parse(statusListJwt), statusListSigningKey, expectedUri);
    }

    /**
     * Verifies the signature of a parsed Status List JWT and extracts the Status List.
     * <p>
     * This method verifies the signature of the provided SignedJWT object using the provided public key,
     * and extracts the Status List from the JWT claims.
     *
     * @param statusList           The parsed SignedJWT object containing the Status List
     * @param statusListSigningKey The public key used to verify the JWT signature
     * @return The extracted Status List if the signature verification is successful
     * @throws ParseException If there's an error parsing the JWT claims
     * @throws JOSEException  If the JWT signature is invalid or if there's an error during verification
     * @throws IOException    If there's an error processing the Status List data
     */
    public static StatusList verifySignatureAndGetStatusList(@NonNull SignedJWT statusList, @NonNull PublicKey statusListSigningKey) throws ParseException, JOSEException, IOException {
        return verifySignatureAndGetStatusList(statusList, statusListSigningKey, null);
    }

    /**
     * Verifies a parsed Status List JWT against the URI the Referenced Token pointed at,
     * and extracts the Status List.
     * <p>
     * In addition to the signature, this applies the validation rules of Section 8.3: the
     * token type, the presence of the required claims, expiry, and step 4a - the subject
     * claim MUST equal the uri claim in the status_list object of the Referenced Token.
     *
     * @param statusList           The parsed SignedJWT object containing the Status List
     * @param statusListSigningKey The public key used to verify the JWT signature
     * @param expectedUri          The uri from the Referenced Token's status_list claim, or null to skip step 4a
     * @return The extracted Status List if verification and validation succeed
     * @throws ParseException                  If there's an error parsing the JWT claims
     * @throws JOSEException                   If the JWT signature is invalid
     * @throws IOException                     If there's an error processing the Status List data
     * @throws StatusListValidationException   If the token fails a Section 8.3 validation rule
     */
    public static StatusList verifySignatureAndGetStatusList(@NonNull SignedJWT statusList, @NonNull PublicKey statusListSigningKey, String expectedUri) throws ParseException, JOSEException, IOException {
        JWSVerifier verifier = Utils.getVerifier(statusListSigningKey);
        if (!statusList.verify(verifier)) {
            throw new JOSEException("Invalid JWT signature");
        }

        // Section 8.3 step 3b/4: the type distinguishes a Status List Token from any other
        // JWT the same key signs, so a Status List Token must not be accepted without it.
        JOSEObjectType type = statusList.getHeader().getType();
        if (type == null || !STATUS_LIST_TYP_JWT.equals(type.toString())) {
            throw new StatusListValidationException(
                    "Expected JWT type " + STATUS_LIST_TYP_JWT + " but was " + type);
        }

        JWTClaimsSet claims = statusList.getJWTClaimsSet();
        validateClaims(claims.getSubject(), claims.getIssueTime() == null ? null : claims.getIssueTime().toInstant(),
                claims.getExpirationTime() == null ? null : claims.getExpirationTime().toInstant(), expectedUri);

        Map<String, Object> statusListClaims = claims.getJSONObjectClaim(STATUS_LIST_CLAIM);
        if (statusListClaims == null) {
            throw new StatusListValidationException("Missing required claim: " + STATUS_LIST_CLAIM);
        }
        Object bits = statusListClaims.get(StatusList.BITS_KEY);
        Object lst = statusListClaims.get(StatusList.LST_KEY);
        if (!(bits instanceof Number bitsNumber)) {
            throw new StatusListValidationException(
                    "Missing or malformed Status List entry: " + StatusList.BITS_KEY);
        }
        if (!(lst instanceof String lstString)) {
            throw new StatusListValidationException(
                    "Missing or malformed Status List entry: " + StatusList.LST_KEY);
        }
        return StatusList.buildFromBytes()
                .bits(bitsNumber.intValue())
                .list(Base64.getUrlDecoder().decode(lstString))
                .build();
    }

    /**
     * Applies the claim-level validation rules of Section 8.3 step 4 that are common to the
     * JWT and CWT representations.
     *
     * @param subject     The sub (2) claim of the Status List Token
     * @param issuedAt    The iat (6) claim, which Section 5.1 and Section 5.2 make REQUIRED
     * @param expiresAt   The exp (4) claim, or null when the RECOMMENDED claim is absent
     * @param expectedUri The uri from the Referenced Token's status_list claim, or null to skip step 4a
     */
    private static void validateClaims(String subject, Instant issuedAt, Instant expiresAt, String expectedUri) {
        if (subject == null) {
            throw new StatusListValidationException("Missing required claim: sub");
        }
        if (issuedAt == null) {
            throw new StatusListValidationException("Missing required claim: iat");
        }
        // step 4a
        if (expectedUri != null && !expectedUri.equals(subject)) {
            throw new StatusListValidationException(
                    "Status List Token subject " + subject + " does not match the Referenced Token uri " + expectedUri);
        }
        // step 4c
        if (expiresAt != null && !Instant.now().isBefore(expiresAt)) {
            throw new StatusListValidationException("Status List Token expired at " + expiresAt);
        }
    }

    /**
     * Verifies the signature of a Status List CWT and extracts the Status List.
     * <p>
     * This is the CWT counterpart of {@link #verifySignatureAndGetStatusList(String, PublicKey)}.
     *
     * @param statusListCwtHex     The Status List CWT as a hexadecimal string
     * @param statusListSigningKey The public key used to verify the CWT signature
     * @return The extracted Status List if the signature verification is successful
     * @throws COSEException If the CWT signature is invalid or if there's an error during verification
     * @throws IOException   If there's an error processing the Status List data
     */
    public static StatusList verifySignatureAndGetStatusListFromCWT(@NonNull String statusListCwtHex, @NonNull PublicKey statusListSigningKey) throws COSEException, IOException {
        return verifySignatureAndGetStatusListFromCWT(HexFormat.of().parseHex(statusListCwtHex), statusListSigningKey, null);
    }

    /**
     * Verifies a Status List CWT against the URI the Referenced Token pointed at, and
     * extracts the Status List.
     *
     * @param statusListCwtHex     The Status List CWT as a hexadecimal string
     * @param statusListSigningKey The public key used to verify the CWT signature
     * @param expectedUri          The uri from the Referenced Token's status_list claim, or null to skip step 4a
     * @return The extracted Status List if verification and validation succeed
     * @throws COSEException                 If the CWT signature is invalid
     * @throws IOException                   If there's an error processing the Status List data
     * @throws StatusListValidationException If the token fails a Section 8.3 validation rule
     */
    public static StatusList verifySignatureAndGetStatusListFromCWT(@NonNull String statusListCwtHex, @NonNull PublicKey statusListSigningKey, String expectedUri) throws COSEException, IOException {
        return verifySignatureAndGetStatusListFromCWT(HexFormat.of().parseHex(statusListCwtHex), statusListSigningKey, expectedUri);
    }

    /**
     * Verifies the signature of a Status List CWT and extracts the Status List.
     * <p>
     * The CWT is expected in the raw binary form served by a Status Provider, that is a
     * tagged COSE_Sign1 (18) whose payload is the CWT Claims Set, as described in
     * Section 5.2 and Section 8.2.
     *
     * @param statusListCwt        The Status List CWT as a byte array
     * @param statusListSigningKey The public key used to verify the CWT signature
     * @return The extracted Status List if the signature verification is successful
     * @throws COSEException If the CWT signature is invalid or if there's an error during verification
     * @throws IOException   If there's an error processing the Status List data
     */
    public static StatusList verifySignatureAndGetStatusListFromCWT(byte @NonNull [] statusListCwt, @NonNull PublicKey statusListSigningKey) throws COSEException, IOException {
        return verifySignatureAndGetStatusListFromCWT(statusListCwt, statusListSigningKey, null);
    }

    /**
     * Verifies a Status List CWT against the URI the Referenced Token pointed at, and
     * extracts the Status List.
     * <p>
     * In addition to the signature, this applies the validation rules of Section 8.3: the
     * CWT type in protected header 16, the presence of the required claims, expiry, and
     * step 4a - the subject claim MUST equal the uri claim in the status_list object of
     * the Referenced Token.
     *
     * @param statusListCwt        The Status List CWT as a byte array
     * @param statusListSigningKey The public key used to verify the CWT signature
     * @param expectedUri          The uri from the Referenced Token's status_list claim, or null to skip step 4a
     * @return The extracted Status List if verification and validation succeed
     * @throws COSEException                 If the CWT signature is invalid
     * @throws IOException                   If there's an error processing the Status List data
     * @throws StatusListValidationException If the token fails a Section 8.3 validation rule
     */
    public static StatusList verifySignatureAndGetStatusListFromCWT(byte @NonNull [] statusListCwt, @NonNull PublicKey statusListSigningKey, String expectedUri) throws COSEException, IOException {
        CBORDecoder decoder = new CBORDecoder(new ByteArrayInputStream(statusListCwt));
        CBORTaggedItem taggedItem = (CBORTaggedItem) decoder.next();
        COSESign1 sign1 = (COSESign1) taggedItem.getTagContent();

        COSEVerifier verifier = new COSEVerifier(statusListSigningKey);
        if (!verifier.verify(sign1)) {
            throw new COSEException("Invalid CWT signature");
        }

        Object type = sign1.getProtectedHeader().getParameters().get(COSE_TYPE_HEADER);
        if (!STATUS_LIST_TYP_CWT.equals(type)) {
            throw new StatusListValidationException(
                    "Expected CWT type " + STATUS_LIST_TYP_CWT + " but was " + type);
        }

        CWTClaimsSet claims = CWTClaimsSet.build(sign1.getPayload());
        validateClaims(claims.getSub(),
                claims.getIat() == null ? null : claims.getIat().toInstant(),
                claims.getExp() == null ? null : claims.getExp().toInstant(),
                expectedUri);

        byte[] payload = (byte[]) sign1.getPayload().parse();
        CBORDecoder claimsDecoder = new CBORDecoder(new ByteArrayInputStream(payload));
        CBORPairList claimsPairList = (CBORPairList) claimsDecoder.next();

        for (CBORPair pair : claimsPairList.getPairs()) {
            Object key = pair.getKey().parse();
            if (key instanceof Number number && number.intValue() == CWT_STATUS_LIST_CLAIM) {
                return StatusList.buildFromCborBytes()
                        .cbor(pair.getValue().encode())
                        .build();
            }
        }

        throw new StatusListValidationException("Missing required claim: " + CWT_STATUS_LIST_CLAIM + " (status list)");
    }

    /**
     * Converts this Status List Token to a signed JWT format.
     * <p>
     * Creates a JWT with the required claims as specified in the Token Status List specification:
     * <ul>
     *   <li>sub (subject): URI of the Status List Token</li>
     *   <li>iat (issued at): Time at which the Status List Token was issued</li>
     *   <li>exp (expiration time): Time at which the Status List Token is considered expired</li>
     *   <li>ttl (time to live): Maximum amount of time in seconds that the Status List Token can be cached</li>
     *   <li>status_list: The Status List containing status information for Referenced Tokens</li>
     * </ul>
     * The JWT header includes the type "statuslist+jwt" and is signed using the configured signing key.
     *
     * @return A signed JWT representing this Status List Token
     * @throws JOSEException If there's an error during JWT signing
     * @throws IOException   If there's an error encoding the Status List
     */
    public String toSignedJWT() throws JOSEException, IOException {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .subject(subject)
                .issueTime(Date.from(issuedAt))
                .claim(STATUS_LIST_CLAIM, statusList.encodeAsMap(true));
        // exp and ttl are RECOMMENDED, not REQUIRED (Section 5.1) - omit them when unset
        if (expiresAt != null) {
            claimsBuilder.expirationTime(Date.from(expiresAt));
        }
        if (timeToLive != null) {
            claimsBuilder.claim(TTL_CLAIM, timeToLive.getSeconds());
        }
        JWTClaimsSet claims = claimsBuilder.build();
        JWSHeader header = new JWSHeader.Builder(Utils.getJWSAlgorithm(signingKey))
                .type(JOSE_STATUS_LIST_TYP_JWT)
                .keyID(keyId)
                .build();
        SignedJWT signedJwt = new SignedJWT(header, claims);
        JWSSigner signer = Utils.getSigner(signingKey);
        signedJwt.sign(signer);
        return signedJwt.serialize();
    }

    /**
     * Converts this Status List Token to a signed CWT (CBOR Web Token) format.
     * <p>
     * Creates a CWT with the required claims as specified in the Token Status List specification:
     * <ul>
     *   <li>2 (subject): URI of the Status List Token</li>
     *   <li>6 (issued at): Time at which the Status List Token was issued</li>
     *   <li>4 (expiration time): Time at which the Status List Token is considered expired</li>
     *   <li>65534 (time to live): Maximum amount of time in seconds that the Status List Token can be cached</li>
     *   <li>65533 (status list): The Status List containing status information for Referenced Tokens</li>
     * </ul>
     * The CWT protected header includes the type "application/statuslist+cwt" and is signed
     * using the configured signing key.
     * <p>
     * The hexadecimal encoding is for display and logging only. Section 8.2 requires the
     * HTTP response body to carry the raw binary form, which {@link #toSignedCWTBytes()}
     * returns.
     *
     * @return A hexadecimal string representation of the signed CWT
     * @throws COSEException If there's an error during CWT signing or encoding
     * @throws IOException   If there's an error encoding the Status List
     */
    public String toSignedCWT() throws COSEException, IOException {
        return HexFormat.of().formatHex(toSignedCWTBytes());
    }

    /**
     * Converts this Status List Token to a signed CWT in its raw binary form.
     * <p>
     * This is the encoding a Status Provider serves as the body of an
     * {@code application/statuslist+cwt} response: the binary encoding defined in
     * Section 9.2.1 of RFC 8392, as required by Section 8.2 of the specification. The
     * examples in the specification are shown in hex purely for readability.
     *
     * @return The signed CWT as a byte array
     * @throws COSEException If there's an error during CWT signing or encoding
     * @throws IOException   If there's an error encoding the Status List
     */
    public byte[] toSignedCWTBytes() throws COSEException, IOException {
        CWTClaimsSetBuilder claimsBuilder = new CWTClaimsSetBuilder()
                .sub(subject)
                .iat(issuedAt.getEpochSecond());
        // exp and the time to live claim are RECOMMENDED, not REQUIRED (Section 5.2)
        if (expiresAt != null) {
            claimsBuilder.exp(expiresAt.getEpochSecond());
        }
        if (timeToLive != null) {
            claimsBuilder.put(CWT_TTL_CLAIM, timeToLive.getSeconds());
        }
        CWTClaimsSet claims = claimsBuilder
                .put(CWT_STATUS_LIST_CLAIM, statusList.encodeAsMap(false))
                .build();
        byte[] encodedClaims = claims.encode();
        int algorithm = Utils.getCOSEAlgorithm(signingKey);
        COSEProtectedHeader protectedHeader = new COSEProtectedHeaderBuilder()
                .alg(algorithm)
                .put(COSE_TYPE_HEADER, STATUS_LIST_TYP_CWT)
                .build();
        COSEUnprotectedHeader unprotectedHeader = new COSEUnprotectedHeaderBuilder().kid(keyId).build();
        CBORByteArray payload = new CBORByteArray(encodedClaims);
        SigStructure structure = new SigStructureBuilder()
                .signature1()
                .bodyAttributes(protectedHeader)
                .payload(payload)
                .build();
        COSESigner signer = new COSESigner(signingKey);
        byte[] signature = signer.sign(structure, algorithm);
        COSESign1 sign1 = new COSESign1Builder()
                .protectedHeader(protectedHeader)
                .unprotectedHeader(unprotectedHeader)
                .payload(payload)
                .signature(signature)
                .build();
        return sign1.getTagged().encode();
    }
}
