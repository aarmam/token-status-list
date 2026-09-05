package io.github.aarmam.tsl;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cose.COSEException;
import com.authlete.cose.COSEProtectedHeader;
import com.authlete.cose.COSEProtectedHeaderBuilder;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSESign1Builder;
import com.authlete.cose.COSESigner;
import com.authlete.cose.COSEUnprotectedHeader;
import com.authlete.cose.COSEUnprotectedHeaderBuilder;
import com.authlete.cose.COSEVerifier;
import com.authlete.cose.SigStructure;
import com.authlete.cose.SigStructureBuilder;
import com.authlete.cwt.CWT;
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
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Represents an Identifier List Token as defined in ISO/IEC 18013-5:2021.
 * <p>
 * An Identifier List Token embeds an Identifier List into a cryptographically secured token.
 * The Identifier List contains identifiers of revoked MSOs (Mobile Security Objects).
 * <p>
 * Key differences from Status List Token:
 * <ul>
 *   <li>Type: "identifierlist+cwt" instead of "statuslist+cwt"</li>
 *   <li>Type: "identifierlist+jwt" instead of "statuslist+jwt"</li>
 *   <li>Claim identifier: 65530 (instead of 65533 for status list)</li>
 *   <li>Contains IdentifierList instead of StatusList</li>
 *   <li>StatusList element shall NOT be present</li>
 * </ul>
 * <p>
 * This class supports both JWT and CWT formats for the Identifier List Token.
 *
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021</a>
 */
@Builder
@AllArgsConstructor
public class IdentifierListToken {
    static final int CWT_TTL_CLAIM = 65534;
    static final int CWT_IDENTIFIER_LIST_CLAIM = 65530;
    /**
     * The JWT {@code typ} header value: the bare subtype, without an
     * {@code application/} prefix.
     */
    public static final String IDENTIFIER_LIST_TYP_JWT = "identifierlist+jwt";
    /**
     * The CWT type (protected header 16) value. As with the Status List Token, RFC 9596
     * carries a full media type in this header, so it is {@code application/identifierlist+cwt}
     * and not the bare subtype.
     */
    public static final String IDENTIFIER_LIST_TYP_CWT = "application/identifierlist+cwt";
    private static final JOSEObjectType JOSE_IDENTIFIER_LIST_TYP_JWT = new JOSEObjectType(IDENTIFIER_LIST_TYP_JWT);

    private String subject;
    private Instant issuedAt;
    private Instant expiresAt;
    private Duration timeToLive;
    private IdentifierList identifierList;
    private Key signingKey;
    private String keyId;

    /**
     * Verifies the signature of an Identifier List JWT and extracts the Identifier List.
     * <p>
     * This method parses the provided JWT string, verifies its signature using the provided public key,
     * and extracts the Identifier List from the JWT claims.
     *
     * @param identifierListJwt    The Identifier List JWT string to verify and extract from
     * @param identifierListSigningKey The public key used to verify the JWT signature
     * @return The extracted Identifier List if the signature verification is successful
     * @throws ParseException If the JWT string cannot be parsed
     * @throws JOSEException  If the JWT signature is invalid or if there's an error during verification
     * @throws IOException    If there's an error processing the Identifier List data
     */
    public static IdentifierList verifySignatureAndGetIdentifierList(@NonNull String identifierListJwt, @NonNull PublicKey identifierListSigningKey) throws ParseException, JOSEException, IOException {
        SignedJWT identifierList = SignedJWT.parse(identifierListJwt);
        return verifySignatureAndGetIdentifierList(identifierList, identifierListSigningKey);
    }

    /**
     * Verifies the signature of a parsed Identifier List JWT and extracts the Identifier List.
     * <p>
     * This method verifies the signature of the provided SignedJWT object using the provided public key,
     * and extracts the Identifier List from the JWT claims.
     *
     * @param identifierList           The parsed SignedJWT object containing the Identifier List
     * @param identifierListSigningKey The public key used to verify the JWT signature
     * @return The extracted Identifier List if the signature verification is successful
     * @throws ParseException If there's an error parsing the JWT claims
     * @throws JOSEException  If the JWT signature is invalid or if there's an error during verification
     * @throws IOException    If there's an error processing the Identifier List data
     */
    public static IdentifierList verifySignatureAndGetIdentifierList(@NonNull SignedJWT identifierList, @NonNull PublicKey identifierListSigningKey) throws ParseException, JOSEException, IOException {
        JWTClaimsSet claims = identifierList.getJWTClaimsSet();
        JWSVerifier verifier = Utils.getVerifier(identifierListSigningKey);
        if (!identifierList.verify(verifier)) {
            throw new JOSEException("Invalid JWT signature");
        }
        Map<String, Object> identifierListClaims = claims.getJSONObjectClaim("identifier_list");
        if (identifierListClaims == null) {
            throw new ParseException("Missing identifier_list claim", 0);
        }

        // Convert the map to JSON and parse as IdentifierList
        com.fasterxml.jackson.databind.ObjectMapper objectMapper = new com.fasterxml.jackson.databind.ObjectMapper();
        String json = objectMapper.writeValueAsString(identifierListClaims);
        return IdentifierList.buildFromJson().json(json).build();
    }

    /**
     * Verifies the signature of an Identifier List CWT and extracts the Identifier List.
     * <p>
     * This method parses the provided CWT hex string, verifies its signature using the provided public key,
     * and extracts the Identifier List from the CWT claims.
     *
     * @param identifierListCwtHex     The Identifier List CWT as a hexadecimal string
     * @param identifierListSigningKey The public key used to verify the CWT signature
     * @return The extracted Identifier List if the signature verification is successful
     * @throws COSEException If the CWT signature is invalid or if there's an error during verification
     * @throws IOException   If there's an error processing the Identifier List data
     */
    public static IdentifierList verifySignatureAndGetIdentifierListFromCWT(@NonNull String identifierListCwtHex, @NonNull PublicKey identifierListSigningKey) throws COSEException, IOException {
        byte[] cwtBytes = HexFormat.of().parseHex(identifierListCwtHex);
        return verifySignatureAndGetIdentifierListFromCWT(cwtBytes, identifierListSigningKey);
    }

    /**
     * Verifies the signature of an Identifier List CWT and extracts the Identifier List.
     * <p>
     * This method parses the provided CWT bytes, verifies its signature using the provided public key,
     * and extracts the Identifier List from the CWT claims.
     *
     * @param identifierListCwt        The Identifier List CWT as a byte array
     * @param identifierListSigningKey The public key used to verify the CWT signature
     * @return The extracted Identifier List if the signature verification is successful
     * @throws COSEException If the CWT signature is invalid or if there's an error during verification
     * @throws IOException   If there's an error processing the Identifier List data
     */
    public static IdentifierList verifySignatureAndGetIdentifierListFromCWT(byte @NonNull [] identifierListCwt, @NonNull PublicKey identifierListSigningKey) throws COSEException, IOException {
        // Parse CBOR to get the tagged item
        CBORDecoder decoder = new CBORDecoder(new ByteArrayInputStream(identifierListCwt));
        com.authlete.cbor.CBORTaggedItem taggedItem = (com.authlete.cbor.CBORTaggedItem) decoder.next();
        COSESign1 sign1 = (COSESign1) taggedItem.getTagContent();

        // Verify signature
        COSEVerifier verifier = new COSEVerifier(identifierListSigningKey);
        if (!verifier.verify(sign1)) {
            throw new COSEException("Invalid CWT signature");
        }

        // Extract claims
        byte[] payload = (byte[]) sign1.getPayload().parse();
        CBORDecoder claimsDecoder = new CBORDecoder(new ByteArrayInputStream(payload));
        CBORPairList claimsPairList = (CBORPairList) claimsDecoder.next();
        List<? extends CBORPair> claimsPairs = claimsPairList.getPairs();

        // Find the identifier_list claim (65530)
        for (CBORPair pair : claimsPairs) {
            Object key = pair.getKey().parse();
            if (key instanceof Number && ((Number) key).intValue() == CWT_IDENTIFIER_LIST_CLAIM) {
                byte[] identifierListBytes = (byte[]) pair.getValue().parse();
                return IdentifierList.buildFromCbor().cbor(identifierListBytes).build();
            }
        }

        throw new COSEException("Missing identifier_list claim (65530)");
    }

    /**
     * Converts this Identifier List Token to a signed JWT format.
     * <p>
     * Creates a JWT with the required claims as specified in the specification:
     * <ul>
     *   <li>sub (subject): URI of the Identifier List Token</li>
     *   <li>iat (issued at): Time at which the Identifier List Token was issued</li>
     *   <li>exp (expiration time): Time at which the Identifier List Token is considered expired</li>
     *   <li>ttl (time to live): Maximum amount of time in seconds that the Identifier List Token can be cached</li>
     *   <li>identifier_list: The Identifier List containing identifiers of revoked MSOs</li>
     * </ul>
     * The JWT header includes the type "identifierlist+jwt" and is signed using the configured signing key.
     *
     * @return A signed JWT representing this Identifier List Token
     * @throws JOSEException If there's an error during JWT signing
     * @throws IOException   If there's an error encoding the Identifier List
     */
    public String toSignedJWT() throws JOSEException, IOException {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .subject(subject)
                .issueTime(Date.from(issuedAt))
                .claim("identifier_list", identifierList.encodeAsMap());
        if (expiresAt != null) {
            claimsBuilder.expirationTime(Date.from(expiresAt));
        }
        if (timeToLive != null) {
            claimsBuilder.claim("ttl", timeToLive.getSeconds());
        }
        JWTClaimsSet claims = claimsBuilder.build();
        JWSHeader header = new JWSHeader.Builder(Utils.getJWSAlgorithm(signingKey))
                .type(JOSE_IDENTIFIER_LIST_TYP_JWT)
                .keyID(keyId)
                .build();
        SignedJWT signedJwt = new SignedJWT(header, claims);
        JWSSigner signer = Utils.getSigner(signingKey);
        signedJwt.sign(signer);
        return signedJwt.serialize();
    }

    /**
     * Converts this Identifier List Token to a signed CWT (CBOR Web Token) format.
     * <p>
     * Creates a CWT with the required claims as specified in ISO/IEC 18013-5:2021:
     * <ul>
     *   <li>2 (subject): URI of the Identifier List Token</li>
     *   <li>6 (issued at): Time at which the Identifier List Token was issued</li>
     *   <li>4 (expiration time): Time at which the Identifier List Token is considered expired</li>
     *   <li>65534 (time to live): Maximum amount of time in seconds that the Identifier List Token can be cached</li>
     *   <li>65530 (identifier list): The Identifier List containing identifiers of revoked MSOs</li>
     * </ul>
     * The CWT protected header includes the type "identifierlist+cwt" and is signed using the configured signing key.
     *
     * @return A hexadecimal string representation of the signed CWT
     * @throws COSEException If there's an error during CWT signing or encoding
     * @throws IOException   If there's an error encoding the Identifier List
     */
    public String toSignedCWT() throws COSEException, IOException {
        CWTClaimsSetBuilder claimsBuilder = new CWTClaimsSetBuilder()
                .sub(subject)
                .iat(issuedAt.getEpochSecond());
        if (expiresAt != null) {
            claimsBuilder.exp(expiresAt.getEpochSecond());
        }
        if (timeToLive != null) {
            claimsBuilder.put(CWT_TTL_CLAIM, timeToLive.getSeconds());
        }
        CWTClaimsSet claims = claimsBuilder
                .put(CWT_IDENTIFIER_LIST_CLAIM, identifierList.encodeAsCBOR())
                .build();
        byte[] encodedClaims = claims.encode();
        int algorithm = Utils.getCOSEAlgorithm(signingKey);
        COSEProtectedHeader protectedHeader = new COSEProtectedHeaderBuilder()
                .alg(algorithm)
                .put(16, IDENTIFIER_LIST_TYP_CWT)
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
        return sign1.getTagged().encodeToHex();
    }
}
