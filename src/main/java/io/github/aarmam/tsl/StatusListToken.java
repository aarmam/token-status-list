package io.github.aarmam.tsl;

import com.authlete.cbor.CBORByteArray;
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

import java.io.IOException;
import java.security.Key;
import java.security.PublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
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
    static final String STATUS_LIST_TYP_JWT = "statuslist+jwt";
    static final String STATUS_LIST_TYP_CWT = "statuslist+cwt";
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
        SignedJWT statusList = SignedJWT.parse(statusListJwt);
        return verifySignatureAndGetStatusList(statusList, statusListSigningKey);
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
        JWTClaimsSet claims = statusList.getJWTClaimsSet();
        JWSVerifier verifier = Utils.getVerifier(statusListSigningKey);
        if (!statusList.verify(verifier)) {
            throw new JOSEException("Invalid JWT signature");
        }
        Map<String, Object> statusListClaims = claims.getJSONObjectClaim("status_list");
        int bits = ((Long) statusListClaims.get("bits")).intValue();
        byte[] lst = Base64.getUrlDecoder().decode((String) statusListClaims.get("lst"));
        return StatusList.buildFromEncoded()
                .bits(bits)
                .list(lst)
                .build();
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
    public SignedJWT toSignedJWT() throws JOSEException, IOException {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(subject)
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiresAt))
                .claim("ttl", timeToLive.getSeconds())
                .claim("status_list", statusList.encodeAsMap(true))
                .build();
        JWSHeader header = new JWSHeader.Builder(Utils.getJWSAlgorithm(signingKey))
                .type(JOSE_STATUS_LIST_TYP_JWT)
                .keyID(keyId)
                .build();
        SignedJWT signedJWT = new SignedJWT(header, claims);
        JWSSigner signer = Utils.getSigner(signingKey);
        signedJWT.sign(signer);
        return signedJWT;
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
     * The CWT protected header includes the type "statuslist+cwt" and is signed using the configured signing key.
     *
     * @return A hexadecimal string representation of the signed CWT
     * @throws COSEException If there's an error during CWT signing or encoding
     * @throws IOException   If there's an error encoding the Status List
     */
    public String toSignedCWT() throws COSEException, IOException {
        CWTClaimsSet claims = new CWTClaimsSetBuilder()
                .sub(subject)
                .iat(issuedAt.getEpochSecond())
                .exp(expiresAt.getEpochSecond())
                .put(CWT_TTL_CLAIM, timeToLive.getSeconds())
                .put(CWT_STATUS_LIST_CLAIM, statusList.encodeAsMap(false))
                .build();
        byte[] encodedClaims = claims.encode();
        int algorithm = Utils.getCOSEAlgorithm(signingKey);
        COSEProtectedHeader protectedHeader = new COSEProtectedHeaderBuilder()
                .alg(algorithm)
                .put(16, STATUS_LIST_TYP_CWT)
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
