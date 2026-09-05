package io.github.aarmam.tsl;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSEException;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSEVerifier;
import com.authlete.cwt.CWTClaimsSet;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Date;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.Map;
import java.util.stream.Collectors;

import static io.github.aarmam.tsl.StatusListToken.CWT_STATUS_LIST_CLAIM;
import static io.github.aarmam.tsl.StatusListToken.CWT_TTL_CLAIM;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StatusListTokenTest extends BaseTest {
    private static final Instant iat = Instant.ofEpochSecond(1686920170);
    private static final Instant exp = Instant.now().plus(1000, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
    private static final Duration ttl = Duration.ofHours(12);

    @Test
    void testStatusListTokenInJWT() throws Exception {
        StatusList statusList = exampleStatusList1Bit();
        StatusListToken statusListToken = StatusListToken.builder()
                .subject("https://example.com/statuslists/1")
                .issuedAt(iat)
                .expiresAt(exp)
                .timeToLive(ttl)
                .statusList(statusList)
                .signingKey(signingKeyJwt.toECKey().toECPrivateKey())
                .keyId(signingKeyJwt.getKeyID())
                .build();
        SignedJWT statusListJwt = SignedJWT.parse(statusListToken.toSignedJWT());
        JWSVerifier verifier = new ECDSAVerifier(signingKeyJwt.toECKey().toECPublicKey());
        assertThat(statusListJwt.verify(verifier), equalTo(true));
        JWTClaimsSet claims = statusListJwt.getJWTClaimsSet();
        assertThat(claims.getSubject(), equalTo("https://example.com/statuslists/1"));
        assertThat(claims.getIssueTime().toInstant(), equalTo(iat));
        assertThat(claims.getExpirationTime().toInstant(), equalTo(exp));
        Map<String, Object> statusListMap = claims.getJSONObjectClaim("status_list");
        assertThat(statusListMap, hasEntry("bits", 1L));
        assertThat(statusListMap, hasEntry("lst", "eNrbuRgAAhcBXQ"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testStatusListTokenInCWT() throws Exception {
        StatusList statusList = exampleStatusList1Bit();
        StatusListToken statusListToken = StatusListToken.builder()
                .subject("https://example.com/statuslists/1")
                .issuedAt(iat)
                .expiresAt(exp)
                .timeToLive(ttl)
                .statusList(statusList)
                .signingKey(signingKeyJwt.toECKey().toECPrivateKey())
                .keyId(signingKeyJwt.getKeyID())
                .build();
        String statusListCwt = statusListToken.toSignedCWT();
        CBORTaggedItem taggedItem = (CBORTaggedItem) new CBORDecoder(HexFormat.of().parseHex(statusListCwt)).next();
        COSEVerifier verifier = new COSEVerifier(signingKeyJwt.toECKey().toECPublicKey());
        COSESign1 coseSign1 = (COSESign1) taggedItem.getTagContent();

        assertThat(verifier.verify(coseSign1), equalTo(true));

        // Section 5.2: protected header 16 (type) carries the full media type
        assertThat(coseSign1.getProtectedHeader().getParameters(),
                hasEntry(16, "application/statuslist+cwt"));

        CWTClaimsSet claims = CWTClaimsSet.build(coseSign1.getPayload());
        assertThat(claims.getSub(), equalTo("https://example.com/statuslists/1"));
        assertThat(claims.getIat().toInstant(), equalTo(iat));
        assertThat(claims.getExp().toInstant(), equalTo(exp));

        Map<Object, Object> claimsMap = claims.getPairs().stream()
                .collect(Collectors.toMap(
                        cborPair -> cborPair.getKey().parse(),
                        cborPair1 -> cborPair1.getValue().parse()
                ));
        assertThat(claimsMap, hasEntry(CWT_TTL_CLAIM, 43200));
        assertThat(claimsMap, hasKey(CWT_STATUS_LIST_CLAIM));
        Map<Object, Object> statusListMap = (Map<Object, Object>) claimsMap.get(CWT_STATUS_LIST_CLAIM);
        assertThat(statusListMap, hasEntry("bits", 1));
        assertThat(statusListMap, hasKey("lst"));
        byte[] lst = (byte[]) statusListMap.get("lst");
        String hexEncoded = HexFormat.of().formatHex(lst);
        assertThat(hexEncoded, equalTo("78dadbb918000217015d"));
    }

    @Test
    void testStatusListTokenFromCWT() throws Exception {
        StatusList statusList = new StatusList(16, 1, "https://example.com/aggregation");
        StatusList source = exampleStatusList1Bit();
        for (int i = 0; i < 16; i++) {
            statusList.set(i, source.get(i));
        }
        StatusListToken statusListToken = StatusListToken.builder()
                .subject("https://example.com/statuslists/1")
                .issuedAt(iat)
                .expiresAt(exp)
                .timeToLive(ttl)
                .statusList(statusList)
                .signingKey(signingKeyJwt.toECKey().toECPrivateKey())
                .keyId(signingKeyJwt.getKeyID())
                .build();

        StatusList statusListFromCwt = StatusListToken.verifySignatureAndGetStatusListFromCWT(
                statusListToken.toSignedCWT(), signingKey.getPublic());

        assertThat(statusListFromCwt.size(), equalTo(16));
        assertThat(statusListFromCwt.getAggregationUri(), equalTo("https://example.com/aggregation"));
        for (int i = 0; i < 16; i++) {
            assertThat(statusListFromCwt.get(i), equalTo(source.get(i)));
        }
    }

    @Test
    void testSignedCWTBytesAreTheRawWireForm() throws Exception {
        StatusListToken statusListToken = StatusListToken.builder()
                .subject("https://example.com/statuslists/1")
                .issuedAt(iat)
                .expiresAt(exp)
                .timeToLive(ttl)
                .statusList(exampleStatusList1Bit())
                .signingKey(signingKeyJwt.toECKey().toECPrivateKey())
                .keyId(signingKeyJwt.getKeyID())
                .build();

        byte[] cwtBytes = statusListToken.toSignedCWTBytes();
        // Section 8.2: the response body is binary; the hex form is for readability only
        // (signing twice yields different ECDSA signatures, so compare the encodings)
        assertThat(HexFormat.of().parseHex(statusListToken.toSignedCWT()).length, equalTo(cwtBytes.length));
        assertThat(cwtBytes[0], equalTo((byte) 0xd2)); // tagged COSE_Sign1 (18)

        StatusList decoded = StatusListToken.verifySignatureAndGetStatusListFromCWT(
                cwtBytes, signingKey.getPublic());
        assertThat(decoded.size(), equalTo(16));
    }

    private StatusListToken exampleToken(Instant expiresAt) throws Exception {
        return StatusListToken.builder()
                .subject("https://example.com/statuslists/1")
                .issuedAt(iat)
                .expiresAt(expiresAt)
                .timeToLive(ttl)
                .statusList(exampleStatusList1Bit())
                .signingKey(signingKeyJwt.toECKey().toECPrivateKey())
                .keyId(signingKeyJwt.getKeyID())
                .build();
    }

    @Test
    void testVerificationAcceptsMatchingSubject() throws Exception {
        // Section 8.3 step 4a
        String jwt = exampleToken(exp).toSignedJWT();
        StatusList statusList = StatusListToken.verifySignatureAndGetStatusList(
                jwt, signingKey.getPublic(), "https://example.com/statuslists/1");
        assertThat(statusList.size(), equalTo(16));
    }

    @Test
    void testVerificationRejectsSubjectMismatch() throws Exception {
        // Section 8.3 step 4a: sub MUST equal the Referenced Token's status_list uri
        String jwt = exampleToken(exp).toSignedJWT();
        StatusListValidationException thrown = assertThrows(StatusListValidationException.class,
                () -> StatusListToken.verifySignatureAndGetStatusList(
                        jwt, signingKey.getPublic(), "https://example.com/statuslists/2"));
        assertThat(thrown.getMessage(), containsString("does not match the Referenced Token uri"));
    }

    @Test
    void testVerificationRejectsExpiredToken() throws Exception {
        // Section 8.3 step 4c
        String jwt = exampleToken(Instant.now().minus(1, ChronoUnit.DAYS)).toSignedJWT();
        StatusListValidationException thrown = assertThrows(StatusListValidationException.class,
                () -> StatusListToken.verifySignatureAndGetStatusList(jwt, signingKey.getPublic()));
        assertThat(thrown.getMessage(), containsString("expired at"));
    }

    @Test
    void testVerificationRejectsExpiredCWT() throws Exception {
        String cwt = exampleToken(Instant.now().minus(1, ChronoUnit.DAYS)).toSignedCWT();
        assertThrows(StatusListValidationException.class,
                () -> StatusListToken.verifySignatureAndGetStatusListFromCWT(cwt, signingKey.getPublic()));
    }

    @Test
    void testVerificationRejectsWrongTokenType() throws Exception {
        // a JWT signed by the same key but not a Status List Token
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("https://example.com/statuslists/1")
                .issueTime(Date.from(iat))
                .claim("status_list", Map.of("bits", 1, "lst", "eNrbuRgAAhcBXQ"))
                .build();
        SignedJWT impostor = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("JWT"))
                        .build(),
                claims);
        impostor.sign(new ECDSASigner(signingKeyJwt.toECKey().toECPrivateKey()));

        StatusListValidationException thrown = assertThrows(StatusListValidationException.class,
                () -> StatusListToken.verifySignatureAndGetStatusList(impostor.serialize(), signingKey.getPublic()));
        assertThat(thrown.getMessage(), containsString("Expected JWT type statuslist+jwt"));
    }

    @Test
    void testVerificationRejectsMissingStatusListClaim() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("https://example.com/statuslists/1")
                .issueTime(Date.from(iat))
                .build();
        SignedJWT withoutClaim = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("statuslist+jwt"))
                        .build(),
                claims);
        withoutClaim.sign(new ECDSASigner(signingKeyJwt.toECKey().toECPrivateKey()));

        StatusListValidationException thrown = assertThrows(StatusListValidationException.class,
                () -> StatusListToken.verifySignatureAndGetStatusList(withoutClaim.serialize(), signingKey.getPublic()));
        assertThat(thrown.getMessage(), equalTo("Missing required claim: status_list"));
    }

    @Test
    void testStatusListTokenFromCWTRejectsWrongKey() throws Exception {
        StatusListToken statusListToken = StatusListToken.builder()
                .subject("https://example.com/statuslists/1")
                .issuedAt(iat)
                .expiresAt(exp)
                .timeToLive(ttl)
                .statusList(exampleStatusList1Bit())
                .signingKey(signingKeyJwt.toECKey().toECPrivateKey())
                .keyId(signingKeyJwt.getKeyID())
                .build();
        String cwt = statusListToken.toSignedCWT();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        PublicKey otherKey = keyGen.generateKeyPair().getPublic();

        assertThrows(COSEException.class,
                () -> StatusListToken.verifySignatureAndGetStatusListFromCWT(cwt, otherKey));
    }

    @Test
    void testStatusListTokenFromJWT() throws Exception {
        StatusList statusList = exampleStatusList1Bit();
        StatusListToken statusListToken = StatusListToken.builder()
                .subject("https://example.com/statuslists/1")
                .issuedAt(iat)
                .expiresAt(exp)
                .timeToLive(ttl)
                .statusList(statusList)
                .signingKey(signingKeyJwt.toECKey().toECPrivateKey())
                .keyId(signingKeyJwt.getKeyID())
                .build();
        SignedJWT signedJwt = SignedJWT.parse(statusListToken.toSignedJWT());
        StatusList statusListFromJwt = StatusListToken.verifySignatureAndGetStatusList(signedJwt.serialize(), signingKey.getPublic());

        assertThat(statusListFromJwt.get(0), equalTo(1));
        assertThat(statusListFromJwt.get(1), equalTo(0));
        assertThat(statusListFromJwt.get(2), equalTo(0));
        assertThat(statusListFromJwt.get(3), equalTo(1));
        assertThat(statusListFromJwt.get(4), equalTo(1));
        assertThat(statusListFromJwt.get(5), equalTo(1));
        assertThat(statusListFromJwt.get(6), equalTo(0));
        assertThat(statusListFromJwt.get(7), equalTo(1));
        assertThat(statusListFromJwt.get(8), equalTo(1));
        assertThat(statusListFromJwt.get(9), equalTo(1));
        assertThat(statusListFromJwt.get(10), equalTo(0));
        assertThat(statusListFromJwt.get(11), equalTo(0));
        assertThat(statusListFromJwt.get(12), equalTo(0));
        assertThat(statusListFromJwt.get(13), equalTo(1));
        assertThat(statusListFromJwt.get(14), equalTo(0));
        assertThat(statusListFromJwt.get(15), equalTo(1));
    }
}