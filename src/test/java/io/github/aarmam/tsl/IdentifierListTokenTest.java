package io.github.aarmam.tsl;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSEVerifier;
import com.authlete.cwt.CWTClaimsSet;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.Map;
import java.util.stream.Collectors;

import static io.github.aarmam.tsl.IdentifierListToken.CWT_IDENTIFIER_LIST_CLAIM;
import static io.github.aarmam.tsl.IdentifierListToken.CWT_TTL_CLAIM;
import static io.github.aarmam.tsl.IdentifierListToken.IDENTIFIER_LIST_TYP_CWT;
import static io.github.aarmam.tsl.IdentifierListToken.IDENTIFIER_LIST_TYP_JWT;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdentifierListTokenTest extends BaseTest {
    private static final Instant iat = Instant.ofEpochSecond(1686920170);
    private static final Instant exp = Instant.ofEpochSecond(1686920170).plus(1000, ChronoUnit.DAYS);
    private static final Duration ttl = Duration.ofHours(12);

    private static final byte[] TEST_ID_1 = "test-identifier-1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TEST_ID_2 = "test-identifier-2".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TEST_ID_3 = "test-identifier-3".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TEST_ID_4 = "test-identifier-4".getBytes(StandardCharsets.UTF_8);

    private IdentifierList exampleIdentifierList() {
        IdentifierList identifierList = new IdentifierList("https://example.com/aggregation");
        identifierList.addIdentifier(TEST_ID_1);
        identifierList.addIdentifier(TEST_ID_2);
        identifierList.addIdentifier(TEST_ID_3);
        return identifierList;
    }

    @Test
    void testIdentifierListTokenInJWT() throws Exception {
        IdentifierList identifierList = exampleIdentifierList();
        IdentifierListToken identifierListToken = IdentifierListToken.builder()
                .subject("https://example.com/identifierlists/1")
                .issuedAt(iat)
                .expiresAt(exp)
                .timeToLive(ttl)
                .identifierList(identifierList)
                .signingKey(signingKeyJwt.toECKey().toECPrivateKey())
                .keyId(signingKeyJwt.getKeyID())
                .build();
        String jwtString = identifierListToken.toSignedJWT();
        SignedJWT identifierListJwt = SignedJWT.parse(jwtString);

        // Verify signature
        JWSVerifier verifier = new ECDSAVerifier(signingKeyJwt.toECKey().toECPublicKey());
        assertThat(identifierListJwt.verify(verifier), equalTo(true));

        // Verify header type
        assertThat(identifierListJwt.getHeader().getType().toString(), equalTo(IDENTIFIER_LIST_TYP_JWT));

        // Verify claims
        JWTClaimsSet claims = identifierListJwt.getJWTClaimsSet();
        assertThat(claims.getSubject(), equalTo("https://example.com/identifierlists/1"));
        assertThat(claims.getIssueTime().toInstant(), equalTo(iat));
        assertThat(claims.getExpirationTime().toInstant(), equalTo(exp));
        assertThat(claims.getLongClaim("ttl"), equalTo(ttl.getSeconds()));

        // Verify identifier_list claim
        Map<String, Object> identifierListMap = claims.getJSONObjectClaim("identifier_list");
        assertThat(identifierListMap, hasKey("identifiers"));
        assertThat(identifierListMap, hasKey("aggregation_uri"));
        assertThat(identifierListMap.get("aggregation_uri"), equalTo("https://example.com/aggregation"));

        @SuppressWarnings("unchecked")
        Map<String, Object> identifiers = (Map<String, Object>) identifierListMap.get("identifiers");
        assertThat(identifiers.size(), equalTo(3));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testIdentifierListTokenInCWT() throws Exception {
        IdentifierList identifierList = exampleIdentifierList();
        IdentifierListToken identifierListToken = IdentifierListToken.builder()
                .subject("https://example.com/identifierlists/1")
                .issuedAt(iat)
                .expiresAt(exp)
                .timeToLive(ttl)
                .identifierList(identifierList)
                .signingKey(signingKeyJwt.toECKey().toECPrivateKey())
                .keyId(signingKeyJwt.getKeyID())
                .build();
        String identifierListCwt = identifierListToken.toSignedCWT();
        CBORTaggedItem taggedItem = (CBORTaggedItem) new CBORDecoder(HexFormat.of().parseHex(identifierListCwt)).next();
        COSEVerifier verifier = new COSEVerifier(signingKeyJwt.toECKey().toECPublicKey());
        COSESign1 coseSign1 = (COSESign1) taggedItem.getTagContent();

        // Verify signature
        assertThat(verifier.verify(coseSign1), equalTo(true));

        // Verify protected header type
        Map<Object, Object> protectedHeaderMap = coseSign1.getProtectedHeader().getPairs().stream()
                .collect(Collectors.toMap(
                        pair -> pair.getKey().parse(),
                        pair -> pair.getValue().parse()
                ));
        assertThat(protectedHeaderMap.get(16), equalTo(IDENTIFIER_LIST_TYP_CWT));

        // Verify claims
        CWTClaimsSet claims = CWTClaimsSet.build(coseSign1.getPayload());
        assertThat(claims.getSub(), equalTo("https://example.com/identifierlists/1"));
        assertThat(claims.getIat().toInstant(), equalTo(iat));
        assertThat(claims.getExp().toInstant(), equalTo(exp));

        Map<Object, Object> claimsMap = claims.getPairs().stream()
                .collect(Collectors.toMap(
                        cborPair -> cborPair.getKey().parse(),
                        cborPair1 -> cborPair1.getValue().parse()
                ));
        assertThat(claimsMap.get(CWT_TTL_CLAIM), equalTo(43200));
        assertThat(claimsMap, hasKey(CWT_IDENTIFIER_LIST_CLAIM));

        // Verify the identifier list claim (65530)
        byte[] identifierListBytes = (byte[]) claimsMap.get(CWT_IDENTIFIER_LIST_CLAIM);
        IdentifierList decodedList = IdentifierList.buildFromCbor()
                .cbor(identifierListBytes)
                .build();
        assertThat(decodedList.size(), equalTo(3));
        assertTrue(decodedList.isRevoked(TEST_ID_1));
        assertTrue(decodedList.isRevoked(TEST_ID_2));
        assertTrue(decodedList.isRevoked(TEST_ID_3));
    }

    @Test
    void testIdentifierListTokenFromJWT() throws Exception {
        IdentifierList identifierList = exampleIdentifierList();
        IdentifierListToken identifierListToken = IdentifierListToken.builder()
                .subject("https://example.com/identifierlists/1")
                .issuedAt(iat)
                .expiresAt(exp)
                .timeToLive(ttl)
                .identifierList(identifierList)
                .signingKey(signingKeyJwt.toECKey().toECPrivateKey())
                .keyId(signingKeyJwt.getKeyID())
                .build();
        String jwtString = identifierListToken.toSignedJWT();
        IdentifierList identifierListFromJwt = IdentifierListToken.verifySignatureAndGetIdentifierList(
                jwtString,
                signingKey.getPublic()
        );

        // Verify identifiers
        assertThat(identifierListFromJwt.size(), equalTo(3));
        assertTrue(identifierListFromJwt.isRevoked(TEST_ID_1));
        assertTrue(identifierListFromJwt.isRevoked(TEST_ID_2));
        assertTrue(identifierListFromJwt.isRevoked(TEST_ID_3));
        assertThat(identifierListFromJwt.isRevoked(TEST_ID_4), is(false));
        assertThat(identifierListFromJwt.getAggregationUri(), equalTo("https://example.com/aggregation"));
    }

    @Test
    void testIdentifierListTokenFromCWT() throws Exception {
        IdentifierList identifierList = exampleIdentifierList();
        IdentifierListToken identifierListToken = IdentifierListToken.builder()
                .subject("https://example.com/identifierlists/1")
                .issuedAt(iat)
                .expiresAt(exp)
                .timeToLive(ttl)
                .identifierList(identifierList)
                .signingKey(signingKeyJwt.toECKey().toECPrivateKey())
                .keyId(signingKeyJwt.getKeyID())
                .build();
        String cwtHex = identifierListToken.toSignedCWT();
        IdentifierList identifierListFromCwt = IdentifierListToken.verifySignatureAndGetIdentifierListFromCWT(
                cwtHex,
                signingKey.getPublic()
        );

        // Verify identifiers
        assertThat(identifierListFromCwt.size(), equalTo(3));
        assertTrue(identifierListFromCwt.isRevoked(TEST_ID_1));
        assertTrue(identifierListFromCwt.isRevoked(TEST_ID_2));
        assertTrue(identifierListFromCwt.isRevoked(TEST_ID_3));
        assertThat(identifierListFromCwt.isRevoked(TEST_ID_4), is(false));
        assertThat(identifierListFromCwt.getAggregationUri(), equalTo("https://example.com/aggregation"));
    }

    @Test
    void testRoundTripJWT() throws Exception {
        IdentifierList original = exampleIdentifierList();
        IdentifierListToken token = IdentifierListToken.builder()
                .subject("https://example.com/identifierlists/1")
                .issuedAt(iat)
                .expiresAt(exp)
                .timeToLive(ttl)
                .identifierList(original)
                .signingKey(signingKeyJwt.toECKey().toECPrivateKey())
                .keyId(signingKeyJwt.getKeyID())
                .build();

        String jwt = token.toSignedJWT();
        IdentifierList decoded = IdentifierListToken.verifySignatureAndGetIdentifierList(jwt, signingKey.getPublic());

        assertThat(decoded.size(), equalTo(original.size()));
        assertTrue(decoded.isRevoked(TEST_ID_1));
        assertTrue(decoded.isRevoked(TEST_ID_2));
        assertTrue(decoded.isRevoked(TEST_ID_3));
        assertThat(decoded.getAggregationUri(), equalTo(original.getAggregationUri()));
    }

    @Test
    void testRoundTripCWT() throws Exception {
        IdentifierList original = exampleIdentifierList();
        IdentifierListToken token = IdentifierListToken.builder()
                .subject("https://example.com/identifierlists/1")
                .issuedAt(iat)
                .expiresAt(exp)
                .timeToLive(ttl)
                .identifierList(original)
                .signingKey(signingKeyJwt.toECKey().toECPrivateKey())
                .keyId(signingKeyJwt.getKeyID())
                .build();

        String cwt = token.toSignedCWT();
        IdentifierList decoded = IdentifierListToken.verifySignatureAndGetIdentifierListFromCWT(cwt, signingKey.getPublic());

        assertThat(decoded.size(), equalTo(original.size()));
        assertTrue(decoded.isRevoked(TEST_ID_1));
        assertTrue(decoded.isRevoked(TEST_ID_2));
        assertTrue(decoded.isRevoked(TEST_ID_3));
        assertThat(decoded.getAggregationUri(), equalTo(original.getAggregationUri()));
    }

    @Test
    void testEmptyIdentifierListInToken() throws Exception {
        IdentifierList emptyList = new IdentifierList();
        IdentifierListToken token = IdentifierListToken.builder()
                .subject("https://example.com/identifierlists/empty")
                .issuedAt(iat)
                .expiresAt(exp)
                .timeToLive(ttl)
                .identifierList(emptyList)
                .signingKey(signingKeyJwt.toECKey().toECPrivateKey())
                .keyId(signingKeyJwt.getKeyID())
                .build();

        String jwt = token.toSignedJWT();
        IdentifierList decoded = IdentifierListToken.verifySignatureAndGetIdentifierList(jwt, signingKey.getPublic());

        assertThat(decoded.size(), equalTo(0));
    }
}
