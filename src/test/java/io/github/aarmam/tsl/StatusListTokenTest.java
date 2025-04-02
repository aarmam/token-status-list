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

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.Map;
import java.util.stream.Collectors;

import static io.github.aarmam.tsl.StatusListToken.CWT_STATUS_LIST_CLAIM;
import static io.github.aarmam.tsl.StatusListToken.CWT_TTL_CLAIM;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;

class StatusListTokenTest extends BaseTest {
    private static final Instant iat = Instant.ofEpochSecond(1686920170);
    private static final Instant exp = Instant.ofEpochSecond(1686920170).plus(1000, ChronoUnit.DAYS);
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
        SignedJWT statusListJwt = statusListToken.toSignedJWT();
        JWSVerifier verifier = new ECDSAVerifier(signingKeyJwt.toECKey().toECPublicKey());
        assertThat(statusListJwt.verify(verifier), equalTo(true));
        JWTClaimsSet claims = statusListJwt.getJWTClaimsSet();
        assertThat(claims.getSubject(), equalTo("https://example.com/statuslists/1"));
        assertThat(claims.getIssueTime().toInstant(), equalTo(iat));
        assertThat(claims.getExpirationTime().toInstant(), equalTo(exp));
        Map<String, Object> statusListMap = claims.getJSONObjectClaim("status_list");
        assertThat(statusListMap, hasEntry("bits", 1));
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
        SignedJWT signedJWT = statusListToken.toSignedJWT();
        StatusList statusListFromJwt = StatusListToken.verifySignatureAndGetStatusList(signedJWT.serialize(), signingKey.getPublic());

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