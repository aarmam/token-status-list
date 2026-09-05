package io.github.aarmam.tsl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Ed25519 is one of the key types Utils.getCOSEAlgorithm recognises, so a Status List Token
 * must be signable and verifiable with it.
 */
class EdDsaStatusListTokenTest {

    private static StatusList exampleStatusList() {
        StatusList statusList = new StatusList(16, 1);
        statusList.set(0, StatusType.INVALID);
        statusList.set(3, StatusType.INVALID);
        return statusList;
    }

    @Test
    void testSignAndVerifyWithEd25519() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();

        StatusListToken token = StatusListToken.builder()
                .subject("https://example.com/statuslists/1")
                .issuedAt(Instant.now().truncatedTo(ChronoUnit.SECONDS))
                .expiresAt(Instant.now().plus(30, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS))
                .timeToLive(Duration.ofHours(12))
                .statusList(exampleStatusList())
                .signingKey(keyPair.getPrivate())
                .keyId("ed25519-1")
                .build();

        String jwt = token.toSignedJWT();
        assertThat(SignedJWT.parse(jwt).getHeader().getAlgorithm(), equalTo(JWSAlgorithm.EdDSA));

        StatusList verified = StatusListToken.verifySignatureAndGetStatusList(
                jwt, keyPair.getPublic(), "https://example.com/statuslists/1");

        assertThat(verified.size(), equalTo(16));
        assertThat(verified.get(0), equalTo(1));
        assertThat(verified.get(3), equalTo(1));
        assertThat(verified.get(1), equalTo(0));
    }

    @Test
    void testEd25519VerificationRejectsWrongKey() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        KeyPair other = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();

        String jwt = StatusListToken.builder()
                .subject("https://example.com/statuslists/1")
                .issuedAt(Instant.now().truncatedTo(ChronoUnit.SECONDS))
                .statusList(exampleStatusList())
                .signingKey(keyPair.getPrivate())
                .build()
                .toSignedJWT();

        assertThrows(com.nimbusds.jose.JOSEException.class,
                () -> StatusListToken.verifySignatureAndGetStatusList(jwt, other.getPublic()));
    }

    @Test
    void testSignAndVerifyWithEd448() throws Exception {
        // COSE registers a single EdDSA algorithm covering both curves
        KeyPair keyPair = KeyPairGenerator.getInstance("Ed448").generateKeyPair();

        String jwt = StatusListToken.builder()
                .subject("https://example.com/statuslists/1")
                .issuedAt(Instant.now().truncatedTo(ChronoUnit.SECONDS))
                .statusList(exampleStatusList())
                .signingKey(keyPair.getPrivate())
                .build()
                .toSignedJWT();

        assertThat(SignedJWT.parse(jwt).getHeader().getAlgorithm(), equalTo(JWSAlgorithm.EdDSA));

        StatusList verified = StatusListToken.verifySignatureAndGetStatusList(jwt, keyPair.getPublic());
        assertThat(verified.get(3), equalTo(1));
    }
}
