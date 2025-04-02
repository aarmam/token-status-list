package io.github.aarmam.tsl;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import org.junit.jupiter.api.BeforeAll;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.UUID;

import static com.nimbusds.jose.jwk.Curve.P_256;
import static com.nimbusds.jose.jwk.KeyUse.SIGNATURE;
import static io.github.aarmam.tsl.StatusType.INVALID;
import static io.github.aarmam.tsl.StatusType.SUSPENDED;
import static io.github.aarmam.tsl.StatusType.VALID;

public abstract class BaseTest {
    protected static JWK signingKeyJwt;
    protected static KeyPair signingKey;

    @BeforeAll
    static void setup() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        signingKey = keyGen.generateKeyPair();
        signingKeyJwt = new ECKey.Builder(
                P_256,
                ((ECPublicKey) signingKey.getPublic()))
                .privateKey((ECPrivateKey) signingKey.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .keyUse(SIGNATURE)
                .algorithm(new Algorithm("ES256"))
                .build();
    }

    protected StatusList exampleStatusList1Bit() {
        StatusList statusList = new StatusList(16, 1);
        statusList.set(0, INVALID);
        statusList.set(1, VALID);
        statusList.set(2, VALID);
        statusList.set(3, INVALID);
        statusList.set(4, INVALID);
        statusList.set(5, INVALID);
        statusList.set(6, VALID);
        statusList.set(7, INVALID);
        statusList.set(8, INVALID);
        statusList.set(9, INVALID);
        statusList.set(10, VALID);
        statusList.set(11, VALID);
        statusList.set(12, VALID);
        statusList.set(13, INVALID);
        statusList.set(14, VALID);
        statusList.set(15, INVALID);
        return statusList;
    }

    protected StatusList exampleStatusList2Bit() {
        StatusList statusList = new StatusList(12, 2);
        statusList.set(0, INVALID);
        statusList.set(1, SUSPENDED);
        statusList.set(2, VALID);
        statusList.set(3, 3);
        statusList.set(4, VALID);
        statusList.set(5, INVALID);
        statusList.set(6, VALID);
        statusList.set(7, INVALID);
        statusList.set(8, INVALID);
        statusList.set(9, SUSPENDED);
        statusList.set(10, 3);
        statusList.set(11, 3);
        return statusList;
    }
}
