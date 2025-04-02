package io.github.aarmam.tsl;

import com.authlete.cose.constants.COSEAlgorithms;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import lombok.experimental.UtilityClass;

import java.security.Key;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Map;

@UtilityClass
class Utils {
    private static final Map<Integer, JWSAlgorithm> COSE_TO_JWS_ALG_MAP;

    static {
        COSE_TO_JWS_ALG_MAP = Map.ofEntries(
                Map.entry(COSEAlgorithms.ES256K, JWSAlgorithm.ES256K),
                Map.entry(COSEAlgorithms.ES256, JWSAlgorithm.ES256),
                Map.entry(COSEAlgorithms.ES384, JWSAlgorithm.ES384),
                Map.entry(COSEAlgorithms.ES512, JWSAlgorithm.ES512),
                Map.entry(COSEAlgorithms.PS256, JWSAlgorithm.PS256),
                Map.entry(COSEAlgorithms.PS384, JWSAlgorithm.PS384),
                Map.entry(COSEAlgorithms.PS512, JWSAlgorithm.PS512),
                Map.entry(COSEAlgorithms.RS256, JWSAlgorithm.RS256),
                Map.entry(COSEAlgorithms.RS384, JWSAlgorithm.RS384),
                Map.entry(COSEAlgorithms.RS512, JWSAlgorithm.RS512),
                Map.entry(COSEAlgorithms.EdDSA, JWSAlgorithm.EdDSA));
    }

    JWSAlgorithm getJWSAlgorithm(Key key) {
        return COSE_TO_JWS_ALG_MAP.get(getCOSEAlgorithm(key));
    }

    int getCOSEAlgorithm(Key key) {
        switch (key) {
            case ECKey ecKey -> {
                ECParameterSpec params = ecKey.getParams();
                if (params.toString().contains("secp256k1")) {
                    return COSEAlgorithms.ES256K;
                }
                int bitLength = params.getOrder().bitLength();
                return switch (bitLength) {
                    case 256 -> COSEAlgorithms.ES256;
                    case 384 -> COSEAlgorithms.ES384;
                    case 521 -> COSEAlgorithms.ES512;
                    default -> throw new IllegalArgumentException("Unsupported key size: " + bitLength);
                };
            }
            case RSAKey rsaKey -> {
                int bitLength = rsaKey.getModulus().bitLength();
                if (rsaKey.getParams().toString().contains("PSS")) {
                    return switch (bitLength) {
                        case 2048 -> COSEAlgorithms.PS256;
                        case 3072 -> COSEAlgorithms.PS384;
                        case 4096 -> COSEAlgorithms.PS512;
                        default -> throw new IllegalArgumentException("Unsupported PSS key size: " + bitLength);
                    };
                }
                return switch (bitLength) {
                    case 2048 -> COSEAlgorithms.RS256;
                    case 3072 -> COSEAlgorithms.RS384;
                    case 4096 -> COSEAlgorithms.RS512;
                    default -> throw new IllegalArgumentException("Unsupported RSA key size: " + bitLength);
                };
            }
            case EdECKey edKey -> {
                NamedParameterSpec params = edKey.getParams();
                return switch (params.getName()) {
                    case "Ed25519", "Ed448" -> COSEAlgorithms.EdDSA;
                    default -> throw new IllegalArgumentException("Unsupported EdDSA curve: " + params.getName());
                };
            }
            case null, default -> throw new IllegalArgumentException("Unsupported key type");
        }
    }

    JWSSigner getSigner(Key key) throws JOSEException {
        return switch (key) {
            case ECPrivateKey ecKey -> new ECDSASigner(ecKey);
            case RSAPrivateKey rsaKey -> new RSASSASigner(rsaKey);
            case null, default -> throw new IllegalArgumentException("Unsupported key type");
        };
    }

    JWSVerifier getVerifier(Key key) throws JOSEException {
        return switch (key) {
            case ECPublicKey ecKey -> new ECDSAVerifier(ecKey);
            case RSAPublicKey rsaKey -> new RSASSAVerifier(rsaKey);
            case null, default -> throw new IllegalArgumentException("Unsupported key type or not a public key");
        };
    }
}
