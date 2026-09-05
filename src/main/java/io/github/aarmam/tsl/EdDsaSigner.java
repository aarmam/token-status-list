package io.github.aarmam.tsl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import java.io.IOException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Set;

/**
 * A JOSE signer and verifier for EdDSA, backed by Bouncy Castle.
 * <p>
 * The JOSE provider's own EdDSA support covers Ed25519 only and requires an additional
 * optional dependency, while the COSE algorithm registry has a single EdDSA entry covering
 * both Ed25519 and Ed448. This implementation supports both curves using Bouncy Castle,
 * which the library already depends on, so any key {@code Utils.getCOSEAlgorithm} maps to
 * EdDSA can actually sign and verify.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8037">RFC 8037</a>
 */
class EdDsaSigner implements JWSSigner, JWSVerifier {
    private static final Set<JWSAlgorithm> SUPPORTED = Set.of(JWSAlgorithm.EdDSA);
    private static final byte[] NO_CONTEXT = new byte[0];

    private final JCAContext jcaContext = new JCAContext();
    private final AsymmetricKeyParameter key;

    private EdDsaSigner(AsymmetricKeyParameter key) {
        this.key = key;
    }

    static EdDsaSigner forSigning(EdECPrivateKey privateKey) {
        try {
            return new EdDsaSigner(PrivateKeyFactory.createKey(privateKey.getEncoded()));
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not read EdDSA private key", e);
        }
    }

    static EdDsaSigner forVerification(EdECPublicKey publicKey) {
        try {
            return new EdDsaSigner(PublicKeyFactory.createKey(publicKey.getEncoded()));
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not read EdDSA public key", e);
        }
    }

    private Signer signer() {
        return switch (key) {
            case Ed25519PrivateKeyParameters ignored -> new Ed25519Signer();
            case Ed25519PublicKeyParameters ignored -> new Ed25519Signer();
            case Ed448PrivateKeyParameters ignored -> new Ed448Signer(NO_CONTEXT);
            case Ed448PublicKeyParameters ignored -> new Ed448Signer(NO_CONTEXT);
            default -> throw new IllegalArgumentException("Unsupported EdDSA key: " + key.getClass().getName());
        };
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        Signer signer = signer();
        signer.init(true, key);
        signer.update(signingInput, 0, signingInput.length);
        try {
            return Base64URL.encode(signer.generateSignature());
        } catch (CryptoException e) {
            throw new JOSEException("EdDSA signing failed", e);
        }
    }

    @Override
    public boolean verify(JWSHeader header, byte[] signingInput, Base64URL signature) {
        Signer verifier = signer();
        verifier.init(false, key);
        verifier.update(signingInput, 0, signingInput.length);
        return verifier.verifySignature(signature.decode());
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return SUPPORTED;
    }

    @Override
    public JCAContext getJCAContext() {
        return jcaContext;
    }
}
