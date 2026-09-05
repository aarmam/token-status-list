package io.github.aarmam.tsl;

/**
 * Thrown when a Status List Token fails one of the validation rules in Section 8.3 of the
 * IETF OAuth Token Status List specification.
 * <p>
 * A signature that does not verify is reported by the underlying JOSE or COSE library; this
 * exception covers the checks layered on top of it - the token type, the presence of the
 * required claims, the subject matching the Referenced Token's {@code uri}, and expiry.
 * <p>
 * Section 8.3 is explicit that when any of these checks fails no statement about the status
 * of the Referenced Token can be made, and the Referenced Token should be rejected.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/">IETF OAuth Token Status List specification</a>
 */
public class StatusListValidationException extends RuntimeException {

    public StatusListValidationException(String message) {
        super(message);
    }
}
