package io.github.aarmam.tsl;

/**
 * Base class for application specific Status Types.
 * <p>
 * Section 7.1 of the specification permanently reserves the Status Type value 0x03 and
 * the range 0x0C to 0x0F as application specific; the processing of Status Types using
 * these values is left to the application. All other values are either registered in the
 * "OAuth Status Types" registry (Section 14.5) or reserved for future registration, so
 * applications MUST NOT use them for their own semantics.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/">IETF OAuth Token Status List specification</a>
 */
public non-sealed abstract class ApplicationSpecificStatusType extends StatusType {
    /**
     * The single application specific Status Type value outside the contiguous range.
     */
    public static final int APPLICATION_SPECIFIC_1 = 0x03;
    private static final int APPLICATION_SPECIFIC_MIN = 0x0C;
    private static final int APPLICATION_SPECIFIC_MAX = 0x0F;

    public ApplicationSpecificStatusType(int value) {
        super(value);
        if (!isApplicationSpecific(value)) {
            throw new IllegalArgumentException("Not a valid application specific status");
        }
    }

    /**
     * Checks whether a Status Type value is reserved as application specific.
     *
     * @param value The Status Type value
     * @return true for 0x03 and for 0x0C through 0x0F, false otherwise
     */
    public static boolean isApplicationSpecific(int value) {
        return value == APPLICATION_SPECIFIC_1 ||
                (value >= APPLICATION_SPECIFIC_MIN && value <= APPLICATION_SPECIFIC_MAX);
    }
}
