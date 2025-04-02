package io.github.aarmam.tsl;

public non-sealed abstract class ApplicationSpecificStatusType extends StatusType {
    public static final int APPLICATION_SPECIFIC_1 = 0x03;
    private static final int APPLICATION_SPECIFIC_MIN = 0x0B;
    private static final int APPLICATION_SPECIFIC_MAX = 0x0F;

    public ApplicationSpecificStatusType(int value) {
        super(value);
        if (!isApplicationSpecific(value)) {
            throw new IllegalArgumentException("Not a valid application specific status");
        }
    }

    public static boolean isApplicationSpecific(int value) {
        return value == APPLICATION_SPECIFIC_1 ||
                (value >= APPLICATION_SPECIFIC_MIN && value <= APPLICATION_SPECIFIC_MAX);
    }
}
