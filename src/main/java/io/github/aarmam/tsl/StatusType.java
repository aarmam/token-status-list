package io.github.aarmam.tsl;

import lombok.Getter;

@Getter
public sealed class StatusType permits ApplicationSpecificStatusType {
    public static final StatusType VALID = new StatusType(0);
    public static final StatusType INVALID = new StatusType(1);
    public static final StatusType SUSPENDED = new StatusType(2);

    private final int value;

    protected StatusType(int value) {
        this.value = value;
    }
}
