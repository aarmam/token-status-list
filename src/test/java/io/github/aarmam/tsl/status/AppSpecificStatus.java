package io.github.aarmam.tsl.status;

import io.github.aarmam.tsl.ApplicationSpecificStatusType;
import io.github.aarmam.tsl.StatusType;

public class AppSpecificStatus extends ApplicationSpecificStatusType {
    public static final StatusType INVALID_STATUS = new AppSpecificStatus(4);

    public AppSpecificStatus(int value) {
        super(value);
    }
}
