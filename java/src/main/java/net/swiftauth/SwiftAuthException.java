package net.swiftauth;

/**
 * Exception thrown by SwiftAuth API operations.
 */
public class SwiftAuthException extends Exception {
    private final String code;

    public SwiftAuthException(String code, String message) {
        super("[" + code + "] " + message);
        this.code = code;
    }

    public String getCode() { return code; }
}
