package se.minaombud.crypto;

public class SignatureVerificationException extends RuntimeException {
    public SignatureVerificationException(String message) {
        super(message);
    }

    public SignatureVerificationException(String message, Throwable cause) {
        super(message, cause);
    }

    public SignatureVerificationException(Throwable cause) {
        super(cause);
    }
}
