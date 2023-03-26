package se.minaombud.crypto;

import com.nimbusds.jose.JWSObject;

public class SignatureVerificationOutcome {

    public final String payload;
    public final JWSObject jws;
    public final Throwable exception;

    public SignatureVerificationOutcome(String payload, JWSObject jws, Throwable exception) {
        this.payload = payload;
        this.jws = jws;
        this.exception = exception;
    }

    public boolean isVerified() {
        return jws.getState() == JWSObject.State.VERIFIED;
    }
}
