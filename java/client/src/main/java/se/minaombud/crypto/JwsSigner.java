package se.minaombud.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWKException;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.util.Base64URL;
import se.minaombud.json.JsonCanonicalizer;
import se.minaombud.model.JwsSig;

import java.util.function.BiFunction;

public class JwsSigner {

    private static final String SIG_FIELD = "_sig";
    private final DefaultJWSSignerFactory signerFactory;
    private final JWSAlgorithm alg;
    private final KeyList keys;
    private final JWKMatcher keyMatcher;


    /**
     * Skapa signeringsinstans.
     *
     * @param keys signeringsnycklar
     * @param alg signingsalgoritm
     */
    public JwsSigner(KeyList keys, JWSAlgorithm alg) {
        this.signerFactory = new DefaultJWSSignerFactory();
        this.alg = alg;
        this.keys = keys;

        final KeyType kty;
        if (JWSAlgorithm.Family.RSA.contains(alg)) {
            kty = KeyType.RSA;
        } else if (JWSAlgorithm.Family.EC.contains(alg)) {
            kty = KeyType.EC;
        } else if (JWSAlgorithm.Family.ED.contains(alg)) {
            kty = KeyType.OKP;
        } else if (JWSAlgorithm.Family.HMAC_SHA.contains(alg)) {
            kty = KeyType.OCT;
        } else {
            throw new IllegalArgumentException("Unsupported algorithm: " + alg);
        }

        this.keyMatcher = new JWKMatcher.Builder()
            .keyType(kty)
            .build();
    }

    /**
     * Signera JSON-sträng.
     * @param json JSON-text
     * @return JWS
     * @throws JOSEException
     */
    public JWSObject signJson(String json) throws JOSEException {
        return sign(new Payload(json));
    }

    /**
     * Signera JSON-bytes.
     * @param json JSON-data
     * @return JWS
     * @throws JOSEException
     */
    public JWSObject signJson(byte[] json) throws JOSEException {
        return sign(new Payload(json));
    }

    /**
     * Signera payload.
     * Generellt signeringsgränssnitt.
     *
     * @param payload data som ska signeras
     * @return JWS
     * @throws JOSEException
     */
    public JWSObject sign(Payload payload) throws JOSEException {
        var key = keys.selectKey(keyMatcher)
            .orElseThrow(() -> new IllegalStateException("No signing key available"));
        if (key.getAlgorithm() != null && !alg.equals(key.getAlgorithm())) {
            throw new JWKException("Key algorithm mismatch: " + key.getAlgorithm());
        }

        var signer = this.signerFactory.createJWSSigner(key);
        var header = new JWSHeader.Builder(alg)
            .keyID(key.getKeyID())
            .build();

        var jws = new JWSObject(header, payload);
        jws.sign(signer);
        return jws;
    }

    private <R> R doApplySignature(Object object, BiFunction<JsonCanonicalizer, JwsSig, R> handler) {
        var canonical = JsonCanonicalizer.root(object)
            .exclude(SIG_FIELD);
        var payload = new Payload(Base64URL.from(canonical.toBase64Url()));
        try {
            var jws = sign(payload);
            var sig = new JwsSig()
                ._protected(jws.getHeader().toBase64URL().toString())
                .signature(jws.getSignature().toString());
            return handler.apply(canonical, sig);
        } catch (JOSEException e) {
            throw new RuntimeException("Signing failed", e);
        }
    }

    public <T, R> R signObject(T object, BiFunction<T, JwsSig, R> handler) {
        return doApplySignature(object, (canonical, sig) -> handler.apply(object, sig));
    }

    @SuppressWarnings("unchecked")
    public <T> T embedSignature(T object) {
        return embedSignature((Class<T>)object.getClass(), object);
    }

    public <T> T embedSignature(Class<T> type, T object) {
        return doApplySignature(object, (canonical, sig) -> canonical
            .include(SIG_FIELD)
            .put(SIG_FIELD, sig)
            .toPojo(type));
    }

}
