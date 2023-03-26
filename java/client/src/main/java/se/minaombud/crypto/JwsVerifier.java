package se.minaombud.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.KeyException;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import se.minaombud.json.JsonCanonicalizer;
import se.minaombud.model.JwsSig;
import se.minaombud.json.Json;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.text.ParseException;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class JwsVerifier implements SecurityContext {

    private static final Json JSON = new Json();
    private static final JWSVerifierFactory JWS_VERIFIER_FACTORY = new DefaultJWSVerifierFactory();

    private final JWSKeySelector<? extends JwsVerifier> keySelector;

    public JwsVerifier(JWSKeySelector<? extends JwsVerifier> keySelector) {
        this.keySelector = keySelector;
    }

    public static class Factory {

        private final Map<String, JwsVerifier> verifiers = new ConcurrentHashMap<>();

        private final String apiUrl;
        private final Set<JWSAlgorithm> algorithms;

        public Factory(URI apiUrl) {
            this(apiUrl, Set.of(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512));
        }

        public Factory(URI apiUrl, Set<JWSAlgorithm> algorithms) {
            this.apiUrl = apiUrl.toString();
            this.algorithms = algorithms;
        }

        public JwsVerifier forTredjeman(String tredjeman) {
            return verifiers.computeIfAbsent(tredjeman, this::create);
        }

        public URL jwksUrl(String tredjeman) {
            try {
                return new URL(apiUrl + "/tredjeman/" + tredjeman + "/jwks");
            } catch (MalformedURLException e) {
                throw new IllegalArgumentException(e);
            }
        }

        private JWKSource<JwsVerifier> createJwkSource(String tredjeman) {
            return JWKSourceBuilder.<JwsVerifier>create(jwksUrl(tredjeman))
                .cache(true)
                .rateLimited(true)
                .build();
        }

        private JWSKeySelector<JwsVerifier> createKeySelector(String tredjeman) {
            return new JWSVerificationKeySelector<>(algorithms, createJwkSource(tredjeman));
        }

        private JwsVerifier create(String tredjeman) {
            return new JwsVerifier(createKeySelector(tredjeman));
        }
    }


    /**
     * Verifiera ett objekt som har en inbäddad signatur i JSON-attributet _sig.
     * @param object objekt att verifiera
     * @return resultat av verifiering
     */
    public SignatureVerificationOutcome verifyEmbeddedSignature(Object object) {
        var payload = JsonCanonicalizer.root(object);
        var sig = JSON.convert(payload.root().get("_sig"), JwsSig.class);
        return verifySignature(payload, sig);
    }

    /**
     * Verifiera ett objekt.
     * @param object objekt att verifiera
     * @param sig signatur
     * @return resultat av verifiering
     */
    public SignatureVerificationOutcome verifyDetachedSignature(Object object, JwsSig sig) {
        var payload = JsonCanonicalizer.root(object);
        return verifySignature(payload, sig);
    }

    private SignatureVerificationOutcome verifySignature(JsonCanonicalizer canonicalizer, JwsSig sig) {
        final JWSObject jws;

        // Produce the canonical JSON representation of the payload
        // without the embedded signature.
        var payload = Base64URL.encode(canonicalizer.exclude("_sig").toBytes());
        var hdr = Base64URL.from(Objects.requireNonNull(sig.getProtected()));
        var signature = Base64URL.from(sig.getSignature());

        // Construct JWS object from the protected header, payload and signature.
        try {
            jws = new JWSObject(hdr, payload, signature);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Malformed embedded signature", e);
        }

        try {
            // Find the public key to use for verification.
            var key = keySelector.selectJWSKeys(jws.getHeader(), null)
                .stream()
                .findFirst()
                .orElseThrow(() -> new KeyException("No matching key for " + jws.getHeader()));
            var verifier = JWS_VERIFIER_FACTORY.createJWSVerifier(jws.getHeader(), key);

            // Verify signature
            jws.verify(verifier);
            return new SignatureVerificationOutcome(jws.getPayload().toString(), jws, null);
        } catch (JOSEException e) {
            return new SignatureVerificationOutcome(jws.getPayload().toString(), jws, e);
        }
    }

}
