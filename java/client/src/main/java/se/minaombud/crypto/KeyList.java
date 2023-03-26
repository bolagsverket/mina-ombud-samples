package se.minaombud.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKParameterNames;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.util.DateUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class KeyList implements SecurityContext {

    static Clock clock = Clock.systemUTC();

    private final JWKSet keySet;

    static JWK normalizeKey(JWK jwk) {
        var kid = jwk.getKeyID();
        var exp = jwk.getExpirationTime();
        var nbf = jwk.getNotBeforeTime();
        List<X509Certificate> certs = jwk.getParsedX509CertChain();
        var hasCerts = certs != null && !certs.isEmpty();

        var expectedKid = keyId(jwk);
        var expectedExp = Optional.ofNullable(exp)
            .or(() -> {
                if (hasCerts) {
                    return Optional.ofNullable(certs.get(0).getNotAfter());
                }
                return Optional.empty();
            })
            .orElse(null);
        var expectedNbf = Optional.ofNullable(nbf)
            .or(() -> {
                if (hasCerts) {
                    return Optional.ofNullable(certs.get(0).getNotBefore());
                }
                return Optional.empty();
            })
            .orElse(null);

        if (!Objects.equals(kid, expectedKid)
            || !Objects.equals(exp, expectedExp)
            || !Objects.equals(nbf, expectedNbf)) {

            if (jwk instanceof RSAKey) {
                return new RSAKey.Builder((RSAKey) jwk)
                    .keyID(expectedKid)
                    .notBeforeTime(expectedNbf)
                    .expirationTime(expectedExp)
                    .build();
            }

            if (jwk instanceof ECKey) {
                return new ECKey.Builder((ECKey) jwk)
                    .keyID(expectedKid)
                    .notBeforeTime(expectedNbf)
                    .expirationTime(expectedExp)
                    .build();
            }

            var json = jwk.toJSONObject();
            json.put(JWKParameterNames.KEY_ID, expectedKid);
            if (expectedNbf != null) {
                json.put(JWKParameterNames.NOT_BEFORE, DateUtils.toSecondsSinceEpoch(expectedNbf));
            }
            if (expectedExp != null) {
                json.put(JWKParameterNames.EXPIRATION_TIME, DateUtils.toSecondsSinceEpoch(expectedExp));
            }
            try {
                return JWK.parse(json);
            } catch (ParseException e) {
                throw new RuntimeException("JWK not round trip safe", e);
            }
        }

        return jwk;
    }

    static String keyId(JWK jwk) {
        String kid = jwk.getKeyID();
        Base64URL x5t256 = jwk.getX509CertSHA256Thumbprint();
        try {
            if (kid != null
                && x5t256 != null
                && kid.equalsIgnoreCase(x5t256.toString())
                && jwk.getKeyStore() != null
                && jwk.getKeyStore().containsAlias(kid)) {
                // If the keystore alias is the lowercase fingerprint of the certificate
                // we use fingerprint instead.
                return x5t256.toString();
            }
        } catch (KeyStoreException ignored) {
            // IGNORED
        }

        try {
            return kid != null ? kid : jwk.computeThumbprint().toString();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public KeyList(JWK key) {
        this.keySet = new JWKSet(normalizeKey(key));
    }

    public KeyList(List<JWK> keySet) {
        this.keySet = new JWKSet(keySet.stream().map(KeyList::normalizeKey).collect(Collectors.toList()));
    }

    public KeyList(JWKSet jwks) {
        this(jwks.getKeys());
    }

    public List<JWK> getKeys() {
        return keySet.getKeys();
    }

    public JWKSet getKeySet() {
        return keySet;
    }

    public List<JWK> getActivePublicKeys() {
        final var jwks = new ArrayList<JWK>(keySet.size());
        final var filter = filterForInstant(Instant.now(clock));
        for (JWK k : keySet.getKeys()) {
            if (filter.test(k)) {
                JWK publicKey = k.toPublicJWK();
                if (publicKey != null) {
                    jwks.add(publicKey);
                }
            }
        }
        return jwks;
    }

    static Predicate<JWK> filterForInstant(Instant now) {
        var d = new Date(now.toEpochMilli());
        return k -> (k.getNotBeforeTime() == null || d.compareTo(k.getNotBeforeTime()) >= 0)
            && (k.getExpirationTime() == null || d.compareTo(k.getExpirationTime()) <= 0);
    }

    public JWKSet getActiveJWKSet() {
        return new JWKSet(getActiveKeys());
    }

    public List<JWK> getActiveKeys() {
        final var jwks = new ArrayList<JWK>(keySet.size());
        final var filter = filterForInstant(Instant.now(clock));
        for (JWK k : keySet.getKeys()) {
            if (filter.test(k)) {
                jwks.add(k);
            }
        }
        return jwks;
    }

    public Optional<JWK> selectKey(JWKMatcher matcher) {
        final Predicate<JWK> filter = filterForInstant(Instant.now(clock));
        for (JWK k : keySet.getKeys()) {
            if (filter.test(k) && matcher.matches(k)) {
                return Optional.of(k);
            }
        }
        return Optional.empty();
    }

    public static KeyList load(Path path, char[] password) {
        final String type;
        final String filename = path.getFileName().toString();
        if (filename.endsWith(".jks")) {
            type = "jks";
        } else if (filename.endsWith(".p12") || filename.endsWith(".pfx")) {
            type = "pkcs12";
        } else if (filename.endsWith(".pem")) {
            type = "pem";
        } else if (filename.endsWith(".json") || filename.endsWith(".jwk") || filename.endsWith(".jwks")) {
            type = "json";
        } else {
            type = null;
        }

        try {
            var data = Files.readAllBytes(path);
            return load(data, password, type);
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed loading keys from " + path, e);
        }
    }

    public static KeyList load(String data) {
        if (data.startsWith("{") || data.startsWith("[")) {
            return loadJson(data);
        }

        if (data.startsWith("-----BEGIN ")) {
            return loadPem(data);
        }

        throw new IllegalArgumentException("Not a PEM or JSON-encoded key");
    }

    public static KeyList load(byte[] data) {
        return load(data, null, null);
    }

    public static KeyList load(byte[] data, char[] password) {
        return load(data, password, null);
    }

    public static KeyList load(byte[] data, char[] password, String type) {
        if ("json".equals(type) || (type == null && data.length > 0 && (data[0] == '{' || data[0] == '['))) {
            return loadJson(new String(data, StandardCharsets.UTF_8));
        }

        if ("pem".equals(type)
            || (type == null
                && data.length > 11
                && data[0] == '-' && "-----BEGIN ".equals(new String(data, 0, 11, StandardCharsets.ISO_8859_1)))) {
            return loadPem(new String(data, StandardCharsets.ISO_8859_1));
        }

        return loadKeyStore(data, password, type);
    }

    static final byte[] JKS_MAGIC = {(byte) 0xfe, (byte) 0xed, (byte) 0xfe, (byte) 0xed};

    private static KeyList loadKeyStore(byte[] data, char[] password, String type) {
        try {
            if (type == null) {
                if (data.length > 4 && Arrays.equals(JKS_MAGIC, Arrays.copyOfRange(data, 0, 4))) {
                    type = "jks";
                } else {
                    type = KeyStore.getDefaultType();
                }
            }

            final var pass = password != null ? password : new char[0];
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(new ByteArrayInputStream(data), pass);
            var jwks = JWKSet.load(keyStore, (alias) -> pass);
            return new KeyList(jwks);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw new IllegalArgumentException("Failed loading key store", e);
        }
    }

    private static KeyList loadJson(String data) {
        try {
            if (data.startsWith("[")) {
                return new KeyList(JWKSet.parse("{\"keys\":" + data + '}'));
            }

            Map<String, Object> jsonObject = JSONObjectUtils.parse(data);
            if (jsonObject.get("keys") instanceof List) {
                return new KeyList(JWKSet.parse(jsonObject));
            } else {
                return new KeyList(JWK.parse(jsonObject));
            }
        } catch (ParseException e) {
            throw new IllegalArgumentException("Failed loading JSON keys", e);
        }
    }

    private static KeyList loadPem(String data) {
        try {
            if (data.startsWith("-----BEGIN CERTIFICATE-----")) {
                return new KeyList(JWK.parseFromPEMEncodedX509Cert(data));
            } else {
                return new KeyList(JWK.parseFromPEMEncodedObjects(data));
            }
        } catch (JOSEException e) {
            throw new IllegalArgumentException("Failed loading PEM", e);
        }
    }

}
