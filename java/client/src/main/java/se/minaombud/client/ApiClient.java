package se.minaombud.client;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.minaombud.crypto.JwsSigner;
import se.minaombud.crypto.JwsVerifier;
import se.minaombud.crypto.KeyList;
import se.minaombud.crypto.SignatureVerificationException;
import se.minaombud.json.Json;
import se.minaombud.model.Behorighetskontext;
import se.minaombud.model.FullmaktMetadataResponse;
import se.minaombud.model.HamtaBehorigheterRequest;
import se.minaombud.model.HamtaBehorigheterResponse;
import se.minaombud.model.HamtaFullmakterRequest;
import se.minaombud.model.HamtaFullmakterResponse;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodySubscribers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Sample API client.
 *
 * <p>
 * For testing purposes it supports signing an ID token for the user on the
 * fly. In a production environment the ID token would be supplied by the caller.
 * </p>
 *
 * <p>
 * API response errors result in an {@link ApiException} being thrown.
 * Other request errors result in a {@link RequestException}.
 * </p>
 *
 * <p>
 * Uses {@link java.net.http.HttpClient} under the hood.
 * </p>
 *
 * <p>
 * Usage:<br>
 * <pre><code>
 * var keys = KeyList.load("keystore.p12"); // If using ApiClient to sign id tokens
 * var client = new ApiClient(keys)
 *   .apiUrl("https://fullmakt-test.minaombud.se/dfm/formedlare/v2")
 *   .tokenEndpoint("https://auth-accept.minaombud.se/auth/realms/dfm/protocol/openid-connect/token")
 *   .clientId("my-client-id")
 *   .clientSecret("secret")
 *   .scope("user:self")
 *   .audience("my-registered-audience")
 *   .issuer("my-registered-issuer");
 * var idToken = client.signJwt(Map.of(
 *      "sub", "...",
 *      "https://claims.oidc.se/1.0/personalNumber", "...",
 *      "given_name", "Test",
 *      "family_name", "Persson",
 *      "name": "Test Persson")); // If using ApiClient to sign id tokens
 * var behorigheter = client.request()
 *   .service("my-service-name")
 *   .idToken(idToken)
 *   .sokBehorigheter(new HamtaBehorigheterRequest()
 *      .tredjeman("...")
 *      .fullmaktshavare(new Identitetsbeteckning()
 *          .id("...")
 *          .typ("pnr))
 *      .behorigheter(List.of("...", "...")));
 * </code></pre>
 * </p>
 */
public class ApiClient {

    private static final Logger LOG = LoggerFactory.getLogger(ApiClient.class);

    private final HttpClient client;
    final Json json;
    final JwsSigner signer;
    private final Map<String, Object> baseClaims = new HashMap<>();
    private Map<String, Object> userClaims = Map.of();
    private String service = null;
    private String clientId = null;
    private String clientSecret = null;
    private final AtomicReference<TokenResponse> tokenResponse = new AtomicReference<>(new TokenResponse());
    URI apiUrl = null;
    URI tokenEndpoint = null;
    private String scope = null;
    private JwsVerifier.Factory verifierFactory;
    private Duration tokenExpiryTime = Duration.ofMinutes(2);

    public ApiClient(HttpClient client,
                     Json json,
                     KeyList keys) {
        this.client = client;
        this.json = json;
        this.signer = new JwsSigner(keys != null ? keys : new KeyList(List.of()), JWSAlgorithm.RS256);
    }

    public ApiClient(KeyList keys) {
        this(HttpClient.newHttpClient(), new Json(), keys);
    }

    public ApiClient apiUrl(URI apiUrl) {
        this.apiUrl = Objects.requireNonNull(apiUrl, "API URL must not be null");
        this.verifierFactory = new JwsVerifier.Factory(apiUrl);
        return this;
    }

    public ApiClient tokenEndpoint(URI tokenEndpoint) {
        this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint, "Token endpoint URL must not be null");
        return this;
    }

    /**
     * Set default service name.
     *
     * @return this
     */
    public ApiClient service(String service) {
        this.service = Objects.requireNonNull(service, "Service name must not be null");
        return this;
    }

    /**
     * Set client id.
     *
     * @return this
     */
    public ApiClient clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    /**
     * Set client secret.
     *
     * @return this
     */
    public ApiClient clientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    /**
     * Set scope of requested access tokens.
     *
     * @param scope scope (user:self, user:any or user:other)
     * @return this
     */
    public ApiClient scope(String scope) {
        if (!Objects.equals(this.scope, scope)) {
            this.scope = scope;
            this.tokenResponse.set(new TokenResponse());
        }
        return this;
    }

    /**
     * Set issuer of ID tokens.
     *
     * @return this
     */
    public ApiClient issuer(String iss) {
        baseClaims.put("iss", iss);
        return this;
    }

    /**
     * Set audience of ID tokens.
     *
     * @return this
     */
    public ApiClient audience(List<String> audience) {
        baseClaims.put("aud", audience.size() == 1 ? audience.get(0) : audience);
        if (audience.size() > 1) {
            baseClaims.putIfAbsent("azp", audience.get(0));
        } else {
            baseClaims.remove("azp");
        }
        return this;
    }

    public ApiClient audience(String audience) {
        return audience(List.of(audience));
    }

    /**
     * Set authorized party of ID tokens.
     *
     * @return this
     */
    public ApiClient authorizedParty(String azp) {
        if (azp == null) {
            baseClaims.remove("azp");
        } else {
            baseClaims.put("azp", azp);
        }
        return this;
    }

    private void ensureApiUrl() {
        if (apiUrl == null) {
            throw new IllegalStateException("API URL not set");
        }
    }

    public ApiClient tokenExpiryTime(Duration tokenExpiryTime) {
        this.tokenExpiryTime = tokenExpiryTime;
        return this;
    }

    public String signJwt(Map<String, Object> claims) {
        return signJwt(claims, tokenExpiryTime);
    }

    public String signJwt(Map<String, Object> claims, Duration expiryTime) {
        var payload = new LinkedHashMap<>(baseClaims);
        payload.putAll(claims);

        var iat = Instant.now().getEpochSecond();
        payload.put("iat", iat);
        if (expiryTime != null) {
            var exp = iat + expiryTime.toSeconds();
            payload.put("exp", exp);
        }

        if (!payload.containsKey("sub")) {
            payload.put("sub", UUID.randomUUID().toString());
        }

        try {
            return signer.signJson(json.toBytes(payload)).serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Token signing failed", e);
        }
    }

    public Behorighetskontext verifySignature(Behorighetskontext kontext) {
        var outcome = verifierFactory.forTredjeman(kontext.getTredjeman())
            .verifyDetachedSignature(kontext, kontext.getSig());
        if (!outcome.isVerified()) {
            var msg = String.format("Ogiltig signatur för behörighetskontext [tredjeman=%s] [fullmaktsgivare=%s]",
                kontext.getTredjeman(), kontext.getFullmaktsgivare().getId());
            throw new SignatureVerificationException(msg, outcome.exception);
        }

        return kontext;
    }

    public HamtaBehorigheterResponse verifySignature(HamtaBehorigheterResponse response) {
        response.getKontext().forEach(this::verifySignature);
        return response;
    }

    public FullmaktMetadataResponse verifySignature(String tredjemanId, UUID fullmaktId, FullmaktMetadataResponse response) {
        var outcome = verifierFactory.forTredjeman(tredjemanId)
            .verifyDetachedSignature(response, response.getSig());

        if (!outcome.isVerified()) {
            var msg = String.format("Ogiltig signatur för fullmakt [tredjeman=%s] [fullmakt=%s]",
                tredjemanId, fullmaktId);
            throw new SignatureVerificationException(msg, outcome.exception);
        }

        return response;
    }

    public FullmaktMetadataResponse verifySignature(FullmaktMetadataResponse response) {
        var fullmakt = response.getFullmakt();
        return verifySignature(fullmakt.getTredjeman().getId(), fullmakt.getId(), response);
    }

    /**
     * API request builder.
     */
    public class ApiRequest {
        String idToken;
        Map<String, Object> userClaims = ApiClient.this.userClaims;
        Map<String, String> headers;
        URI uri;

        private ApiRequest() {
        }

        /**
         * Set user claims for request.
         * A signed ID token will sent in the request.
         *
         * @param user User claims
         * @return this
         */
        public ApiRequest userClaims(Map<String, Object> user) {
            this.userClaims = new LinkedHashMap<>(user);
            this.userClaims.computeIfAbsent("sub", k -> UUID.randomUUID().toString());
            return this;
        }

        public ApiRequest requestId(String requestId) {
            return header("x-request-id", requestId);
        }

        /**
         * Set ID token for request.
         *
         * @param idToken Signed ID token identifying the user
         * @return this
         */
        public ApiRequest idToken(String idToken) {
            this.idToken = idToken;
            return this;
        }

        /**
         * Set service name for request.
         * <p>This overrides the default service (if any).</p>
         *
         * @return this
         */
        public ApiRequest service(String service) {
            return header("x-service-name", service);
        }

        /**
         * Set request header.
         *
         * @param name  header name
         * @param value header value
         * @return this
         */
        public ApiRequest header(String name, String value) {
            if (headers == null) {
                headers = new LinkedHashMap<>();
            }
            headers.put(name.toLowerCase(Locale.ROOT), value);
            return this;
        }

        /**
         * Set request URI.
         *
         * @param uri can be relative or absolute
         * @return this
         */
        public ApiRequest uri(URI uri) {
            if (uri.getHost() == null) {
                ensureApiUrl();
                try {
                    this.uri = new URI(apiUrl.getScheme(), apiUrl.getAuthority(), uri.getPath(), uri.getQuery(), null);
                } catch (URISyntaxException e) {
                    throw new IllegalArgumentException(e);
                }
            } else {
                this.uri = uri;
            }
            return this;
        }

        /**
         * Set request URI.
         *
         * @param uri can be relative or absolute
         * @return this
         */
        public ApiRequest uri(String uri) {
            if (!uri.startsWith("http:") && !uri.startsWith("https:")) {
                ensureApiUrl();
                var path = uri.startsWith("/") ? uri : '/' + uri;
                return uri(URI.create(apiUrl + path));
            } else {
                return uri(URI.create(uri));
            }
        }

        /**
         * Set request path relative to API base URL.
         *
         * @param path   path that can contain path variables on the form {name}
         * @param params parameters matching the order in the path
         * @return this
         */
        public ApiRequest path(String path, Object... params) {
            return uri(expandPathVariables(path, params));
        }

        /**
         * Set request headers.
         *
         * @param consumer a callback receiving a map of headers
         * @return this
         */
        public ApiRequest headers(Consumer<Map<String, String>> consumer) {
            Map<String, String> temp = new LinkedHashMap<>();
            consumer.accept(temp);
            temp.forEach(this::header);
            return this;
        }

        private void finish() {
            if (idToken != null) {
                header("x-id-token", idToken);
            } else if (scope != null && scope.matches(".*\\buser:(self|other)\\b.*")) {
                header("x-id-token", signJwt(userClaims));
            }
        }

        private <T> T request(Class<T> type, String method, Object body) {
            finish();
            return ApiClient.this.request(type, method, uri, headers != null ? headers : Map.of(), body);
        }

        private <T> CompletableFuture<T> requestAsync(Class<T> type, String method, Object body) {
            finish();
            return ApiClient.this.requestAsync(type, method, uri, headers != null ? headers : Map.of(), body);
        }


        /**
         * General POST request
         *
         * @param type type of response (use {@code Void.class} if no response is expected)
         * @param body request body
         * @return this
         */
        public <T> T post(Class<T> type, Object body) {
            return request(type, "POST", body);
        }

        public <T> CompletableFuture<T> postAsync(Class<T> type, Object body) {
            return requestAsync(type, "POST", body);
        }

        /**
         * General POST request
         *
         * @param type type of response (use {@code Void.class} if no response is expected)
         * @return this
         */
        public <T> T get(Class<T> type) {
            return request(type, "GET", null);
        }

        public <T> CompletableFuture<T> getAsync(Class<T> type) {
            return requestAsync(type, "GET", null);
        }

        /**
         * Search power of attorneys.
         *
         * @return search response
         * @see #sokFullmakterAsync(HamtaFullmakterRequest)
         */
        public HamtaFullmakterResponse sokFullmakter(HamtaFullmakterRequest request) {
            return path("/sok/fullmakter").post(HamtaFullmakterResponse.class, request);
        }

        /**
         * Search power of attorneys.
         *
         * @return search response
         * @see #sokFullmakter(HamtaFullmakterRequest)
         */
        public CompletableFuture<HamtaFullmakterResponse> sokFullmakterAsync(HamtaFullmakterRequest request) {
            return path("/sok/fullmakter").postAsync(HamtaFullmakterResponse.class, request);
        }

        /**
         * Search permissions.
         *
         * @return search response
         * @see #sokBehorigheterAsync(HamtaBehorigheterRequest)
         */
        public HamtaBehorigheterResponse sokBehorigheter(HamtaBehorigheterRequest request) {
            var response = path("/sok/behorigheter").post(HamtaBehorigheterResponse.class, request);
            return verifySignature(response);
        }

        /**
         * Search permissions.
         *
         * @return search response
         * @see #sokBehorigheter(HamtaBehorigheterRequest)
         */
        public CompletableFuture<HamtaBehorigheterResponse> sokBehorigheterAsync(HamtaBehorigheterRequest request) {
            return path("/sok/behorigheter")
                .postAsync(HamtaBehorigheterResponse.class, request)
                .thenApply(ApiClient.this::verifySignature);
        }

        /**
         * Retrieve full power of attorney.
         *
         * @return power of attorney and metadata
         * @see #hamtaFullmaktAsync(String, UUID)
         */
        public FullmaktMetadataResponse hamtaFullmakt(String tredjemanId, UUID fullmaktId) {
            var response = path("/tredjeman/{tredjemanId}/fullmakter/{fullmaktId}", tredjemanId, fullmaktId)
                .get(FullmaktMetadataResponse.class);

            return verifySignature(tredjemanId, fullmaktId, response);
        }

        /**
         * Retrieve full power of attorney.
         *
         * @return power of attorney and metadata
         * @see #hamtaFullmakt(String, UUID)
         */
        public CompletableFuture<FullmaktMetadataResponse> hamtaFullmaktAsync(String tredjemanId, UUID fullmaktId) {
            return path("/tredjeman/{tredjemanId}/fullmakter/{fullmaktId}", tredjemanId, fullmaktId)
                .getAsync(FullmaktMetadataResponse.class)
                .thenApply(f -> verifySignature(tredjemanId, fullmaktId, f));
        }
    }

    public ApiClient user(Map<String, Object> user) {
        this.userClaims = new LinkedHashMap<>(user);
        this.userClaims.computeIfAbsent("sub", k -> UUID.randomUUID().toString());
        return this;
    }

    public ApiRequest request() {
        return new ApiRequest();
    }

    private static void logRequest(RequestContext<?> context) {
        if (LOG.isTraceEnabled()) {
            var request = context.request;
            StringBuilder sb = new StringBuilder();
            sb.append("Request ").append(request.method()).append(' ').append(request.uri()).append('\n');
            for (var e : request.headers().map().entrySet()) {
                for (var v : e.getValue()) {
                    sb.append(e.getKey()).append(": ").append(v).append('\n');
                }
            }

            if (context.body != null) {
                sb.append('\n');
                if (context.body instanceof byte[]) {
                    sb.append(new String((byte[]) context.body, StandardCharsets.UTF_8));
                } else {
                    sb.append(context.body);
                }
            } else if (context.entity != null) {
                sb.append(context.entity);
            }

            LOG.trace(sb.toString());
        }
    }

    private static void logResponse(RequestContext<?> context, String text) {
        if (LOG.isTraceEnabled()) {
            var request = context.request;
            var responseInfo = context.response;
            StringBuilder sb = new StringBuilder();
            sb.append("Response ").append(request.method()).append(' ').append(request.uri()).append('\n');
            for (var e : responseInfo.headers().map().entrySet()) {
                for (var v : e.getValue()) {
                    sb.append(e.getKey()).append(": ").append(v).append('\n');
                }
            }

            if (!text.isEmpty()) {
                sb.append('\n').append(text);
            }

            LOG.trace(sb.toString());
        }
    }

    <T> HttpResponse<T> doRequest(RequestContext<T> context,
                                  BiFunction<RequestContext<T>, String, RuntimeException> errorFilter) {
        var request = context.request;
        try {
            logRequest(context);
            return client.send(request, bodyHandler(context, errorFilter));
        } catch (IOException e) {
            // HttpClient kastar ett IOException i det generella fallet med ursprungsundantaget som cause.
            // Vissa protokoll- och nätverksrelaterade fel propageras med ursprungstypen.
            Throwable cause = e.getCause();
            if (cause instanceof ApiException) {
                throw (ApiException) cause;
            }

            throw new RequestException("Error in " + request.method() + " " + request.uri(), e);
        } catch (InterruptedException e) {
            throw new RequestException("Request interrupted: " + request.method() + " " + request.uri(), e);
        }
    }

    <T> CompletableFuture<HttpResponse<T>> doRequestAsync(RequestContext<T> context,
                                                          BiFunction<RequestContext<T>, String, RuntimeException> errorFilter) {
        var request = context.request;
        logRequest(context);
        return client.sendAsync(request, bodyHandler(context, errorFilter));
    }

    <T> HttpResponse.BodyHandler<T> bodyHandler(RequestContext<T> context,
                                                BiFunction<RequestContext<T>, String, RuntimeException> errorFilter) {
        var sub = BodySubscribers.ofString(StandardCharsets.UTF_8);
        return responseInfo -> {
            context.response = responseInfo;
            return BodySubscribers.mapping(sub, text -> {
                logResponse(context, text);
                if (responseInfo.statusCode() >= 400) {
                    Optional.ofNullable(errorFilter.apply(context, text))
                        .ifPresent(error -> {
                            throw error;
                        });
                }

                return text.length() == 0 ? null : json.parse(text, context.type);
            });
        };
    }

    static ApiException apiErrorFilter(RequestContext<?> context, String body) {
        var code = context.response.statusCode();
        var msg = "Error in " + context.request.method() + " " + context.request.uri() + ": HTTP " + code;
        LOG.debug(msg);
        return new ApiException(msg, code, context.response.headers(), body);
    }

    private static final Pattern PATH_VARIABLE_PATTERN = Pattern.compile("\\{([a-zA-Z0-9]+)}");

    private static String expandPathVariables(String path, Object... params) {
        if (params.length == 0) {
            return path;
        }

        final var encodedParams = Stream.of(params)
            .map(p -> URLEncoder.encode(Objects.toString(p), StandardCharsets.UTF_8).replace("+", "%20"))
            .collect(Collectors.toList());

        final var counter = new int[1];
        return PATH_VARIABLE_PATTERN
            .matcher(path)
            .replaceAll(m -> encodedParams.get(counter[0]++));
    }

    static class RequestContext<T> {
        final Class<T> type;
        final HttpRequest request;
        final Object entity;
        final Object body;
        HttpResponse.ResponseInfo response;

        RequestContext(Class<T> type, HttpRequest request, Object entity, Object body) {
            this.type = type;
            this.request = request;
            this.entity = entity;
            this.body = body;
        }
    }

    private <T> RequestContext<T> buildRequest(Class<T> type,
                                               String method,
                                               URI uri,
                                               Map<String, String> headers,
                                               Object entity) {
        var request = HttpRequest.newBuilder()
            .uri(uri)
            .header("authorization", "Bearer " + accessToken());

        if (service != null) {
            request.header("x-service-name", service);
        }

        String contentType = headers.get("application/json");
        if (entity != null && contentType == null) {
            contentType = "application/json";
            request.header("content-type", contentType);
        }

        headers.forEach(request::header);

        HttpRequest.BodyPublisher bodyPublisher;
        Object body = LOG.isTraceEnabled() ? entity : null;
        if (entity == null) {
            bodyPublisher = BodyPublishers.noBody();
        } else if (entity instanceof String) {
            bodyPublisher = BodyPublishers.ofString((String) entity);
        } else if (entity instanceof byte[]) {
            bodyPublisher = BodyPublishers.ofByteArray((byte[]) entity);
        } else if ("application/json".equals(contentType)) {
            if (LOG.isTraceEnabled()) {
                body = json.toString(entity);
                bodyPublisher = BodyPublishers.ofString((String) body);
            } else {
                bodyPublisher = BodyPublishers.ofByteArray(json.toBytes(entity));
            }
        } else {
            throw new IllegalArgumentException("Unsupported body and content type: " + contentType + ", " + entity.getClass());
        }

        return new RequestContext<>(type, request.method(method, bodyPublisher).build(), entity, body);
    }

    private <T> T request(Class<T> type,
                          String method,
                          URI uri,
                          Map<String, String> headers,
                          Object entity) {
        var context = buildRequest(type, method, uri, headers, entity);
        return doRequest(context, ApiClient::apiErrorFilter).body();
    }

    private <T> CompletableFuture<T> requestAsync(Class<T> type,
                                                  String method,
                                                  URI uri,
                                                  Map<String, String> headers,
                                                  Object entity) {
        var context = buildRequest(type, method, uri, headers, entity);
        return doRequestAsync(context, ApiClient::apiErrorFilter).thenApply(HttpResponse::body);
    }

    private TokenResponse requestToken() {
        if (tokenEndpoint == null) {
            throw new IllegalStateException("Token endpoint not set");
        }

        if (clientId == null || clientSecret == null) {
            throw new IllegalStateException("Client credentials not set");
        }

        if (scope == null) {
            throw new IllegalStateException("Scope not set");
        }

        var prev = tokenResponse.get();
        var tokenRequest = Map.of(
            "grant_type", "client_credentials",
            "client_id", clientId,
            "client_secret", clientSecret,
            "scope", scope);

        LOG.debug("Requesting access token [client_id={}] [scope={}]", clientId, scope);

        var requestForm = tokenRequest.entrySet().stream()
            .map(e -> e.getKey() + '=' + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .collect(Collectors.joining("&"));

        var request = HttpRequest.newBuilder()
            .uri(tokenEndpoint)
            .header("accept", "application/json")
            .header("content-type", "application/x-www-form-urlencoded")
            .POST(BodyPublishers.ofString(requestForm))
            .build();

        var start = System.currentTimeMillis() / 1000;
        var context = new RequestContext<>(TokenResponse.class, request, tokenRequest, requestForm);
        var response = doRequest(context, (c, t) -> null);
        var body = response.body();
        if (body != null) {
            if (body.getAccessToken() != null && body.getExpiresIn() > 0) {
                body.requestTime(start);
                LOG.debug("Access token [scope={}] [expires_in={}] expires at {}", body.getScope(),
                    body.getExpiresIn(),
                    Instant.ofEpochSecond(body.getExpiresAt()));
                tokenResponse.compareAndSet(prev, body);
                return body;
            }

            String msg = String.format("Access token request failed [error=%s] [error_description=%s] [error_uri=%s]",
                body.getError(), body.getErrorDescription(), body.getErrorUri());
            LOG.warn(msg);
            if (tokenResponse.get().isExpired()) {
                throw new AuthException(msg);
            }
        }

        return null;
    }

    public String accessToken() {
        return Optional.of(tokenResponse.get())
            .filter(r -> !r.isExpired())
            .or(() -> Optional.ofNullable(requestToken()))
            .map(TokenResponse::getAccessToken)
            .orElseThrow(() -> new AuthException("Failed to acquire access token"));
    }

}
