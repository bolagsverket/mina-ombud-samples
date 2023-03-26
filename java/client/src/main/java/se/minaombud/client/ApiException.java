package se.minaombud.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import se.minaombud.model.ApiError;
import se.minaombud.json.Json;

import java.net.http.HttpHeaders;
import java.util.Optional;

public class ApiException extends RuntimeException {
    private final int code;
    private final HttpHeaders responseHeaders;
    private final String responseBody;
    private final ApiError error;

    public ApiException(String message, Throwable throwable, int code, HttpHeaders responseHeaders, String responseBody) {
        super(message, throwable);
        this.code = code;
        this.responseHeaders = responseHeaders;
        this.responseBody = responseBody;

        ApiError error = null;
        String contentType = Optional.ofNullable(responseHeaders).flatMap(h -> h.firstValue("content-type"))
            .map(String::toLowerCase)
            .orElse("");
        if ("application/json".equals(contentType) && responseBody != null && responseBody.startsWith("{")) {
            try {
                error = Json.DEFAULT_MAPPER
                    .readerFor(ApiError.class)
                    .without(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                    .readValue(responseBody);
            } catch (JsonProcessingException ignored) {
                // IGNORED
            }
        }

        this.error = error;
    }

    public ApiException(String message, int code, HttpHeaders responseHeaders, String responseBody) {
        this(message, null, code, responseHeaders, responseBody);
    }

    public ApiException(String message, Throwable throwable, int code, HttpHeaders responseHeaders) {
        this(message, throwable, code, responseHeaders, null);
    }

    public ApiException(int code, HttpHeaders responseHeaders, String responseBody) {
        this(null, null, code, responseHeaders, responseBody);
    }

    public ApiException(int code, String message) {
        this(message, null, code, null, null);
    }

    public ApiException(int code, String message, HttpHeaders responseHeaders, String responseBody) {
        this(message, null, code, responseHeaders, responseBody);
    }

    /**
     * Get the HTTP status code.
     *
     * @return HTTP status code
     */
    public int getCode() {
        return code;
    }

    /**
     * Get the HTTP response headers.
     *
     * @return Headers as an HttpHeaders object
     */
    public HttpHeaders getResponseHeaders() {
        return responseHeaders;
    }

    /**
     * Get the HTTP response body.
     *
     * @return Response body in the form of string
     */
    public String getResponseBody() {
        return responseBody;
    }

    public ApiError getError() {
        return error;
    }
}
