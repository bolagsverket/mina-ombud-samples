package se.minaombud.samples;

import se.minaombud.crypto.JwsVerifier;
import se.minaombud.json.Json;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class SampleBase {

    static String apiUrl = Defaults.MINA_OMBUD_API_URL.toString();
    static String authUrl = Defaults.MINA_OMBUD_API_TOKEN_URL.toString();
    static String clientId = Defaults.MINA_OMBUD_API_CLIENT_ID;
    static String clientSecret = Defaults.MINA_OMBUD_API_CLIENT_SECRET;

    static Map<String, String> defaultHeaders = new LinkedHashMap<>();

    static final JwsVerifier.Factory verifierFactory = new JwsVerifier.Factory(URI.create(apiUrl));

    static Json json = new Json();

    ///////////////////////////////////////////////////////////////////////////////
    // HTTP utilities
    ///////////////////////////////////////////////////////////////////////////////
    static final Pattern CHARSET_PARAM_PATTERN = Pattern.compile("\\bcharset=\"?(.*)\"?\\b");

    static <T> T post(Class<T> type, String url, Object body) throws IOException {
        return post(type, url, defaultHeaders, body);
    }

    static <T> T post(Class<T> type, String url, Map<String, String> headers, Object body) throws IOException {
        var conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setRequestProperty("accept", "application/json");
        headers.forEach(conn::setRequestProperty);

        var contentType = conn.getRequestProperty("content-type");
        if (contentType == null) {
            contentType = "application/json";
            conn.setRequestProperty("content-type", contentType);
        }

        try (var os = conn.getOutputStream()) {
            if (body instanceof String) {
                os.write(((String) body).getBytes(StandardCharsets.UTF_8));
            } else if (body instanceof byte[]) {
                os.write((byte[]) body);
            } else if ("application/json".equals(contentType)) {
                os.write(json.toBytes(body));
            } else {
                throw new IllegalArgumentException("Unsupported body and content type: " + contentType + " " + body.getClass());
            }
        }

        return handleResponse(conn, type, headers);
    }

    static <T> T get(Class<T> type, String url) throws IOException {
        return get(type, url, defaultHeaders);
    }

    static <T> T get(Class<T> type, String url, Map<String, String> headers) throws IOException {
        var conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("GET");
        conn.setDoOutput(false);
        conn.setDoInput(true);
        conn.setRequestProperty("accept", "application/json");
        headers.forEach(conn::setRequestProperty);

        return handleResponse(conn, type, headers);
    }

    static <T> T handleResponse(HttpURLConnection conn, Class<T> type, Map<String, String> headers) throws IOException {
        var status = conn.getResponseCode();
        try (var is = status >= 400 ? conn.getErrorStream() : conn.getInputStream()) {
            var response = is != null ? is.readAllBytes() : new byte[0];
            var responseType = Optional.ofNullable(conn.getContentType())
                .map(t -> t.split(";")[0].trim())
                .orElse("");
            var isJson = "application/json".equals(responseType) || responseType.endsWith("+json");
            if (status >= 400 || (!isJson && response.length > 0)) {
                System.err.println("> " + conn.getRequestMethod() + ' ' + conn.getURL());
                for (var  h : headers.entrySet()) {
                    System.err.println("> " + h.getKey() + ": " + h.getValue());
                }

                System.err.println();

                String responseLine = Optional.ofNullable(conn.getHeaderField(null))
                    .orElse("HTTP/1.1 " + status + ' ' + conn.getResponseMessage());
                System.err.println("< " + responseLine);
                for (var h : conn.getHeaderFields().entrySet()) {
                    if (h.getKey() != null) {
                        for (var v : h.getValue()) {
                            System.err.println("< " + h.getKey() + ": " + v);
                        }
                    }
                }

                var responseCharset = Optional.ofNullable(conn.getContentType())
                    .map(CHARSET_PARAM_PATTERN::matcher)
                    .filter(Matcher::find)
                    .map(m -> Charset.forName(m.group(1)))
                    .orElse(responseType.startsWith("text/") ? StandardCharsets.ISO_8859_1 : StandardCharsets.UTF_8);

                var text = new String(response, responseCharset);
                if (!text.isEmpty()) {
                    System.err.println();
                    if (isJson && text.startsWith("{")) {
                        System.err.println(json.toPrettyString(json.parseJsonObject(text)));
                    } else {
                        System.err.println(text);
                    }
                }

                if (status >= 400) {
                    throw new IOException("HTTP " + status + " from " + conn.getRequestMethod() + ' ' + conn.getURL());
                } else {
                    throw new IOException(conn.getRequestMethod() + ' ' + conn.getURL() + " returned " + conn.getContentType());
                }
            }

            if (status >= 300) {
                throw new IOException(conn.getRequestMethod() + ' ' + conn.getURL() + " redirected to " + conn.getHeaderField("location"));
            }

            if (response.length == 0 || type == Void.class) {
                return null;
            }

            return json.parse(response, type);
        }
    }

}
