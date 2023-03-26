package se.minaombud.samples;

import com.fasterxml.jackson.core.type.TypeReference;
import se.minaombud.json.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static se.minaombud.json.Json.DEFAULT_MAPPER;

public final class Users {

    private Users() {
    }

    private static final TypeReference<List<Map<String, Object>>> USER_LIST_TYPE = new TypeReference<>() {
    };

    private static final String[] ID_CLAIMS = {
        "https://claims.oidc.se/1.0/personalNumber",
        "https://claims.oidc.se/1.0/coordinationNumber",
        "preferred_username",
        "sub"
    };

    public static Map<String, Map<String, Object>> loadSampleUsers(Path path) {
        try (var is = Files.newInputStream(path)) {
            var users = new LinkedHashMap<String, Map<String, Object>>();
            for (var u : DEFAULT_MAPPER.readValue(is, USER_LIST_TYPE)) {
                for (var claim : ID_CLAIMS) {
                    var id = (String) u.get(claim);
                    if (id != null) {
                        users.put(id, u);
                    }
                }
            }
            return users;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static final Pattern SWEDISH_NATIONAL_ID_PATTERN = Pattern.compile("(1[69]|20)?\\d{10}");

    public static String classifyNationalIdentity(String id) {
        if (SWEDISH_NATIONAL_ID_PATTERN.matcher(id).matches()) {
            if (id.startsWith("16") && id.length() == 12) {
                id = id.substring(2);
            }

            if (id.length() == 10) {
                if (id.startsWith("302")) {
                    return "gdnr";
                }

                if (id.charAt(2) >= '2') {
                    return "orgnr";
                }
            } else if (id.length() == 12 && (id.startsWith("19") || id.startsWith("20"))) {
                return id.charAt(6) >= '6' ? "samnr" : "pnr";
            }
        }

        throw new IllegalArgumentException("Invalid identification number: " + id);
    }

    public static Map<String, Object> createUser(String userSpec, Map<String, Map<String, Object>> users) {
        if (userSpec.startsWith("{")) {
            return new Json().parseJsonObject(userSpec);
        }

        if (userSpec.contains(",")) {
            String[] parts = userSpec.split(",");
            String id = parts[0];
            String typ = parts[1];
            var claims = new LinkedHashMap<String, Object>();
            if ("pnr".equals(typ)) {
                claims.put("https://claims.oidc.se/1.0/personalNumber", id);
            } else if ("samnr".equals(typ)) {
                claims.put("https://claims.oidc.se/1.0/coordinationNumber", id);
            } else {
                claims.put("sub", id);
            }

            String givenName = parts.length > 3 ? parts[2] : (parts.length == 3 ? null : "Test");
            String familyName = parts.length > 3 ? parts[3] : (parts.length > 2 ? parts[2] : "Persson");
            claims.put("given_name", givenName);
            claims.put("family_name", familyName);
            if (givenName != null && familyName != null) {
                claims.put("name", givenName + ' ' + familyName);
            } else {
                claims.put("name", familyName);
            }

            return claims;
        }

        var claims = users.get(userSpec);
        if (claims == null) {
            claims = new LinkedHashMap<>();
            if (userSpec.matches("(1[69]|20)?\\d{6}-?\\d{4}")) {
                String id = userSpec.replace("-", "");
                String typ = Users.classifyNationalIdentity(id);
                if ("pnr".equals(typ)) {
                    claims.put("https://claims.oidc.se/1.0/personalNumber", id);
                } else if ("samnr".equals(typ)) {
                    claims.put("https://claims.oidc.se/1.0/coordinationNumber", id);
                } else {
                    claims.put("sub", id);
                }
            } else {
                claims.put("preferred_username", userSpec);
            }
            claims.put("name", "Test Persson");
            claims.put("given_name", "Test");
            claims.put("family_name", "Persson");
        }

        return claims;
    }

}
