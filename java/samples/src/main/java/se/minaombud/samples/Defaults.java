package se.minaombud.samples;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class Defaults {
    public static final String MINA_OMBUD_API_CLIENT_ID = getConfig("MINA_OMBUD_API_CLIENT_ID", "mina-ombud-sample");

    public static final String MINA_OMBUD_API_CLIENT_SECRET =
        getConfig("MINA_OMBUD_API_CLIENT_SECRET", "3392d044-d0f2-491d-a40d-edda4f1361c0");

    public static final URI MINA_OMBUD_API_TOKEN_URL = URI.create(getConfig("MINA_OMBUD_API_TOKEN_URL",
        "https://auth-accept.minaombud.se/auth/realms/dfm-accept2/protocol/openid-connect/token"));

    public static final URI MINA_OMBUD_API_URL =
        URI.create(getConfig("MINA_OMBUD_API_URL", "https://fullmakt-test.minaombud.se/dfm/formedlare/v1"));

    public static final String MINA_OMBUD_SAMPLE_SERVICE = getConfig("MINA_OMBUD_SAMPLE_SERVICE", "mina-ombud-sample");
    public static final String MINA_OMBUD_SAMPLE_ISSUER = getConfig("MINA_OMBUD_SAMPLE_ISSUER", "http://localhost");
    public static final List<String> MINA_OMBUD_SAMPLE_AUDIENCE;

    public static final Path MINA_OMBUD_SAMPLE_DATA;

    public static final Path MINA_OMBUD_SAMPLE_USER_DB;

    public static final String MINA_OMBUD_TREDJE_MAN = getConfig("MINA_OMBUD_TREDJE_MAN", "2120000829");

    static {
        var aud = getConfig("MINA_OMBUD_SAMPLE_AUDIENCE", "mina-ombud");
        MINA_OMBUD_SAMPLE_AUDIENCE = Stream.of(aud.split(","))
            .filter(s -> !s.isBlank())
            .collect(Collectors.toList());
        Path dataPath;
        try {
            dataPath = findSampleDataFolder();
        } catch (IOException ignored) {
            dataPath = null;
        }
        MINA_OMBUD_SAMPLE_DATA = dataPath;
        MINA_OMBUD_SAMPLE_USER_DB = findSampleUsers();
    }

    private static String getConfig(String name, String defaultValue) {
        var value = Optional.ofNullable(System.getProperty(name))
            .orElse(System.getenv(name));
        return value == null || value.isBlank()
            ? defaultValue
            : value;
    }

    private static Path findSampleDataFolder() throws IOException {
        var pathEnv = System.getenv("MINA_OMBUD_SAMPLE_DATA");
        if (pathEnv != null) {
            return Paths.get(pathEnv);
        }

        var path = new File("").getAbsoluteFile();
        do {
            var data = new File(path, "data");
            if (new File(data, "keys").exists()) {
                return data.toPath();
            }

            if ("mina-ombud-samples".equals(path.getName())) {
                break;
            }

            path = path.getParentFile();
        } while (path != null && path.exists());

        path = new File("mina-ombud-samples/data").getAbsoluteFile();
        if (path.exists()) {
            return path.toPath();
        }

        path = new File("../mina-ombud-samples/data").getAbsoluteFile();
        if (path.exists()) {
            return path.toPath();
        }

        return null;
    }

    private static Path findSampleUsers() {
        String pathEnv = System.getenv("MINA_OMBUD_SAMPLE_USER_DB");
        if (pathEnv != null) {
            return Paths.get(pathEnv);
        }

        List<Path> paths = new ArrayList<>();
        if (MINA_OMBUD_SAMPLE_DATA != null) {
            paths.add(MINA_OMBUD_SAMPLE_DATA.resolve("users.json"));
        }

        paths.add(Paths.get("users.json"));

        for (var f : paths) {
            if (Files.exists(f)) {
                return f;
            }
        }

        return null;
    }

}
