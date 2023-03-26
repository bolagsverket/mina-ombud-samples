package se.minaombud.client;

import se.minaombud.crypto.KeyList;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

public class TestUtil {

    public static KeyList loadTestKeys() {
        var password = Optional.ofNullable(System.getProperty("minaombud.keystore.password")).orElse("").toCharArray();
        var pathProperty = System.getProperty("minaombud.keystore.path");
        if (pathProperty != null) {
            return KeyList.load(Paths.get(pathProperty), password);
        }

        String[] paths = { "data", "../data", "../../data", "mina-ombud-samples/data", "../mina-ombud-samples/data" };
        for (String p : paths) {
            Path path = Paths.get(p).resolve("keys").resolve("signing.p12");
            if (Files.exists(path)) {
                return KeyList.load(path, password);
            }
        }

        throw new IllegalStateException("Unable to to locate signing.p12, please set minaombud.keystore.path");
    }

}
