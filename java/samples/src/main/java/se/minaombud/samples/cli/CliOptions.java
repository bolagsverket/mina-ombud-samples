package se.minaombud.samples.cli;

import se.minaombud.model.FullmaktsgivareRoll;
import se.minaombud.samples.Defaults;
import se.minaombud.crypto.KeyList;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

class CliOptions {
    String apiUrl = Defaults.MINA_OMBUD_API_URL.toString();
    String tokenEndpoint = Defaults.MINA_OMBUD_API_TOKEN_URL.toString();
    KeyList keys;
    String iss = Defaults.MINA_OMBUD_SAMPLE_ISSUER;
    List<String> aud = new ArrayList<>();
    Map<String, Map<String, Object>> users = new LinkedHashMap<>();
    String scope = "user:self";
    Map<String, Object> user = null;
    String service = Defaults.MINA_OMBUD_SAMPLE_SERVICE;
    String clientId = Defaults.MINA_OMBUD_API_CLIENT_ID;
    String clientSecret = Defaults.MINA_OMBUD_API_CLIENT_SECRET;
    String fullmaktsgivare;
    String fullmaktshavare;
    String tredjeman;
    Set<FullmaktsgivareRoll> roller = new HashSet<>();

    String cmd;
    List<String> behorigheter = new ArrayList<>();
    List<String> fullmakter = new ArrayList<>();

    String logLevel = "debug";
}
