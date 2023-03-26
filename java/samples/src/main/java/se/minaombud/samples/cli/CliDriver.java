package se.minaombud.samples.cli;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.minaombud.model.FullmaktMetadataResponse;
import se.minaombud.model.FullmaktsgivareRoll;
import se.minaombud.model.HamtaBehorigheterRequest;
import se.minaombud.model.HamtaBehorigheterResponse;
import se.minaombud.model.HamtaFullmakterRequest;
import se.minaombud.model.HamtaFullmakterResponse;
import se.minaombud.model.Identitetsbeteckning;
import se.minaombud.samples.Defaults;
import se.minaombud.samples.Users;
import se.minaombud.client.ApiClient;
import se.minaombud.client.ApiException;
import se.minaombud.crypto.KeyList;
import se.minaombud.json.Json;

import java.io.PrintStream;
import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public class CliDriver {

    private static final Logger LOG = LoggerFactory.getLogger(CliDriver.class);

    private final ApiClient client;

    CliDriver(ApiClient client) {
        this.client = client;
    }

    Object executeCommand(CliOptions opts) {
        if ("help".equals(opts.cmd)) {
            help(System.out);
            return null;
        }

        if ("fullmakter".equals(opts.cmd)) {
            if (opts.fullmakter.isEmpty()) {
                return sokFullmakter(opts);
            }

            var fullmakter = hamtaFullmakter(opts);
            return fullmakter.size() == 1 ? fullmakter.get(0) : fullmakter;
        }

        if ("behorigheter".equals(opts.cmd)) {
            return sokBehorigheter(opts);
        }

        throw new IllegalArgumentException("Unsupported command: " + opts.cmd);
    }

    HamtaFullmakterResponse sokFullmakter(CliOptions opts) {
        var request = new HamtaFullmakterRequest();
        if (!opts.roller.isEmpty()) {
            request.setFullmaktsgivarroll(new ArrayList<>(opts.roller));
        }

        if (opts.tredjeman != null) {
            request.addTredjemanItem(opts.tredjeman);
        }

        if (opts.fullmaktshavare != null) {
            request.fullmaktshavare(new Identitetsbeteckning()
                .id(opts.fullmaktshavare)
                .typ(Users.classifyNationalIdentity(opts.fullmaktshavare)));
        }

        if (opts.fullmaktsgivare != null) {
            request.fullmaktsgivare(new Identitetsbeteckning()
                .id(opts.fullmaktsgivare)
                .typ(Users.classifyNationalIdentity(opts.fullmaktsgivare)));
        }

        return client.request().sokFullmakter(request);
    }

    List<FullmaktMetadataResponse> hamtaFullmakter(CliOptions opts) {
        var fullmakter = new ArrayList<FullmaktMetadataResponse>();
        for (String id : opts.fullmakter) {
            fullmakter.add(client.request().hamtaFullmakt(opts.tredjeman, UUID.fromString(id)));
        }

        return fullmakter;
    }

    HamtaBehorigheterResponse sokBehorigheter(CliOptions opts) {
        var request = new HamtaBehorigheterRequest()
            .tredjeman(opts.tredjeman);

        if (!opts.roller.isEmpty()) {
            request.setFullmaktsgivarroll(new ArrayList<>(opts.roller));
        }

        if (opts.fullmaktshavare != null) {
            request.fullmaktshavare(new Identitetsbeteckning()
                .id(opts.fullmaktshavare)
                .typ(Users.classifyNationalIdentity(opts.fullmaktshavare)));
        }

        if (opts.fullmaktsgivare != null) {
            request.fullmaktsgivare(new Identitetsbeteckning()
                .id(opts.fullmaktsgivare)
                .typ(Users.classifyNationalIdentity(opts.fullmaktsgivare)));
        }

        if (!opts.behorigheter.isEmpty()) {
            request.behorigheter(opts.behorigheter);
        }

        return client.request().sokBehorigheter(request);
    }

    static void help(PrintStream out) {
        out.println("Syntax: [VÄXLAR] kommando [argument...]");
        out.println("Växlar:");
        out.println("   --audience, --aud AUD          audience för id token");
        out.println("   --client-id CLIENT_ID          client id för token request");
        out.println("   --client-secret CLIENT_SECRET  client secret för token request");
        out.println("   --issuer, --iss URI            issuer av id token");
        out.println("   --keys, -k PATH                sökväg till signeringsnycklar");
        out.println("   --log-level, --log LEVEL       ange loggnivå (trace, debug, info, warn, error)");
        out.println("   --fullmaktsgivare ORGNR/PNR    filtrera på fullmaktsgivare");
        out.println("   --fullmaktshavare PNR          filtrera på fullmaktshavare");
        out.println("   --roll PRIVAT|ORGANISATION     filtrera på fullmaktsgivarens roll");
        out.println("   --scope SCOPE                  begärt scope för access token");
        out.println("   --tredjeman ORGNR              tredje mans organisationsnummer");
        out.println("   --user, -u USERID              agera som angiven användare");
        out.println("   --user-db PATH                 ladda användare från angiven JSON-fil");
        out.println();
        out.println("Kommandon:");
        out.println("   behorigheter [KOD...]          sök behörigheter");
        out.println("   fullmakter [ID...]             sök eller hämta angivna fullmakter");
        out.println("   help                           denna text");
    }

    static CliOptions parseOptions(String[] args) throws CliException {
        final var CMD_ARG_COUNT = Map.of(
            "help", new int[]{ 0, 1 },
            "fullmakter", new int[]{ 0, Integer.MAX_VALUE },
            "behorigheter", new int[]{ 0, Integer.MAX_VALUE }
        );

        var opts = new CliOptions();
        if (Defaults.MINA_OMBUD_SAMPLE_USER_DB != null) {
            opts.users.putAll(Users.loadSampleUsers(Defaults.MINA_OMBUD_SAMPLE_USER_DB));
        }

        Path keyPath = Optional.ofNullable(System.getProperty("minaombud.keystore.path"))
            .or(() -> Optional.ofNullable(Defaults.MINA_OMBUD_SAMPLE_DATA)
                .map(p -> p.resolve("keys").resolve("signing.p12").toString()))
            .map(Paths::get)
            .orElse(null);
        String keyPass = Optional.ofNullable(System.getProperty("minaombud.keystore.password"))
            .orElse("");
        List<String> cmdArgs = new ArrayList<>();
        String user = null;
        int minCmdArgs = 0;
        int maxCmdArgs = 0;
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            try {
                if ("-u".equals(arg) || "--user".equals(arg)) {
                    user = args[++i];
                } else if ("--fullmaktshavare".equals(arg)) {
                    opts.fullmaktshavare = args[++i].replace("-", "");
                } else if ("--fullmaktsgivare".equals(arg)) {
                    opts.fullmaktsgivare = args[++i].replace("-", "");
                } else if ("--tredjeman".equals(arg)) {
                    opts.tredjeman = args[++i].replace("-", "");
                } else if ("--privat".equals(arg)) {
                    opts.roller.add(FullmaktsgivareRoll.PRIVAT);
                } else if ("--organisation".equals(arg)) {
                    opts.roller.add(FullmaktsgivareRoll.ORGANISATION);
                } else if ("--roll".equals(arg)) {
                    opts.roller.add(FullmaktsgivareRoll.valueOf(args[++i].toUpperCase(Locale.ROOT)));
                } else if ("--aud".equals(arg) || "--audience".equals(arg)) {
                    opts.aud.add(args[++i]);
                } else if ("-k".equals(arg) || "--key".equals(arg) || "--keys".equals(arg) || "--keystore".equals(arg)) {
                    keyPath = Paths.get(args[++i]);
                } else if ("-kp".equals(arg) || "--keypass".equals(arg) || "--keystore-password".equals(arg)) {
                    keyPass = args[++i];
                } else if ("--user-db".equals(arg)) {
                    opts.users.putAll(Users.loadSampleUsers(Paths.get(args[++i])));
                } else if ("--scope".equals(arg)) {
                    opts.scope = args[++i];
                } else if ("--user-scope".equals(arg)) {
                    String opt = args[++i];
                    opts.scope = opt.startsWith("user:") ? opt : "user:" + opt;
                } else if ("--url".equals(arg) || "--api-url".equals(arg) || "--api".equals(arg)) {
                    opts.apiUrl = args[++i];
                } else if ("--token-url".equals(arg) || "--token-endpoint".equals(arg)) {
                    opts.tokenEndpoint = args[++i];
                } else if ("--service".equals(arg) || "--service-name".equals(arg)) {
                    opts.service = args[++i];
                } else if ("--client-id".equals(arg)) {
                    opts.clientId = args[++i];
                } else if ("--client-secret".equals(arg)) {
                    opts.clientSecret = args[++i];
                } else if ("--log".equals(arg) || "--log-level".equals(arg)) {
                    opts.logLevel = args[++i];
                } else if (arg.startsWith("-")) {
                    throw new CliException(arg + " is not a valid option");
                } else if (opts.cmd == null) {
                    opts.cmd = arg;
                    int[] argLimits = CMD_ARG_COUNT.get(opts.cmd);
                    if (argLimits == null) {
                        throw new CliException(arg + " is not a valid command");
                    }

                    minCmdArgs = argLimits[0];
                    maxCmdArgs = argLimits[1];
                } else if (cmdArgs.size() >= maxCmdArgs) {
                    throw new CliException("Too many arguments for " + opts.cmd + " command: " + arg);
                } else {
                    cmdArgs.add(arg);
                }
            } catch (IndexOutOfBoundsException e) {
                throw new CliException(arg + " option requires an argument");
            }
        }

        if (opts.cmd == null) {
            opts.cmd = "help";
        }

        if (cmdArgs.size() < minCmdArgs) {
            throw new CliException("Too few arguments for " + opts.cmd + " command");
        }

        if ("fullmakter".equals(opts.cmd)) {
            opts.fullmakter = cmdArgs;
            if (!cmdArgs.isEmpty() && opts.tredjeman == null) {
                throw new CliException("Syntax: fullmakter --tredjeman ORGNR FULLMAKT...");
            }
        } else if ("behorigheter".equals(opts.cmd)) {
            if (opts.tredjeman == null) {
                throw new CliException("Syntax: behorigheter --tredjeman ORGNR [BEHORIGHETSKOD...]");
            }
            opts.behorigheter = cmdArgs;
        }

        if (opts.fullmaktshavare == null && user != null && user.matches("(19|20)\\d{6}-?\\d{4}")) {
            opts.fullmaktshavare = user.replace("-", "");
        } else if (user == null && opts.fullmaktshavare != null) {
            user = opts.fullmaktshavare;
        }

        if (opts.aud.isEmpty()) {
            opts.aud.addAll(Defaults.MINA_OMBUD_SAMPLE_AUDIENCE);
        }

        if (user != null) {
            opts.user = Users.createUser(user, opts.users);
        } else {
            opts.user = Map.of(
                "sub", "9ebe70e4-ca61-11ed-97ed-00155d52ccdb",
                "https://claims.oidc.se/1.0/personalNumber", "198602262381",
                "name", "Beri Ylles",
                "given_name", "Beri",
                "family_name", "Ylles");
        }

        if (keyPath != null) {
            opts.keys = KeyList.load(keyPath, keyPass.toCharArray());
        }

        return opts;
    }

    public static void main(String[] args) {
        final CliOptions opts;
        try {
            opts = parseOptions(args);
        } catch (CliException e) {
            System.err.println(e.getMessage());
            help(System.err);
            System.exit(1);
            return;
        }

        if ("help".equals(opts.cmd)) {
            help(System.out);
            return;
        }

        System.setProperty("org.slf4j.simpleLogger.log.se.minaombud", opts.logLevel);

        var json = new Json();
        var httpClient = HttpClient.newBuilder()
            .cookieHandler(new CookieManager())
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
        var apiClient = new ApiClient(httpClient, json, opts.keys)
            .apiUrl(URI.create(opts.apiUrl))
            .tokenEndpoint(URI.create(opts.tokenEndpoint))
            .clientId(opts.clientId)
            .clientSecret(opts.clientSecret)
            .service(opts.service)
            .scope(opts.scope)
            .issuer(opts.iss)
            .audience(opts.aud)
            .user(opts.user);


        var cli = new CliDriver(apiClient);
        try {
            Object response = cli.executeCommand(opts);
            System.out.println(json.toPrettyString(response));
        } catch (ApiException e) {
            LOG.error(e.getMessage());

            if (!"trace".equals(opts.logLevel)) {
                if (e.getResponseHeaders() != null) {
                    for (var h : e.getResponseHeaders().map().entrySet()) {
                        for (var v : h.getValue()) {
                            System.err.println(h.getKey() + ": " + v);
                        }
                    }
                }

                String error = e.getResponseBody();
                if (error != null && !error.isEmpty()) {
                    if (error.startsWith("{")) {
                        try {
                            error = json.toPrettyString(json.parseJsonObject(e.getResponseBody()));
                        } catch (Exception ignored) {
                            // IGNORED
                        }
                    }
                    System.err.println(error);
                }
            }

            System.exit(1);
        } catch (Exception e) {
            LOG.error("", e);
            System.exit(1);
        }
    }

}
