package se.minaombud.samples;

import static se.minaombud.samples.Defaults.MINA_OMBUD_STATIC_URL;
import static se.minaombud.samples.Defaults.MINA_OMBUD_TREDJE_MAN;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.xml.sax.SAXException;
import se.minaombud.client.TokenResponse;
import se.minaombud.model.ArkiveringRaderingResponse;
import se.minaombud.model.ArkiveringsinformationResponse;
import se.minaombud.model.Arkiveringspaket;
import se.minaombud.model.PageParameters;

/**
 * API sample downloading packages for archiving.
 *
 * <p>
 * Runs top to bottom illustrating each step:
 * </p>
 * <ol>
 *     <li>Request access token</li>
 *     <li>Invoke API "sokarkiveringspaket" - Check if you have any new archives to download </li>
 *     <li>Invoke API "hamtaArkiveringspaket" - Download and verify the packages in the previous response</li>
 *     <li>Invoke API "raderaArkiveringspaket" - If everything is saved and verified</li>
 * </ol>
 *
 * <p>
 * Uses {@link java.net.HttpURLConnection} for simplicity.
 * </p>
 */
public class ArkiveringSample extends SampleBase {

    static String tredjemanUrl = String.format("/tredjeman/%s", MINA_OMBUD_TREDJE_MAN);
    static String arkiveringUrl = apiUrl + tredjemanUrl + "/arkivering/paket";
    static Path outputDir = Paths.get("archive");

    public static void main(String[] args) throws Exception {

        boolean keep = Arrays.stream(args).anyMatch(arg -> "-k".equals(arg) || "--keep".equals(arg));

        ///////////////////////////////////////////////////////////////////////////////
        // 1. Request API access token with scope fullmakt:arkivering.
        // The access token should be requested and reused for subsequent requests
        // until it expires at which point a new token must be requested.
        var tokenRequestParams = Map.of(
            "grant_type", "client_credentials",
            "client_id", clientId,
            "client_secret", clientSecret,
            "scope", "fullmakt:arkivering");
        var tokenRequest = tokenRequestParams.entrySet().stream()
            .map(e -> e.getKey() + '=' + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .collect(Collectors.joining("&"));

        var tokenRequestHeaders = Map.of("content-type", "application/x-www-form-urlencoded");
        var tokenResponse = post(TokenResponse.class, authUrl, tokenRequestHeaders, tokenRequest);
        defaultHeaders.put("authorization", "Bearer " + tokenResponse.getAccessToken());
        defaultHeaders.put("x-service-name", "ArkiveringSample.java");
        defaultHeaders.put("x-request-id", UUID.randomUUID().toString());

        ///////////////////////////////////////////////////////////////////////////////
        // 2. Invoke API - sokarkiveringspaket
        // Check if we have any new archives to download.
        // List 20 at a time.
        long packagesDownloaded = 0;
        long filesUnpacked = 0;
        long filesValidated = 0;
        long archivesDeleted = 0;

        var pageQueryString = "?" + new PageParameters()
            .page(0)
            .size(20)
            .toUrlQueryString();
        try {
            while (true) {
                var response = get(ArkiveringsinformationResponse.class, arkiveringUrl + pageQueryString);
                Objects.requireNonNull(response, arkiveringUrl + " returned no body");
                if (response.getPaket().isEmpty()) {
                    break;
                }

                for (var pkg : response.getPaket()) {
                    ///////////////////////////////////////////////////////////////////////////////
                    // 3. Invoke API "hamtaArkiveringspaket"
                    // Download, unpack and validate package
                    var zipDir = outputDir.resolve(pkg.getNamn());
                    Files.createDirectories(zipDir);
                    var zipPath = downloadPackage(pkg, zipDir);
                    System.out.printf("Package %s with %d files downloaded: %s%n", pkg.getNamn(), pkg.getAntalFullmakter(), zipPath);
                    packagesDownloaded++;

                    var contents = unpackZipFile(zipDir, zipPath);
                    filesUnpacked += contents.size();
                    for (var xmlPath : contents) {
                        validateXml(xmlPath);
                        filesValidated++;
                    }

                    ///////////////////////////////////////////////////////////////////////////////
                    // 4. Invoke API "raderaArkiveringspaket"
                    // If the package is securely saved and validated then we can send a delete message
                    if (!keep) {
                        deletePackage(pkg);
                        archivesDeleted++;
                        System.out.printf("Package %s with %d files removed from server.",
                            pkg.getId(), pkg.getAntalFullmakter());
                    }
                }
            }
        } finally {
            System.out.printf("%d packages downloaded, %d files unpacked, %d validated and %d packages deleted%n",
                packagesDownloaded, filesUnpacked, filesValidated, archivesDeleted);
        }
    }

    static Path downloadPackage(Arkiveringspaket pkg, Path zipDir) throws IOException {
        var url =  arkiveringUrl + "/" + pkg.getId();
        var conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("GET");
        conn.setDoOutput(false);
        conn.setDoInput(true);
        conn.setRequestProperty("accept", "application/zip");
        defaultHeaders.forEach(conn::setRequestProperty);

        // Open the connection
        conn.connect();
        int responseCode = conn.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            handleResponse(conn, Void.class, Map.of());
            // Never reached
            throw new IOException("Expected HTTP 200 OK from " + url);
        }

        var zipPath = zipDir.resolve(pkg.getId() + ".zip");
        long nread = 0L;
        try (InputStream is = conn.getInputStream();
             var os = Files.newOutputStream(zipPath)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) {
                os.write(buf, 0, n);
                nread += n;
            }
        }

        if (nread <= 0) {
            throw new IOException(url + " returned no data");
        }

        return zipPath;
    }

    static List<Path> unpackZipFile(Path zipDir, Path zipPath) throws IOException {
        try (ZipFile zipFile = new ZipFile(zipPath.toFile())) {
            var contents = new ArrayList<Path>();
            // Validate XML files
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            var buf = new byte[8192];
            while (entries.hasMoreElements()) {
                ZipEntry zipEntry = entries.nextElement();
                if (zipEntry.isDirectory() || !zipEntry.getName().matches("[0-9a-f-]{36}\\.xml")) {
                    throw new IOException("ZIP contains extra files or directories: %s" + zipPath);
                }

                var xmlPath = zipDir.resolve(zipEntry.getName());
                try (var is = zipFile.getInputStream(zipEntry);
                     var os = Files.newOutputStream(xmlPath)) {
                    int n;
                    while ((n = is.read(buf)) > 0) {
                        os.write(buf, 0, n);
                    }
                }

                contents.add(xmlPath);
            }

            return contents;
        }
    }

    private static void validateXml(Path xmlPath) throws IOException {
        try (var reader = Files.newBufferedReader(xmlPath)) {
            validator().validate(new StreamSource(reader, xmlPath.toString()));
        } catch (SAXException e) {
            var message = String.format("XML validation failed for %s/%s",
                xmlPath.getParent().getFileName(), xmlPath.getFileName());
            throw new IOException(message, e);
        }
    }

    static void deletePackage(Arkiveringspaket pkg) throws IOException {
        try {
            delete(ArkiveringRaderingResponse.class, arkiveringUrl + "/" + pkg.getId());
        } catch (Exception e) {
            throw new IOException(String.format("Failed to delete package id %s", pkg.getId()), e);
        }
    }

    private static Validator validator;

    static Validator validator() throws SAXException, MalformedURLException {
        if (validator == null) {
            SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = schemaFactory.newSchema(new URL(MINA_OMBUD_STATIC_URL + "/xsd/arkiveringsinformation_1.0.xsd"));
            validator = schema.newValidator();
        }

        return validator;
    }

}
