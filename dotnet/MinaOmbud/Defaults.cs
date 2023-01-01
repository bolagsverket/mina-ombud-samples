// ReSharper disable All
namespace MinaOmbud;

public class Defaults
{
    public string MINA_OMBUD_API_CLIENT_ID = GetEnv("MINA_OMBUD_API_CLIENT_ID", "mina-ombud-sample");

    public string MINA_OMBUD_API_CLIENT_SECRET =
        GetEnv("MINA_OMBUD_API_CLIENT_SECRET", "3392d044-d0f2-491d-a40d-edda4f1361c0");

    public string MINA_OMBUD_API_TOKEN_URL = GetEnv("MINA_OMBUD_API_TOKEN_URL",
        "https://auth-accept.minaombud.se/auth/realms/dfm/protocol/openid-connect/token");

    public string MINA_OMBUD_API_URL =
        GetEnv("MINA_OMBUD_API_URL", "https://fullmakt-test.minaombud.se/dfm/formedlare/v1");

    public string MINA_OMBUD_SAMPLE_SERVICE = GetEnv("MINA_OMBUD_SAMPLE_SERVICE", "mina-ombud-sample");
    public string MINA_OMBUD_SAMPLE_ISSUER = GetEnv("MINA_OMBUD_SAMPLE_ISSUER", "http://localhost");
    public string[] MINA_OMBUD_SAMPLE_AUDIENCE;

    public string? MINA_OMBUD_SAMPLE_DATA;

    public Defaults()
    {
        var aud = GetEnv("MINA_OMBUD_SAMPLE_AUDIENCE", "mina-ombud");
        MINA_OMBUD_SAMPLE_AUDIENCE =
            aud.Split(",", StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        MINA_OMBUD_SAMPLE_DATA = findSampleDataFolder();
    }

    private static string? findSampleDataFolder()
    {
        var path = Environment.GetEnvironmentVariable("MINA_OMBUD_SAMPLE_DATA");
        if (path != null)
        {
            return Path.GetFullPath(path);
        }

        path = Environment.CurrentDirectory;
        do
        {
            var data = Path.Join(path, "data");
            if (Directory.Exists(Path.Join(data, "keys")))
            {
                return data;
            }

            if (Path.GetFileName(path) == "mina-ombud-samples")
            {
                break;
            }

            path = Path.GetDirectoryName(path);
        } while (Directory.Exists(path));

        return null;
    }

    public static readonly Defaults Instance = new Defaults();

    private static string GetEnv(string name, string defaultValue)
    {
        var value = System.Environment.GetEnvironmentVariable(name);
        return value == null || value.Trim().Length == 0
            ? defaultValue
            : value;
    }
}
