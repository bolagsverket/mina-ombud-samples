using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace MinaOmbud;

public abstract class JsonCanonicalizer
{
    internal JsonCanonicalizer()
    {
    }

    public static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        NumberHandling = JsonNumberHandling.Strict,
        UnknownTypeHandling = JsonUnknownTypeHandling.JsonNode,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
        WriteIndented = false
    };

    public static string Serialize(string json, bool detachSig = true)
    {
        var node = JsonSerializer.Deserialize<JsonNode>(json);
        return Serialize(node, detachSig);
    }

    public static string Serialize(object? json, bool detachSig = true, JsonSerializerOptions? options = null)
    {
        options ??= SerializerOptions;
        var node = JsonSerializer.SerializeToNode(json, options);
        return Serialize(node, detachSig, options);
    }

    private static string Serialize(JsonNode? json, bool detachSig, JsonSerializerOptions options)
    {
        var node = ToCanonicalNode(json);
        if (detachSig && node is JsonObject obj)
        {
            obj.Remove("_sig");
        }

        return JsonSerializer.Serialize(node, options);
    }

    private static JsonNode? ToCanonicalNode(JsonNode? node)
    {
        switch (node)
        {
            case JsonArray arr:
                return new JsonArray(arr.Select(ToCanonicalNode).ToArray());
            case JsonObject obj:
            {
                var props = (
                    from field in obj
                    select new KeyValuePair<string, JsonNode?>(field.Key, ToCanonicalNode(field.Value))
                ).ToList();
                props.Sort((a, b) => string.Compare(a.Key, b.Key, StringComparison.Ordinal));
                return new JsonObject(props);
            }
            case JsonValue val:
            {
                var ov = val.GetValue<object>();
                return JsonValue.Create(ov);
            }
            default:
                return node;
        }
    }
}
