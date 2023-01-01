using System.Text.Json.Serialization;

// ReSharper disable All
#pragma warning disable CS8618

namespace MinaOmbud.Models;

public class Identitetsbeteckning
{
    public string Id { get; set; }
    public string Typ { get; set; }

    public Identitetsbeteckning()
    {
    }

    public Identitetsbeteckning(string id, string typ)
    {
        Id = id;
        Typ = typ;
    }

    public Identitetsbeteckning(string id)
    {
        Id = id;
        Typ = Classify(id);
    }

    public static string Classify(string id)
    {
        if (id.StartsWith("16") && id.Length == 12)
        {
            id = id[2..];
        }

        if (id.Length == 10)
        {
            if (id.StartsWith("302"))
            {
                return "gdnr";
            }

            if (id[2] >= '2')
            {
                return "orgnr";
            }
        }
        else if (id.Length == 12 && (id.StartsWith("19") || id.StartsWith("20")))
        {
            return id[6] >= '6' ? "samnr" : "pnr";
        }

        throw new ArgumentException($"Invalid identification number: {id}");
    }
}

public class PageParameters
{
    public int? Page { get; set; }
    public int? Size { get; set; }

    public PageParameters()
    {
    }

    public PageParameters(int page, int size)
    {
        Page = page;
        Size = size;
    }
}

public class HamtaBehorigheterRequest
{
    public string Tredjeman { get; set; }
    public Identitetsbeteckning Fullmaktshavare { get; set; }
    public Identitetsbeteckning Fullmaktsgivare { get; set; }
    public List<string>? Fullmaktsgivarroll { get; set; }
    public List<string>? Behorigheter { get; set; }
    public PageParameters? Page { get; set; }
}

public class NamnIdentitet : Identitetsbeteckning
{
    public string? Fornamn { get; set; }
    public string Namn { get; set; }
}

public class Fullmaktshavare : NamnIdentitet
{
}

public class Fullmaktsgivare : NamnIdentitet
{
}

public class UtdeladBehorighet
{
    public string Kod { get; set; }
    public string Typ { get; set; }
    public string Fullmakt { get; set; }
}

public class JwsSig
{
    public string Protected { get; set; }
    public string Signature { get; set; }
}

public class Behorighetskontext
{
    public string Tredjeman { get; set; }
    public Fullmaktsgivare Fullmaktsgivare { get; set; }
    public string Fullmaktsgivarroll { get; set; }
    public List<Fullmaktshavare> Fullmaktshavare { get; set; }
    public List<UtdeladBehorighet> Behorigheter { get; set; }
    public string Tidpunkt { get; set; }
    [JsonPropertyName("_sig")] public JwsSig Sig { get; set; }
}

public class HamtaBehorigheterResponse
{
    public List<Behorighetskontext> Kontext { get; set; }
    public PageMetadata Page { get; set; }
}

public class PageMetadata
{
    public int Size { get; set; }
    public int Number { get; set; }
    public long TotalElements { get; set; }
    public int TotalPages { get; set; }
}
