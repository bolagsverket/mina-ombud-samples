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
    public Identitetsbeteckning? Fullmaktsgivare { get; set; }
    public List<string>? Fullmaktsgivarroll { get; set; }
    public List<string>? Behorigheter { get; set; }
    public PageParameters? Page { get; set; }
}

public class NamnIdentitet : Identitetsbeteckning
{
    public string? Fornamn { get; set; }
    public string Namn { get; set; }
}

public class FysiskPerson : NamnIdentitet
{
}

public class JuridiskPerson : NamnIdentitet
{
}

public class Fullmaktshavare : NamnIdentitet
{
}

public class Fullmaktsgivare : NamnIdentitet
{
}

public static class FullmaktsgivareRoll
{
    public static readonly string Organisation = "ORGANISATION";
    public static readonly string Privat = "PRIVAT";
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

public static class FullmaktStatus
{
    public static readonly string Aktuell = "AKTUELL";
    public static readonly string Giltig = "GILTIG";
    public static readonly string Historisk = "HISTORISK";
}

public class HamtaFullmakterRequest
{
    public Identitetsbeteckning? Fullmaktshavare { get; set; }
    public Identitetsbeteckning? Fullmaktsgivare { get; set; }
    public List<string>? Fullmaktsgivarroll { get; set; }
    public List<string>? Tredjeman { get; set; }
    public string? Status { get; set; }
    public bool? Aterkallad { get; set; }
    public string? Ursprung { get; set; }
}

public class ApiError
{
    public string Type { get; set; }
    public string Instance { get; set; }
    public string Title { get; set; }
    public string Detail { get; set; }
    public int Status { get; set; }
    public DateTimeOffset Timestamp { get; set; }

    public string? RequestId { get; set; }

    [JsonExtensionData] public Dictionary<string, Object>? AdditionalProperties { get; set; }
}

public class HamtaFullmakterResponse
{
    public List<FullmaktListItem> Fullmakter { get; set; }
    public IDictionary<String, ApiError>? Problem { get; set; }
    public PageMetadata Page;
}

public class FullmaktUrsprung
{
    public string Mall { get; set; }
    public string Fullmakt { get; set; }
}

public class Tredjeman
{
    public string Id { get; set; }
    public string Namn { get; set; }
}

public class FullmaktJuridiskSignatar
{
    public JuridiskPerson JuridiskPerson { get; set; }
    public List<FysiskPerson> Foretradare { get; set; }
}

public class FullmaktSignatar
{
    public FysiskPerson? FysiskPerson { get; set; }
    public FullmaktJuridiskSignatar? JuridiskSignatar { get; set; }
}

public class BehorighetTyp
{
    public string Typ { get; set; }
    public string? Rubrik { get; set; }
    public string? Beskrivning { get; set; }
    public bool Vald { get; set; }
    public int Niva { get; set; }
}

public class Behorighetsobjekt
{
    public string Kod { get; set; }
    public string? Rubrik { get; set; }
    public List<BehorighetTyp> Typer { get; set; }
}

public class Behorighet
{
    public Behorighetsobjekt Behorighetsobjekt { get; set; }
}

public class FullmaktListItem
{
    public string Id { get; set; }
    public String Referensnummer { get; set; }
    public string Registreringstidpunkt { get; set; }
    public AterkalladFullmaktDetaljer? Aterkallad { get; set; }
    public string Status { get; set; }
    public bool? Vidaredelad { get; set; }
    public string Rubrik { get; set; }
    public string GiltigFrom { get; set; }
    public string? GiltigTom { get; set; }
    public string Tredjeman { get; set; }
    public Fullmaktsgivare Fullmaktsgivare { get; set; }
    public string Fullmaktsgivarroll { get; set; }
    public List<Fullmaktshavare> Fullmaktshavare { get; set; }
    public bool? Vidaredelning { get; set; }
    public bool? Transportfullmakt { get; set; }
}


public class Fullmakt
{
    public string Id { get; set; }
    public FullmaktUrsprung Ursprung { get; set; }
    public string Rubrik { get; set; }
    public string Beskrivning { get; set; }
    public string GiltigFrom { get; set; }
    public string? GiltigTom { get; set; }
    public NamnIdentitet Skapare { get; set; }
    public string SkapadTidpunkt { get; set; }
    public bool? Vidaredelning { get; set; }
    public bool? Transportfullmakt { get; set; }
    public Fullmaktsgivare Fullmaktsgivare { get; set; }
    public string Fullmaktsgivarroll { get; set; }
    public List<Fullmaktshavare> Fullmaktshavare { get; set; }
    public Tredjeman Tredjeman { get; set; }
    //public List<Behorighet> Behorigheter { get; set; }

    [JsonExtensionData] public Dictionary<string, Object>? AdditionalProperties { get; set; }
}

public class AterkalladFullmaktDetaljer
{
    public string Part { get; set; }
    public NamnIdentitet Person { get; set; }
    public string Tidpunkt { get; set; }
}

public class Underskriftsinformation
{
    public FysiskPerson Person { get; set; }
    public string Tidpunkt { get; set; }
}

public class FullmaktUtdelning
{
    public string Id { get; set; }
    public string Status { get; set; }
    public string GiltigFrom { get; set; }
    public string? GiltigTom { get; set; }
    public bool Vidaredelning { get; set; }
    public bool vidaredelad { get; set; }
    public List<Fullmaktshavare> Fullmaktshavare { get; set; }
}

public class FullmaktMetadata
{
    public string Referensnummer { get; set; }
    public string Registreringstidpunkt { get; set; }
    public AterkalladFullmaktDetaljer? Aterkallad { get; set; }
    public string Status { get; set; }
    public bool? vidaredelad { get; set; }
    public List<Underskriftsinformation> Underskrifter { get; set; }
    public List<FullmaktUtdelning>? Utdelningar { get; set; }

    [JsonExtensionData] public Dictionary<string, Object>? AdditionalProperties { get; set; }
}

public class FullmaktMetadataResponse
{
    public Fullmakt Fullmakt { get; set; }
    public FullmaktMetadata Metadata { get; set; }
    public string Svarstidpunkt { get; set; }
    [JsonPropertyName("_sig")] public JwsSig Sig { get; set; }
    [JsonExtensionData] public Dictionary<string, Object>? AdditionalProperties { get; set; }
}
