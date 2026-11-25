using System.Text.RegularExpressions;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Dataflow;

/// <summary>What a detector adapter needs to sign a receipt. <see cref="Session"/> and <see cref="CalibrationRef"/> default to
/// <see cref="DataFlow.Undefined"/> (absent); any other value is carried and validated (a null or non-string one makes the receipt malformed).</summary>
public sealed class AdapterContext
{
    /// <summary>Policy id of the detector (<c>^[a-z][a-z0-9_]{0,63}$</c>).</summary>
    public string Detector { get; init; } = "";
    /// <summary>Model / ruleset version (1..64 bytes).</summary>
    public string Version { get; init; } = "";
    /// <summary>The exact content sent to the detector (any JSON tree value).</summary>
    public object? Content { get; init; }
    /// <summary>The gateway's Ed25519 seed (32 bytes).</summary>
    public byte[] SecretKey { get; init; } = Array.Empty<byte>();
    /// <summary>Epoch ms.</summary>
    public double Now { get; init; }
    public object? Session { get; init; } = DataFlow.Undefined;
    public object? CalibrationRef { get; init; } = DataFlow.Undefined;
}

/// <summary>Detector adapters: a vendor guardrail response becomes a signed, tighten-only receipt. A response is <c>no_finding</c> only when it
/// is well-formed AND says nothing was detected; anything malformed or ambiguous is <c>suspicious</c> with category <c>detector_error</c>.</summary>
public static class Detectors
{
    public const string ReceiptDomain = "atlas-pca/detector-receipt/v1\0";
    static readonly Regex IdRe = new(@"\A[a-z][a-z0-9_]{0,63}\z", RegexOptions.CultureInvariant);
    static readonly Regex NonAlnum = new(@"[^a-z0-9]+", RegexOptions.CultureInvariant);

    static bool IsObj(object? v) => v is D;

    /// <summary>Vendor category text to a receipt category id (lowercase, non-alphanumerics to <c>_</c>); unusable text becomes <c>other</c>.</summary>
    public static string CategoryId(object? s)
    {
        if (s is not string str) return "other";
        // JavaScript lower-cases U+0130 to "i" + U+0307 (two code units); the invariant simple mapping would give "i"
        var lower = str.Replace("İ", "i̇", StringComparison.Ordinal).ToLowerInvariant();
        var c = NonAlnum.Replace(lower, "_").Trim('_');
        if (c.Length > 0 && c[0] >= '0' && c[0] <= '9') c = "c_" + c;
        if (c.Length > 64) c = c[..64];
        return IdRe.IsMatch(c) ? c : "other";
    }

    /// <summary>b64u(sha256(strictCanonical({d, content}))): the digest a receipt binds.</summary>
    public static string DetectorInputDigest(object? content) => Pca.HashCanonical(new D { ["d"] = "atlas-pca/detector-input/v1", ["content"] = content });

    internal static string? ShapeError(D r)
    {
        var e = IntentArtifacts.ClosedMembers(r, new[] { "v", "kind", "detector", "version", "input_digest", "verdict", "categories", "iat", "sig" }, new[] { "session", "calibration_ref", "alg", "pq_pk", "pq_sig" }, "receipt");
        if (e != null) return e;
        if (!(IntentJs.NumOf(r["v"]) == 1) || !(r["kind"] is string k && k == "pca-detector-receipt")) return "not a pca-detector-receipt v1";
        if (r["detector"] is not string det || !IdRe.IsMatch(det)) return "detector id is malformed";
        if (!IntentArtifacts.IsBoundedString(r["version"], 64)) return "version must be 1..64 bytes";
        if (!IntentArtifacts.IsDigest(r["input_digest"])) return "input_digest must be a b64u 32-byte digest";
        if (r["verdict"] is not string verdict || (verdict != "suspicious" && verdict != "no_finding")) return "verdict must be 'suspicious' or 'no_finding'";
        if (r["categories"] is not L c || c.Count > 8 || !c.All(x => x is string s && IdRe.IsMatch(s))) return "categories must be 0..8 ids";
        for (int i = 1; i < c.Count; i++) if (string.CompareOrdinal((string)c[i - 1]!, (string)c[i]!) >= 0) return "categories must be sorted and distinct";
        if (verdict == "no_finding" && c.Count > 0) return "a no_finding receipt carries no categories";
        if (!IntentJs.IsNonNeg(r["iat"])) return "iat must be a non-negative integer";
        if (r.ContainsKey("session") && !IntentArtifacts.IsDigest(r["session"])) return "session must be a b64u 32-byte id";
        if (r.ContainsKey("calibration_ref") && !IntentArtifacts.IsBoundedString(r["calibration_ref"], 256)) return "calibration_ref must be 1..256 bytes";
        if (r["sig"] is not string) return "sig must be a string";
        return IntentArtifacts.ArtifactSuiteError(r);
    }

    static D Receipt(AdapterContext ctx, bool suspicious, IEnumerable<string> categories)
    {
        if (BitConverter.DoubleToInt64Bits(ctx.Now) == long.MinValue) throw new ArgumentException("signDetectorReceipt: iat must be a non-negative integer"); // -0
        var cats = suspicious ? categories.Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).Take(8).Cast<object?>().ToList() : new L();
        var body = new D
        {
            ["v"] = new Num("1"),
            ["kind"] = "pca-detector-receipt",
            ["detector"] = ctx.Detector,
            ["version"] = ctx.Version,
            ["input_digest"] = DetectorInputDigest(ctx.Content),
            ["verdict"] = suspicious ? "suspicious" : "no_finding",
            ["categories"] = cats,
            ["iat"] = new Num(JsJson.NumberToString(ctx.Now)),
        };
        if (!ReferenceEquals(ctx.Session, DataFlow.Undefined)) body["session"] = ctx.Session;
        if (!ReferenceEquals(ctx.CalibrationRef, DataFlow.Undefined)) body["calibration_ref"] = ctx.CalibrationRef;
        return SignDetectorReceipt(body, ctx.SecretKey);
    }

    /// <summary>Signs a detector receipt body with the gateway's Ed25519 key (a 32-byte seed) and returns it with <c>sig</c>. Throws
    /// <see cref="ArgumentException"/> when the signed receipt is not well formed (a signer never emits a receipt a verifier would refuse).</summary>
    public static D SignDetectorReceipt(D body, byte[] secretKey)
    {
        using var key = SuiteKey.Ed25519(EdKey.FromSeed(secretKey));
        var signed = Issue.SignArtifact(ReceiptDomain, body, key);
        var err = ShapeError(signed);
        if (err != null) throw new ArgumentException("signDetectorReceipt: " + err);
        return signed;
    }

    static D ErrorReceipt(AdapterContext ctx) => Receipt(ctx, true, new[] { "detector_error" });

    /// <summary>Lakera Guard v2 <c>/guard</c> response: <c>{flagged, breakdown?:[{detector_type, detected}]}</c>.</summary>
    public static D LakeraReceipt(object? response, AdapterContext ctx)
    {
        if (response is not D r || r.GetValueOrDefault("flagged") is not bool flagged) return ErrorReceipt(ctx);
        var cats = new HashSet<string>(StringComparer.Ordinal);
        if (r.TryGetValue("breakdown", out var bd))
        {
            if (bd is not L bl) return ErrorReceipt(ctx);
            foreach (var b in bl)
            {
                if (b is not D bm || bm.GetValueOrDefault("detected") is not bool detected) return ErrorReceipt(ctx);
                if (detected) cats.Add(CategoryId(bm.GetValueOrDefault("detector_type")));
            }
        }
        var suspicious = flagged || cats.Count > 0;
        if (suspicious && cats.Count == 0) cats.Add("flagged");
        return Receipt(ctx, suspicious, cats);
    }

    /// <summary>Prompt Security <c>/api/protect</c> response (shape unverified against the vendor docs; both integration shapes accepted):
    /// clean only when every action present is neither <c>block</c> nor <c>modify</c> and no violation is listed.</summary>
    public static D PromptSecurityReceipt(object? response, AdapterContext ctx)
    {
        if (response is not D top || !top.TryGetValue("result", out var rv) || rv is not D r) return ErrorReceipt(ctx);
        object? p = null; var hasP = r.TryGetValue("prompt", out p);
        if (hasP && p is not D) return ErrorReceipt(ctx);
        var pm = p as D;
        var actions = new List<object?>();
        if (r.TryGetValue("action", out var ra)) actions.Add(ra);
        if (pm != null && pm.TryGetValue("action", out var pa)) actions.Add(pa);
        if (actions.Count == 0 || !actions.All(a => a is string)) return ErrorReceipt(ctx);
        L? violations = null;
        if (pm != null && pm.TryGetValue("violations", out var vv))
        {
            if (vv is not L vl) return ErrorReceipt(ctx);
            violations = vl;
        }
        var cats = new HashSet<string>(StringComparer.Ordinal);
        foreach (var v in violations ?? new L()) cats.Add(CategoryId(v));
        if (actions.Any(a => (string)a! == "block")) cats.Add("blocked");
        if (actions.Any(a => (string)a! == "modify")) cats.Add("modified");
        return Receipt(ctx, cats.Count > 0, cats);
    }

    /// <summary>Any detector that answers <c>{flagged, categories?}</c>; categories on a clean answer are ambiguous (an error receipt).</summary>
    public static D GenericReceipt(object? response, AdapterContext ctx)
    {
        if (response is not D r || r.GetValueOrDefault("flagged") is not bool flagged) return ErrorReceipt(ctx);
        L? cl = null;
        if (r.TryGetValue("categories", out var cv))
        {
            if (cv is not L l) return ErrorReceipt(ctx);
            cl = l;
        }
        var cats = new HashSet<string>(StringComparer.Ordinal);
        foreach (var c in cl ?? new L()) cats.Add(CategoryId(c));
        if (!flagged && cats.Count > 0) return ErrorReceipt(ctx);
        if (flagged && cats.Count == 0) cats.Add("flagged");
        return Receipt(ctx, flagged, cats);
    }
}
