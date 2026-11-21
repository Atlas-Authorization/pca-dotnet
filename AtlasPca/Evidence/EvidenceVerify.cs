using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Evidence;

/// <summary>The pure validators and readers of the evidence verifier: trust-input checks, the anchor leaf and the cap a grant's envelope
/// states. (Replaying a whole bundle needs the intent-v2, wallet and WebAuthn verifiers as ports and is not part of this surface.)</summary>
public static class EvidenceVerify
{
    public const string EvidenceReportDomain = "atlas-pca/intent-evidence-report/v1";
    public const string IntentAnchorDomain = "atlas-pca/intent-anchor/v1";
    /// <summary>The principal an intent-anchor log's signed tree head names.</summary>
    public const string IntentAnchorLog = "pca-intent:v1";

    /// <summary>Validate <c>trust.principals</c> when it is supplied: a non-empty list of closed <c>{key, pq_pk?}</c> with canonical keys. Null = valid.</summary>
    public static string? PrincipalsTrustError(object? p)
    {
        if (p is not L l || l.Count == 0) return "trust.principals must be a non-empty array of {key, pq_pk?}";
        for (int i = 0; i < l.Count; i++)
        {
            if (l[i] is not D o) return $"trust.principals[{i}] must be an object {{key, pq_pk?}}";
            foreach (var k in IntentJs.JsKeys(o.Keys)) if (k != "key" && k != "pq_pk") return $"trust.principals[{i}]: unknown member '{k}'";
            if (Pca.B64uDecode(o.GetValueOrDefault("key"), 32) == null) return $"trust.principals[{i}].key must be canonical base64url (32 bytes)";
            if (o.ContainsKey("pq_pk") && Pca.B64uDecode(o["pq_pk"]) == null) return $"trust.principals[{i}].pq_pk must be canonical base64url";
        }
        return null;
    }

    /// <summary>No <c>trust.principals</c> supplied (undefined): valid.</summary>
    public static string? PrincipalsTrustError() => null;

    /// <summary>Validate <c>trust.acc</c> when supplied: closed members, non-negative safe integers. Null = valid.</summary>
    public static string? AccTrustError(object? a)
    {
        if (a is not D m) return "trust.acc must be an object";
        foreach (var k in IntentJs.JsKeys(m.Keys))
        {
            if (k != "max_receipt_age_s" && k != "max_keyset_age_s") return $"trust.acc: unknown member '{k}'";
            if (!IntentJs.IsNonNeg(m[k])) return $"trust.acc.{k} must be a non-negative safe integer";
        }
        return null;
    }

    /// <summary>No <c>trust.acc</c> supplied (undefined): valid.</summary>
    public static string? AccTrustError() => null;

    /// <summary>The intent-log leaf for an anchored artifact (any kind).</summary>
    public static string AnchorCommit(string kind, string digest) => Pca.HashCanonical(new D { ["d"] = IntentAnchorDomain, ["kind"] = kind, ["digest"] = digest });

    // JavaScript for-of over a condition list: an array, a string (its characters, none of them a condition), or absent; else a TypeError
    static IEnumerable<object?> Iter(object? conds) => conds switch
    {
        null => Array.Empty<object?>(),
        L l => l,
        string s => s.Select(_ => (object?)null).ToList(), // characters are not objects, so every one is skipped
        _ => throw new InvalidOperationException("conds is not iterable"),
    };

    static bool IsGroup(D c) => c.ContainsKey("all_of") || c.ContainsKey("any_of") || c.ContainsKey("not");

    static List<double> LeafCaps(object? conds, string path)
    {
        var outp = new List<double>();
        foreach (var c in Iter(conds))
        {
            if (c is not D m) continue;
            if (IsGroup(m))
            {
                if (m.TryGetValue("all_of", out var all)) outp.AddRange(LeafCaps(all, path));
                continue;
            }
            if (m.GetValueOrDefault("field") is not string field) continue; // not a leaf
            if (field != path || m.ContainsKey("ref") || m.GetValueOrDefault("value") is not Num v) continue;
            var x = JsJson.ToJsNumber(v);
            var op = m.GetValueOrDefault("op");
            if (op is string o && o == "lte") outp.Add(x);
            else if (op is string o2 && o2 == "lt") outp.Add(x - 1);
        }
        return outp;
    }

    /// <summary>The cap <c>env.acc.&lt;id&gt;.post &lt;= v</c> the grant's envelope states for <paramref name="verb"/>: per predicate the tightest bound
    /// in its <c>where</c> (descending into <c>all_of</c>), across predicates (a union) the loosest. Null when a predicate admitting the verb states
    /// no bound, or none admits it. Returns a <see cref="Num"/> or null.</summary>
    public static Num? CapOf(object? grant, string accId, string verb)
    {
        var env = Pca.ReadEnvelope(grant);
        if (env == null) return null;
        var path = $"env.acc.{accId}.post";
        double? cap = null;
        foreach (var pv in (L)env["predicates"]!)
        {
            if (pv is not D p) throw new InvalidOperationException("Cannot read properties of a non-object predicate");
            var v = p.TryGetValue("verb", out var vv) ? vv : null;
            var verbs = p.ContainsKey("verb") ? (v is L vl ? vl.Select(Str).ToList() : new List<string> { Str(v) }) : new List<string> { "undefined" };
            if (!verbs.Contains(verb) && !verbs.Contains("*")) continue;
            var caps = LeafCaps(p.GetValueOrDefault("where"), path);
            if (caps.Count == 0) return null;
            var m = caps.Min();
            cap = cap == null ? m : Math.Max(cap.Value, m);
        }
        return cap == null ? null : new Num(JsJson.NumberToString(cap.Value));
    }

    static string Str(object? x) => JsJson.ToJsString(x);

    /// <summary>Replays a dispute evidence bundle (spec section 3.11). <paramref name="trust"/> is the reader's trust input as a JSON tree (siteKeys, principals, minTier,
    /// typedValues, credentials, canaryLabels, oracleKeys, judges, labelKeys, anchorGuardian, acc, jitTier, sessionRootDigest); <paramref name="verifiers"/> are the optional
    /// ports keyed sessionRoot, schema, receipt, fact, classifier, offerSet, labels, effect, verdict, settlement. Never throws: a malformed bundle is a report with a failed
    /// <c>shape</c> finding.</summary>
    public static D VerifyEvidenceBundle(object? input, D? trust = null, IReadOnlyDictionary<string, EvidencePort>? verifiers = null) => EvidenceReplay.Verify(input, trust, verifiers);
}
