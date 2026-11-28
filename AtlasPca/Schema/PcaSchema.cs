using System.Globalization;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Schema;

/// <summary>The outcome of <see cref="PcaSchema.Validate"/>: <c>Valid</c> plus a human-readable error list (empty when valid).</summary>
public sealed record ValidationResult(bool Valid, List<string> Errors)
{
    public D ToJson() => new() { ["valid"] = Valid, ["errors"] = new L(Errors.Select(e => (object?)e)) };
}

/// <summary>
/// JSON Schema (draft 2020-12) for the Proof-Carrying Authority wire types, as plain JSON trees: the signed <c>PCActn</c>, one <c>Capability</c> hop and the
/// <c>.well-known/pca-configuration</c> discovery document, plus a dependency-free STRUCTURAL validator (wrong JSON type, missing required property, value
/// outside an enum, recursively through nested objects, arrays and local <c>#/...</c> references). The schemas describe structure only: passing them means
/// "well-formed", never "authorized". Every object is <c>additionalProperties: true</c> so an unknown future field never fails structural validation.
/// shortcut: a <c>properties</c> member that is neither an object nor an array is treated as having no entries (the reference would enumerate a string's characters).
/// </summary>
public static class PcaSchema
{
    const string Draft = "https://json-schema.org/draft/2020-12/schema";
    static readonly string[] Algs = { "ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65" };

    static D O(params (string Key, object? Value)[] kv) { var d = new D(); foreach (var (k, v) in kv) d[k] = v; return d; }
    static L A(params object?[] items) => new(items);
    static D Str() => O(("type", "string"));
    static D Type(string t) => O(("type", t));
    static D Ref(string name) => O(("$ref", "#/$defs/" + name));
    static D Arr(D items) => O(("type", "array"), ("items", items));
    static D AlgDef() => O(("type", "string"), ("enum", new L(Algs.Select(x => (object?)x))));

    static D CaveatDef() => O(("type", "object"), ("required", A("type")), ("properties", O(("type", Str()))), ("additionalProperties", true));

    static D CapabilityDef() => O(
        ("type", "object"),
        ("required", A("id", "issuer", "holder", "caveats", "body_digest", "sig")),
        ("properties", O(("id", Str()), ("issuer", Str()), ("holder", Str()), ("caveats", Arr(Ref("caveat"))), ("parent", Str()), ("body_digest", Str()), ("sig", Str()),
            ("alg", AlgDef()), ("pq_pk", Str()), ("pq_sig", Str()))),
        ("additionalProperties", true));

    static D ActionDef() => O(("type", "object"), ("required", A("verb", "resource", "params_digest", "reversibility_class")),
        ("properties", O(("verb", Str()), ("resource", Str()), ("params_digest", Str()), ("reversibility_class", Str()))), ("additionalProperties", true));

    static D InclusionProofDef() => O(("type", "object"), ("required", A("index", "size", "path")),
        ("properties", O(("index", Type("integer")), ("size", Type("integer")), ("path", Arr(O(("type", "object"), ("additionalProperties", true)))))),
        ("additionalProperties", true));

    static D PlanDef() => O(("type", "object"), ("required", A("root", "inclusion_proof", "node_id")),
        ("properties", O(("root", Str()), ("inclusion_proof", Ref("inclusionProof")), ("node_id", Str()), ("conditions_digest", Str()))), ("additionalProperties", true));

    static D RiskClaimDef() => O(("type", "object"), ("required", A("r", "inputs")),
        ("properties", O(("r", Type("number")), ("inputs", O(("type", "object"), ("additionalProperties", true))))), ("additionalProperties", true));

    static D AttestationDef() => O(("type", "object"), ("required", A("quote_digest", "epoch", "model_id", "measurement", "operator")),
        ("properties", O(("quote_digest", Str()), ("epoch", Type("integer")), ("model_id", Str()), ("measurement", Str()), ("operator", Str()))), ("additionalProperties", true));

    static D ProvenanceDef() => O(("type", "object"), ("required", A("causal_hash", "taint_level", "trusted_refs")),
        ("properties", O(("causal_hash", Str()), ("taint_level", Type("number")), ("trusted_refs", Arr(Str())))), ("additionalProperties", true));

    static D FreshnessDef() => O(("type", "object"), ("required", A("beacon_ref", "epoch", "accumulator_witness")),
        ("properties", O(("beacon_ref", Str()), ("epoch", Type("integer")), ("accumulator_witness", Str()))), ("additionalProperties", true));

    /// <summary><c>PCActn</c>: a signed intent for ONE action (wire v2).</summary>
    public static D PcactnSchema() => O(
        ("$schema", Draft),
        ("$id", "https://atlasauth.net/schemas/pca/pcactn.schema.json"),
        ("title", "PCActn"),
        ("description", "Proof-Carrying Authority action object (spec §7, wire format v2)."),
        ("type", "object"),
        ("required", A("ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim", "aud", "iat", "exp", "sig")),
        ("properties", O(
            ("ver", Type("integer")),
            ("action", Ref("action")),
            ("grant_ref", Str()),
            ("cap_chain", O(("type", "array"), ("minItems", new Num("1")), ("items", Ref("capability")))),
            ("plan", Ref("plan")),
            ("attestation", Ref("attestation")),
            ("provenance", Ref("provenance")),
            ("freshness", Ref("freshness")),
            ("counter", Type("integer")),
            ("risk_claim", Ref("riskClaim")),
            ("aud", Str()),
            ("iat", Type("integer")),
            ("exp", Type("integer")),
            ("nonce", Str()),
            ("caution", Type("number")),
            ("rationale_commitment", Str()),
            ("progress_step", O(("type", "object"), ("additionalProperties", true))),
            ("prohibition_evidence", O(("type", A("object", "array")))),
            ("tool_binding", Str()),
            ("alg", AlgDef()),
            ("pq_pk", Str()),
            ("sig", Str()),
            ("pq_sig", Str()),
            ("threshold", O(("type", "object"), ("additionalProperties", true))),
            ("zk_compliance", O(("description", "Opaque zk-compliance proof; shape is verifier-defined."))),
            ("bond_ref", Str()))),
        ("additionalProperties", true),
        ("$defs", O(
            ("caveat", CaveatDef()), ("capability", CapabilityDef()), ("action", ActionDef()), ("inclusionProof", InclusionProofDef()), ("plan", PlanDef()),
            ("riskClaim", RiskClaimDef()), ("attestation", AttestationDef()), ("provenance", ProvenanceDef()), ("freshness", FreshnessDef()))));

    /// <summary><c>Capability</c>: one hop of a <c>cap_chain</c>; validates a single hop.</summary>
    public static D CapabilitySchema()
    {
        var s = O(
            ("$schema", Draft),
            ("$id", "https://atlasauth.net/schemas/pca/capability.schema.json"),
            ("title", "Capability"),
            ("description", "An attenuable capability chain hop (spec §5.2)."));
        foreach (var (k, v) in CapabilityDef()) s[k] = v;
        s["$defs"] = O(("caveat", CaveatDef()));
        return s;
    }

    /// <summary><c>PcaDiscoveryDocument</c>: the <c>.well-known/pca-configuration</c> resource-server descriptor.</summary>
    public static D DiscoverySchema() => O(
        ("$schema", Draft),
        ("$id", "https://atlasauth.net/schemas/pca/discovery.schema.json"),
        ("title", "PcaDiscoveryDocument"),
        ("description", "The .well-known/pca-configuration discovery document (internet-wide integration)."),
        ("type", "object"),
        ("required", A("audience", "pca_versions", "signature_suites", "action_header")),
        ("properties", O(
            ("audience", Str()),
            ("pca_versions", Arr(Type("integer"))),
            ("signature_suites", Arr(Str())),
            ("action_header", Str()),
            ("required_checks", Arr(Str())),
            ("endpoints", Ref("endpoints")),
            ("trusted_roots", Arr(Str())),
            ("metadata", O(("type", "object"), ("additionalProperties", true))))),
        ("additionalProperties", true),
        ("$defs", O(("endpoints", O(
            ("type", "object"),
            ("properties", O(("attestation_challenge", Str()), ("revocation_epoch", Str()), ("liveness_beacon", Str()), ("stepup", Str()), ("grant", Str()))),
            ("additionalProperties", true))))));

    /// <summary>Every published schema, keyed by its wire-type name.</summary>
    public static D AllSchemas() => O(("PCActn", PcactnSchema()), ("Capability", CapabilitySchema()), ("PcaDiscoveryDocument", DiscoverySchema()));

    // ---- the structural validator ----------------------------------------------------------------------------------

    static double ToDouble(Num n) => double.Parse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture);

    static bool IsInteger(double d) => !double.IsNaN(d) && !double.IsInfinity(d) && Math.Floor(d) == d;

    static string JsonTypeOf(object? v) => v switch
    {
        null => "null",
        L => "array",
        Num n => IsInteger(ToDouble(n)) ? "integer" : "number",
        bool => "boolean",
        string => "string",
        _ => "object",
    };

    static bool MatchesType(object? expected, object? v)
    {
        switch (expected as string)
        {
            case "object": return v is D;
            case "array": return v is L;
            case "string": return v is string;
            case "number": return v is Num n && !double.IsInfinity(ToDouble(n)) && !double.IsNaN(ToDouble(n));
            case "integer": return v is Num m && IsInteger(ToDouble(m)) && !(ToDouble(m) == 0 && double.IsNegative(ToDouble(m)));
            case "boolean": return v is bool;
            case "null": return v == null;
            default: return false;
        }
    }

    /// <summary>JavaScript truthiness of a JSON tree value.</summary>
    static bool Truthy(object? v) => v switch
    {
        null => false,
        bool b => b,
        string s => s.Length > 0,
        Num n => ToDouble(n) != 0 && !double.IsNaN(ToDouble(n)),
        _ => true,
    };

    /// <summary>Object.keys order: array-index keys ascending first, then the rest in insertion order.</summary>
    static List<string> JsKeys(D d)
    {
        static bool IsIndex(string k) => k.Length > 0 && k.Length <= 10 && k.All(c => c is >= '0' and <= '9') && (k == "0" || k[0] != '0') && ulong.Parse(k, CultureInfo.InvariantCulture) < 4294967295UL;
        var idx = d.Keys.Where(IsIndex).OrderBy(k => ulong.Parse(k, CultureInfo.InvariantCulture)).ToList();
        idx.AddRange(d.Keys.Where(k => !IsIndex(k)));
        return idx;
    }

    /// <summary>Object.entries of a <c>properties</c> value (an object; an array enumerates its indices).</summary>
    static List<(string Key, object? Sub)> Entries(object? props) => props switch
    {
        D d => JsKeys(d).Select(k => (k, d[k])).ToList(),
        L l => l.Select((x, i) => (i.ToString(CultureInfo.InvariantCulture), x)).ToList(),
        _ => new List<(string, object?)>(),
    };

    /// <summary>A local <c>#/...</c> JSON pointer against the root schema (only own keys are walked; no escape decoding).</summary>
    static object? ResolveRef(object? root, string reference)
    {
        if (!reference.StartsWith("#/", StringComparison.Ordinal)) return null;
        object? cur = root;
        foreach (var token in reference[2..].Split('/'))
        {
            if (cur is not D d || !d.ContainsKey(token)) return null;
            cur = d[token];
        }
        return cur as D;
    }

    static string Label(string path) => path == "" ? "(root)" : path;

    static bool StrictEq(object? a, object? b) => a switch
    {
        null => b == null,
        string s => b is string t && s == t,
        bool x => b is bool y && x == y,
        Num n => b is Num m && ToDouble(n) == ToDouble(m),
        _ => false,
    };

    static string Prefix(string path) => path == "" ? "" : path + ".";

    static void CheckNode(object? schema, object? value, string path, object? root, List<string> errors)
    {
        if (schema == null) throw new InvalidOperationException("Cannot read properties of null (reading '$ref')");
        var sd = schema as D; // any other non-object schema carries none of the keywords below
        if (sd != null && sd.GetValueOrDefault("$ref") is string r)
        {
            var resolved = ResolveRef(root, r);
            if (resolved == null)
            {
                errors.Add($"{Label(path)}: unresolved $ref '{r}'");
                return;
            }
            CheckNode(resolved, value, path, root, errors);
            return;
        }
        if (sd == null) return;

        if (sd.TryGetValue("type", out var ty))
        {
            var types = ty is L tl ? tl : new L { ty };
            if (!types.Any(t => MatchesType(t, value)))
            {
                errors.Add($"{Label(path)}: expected type {string.Join("|", types.Select(t => t == null ? "" : JsJson.ToJsString(t)))}, got {JsonTypeOf(value)}");
                return; // a wrong base type makes any deeper check meaningless
            }
        }

        if (sd.GetValueOrDefault("enum") is L en && !en.Any(e => StrictEq(e, value)))
            errors.Add($"{Label(path)}: value is not one of [{string.Join(", ", en.Select(e => JsJson.Stringify(e)))}]");

        if (value is D vd)
        {
            if (sd.GetValueOrDefault("required") is L req)
                foreach (var keyObj in req)
                {
                    var key = keyObj is string ks ? ks : JsJson.ToJsString(keyObj);
                    if (!vd.ContainsKey(key)) errors.Add($"{Prefix(path)}{key}: missing required property '{key}'");
                }
            var props = sd.GetValueOrDefault("properties");
            if (Truthy(props))
                foreach (var (key, sub) in Entries(props))
                    if (vd.TryGetValue(key, out var child)) CheckNode(sub, child, Prefix(path) + key, root, errors);
            if (sd.GetValueOrDefault("additionalProperties") is false && Truthy(props))
            {
                var allowed = new HashSet<string>(Entries(props).Select(e => e.Key));
                foreach (var key in JsKeys(vd))
                    if (!allowed.Contains(key)) errors.Add($"{Prefix(path)}{key}: additional property not allowed");
            }
        }

        var items = sd.GetValueOrDefault("items");
        if (value is L vl && Truthy(items))
            for (int i = 0; i < vl.Count; i++) CheckNode(items, vl[i], $"{path}[{i}]", root, errors);
    }

    /// <summary>A LIGHTWEIGHT structural validator: wrong JSON type, a missing required property (named in the error), a value outside an <c>enum</c>, recursively
    /// through nested objects, arrays and local <c>#/$defs/...</c> references. It does NOT implement all of draft 2020-12 (no pattern, format, oneOf / anyOf, numeric
    /// bounds, minItems, remote references). For full validation feed the same schema objects to a real validator.</summary>
    public static ValidationResult Validate(object? schema, object? value)
    {
        var errors = new List<string>();
        CheckNode(schema, value, "", schema, errors);
        return new ValidationResult(errors.Count == 0, errors);
    }
}
