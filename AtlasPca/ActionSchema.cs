// Rule 14: signed action schemas and the closed-world conformance check (packages/pca/src/action-schema.ts), mirroring
// ActionSchema.java. A schema `pca-action-schema` v1 is signed by a site key listed in the verifier's discovery key list;
// the suite is pinned by the KEY ENTRY. Anything the schema does not declare is the fail-closed cell (a terminal deny).
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class ActionSchema
{
    public const string ActionSchemaDomain = "atlas-pca/action-schema/v1\0";
    public const string ActionSchemaRefDomain = "atlas-pca/action-schema-ref/v1";
    public const string ActionSchemaKind = "pca-action-schema";
    public const int MaxSchemaVerbs = 256;
    public const int MaxSchemaParams = 64;
    public const int MaxSchemaValues = 256;
    public const int DefaultMaxLen = 1024;
    public const int DefaultMaxItems = 64;
    static readonly Regex ParamPathRe = new(@"^action\.params\.[A-Za-z0-9_]{1,64}\z", RegexOptions.CultureInvariant);
    internal static readonly Regex UnitIdRe = new(@"^[a-z0-9_]+(?:\.[a-z0-9_]+)*\z", RegexOptions.CultureInvariant);
    static readonly Regex DateRe = new(@"^([0-9]{4})-([0-9]{2})-([0-9]{2})\z", RegexOptions.CultureInvariant);
    internal static readonly HashSet<string> ReservedNames = new() { "__proto__", "constructor", "prototype" };
    static readonly string[] Sensitivities = { "free", "material", "critical" };
    static readonly string[] SchemaReversibility = { "reversible", "rate_limited", "irreversible" };
    static readonly string[] ParamTypes = { "string", "integer", "boolean", "date", "set", "array" };
    static readonly string[] DocKeys = { "v", "kind", "site", "aud", "version", "units", "state", "verbs", "sig" };
    static readonly string[] VerbKeys = { "verb", "kind", "params", "reversibility", "reversibility_by", "mcp", "openapi", "harm", "world", "effects", "returns", "description" };
    static readonly string[] ParamKeys = { "type", "semantic", "sensitivity", "required", "values", "min", "max", "unit", "max_len", "items",
        "min_items", "max_items", "default", "principal_neutral_default", "accumulates_into", "issued_by_site", "description" };
    static readonly string[] SigKeys = { "alg", "kid", "value", "pq_value" };

    /// <summary>A conformance verdict: <c>Ok</c>, else the violation <c>Code</c> (and <c>Path</c> for a parameter).</summary>
    public sealed record Conform(bool Ok, string? Code, string? Path, string? Reason)
    {
        internal static readonly Conform Pass = new(true, null, null, null);
    }

    internal static bool IsStr(object? v, int max = 256) => v is string s && s.Length > 0 && !Pca.HasLoneSurrogate(s) && IntentJs.U8Len(s) <= max;
    static bool In(string[] xs, object? v) => v is string s && xs.Contains(s);
    static bool Distinct(L xs) => xs.Distinct(JsonEq.Instance).Count() == xs.Count;

    /// <summary>Set semantics over JSON values (string / number / boolean), matching the reference's <c>new Set(...)</c>.</summary>
    sealed class JsonEq : IEqualityComparer<object?>
    {
        internal static readonly JsonEq Instance = new();
        public new bool Equals(object? a, object? b) => IntentJs.JsonEquals(a, b);
        public int GetHashCode(object? o) => o switch { string s => s.GetHashCode(), bool b => b ? 1 : 2, _ => IntentJs.NumOf(o)?.GetHashCode() ?? 0 };
    }

    static string? ParamDeclError(string path, object? dO, object? units)
    {
        if (!ParamPathRe.IsMatch(path)) return $"parameter path '{path}' is not action.params.<name>";
        if (ReservedNames.Contains(path.Substring("action.params.".Length))) return $"parameter name '{path}' is reserved (__proto__ / constructor / prototype)";
        if (dO is not D d) return path + ": declaration must be an object";
        foreach (var k in d.Keys) if (!ParamKeys.Contains(k)) return $"{path}: unknown member '{k}'";
        var type = IntentJs.Get(d, "type");
        if (!In(ParamTypes, type)) return path + ": unknown type";
        if (!IsStr(IntentJs.Get(d, "semantic"), 128)) return path + ": semantic must be a non-empty string";
        if (!In(Sensitivities, IntentJs.Get(d, "sensitivity"))) return path + ": unknown sensitivity";
        if (d.ContainsKey("required") && d["required"] is not bool) return path + ": required must be a boolean";
        if (d.ContainsKey("values"))
        {
            if (d["values"] is not L vs || vs.Count == 0 || vs.Count > MaxSchemaValues || vs.Any(x => !IsStr(x))) return $"{path}: values must be 1..{MaxSchemaValues} strings";
            if (!Distinct(vs)) return path + ": values must be distinct";
            if (type as string != "string" && type as string != "set") return path + ": values apply to string and set only";
        }
        if (type as string == "set" && !d.ContainsKey("values")) return path + ": a set needs values";
        bool intItems = type as string == "array" && IntentJs.Get(d, "items") as string == "integer";
        foreach (var k in new[] { "min", "max" })
            if (d.ContainsKey(k) && (!IntentJs.IsInt(d[k]) || (type as string != "integer" && !intItems))) return $"{path}: {k} must be a safe integer on an integer parameter";
        if (IntentJs.IsInt(IntentJs.Get(d, "min")) && IntentJs.IsInt(IntentJs.Get(d, "max")) && IntentJs.NumOf(d["min"]) > IntentJs.NumOf(d["max"])) return path + ": min > max";
        if (d.ContainsKey("unit") && (type as string != "integer" || d["unit"] is not string u || units is not D ud || !ud.ContainsKey(u)))
            return path + ": unit must name a declared unit of an integer parameter";
        if (d.ContainsKey("max_len") && (!IntentJs.IsInt(d["max_len"]) || IntentJs.NumOf(d["max_len"]) < 1)) return path + ": max_len must be a positive safe integer";
        if (d.ContainsKey("items") && (type as string != "array" || !IsStr(d["items"], 64))) return path + ": items applies to array only";
        foreach (var k in new[] { "min_items", "max_items" })
            if (d.ContainsKey(k) && (!IntentJs.IsNonNeg(d[k]) || (type as string != "set" && type as string != "array"))) return $"{path}: {k} must be a non-negative safe integer on a set or array";
        if (IntentJs.IsInt(IntentJs.Get(d, "min_items")) && IntentJs.IsInt(IntentJs.Get(d, "max_items")) && IntentJs.NumOf(d["min_items"]) > IntentJs.NumOf(d["max_items"])) return path + ": min_items > max_items";
        if (d.ContainsKey("principal_neutral_default") && d["principal_neutral_default"] is not bool) return path + ": principal_neutral_default must be a boolean";
        if (IntentJs.Get(d, "principal_neutral_default") is true && !d.ContainsKey("default")) return path + ": principal_neutral_default needs a default";
        if (d.ContainsKey("accumulates_into"))
        {
            if (type as string != "integer") return path + ": accumulates_into applies to integer parameters only";
            if (d["accumulates_into"] is not L ai || ai.Count == 0 || ai.Count > 8) return path + ": accumulates_into must be 1..8 unit ids";
            if (ai.Any(x => x is not string us || us.Length > 64 || !UnitIdRe.IsMatch(us))) return path + ": accumulates_into entries must be unit ids";
            if (!Distinct(ai)) return path + ": accumulates_into must be distinct";
        }
        if (d.ContainsKey("default") && d["default"] == null) return path + ": default must not be null (absent = no default)";
        if (d.ContainsKey("issued_by_site") && d["issued_by_site"] is not bool) return path + ": issued_by_site must be a boolean";
        if (d.ContainsKey("description") && !IsStr(d["description"], 1024)) return path + ": description must be a string";
        return null;
    }

    static bool ExactKeys(object? o, params string[] keys) => o is D m && m.Count == keys.Length && keys.All(m.ContainsKey);

    static string? VerbDeclError(object? vO, object? units)
    {
        if (vO is not D v) return "verb entry must be an object";
        foreach (var k in v.Keys) if (!VerbKeys.Contains(k)) return $"verb entry: unknown member '{k}'";
        if (!IsStr(IntentJs.Get(v, "verb"), 128)) return "verb entry: verb must be a non-empty string";
        var at = $"verb '{v["verb"]}'";
        if (IntentJs.Get(v, "kind") as string != "read" && IntentJs.Get(v, "kind") as string != "write") return at + ": kind must be read or write";
        if (IntentJs.Get(v, "params") is not D parameters) return at + ": params must be an object";
        if (parameters.Count > MaxSchemaParams) return $"{at}: more than {MaxSchemaParams} parameters";
        foreach (var (k, pd) in parameters)
        {
            var err = ParamDeclError(k, pd, units);
            if (err != null) return at + ": " + err;
        }
        if (v.ContainsKey("reversibility") && !In(SchemaReversibility, v["reversibility"])) return at + ": unknown reversibility";
        if (v.ContainsKey("reversibility_by"))
        {
            if (v["reversibility_by"] is not D r || r.Keys.Any(k => k != "param" && k != "map" && k != "default")) return at + ": reversibility_by must be {param, map, default?}";
            if (IntentJs.Get(r, "param") is not string rp || !parameters.ContainsKey(rp)) return at + ": reversibility_by.param must be a declared parameter";
            if (IntentJs.Get(r, "map") is not D rm || rm.Count == 0 || rm.Values.Any(x => !In(SchemaReversibility, x))) return at + ": reversibility_by.map must map values to reversibility classes";
            if (r.ContainsKey("default") && !In(SchemaReversibility, r["default"])) return at + ": reversibility_by.default is not a reversibility class";
        }
        if (v.ContainsKey("mcp") && (!ExactKeys(v["mcp"], "tool") || !IsStr(IntentJs.Get(v["mcp"], "tool"), 128))) return at + ": mcp must be {tool}";
        if (v.ContainsKey("openapi") && (!ExactKeys(v["openapi"], "operationId") || !IsStr(IntentJs.Get(v["openapi"], "operationId"), 128))) return at + ": openapi must be {operationId}";
        foreach (var k in new[] { "harm", "effects", "returns" }) if (v.ContainsKey(k) && v[k] is not D) return $"{at}: {k} must be an object";
        if (v.ContainsKey("world") && v["world"] is not L) return at + ": world must be an array";
        if (v.ContainsKey("description") && !IsStr(v["description"], 1024)) return at + ": description must be a string";
        return null;
    }

    /// <summary>Structural validation of a signed schema. Null = well-formed. Never throws.</summary>
    public static string? ShapeError(object? docO)
    {
        try
        {
            if (docO is not D doc) return "schema is not an object";
            foreach (var k in doc.Keys) if (!DocKeys.Contains(k)) return $"unknown member '{k}'";
            if (!OracleFacts.IsOne(IntentJs.Get(doc, "v"))) return "unsupported schema version";
            if (IntentJs.Get(doc, "kind") as string != ActionSchemaKind) return $"kind must be '{ActionSchemaKind}'";
            if (!IsStr(IntentJs.Get(doc, "site"), 2048) || !IsStr(IntentJs.Get(doc, "aud"), 256) || !IsStr(IntentJs.Get(doc, "version"), 128)) return "site, aud and version must be non-empty strings";
            if (doc.ContainsKey("units"))
            {
                if (doc["units"] is not D units) return "units must be an object";
                foreach (var (id, u) in units)
                {
                    if (!UnitIdRe.IsMatch(id) || id.Length > 64) return $"unit id '{id}' is malformed";
                    if (u is not D ud || !IsStr(IntentJs.Get(ud, "kind"), 64)) return $"unit '{id}' must be an object with a kind";
                    if (ud.Keys.Any(k => k != "kind" && k != "currency" && k != "exponent")) return $"unit '{id}': unknown member";
                    if (ud.ContainsKey("currency") && !IsStr(ud["currency"], 16)) return $"unit '{id}': currency must be a string";
                    if (ud.ContainsKey("exponent") && !(IntentJs.IsNonNeg(ud["exponent"]) && IntentJs.NumOf(ud["exponent"]) <= 18)) return $"unit '{id}': exponent must be an integer in [0, 18]";
                }
            }
            if (doc.ContainsKey("state") && doc["state"] is not L) return "state must be an array";
            if (IntentJs.Get(doc, "verbs") is not L verbs || verbs.Count == 0 || verbs.Count > MaxSchemaVerbs) return $"verbs must be 1..{MaxSchemaVerbs} entries";
            var seen = new HashSet<string>();
            foreach (var v in verbs)
            {
                var e = VerbDeclError(v, IntentJs.Get(doc, "units"));
                if (e != null) return e;
                var name = (string)((D)v!)["verb"]!;
                if (!seen.Add(name)) return $"verb '{name}' is declared twice";
            }
            if (IntentJs.Get(doc, "sig") is not D sig) return "sig must be an object";
            foreach (var k in sig.Keys) if (!SigKeys.Contains(k)) return $"sig: unknown member '{k}'";
            var se = IntentJs.SuiteError(IntentJs.Get(sig, "alg"), sig.ContainsKey("alg"));
            if (se != null) return "sig.alg: " + se;
            if (!IsStr(IntentJs.Get(sig, "kid"), 128)) return "sig.kid must be a non-empty string";
            if (!IntentJs.B64Any(IntentJs.Get(sig, "value"))) return "sig.value is not canonical base64url";
            if (sig.ContainsKey("pq_value") && !IntentJs.B64Any(sig["pq_value"])) return "sig.pq_value is not canonical base64url";
            IntentJs.CanonBytes(Body(doc));
            return null;
        }
        catch (Exception e) { return "malformed schema: " + e.Message; }
    }

    static D Body(D doc)
    {
        var b = new D(doc);
        b.Remove("sig");
        return b;
    }

    /// <summary>Verify a site-signed schema against the discovery key list: shape, <c>sig.kid</c> names a listed key,
    /// <c>sig.alg</c> equals that key's suite, and the signature verifies. Null = valid.</summary>
    public static string? Verify(object? docO, object? keys)
    {
        try
        {
            var bad = ShapeError(docO);
            if (bad != null) return bad;
            var doc = (D)docO!;
            var sig = (D)doc["sig"]!;
            if (keys is not L kl) return "the schema keys must be an array";
            var key = kl.Select(k => k as D).FirstOrDefault(k => k != null && IntentJs.Get(k, "kid") is string kid && kid == sig["kid"] as string);
            if (key == null) return $"no schema key with kid '{sig["kid"]}'";
            if (key.ContainsKey("pq_pk") && key["pq_pk"] is not string) return "the schema key pq_pk must be a string";
            if (Pca.B64uDecode(IntentJs.Get(key, "pk"), 32) == null) return "schema key pk is not canonical base64url (32 bytes)";
            var kse = IntentJs.SuiteError(IntentJs.Get(key, "alg"), key.ContainsKey("alg"));
            if (kse != null) return "schema key: " + kse;
            var ka = IntentJs.SuiteOf(key);
            if (ka == null || ka != IntentJs.SuiteOf(sig)) return "sig.alg does not match the pinned key suite";
            var pk = (string)key["pk"]!;
            var pin = key.ContainsKey("pq_pk") ? IntentJs.Pin(pk, key["pq_pk"]) : null;
            var msg = IntentJs.Message(ActionSchemaDomain, Body(doc));
            if (!IntentJs.VerifyPinnedSuite(ka, true, pk, IntentJs.Get(key, "pq_pk"), msg, IntentJs.Get(sig, "value"), IntentJs.Get(sig, "pq_value"), pin)) return "schema signature invalid";
            return null;
        }
        catch (Exception e) { return "schema verification error: " + e.Message; }
    }

    /// <summary>The schema's content address (over the whole signed document).</summary>
    public static string Digest(object? doc) => IntentJs.Ref(ActionSchemaRefDomain, "s", doc);

    internal static D? SchemaVerb(object? doc, string verb) =>
        IntentJs.Get(doc, "verbs") is L verbs ? verbs.Select(v => v as D).FirstOrDefault(v => v != null && IntentJs.Get(v, "verb") as string == verb) : null;

    static bool IsCalendarDate(string s)
    {
        var m = DateRe.Match(s);
        if (!m.Success) return false;
        int y = int.Parse(m.Groups[1].Value), mo = int.Parse(m.Groups[2].Value), d = int.Parse(m.Groups[3].Value);
        if (y < 1 || mo < 1 || mo > 12 || d < 1) return false;
        bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        int[] dim = { 31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        return d <= dim[mo - 1];
    }

    static bool StrOk(object? x, double maxLen) => x is string s && !Pca.HasLoneSurrogate(s) && IntentJs.U8Len(s) <= maxLen;
    static double NumOr(D d, string k, double dflt) => d.TryGetValue(k, out var v) && v != null ? IntentJs.NumOf(v)!.Value : dflt;

    /// <summary>The value check of one declared parameter: null = in the domain, else (code, reason).</summary>
    internal static (string Code, string Reason)? ParamValueViolation(D d, object? x)
    {
        double maxLen = NumOr(d, "max_len", DefaultMaxLen);
        switch (IntentJs.Get(d, "type") as string ?? "")
        {
            case "string":
                if (x is not string s || Pca.HasLoneSurrogate(s)) return ("bad_type", "expected a string");
                if (IntentJs.U8Len(s) > maxLen) return ("out_of_domain", "longer than the declared max_len");
                if (d.ContainsKey("values") && !((L)d["values"]!).Any(v => v as string == s)) return ("out_of_domain", "not one of the declared values");
                return null;
            case "integer":
                {
                    if (!IntentJs.IsInt(x)) return ("bad_type", "expected a safe integer");
                    double v = IntentJs.NumOf(x)!.Value;
                    if (d.ContainsKey("min") && v < IntentJs.NumOf(d["min"])!.Value) return ("out_of_domain", "below min");
                    if (d.ContainsKey("max") && v > IntentJs.NumOf(d["max"])!.Value) return ("out_of_domain", "above max");
                    return null;
                }
            case "boolean":
                return x is bool ? null : ("bad_type", "expected a boolean");
            case "date":
                if (x is not string ds) return ("bad_type", "expected a YYYY-MM-DD string");
                return IsCalendarDate(ds) ? null : ("out_of_domain", "not a calendar date YYYY-MM-DD");
            case "set":
                {
                    if (x is not L xs || xs.Any(e => e is not string)) return ("bad_type", "expected an array of strings");
                    if (!Distinct(xs)) return ("out_of_domain", "set members must be distinct");
                    var values = (L)d["values"]!;
                    if (xs.Any(e => !values.Any(v => v as string == (string)e!))) return ("out_of_domain", "set member not among the declared values");
                    if (xs.Count < NumOr(d, "min_items", 0) || xs.Count > NumOr(d, "max_items", values.Count)) return ("out_of_domain", "set size outside the declared bounds");
                    return null;
                }
            case "array":
                {
                    if (x is not L xs) return ("bad_type", "expected an array");
                    bool ints = IntentJs.Get(d, "items") as string == "integer";
                    foreach (var e in xs)
                    {
                        if (ints ? !IntentJs.IsInt(e) : !StrOk(e, maxLen))
                            return ("bad_type", ints ? "array items must be safe integers" : "array items must be strings within max_len UTF-8 bytes");
                        if (ints && ((d.ContainsKey("min") && IntentJs.NumOf(e) < IntentJs.NumOf(d["min"])) || (d.ContainsKey("max") && IntentJs.NumOf(e) > IntentJs.NumOf(d["max"]))))
                            return ("out_of_domain", "array item outside min/max");
                    }
                    if (xs.Count < NumOr(d, "min_items", 0) || xs.Count > NumOr(d, "max_items", DefaultMaxItems)) return ("out_of_domain", "array length outside the declared bounds");
                    return null;
                }
            default:
                return ("bad_type", "unknown declared type");
        }
    }

    /// <summary>Map an action to the declared domain or to the fail-closed cell (rule 14 step 5). First failure wins:
    /// params_not_object; unknown_verb; undeclared_param (params keys in UTF-8 byte order); then for every declared path in UTF-8
    /// byte order: missing_param (absent and required, default true), else bad_type / out_of_domain.</summary>
    public static Conform ConformAction(object? doc, string verb, object? parameters)
    {
        if (parameters is not D p) return new(false, "params_not_object", null, "params must be a JSON object");
        var v = SchemaVerb(doc, verb);
        if (v == null) return new(false, "unknown_verb", null, $"verb '{verb}' is not declared by the schema");
        var declared = (D)v["params"]!;
        foreach (var k in IntentJs.SortedUtf8(p.Keys))
        {
            var path = "action.params." + k;
            if (!declared.ContainsKey(path)) return new(false, "undeclared_param", path, $"parameter '{path}' is not declared for '{verb}'");
        }
        foreach (var path in IntentJs.SortedUtf8(declared.Keys))
        {
            var d = (D)declared[path]!;
            var name = path.Substring("action.params.".Length);
            if (!p.ContainsKey(name))
            {
                if (IntentJs.Get(d, "required") is not false) return new(false, "missing_param", path, $"required parameter '{path}' is missing");
                continue;
            }
            var bad = ParamValueViolation(d, p[name]);
            if (bad != null) return new(false, bad.Value.Code, path, $"'{path}': {bad.Value.Reason}");
        }
        return Conform.Pass;
    }

    /// <summary>The integer parameters of a verb entry that feed <paramref name="unit"/>, in UTF-8 byte order.</summary>
    internal static List<string> AccumulationParams(D v, string unit) =>
        IntentJs.SortedUtf8(((D)v["params"]!).Where(e => IntentJs.Get(e.Value, "type") as string == "integer"
            && IntentJs.Get(e.Value, "accumulates_into") is L ai && ai.Any(x => x as string == unit)).Select(e => e.Key));

    /// <summary><c>env.canon</c>: for every PRESENT boolean / set / array parameter, its canonical text.</summary>
    public static D CanonProjection(object? doc, string verb, D parameters)
    {
        var output = new D();
        var v = SchemaVerb(doc, verb);
        if (v == null) return output;
        var declared = (D)v["params"]!;
        foreach (var path in IntentJs.SortedUtf8(declared.Keys))
        {
            var type = IntentJs.Get(declared[path], "type") as string;
            var name = path.Substring("action.params.".Length);
            if (!parameters.TryGetValue(name, out var x)) continue;
            if (type == "boolean") output[name] = x is true ? "true" : "false";
            else if (type == "set") output[name] = IntentJs.Canon(IntentJs.SortedUtf8(((L)x!).Cast<string>()).Cast<object?>().ToList());
            else if (type == "array") output[name] = IntentJs.Canon(x);
        }
        return output;
    }
}
