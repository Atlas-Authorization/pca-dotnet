// Action kit (native port of the small deterministic core of the action-kit reference): strict ActionDef parse, normalize and
// canonical digest, the trait registry and its closure/floor algebra, rule 22 (FloorDecision and the schema floor integrity
// check), the pack Merkle root and inclusion proof, and T(d)/eff(d). Integers and sets only; every function is pure. Mirrors
// atlas_pca/actions.py. ActionSchema v2 parsing and the v2 parameter types/formats live in ActionSchema.cs.
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public sealed class ActionKitError : Exception
{
    public string Code { get; }
    public ActionKitError(string code, string message) : base(message) { Code = code; }
}

public static partial class Actions
{
    public const string ActionDefKind = "pca-action-def";
    public const string DefDigestDomain = "atlas-pca/action-def/v1";
    public const string TraitsDigestDomain = "atlas-pca/action-traits/v1";
    public const string RolesDigestDomain = "atlas-pca/action-roles/v1";
    public const string PackDigestDomain = "atlas-pca/action-pack/v1";

    const int MaxVerbBytes = 128, MaxTitleBytes = 120, MaxDescriptionBytes = 1024, MaxDefParams = 64, MaxDefAliases = 16, MaxDefTraits = 32,
        MaxDefContext = 16, MaxDefSideEffects = 16, MaxTraitImpliesDepth = 8, MaxRegistryTraits = 512, PpmMax = 1_000_000;

    static readonly string[] Effects = { "read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign" };
    static readonly string[] Reversibility = { "reversible", "rate_limited", "irreversible" };
    static readonly Dictionary<string, int> RevRank = new() { ["reversible"] = 0, ["rate_limited"] = 1, ["irreversible"] = 2 };
    static readonly string[] BlastRadii = { "one", "bounded", "tenant", "global" };
    static readonly Dictionary<string, long> BlastPpm = new() { ["one"] = 50_000, ["bounded"] = 300_000, ["tenant"] = 700_000, ["global"] = 1_000_000 };
    static readonly string[] ResourceScopes = { "one", "set", "tenant", "global" };
    static readonly Dictionary<string, string> ScopeBlast = new() { ["one"] = "one", ["set"] = "bounded", ["tenant"] = "tenant", ["global"] = "global" };
    static readonly string[] ParamTypes = { "string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref" };
    static readonly Dictionary<string, int> SensRank = new() { ["free"] = 0, ["material"] = 1, ["critical"] = 2 };
    static readonly string[] ProvenanceLevels = { "first_party", "tool", "agent" };
    static readonly string[] CoreRoles =
    {
        "money.amount", "money.currency", "money.fee", "party.payee", "party.payer",
        "contact.email", "contact.phone", "contact.address", "person.name", "person.dob", "person.national_id",
        "credential.secret", "credential.token", "credential.key",
        "path.fs", "query.sql", "query.search", "code.source", "code.command", "url.target",
        "text.message", "text.public", "time.not_before", "time.not_after", "count.limit", "bytes.size",
    };
    static readonly string[] ParamTags = { "pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql" };
    static readonly string[] ParamFormats = { "email", "url", "uri_https", "uuid", "iban", "phone_e164", "cidr", "iso_country", "iso_currency", "semver", "sha256" };
    static readonly string[] UnitKinds = { "money", "count", "bytes", "duration", "ratio" };
    static readonly string[] CaveatKinds = { "amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap" };
    static readonly string[] ContextKeys = { "approval_ref", "dry_run_first", "fresh_revocation", "idempotency", "revocable", "sandbox_attested" };
    static readonly string[] ParamRuleIds = { "array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency", "pay_has_idempotency", "recipient_param_declared", "secret_not_logged" };
    static readonly string[] IdempotencyModes = { "key_param", "natural", "none" };
    static readonly string[] ReviewStates = { "authored", "unreviewed", "suggested", "confirmed" };
    static readonly string[] BindingKinds = { "mcp", "openapi", "http", "graphql", "grpc", "asyncapi" };
    static readonly string[] IdClasses = { "digits", "hex", "alnum", "slug", "uuid", "any_safe" };
    static readonly string[] IntRoles = { "money.amount", "money.fee", "count.limit", "bytes.size" };
    static readonly string[] Reserved = { "__proto__", "constructor", "prototype" };

    const RegexOptions Ro = RegexOptions.CultureInvariant;
    static readonly Regex IdRoleRe = new(@"\Aid\.[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}\z", Ro);
    static readonly Regex CustomRoleRe = new(@"\Ax\.[a-z0-9_]+(?:\.[a-z0-9_]+){1,3}\z", Ro);
    static readonly Regex IdFormatRe = new(@"\Aid:[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}\z", Ro);
    static readonly Regex TaintRe = new(@"\Asession_taint_max:[a-z_]{1,16}\z", Ro);
    static readonly Regex VerbRe = new(@"\A[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){1,5}\z", Ro);
    static readonly Regex AliasRe = new(@"\A[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,5}\z", Ro);
    static readonly Regex ParamNameRe = new(@"\A[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}\z", Ro);
    static readonly Regex TraitIdRe = new(@"\A[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}\z", Ro);
    static readonly Regex ResourceTypeRe = new(@"\A[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,4}\z", Ro);
    static readonly Regex UnitIdRe = new(@"\A[a-z0-9_]+(?:\.[a-z0-9_]+)*\z", Ro);
    static readonly Regex CcyRe = new(@"\A[A-Z]{3}\z", Ro);

    // ---- helpers ------------------------------------------------------------------------------------------------------------
    static bool Has(object? o, string k) => o is D d && d.ContainsKey(k);
    static object? G(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : null;
    static bool IsInt(object? v) => IntentJs.IsInt(v);
    static bool IsNonNeg(object? v) => IntentJs.IsNonNeg(v);
    static long I(object? v) => (long)IntentJs.NumOf(v)!.Value;
    static bool IsStr(object? v, int max = 256) => v is string s && s.Length > 0 && IntentJs.U8Len(s) <= max;
    static bool In(object? x, string[] xs) => x is string s && xs.Contains(s);
    static List<string> SortUniq(IEnumerable<string>? xs) { var l = (xs ?? Array.Empty<string>()).Distinct(StringComparer.Ordinal).ToList(); l.Sort(StringComparer.Ordinal); return l; }
    static L ToL(IEnumerable<string> xs) => new(xs.Cast<object?>());
    static List<string> Strs(object? v) => v is L l ? l.Select(x => (string)x!).ToList() : new List<string>();
    static bool IsContextKey(object? k) => k is string s && (ContextKeys.Contains(s) || TaintRe.IsMatch(s));
    static bool StrList(object? v, int max, Func<string, bool> ok) =>
        v is L l && l.Count <= max && l.All(x => x is string s && ok(s)) && l.Select(x => (string)x!).Distinct(StringComparer.Ordinal).Count() == l.Count;
    static bool Subset(IEnumerable<string> a, ICollection<string> b) => a.All(b.Contains);

    // ---- strict JSON profile + ActionDef validation --------------------------------------------------------------------------
    /// <summary>Strict JSON profile: plain objects/arrays, NFC strings without lone surrogates, safe integers only, depth &lt;= 32.</summary>
    public static string? JsonProfileError(object? v, int depth = 0)
    {
        if (depth > 32) return "nesting deeper than 32";
        switch (v)
        {
            case null: case bool: return null;
            case Num or int or long or double: return IsInt(v) ? null : "numbers must be safe integers (no floats, no -0)";
            case string s: return Pca.HasLoneSurrogate(s) ? "string has a lone surrogate" : s.IsNormalized(NormalizationForm.FormC) ? null : "string is not NFC";
            case L l:
                foreach (var x in l) { var e = JsonProfileError(x, depth + 1); if (e != null) return e; }
                return null;
            case D d:
                foreach (var (k, x) in d)
                {
                    if (Pca.HasLoneSurrogate(k) || !k.IsNormalized(NormalizationForm.FormC)) return "member name is not NFC / has a lone surrogate";
                    var e = JsonProfileError(x, depth + 1); if (e != null) return e;
                }
                return null;
        }
        return "only JSON values are allowed";
    }

    static bool IsRole(object? r) => r is string s && (CoreRoles.Contains(s) || IdRoleRe.IsMatch(s) || CustomRoleRe.IsMatch(s));
    static bool IsFormat(object? f) => f is string s && (ParamFormats.Contains(s) || IdFormatRe.IsMatch(s));

    static string IdClassChars(string c)
    {
        const string digits = "0123456789", lower = "abcdefghijklmnopqrstuvwxyz", upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        return c switch
        {
            "digits" => digits, "hex" => digits + "abcdef", "alnum" => digits + lower + upper, "slug" => digits + lower + "-_",
            "uuid" => digits + "abcdef-", _ => digits + lower + upper + "._-:/",
        };
    }
    static bool InClass(string s, string c) { var cs = IdClassChars(c); return s.All(cs.Contains); }

    static string? IdPatternError(object? p)
    {
        if (p is string star && star == "*") return null;
        const string shape = "resource.id must be '*', {exact} or {prefix, class, len}";
        if (p is not D d) return shape;
        var keys = string.Join(",", d.Keys.OrderBy(k => k, StringComparer.Ordinal));
        if (keys == "exact") return d["exact"] is string e && e.Length is >= 1 and <= 128 && InClass(e, "any_safe") ? null : "resource.id.exact must be 1..128 safe characters";
        if (keys != "class,len,prefix") return shape;
        if (d["prefix"] is not string pf || pf.Length > 32 || !InClass(pf, "any_safe")) return "resource.id.prefix must be up to 32 safe characters";
        if (!In(d["class"], IdClasses)) return "resource.id.class is not an id class";
        if (d["len"] is not L ln || ln.Count != 2 || !ln.All(n => IsInt(n) && I(n) >= 1 && I(n) <= 128)) return "resource.id.len must be [min, max] in 1..128";
        if (I(ln[0]) > I(ln[1])) return "resource.id.len: min > max";
        if ((string)d["class"]! == "uuid" && (pf != "" || I(ln[0]) != 36 || I(ln[1]) != 36)) return "a uuid id has no prefix and length exactly [36, 36]";
        return null;
    }

    static string? ParamNameError(string name)
    {
        if (!ParamNameRe.IsMatch(name)) return $"param name '{name}' is malformed";
        if (name.Split('.').Any(s => Reserved.Contains(s))) return $"param name '{name}' is reserved";
        return null;
    }

    static string? ParamError(string name, object? po, HashSet<string> names)
    {
        if (po is not D p) return name + ": declaration must be an object";
        string[] keys = { "type", "role", "required", "values", "min", "max", "max_len", "items", "min_items", "max_items", "format", "unit", "tags",
            "provenance_min", "sensitivity", "accumulates", "default", "principal_neutral_default", "description" };
        foreach (var k in p.Keys) if (!keys.Contains(k)) return $"{name}: unknown member '{k}'";
        if (!In(G(p, "type"), ParamTypes)) return name + ": unknown type";
        var t = (string)p["type"]!;
        if (p.ContainsKey("role") && !IsRole(p["role"])) return name + ": unknown role";
        if (G(p, "role") is string r && IntRoles.Contains(r) && t != "integer") return name + ": role requires an integer parameter";
        if (p.ContainsKey("required") && p["required"] is not bool) return name + ": required must be a boolean";
        if (p.ContainsKey("values"))
        {
            if (p["values"] is not L vs || vs.Count == 0 || vs.Count > 256 || !vs.All(x => IsStr(x))) return name + ": values must be 1..256 non-empty strings";
            if (vs.Select(x => (string)x!).Distinct(StringComparer.Ordinal).Count() != vs.Count) return name + ": values must be distinct";
            if (t != "string" && t != "set") return name + ": values apply to string and set only";
        }
        if (t == "set" && !p.ContainsKey("values")) return name + ": a set needs values";
        bool intLike = t == "integer" || t == "duration" || (t == "array" && G(p, "items") is string it && it == "integer");
        foreach (var k in new[] { "min", "max" })
            if (p.ContainsKey(k) && (!IsInt(p[k]) || !intLike)) return $"{name}: {k} must be a safe integer on an integer parameter";
        if (IsInt(G(p, "min")) && IsInt(G(p, "max")) && I(p["min"]) > I(p["max"])) return name + ": min > max";
        if (p.ContainsKey("max_len") && (!IsInt(p["max_len"]) || I(p["max_len"]) < 1 || I(p["max_len"]) > 16_777_216 || (t != "string" && t != "array" && t != "object_ref")))
            return name + ": max_len must be 1..16777216 on a string or array";
        if (p.ContainsKey("items") && (t != "array" || !IsStr(p["items"], 64))) return name + ": items applies to array only";
        foreach (var k in new[] { "min_items", "max_items" })
            if (p.ContainsKey(k) && (!IsNonNeg(p[k]) || (t != "set" && t != "array"))) return $"{name}: {k} must be a non-negative integer on a set or array";
        if (IsInt(G(p, "min_items")) && IsInt(G(p, "max_items")) && I(p["min_items"]) > I(p["max_items"])) return name + ": min_items > max_items";
        if (p.ContainsKey("format") && (!IsFormat(p["format"]) || (t != "string" && t != "object_ref"))) return name + ": format must be a known format on a string parameter";
        if (p.ContainsKey("unit"))
        {
            if (t != "integer") return name + ": unit applies to integer parameters only";
            if (p["unit"] is not D u || !In(G(u, "kind"), UnitKinds)) return name + ": unit.kind is not a known kind";
            if ((string)u["kind"]! == "money")
            {
                if (u.Keys.Any(k => k is not ("kind" or "ccy" or "exp"))) return name + ": unit has unknown members";
                if (!IsInt(G(u, "exp")) || I(u["exp"]) < 0 || I(u["exp"]) > 18) return name + ": unit.exp must be an integer in 0..18";
                var c = G(u, "ccy");
                if (c is string cs) { if (!CcyRe.IsMatch(cs)) return name + ": unit.ccy must be an ISO 4217 style code"; }
                else if (c is not D cd || string.Join(",", cd.Keys) != "from" || cd["from"] is not string fr || !names.Contains(fr)) return name + ": unit.ccy.from must name a declared parameter";
            }
            else if (string.Join(",", u.Keys) != "kind") return name + ": unit has unknown members";
        }
        if (p.ContainsKey("tags"))
        {
            if (p["tags"] is not L tg || tg.Count > ParamTags.Length || !tg.All(x => In(x, ParamTags)) || tg.Select(x => (string)x!).Distinct(StringComparer.Ordinal).Count() != tg.Count) return name + ": tags must be distinct known tags";
        }
        if (p.ContainsKey("provenance_min") && !In(p["provenance_min"], ProvenanceLevels)) return name + ": unknown provenance_min";
        if (p.ContainsKey("sensitivity") && !In(p["sensitivity"], SensRank.Keys.ToArray())) return name + ": unknown sensitivity";
        if (p.ContainsKey("accumulates"))
        {
            if (t != "integer") return name + ": accumulates applies to integer parameters only";
            if (p["accumulates"] is not L a || a.Count == 0 || a.Count > 8 || !a.All(x => x is string xs && xs.Length <= 64 && UnitIdRe.IsMatch(xs)) || a.Select(x => (string)x!).Distinct(StringComparer.Ordinal).Count() != a.Count)
                return name + ": accumulates must be 1..8 distinct unit ids";
        }
        if (p.ContainsKey("default") && p["default"] == null) return name + ": default must not be null (absent = no default)";
        if (p.ContainsKey("principal_neutral_default") && p["principal_neutral_default"] is not bool) return name + ": principal_neutral_default must be a boolean";
        if (G(p, "principal_neutral_default") is true && !p.ContainsKey("default")) return name + ": principal_neutral_default needs a default";
        if (p.ContainsKey("description") && !IsStr(p["description"], MaxDescriptionBytes)) return $"{name}: description must be a string up to {MaxDescriptionBytes} bytes";
        return null;
    }

    static string? BindingsError(object? bo)
    {
        if (bo is not D b) return "bindings must be an object";
        var shapes = new Dictionary<string, (string[] Req, string[] Opt)>
        {
            ["mcp"] = (new[] { "tool" }, new string[0]), ["openapi"] = (new[] { "operationId" }, new[] { "method", "path" }), ["http"] = (new[] { "method", "path" }, new string[0]),
            ["graphql"] = (new[] { "op", "field" }, new string[0]), ["grpc"] = (new[] { "service", "method" }, new string[0]), ["asyncapi"] = (new[] { "channel", "op" }, new string[0]),
        };
        foreach (var (k, v) in b)
        {
            if (!BindingKinds.Contains(k)) return $"bindings: unknown kind '{k}'";
            var (req, opt) = shapes[k];
            if (v is not D vd) return $"bindings.{k} must be an object";
            foreach (var m in vd.Keys) if (!req.Contains(m) && !opt.Contains(m)) return $"bindings.{k}: unknown member '{m}'";
            foreach (var m in req) if (!IsStr(G(vd, m), 256)) return $"bindings.{k}.{m} must be a non-empty string";
            foreach (var m in opt) if (vd.ContainsKey(m) && !IsStr(vd[m], 256)) return $"bindings.{k}.{m} must be a non-empty string";
        }
        if (b.ContainsKey("graphql") && !(G(b["graphql"], "op") is string go && (go == "query" || go == "mutation" || go == "subscription"))) return "bindings.graphql.op is not a GraphQL operation kind";
        if (b.ContainsKey("asyncapi") && !(G(b["asyncapi"], "op") is string ao && (ao == "send" || ao == "receive"))) return "bindings.asyncapi.op must be send or receive";
        return null;
    }

    static string? ReviewError(object? ro)
    {
        if (ro is not D r) return "review must be an object";
        foreach (var k in r.Keys) if (k is not ("state" or "attestation" or "suggested_by")) return $"review: unknown member '{k}'";
        if (!In(G(r, "state"), ReviewStates)) return "review.state is not a review state";
        if (r.ContainsKey("attestation"))
        {
            if (r["attestation"] is not D a) return "review.attestation must be an object";
            foreach (var k in a.Keys) if (k is not ("def_digest" or "traits_digest" or "facts_digest" or "final_traits" or "dismissed" or "reviewer_kid" or "ts" or "sig")) return $"review.attestation: unknown member '{k}'";
            if (!IsStr(G(a, "def_digest"), 64) || !IsStr(G(a, "traits_digest"), 64) || !IsStr(G(a, "facts_digest"), 64) || !IsStr(G(a, "reviewer_kid"), 128) || !IsNonNeg(G(a, "ts"))) return "review.attestation: def_digest, traits_digest, facts_digest, reviewer_kid and ts are required";
            if (!StrList(G(a, "final_traits"), MaxDefTraits, s => TraitIdRe.IsMatch(s))) return "review.attestation.final_traits must be distinct trait ids";
            if (G(a, "dismissed") is not L dl || dl.Count > MaxDefTraits || !dl.All(x => x is D xd && string.Join(",", xd.Keys.OrderBy(k => k, StringComparer.Ordinal)) == "reason,trait" && xd["trait"] is string ts && TraitIdRe.IsMatch(ts) && IsStr(xd["reason"], 256)))
                return "review.attestation.dismissed must be {trait, reason} entries";
            if (a.ContainsKey("sig") && !IsStr(a["sig"], 4096)) return "review.attestation.sig must be a string";
        }
        return null;
    }

    /// <summary>Null if <paramref name="xo"/> is a well-formed ActionDef (structure only: registry, prules and lint checks are separate). Never throws.</summary>
    public static string? ValidateDef(object? xo)
    {
        try
        {
            var je = JsonProfileError(xo);
            if (je != null) return "not strict JSON: " + je;
            if (xo is not D x) return "def must be an object";
            string[] keys = { "v", "kind", "verb", "aliases", "title", "description", "effects", "resource", "params", "reversibility", "blast", "side_effects",
                "idempotency", "context", "traits", "audience", "compensates", "bindings", "examples", "review", "source", "since" };
            foreach (var k in x.Keys) if (!keys.Contains(k)) return $"unknown member '{k}'";
            if (!(x.TryGetValue("v", out var vv) && vv is Num && IntentJs.NumOf(vv) == 1)) return "unsupported def version";
            if (G(x, "kind") as string != ActionDefKind) return $"kind must be '{ActionDefKind}'";
            if (G(x, "verb") is not string verb || !VerbRe.IsMatch(verb) || IntentJs.U8Len(verb) > MaxVerbBytes) return "verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)";
            if (x.ContainsKey("aliases") && (!StrList(x["aliases"], MaxDefAliases, s => AliasRe.IsMatch(s) && IntentJs.U8Len(s) <= MaxVerbBytes) || Strs(x["aliases"]).Contains(verb)))
                return "aliases must be distinct verb-shaped names other than the verb";
            if (!IsStr(G(x, "title"), MaxTitleBytes)) return $"title must be a non-empty string up to {MaxTitleBytes} bytes";
            if (x.ContainsKey("description") && !IsStr(x["description"], MaxDescriptionBytes)) return "description must be a string";
            if (!StrList(G(x, "effects"), Effects.Length, s => Effects.Contains(s)) || ((L)x["effects"]!).Count == 0) return "effects must be 1..12 distinct known effects";
            if (G(x, "resource") is not D r || string.Join(",", r.Keys.OrderBy(k => k, StringComparer.Ordinal)) != "id,scope,type") return "resource must be {type, id, scope}";
            if (r["type"] is not string rt || !ResourceTypeRe.IsMatch(rt) || rt.Length > 128) return "resource.type is malformed";
            var ide = IdPatternError(r["id"]);
            if (ide != null) return ide;
            if (!In(r["scope"], ResourceScopes)) return "resource.scope is not a scope";
            if (G(x, "params") is not D pars) return "params must be an object";
            var names = pars.Keys.ToList();
            if (names.Count > MaxDefParams) return $"more than {MaxDefParams} parameters";
            var nameSet = new HashSet<string>(names);
            foreach (var n in names)
            {
                var ne = ParamNameError(n);
                if (ne != null) return ne;
                foreach (var m in names) if (m != n && m.StartsWith(n + ".", StringComparison.Ordinal)) return $"param '{n}' is both a value and the parent of '{m}'";
            }
            foreach (var n in names) { var e = ParamError(n, pars[n], nameSet); if (e != null) return e; }
            if (x.ContainsKey("reversibility"))
            {
                var rv = x["reversibility"];
                if (rv is not string)
                {
                    if (rv is not D rd || rd.Keys.Any(k => k is not ("by" or "map" or "default"))) return "reversibility must be a class or {by, map, default?}";
                    if (G(rd, "by") is not string by || !nameSet.Contains(by)) return "reversibility.by must name a declared parameter";
                    if (G(rd, "map") is not D m || m.Count == 0 || m.Count > 256 || !m.All(kv => IsStr(kv.Key, 128) && In(kv.Value, Reversibility))) return "reversibility.map must map values to reversibility classes";
                    if (rd.ContainsKey("default") && !In(rd["default"], Reversibility)) return "reversibility.default is not a class";
                }
                else if (!Reversibility.Contains((string)rv)) return "unknown reversibility class";
            }
            if (x.ContainsKey("blast"))
            {
                if (x["blast"] is not D b || b.Keys.Any(k => k is not ("radius" or "ppm")) || !In(G(b, "radius"), BlastRadii)) return "blast must be {radius, ppm?}";
                if (b.ContainsKey("ppm") && !(IsInt(b["ppm"]) && I(b["ppm"]) >= 0 && I(b["ppm"]) <= PpmMax)) return "blast.ppm must be an integer in 0..1000000";
            }
            if (x.ContainsKey("side_effects"))
            {
                if (x["side_effects"] is not L s || s.Count > MaxDefSideEffects || !s.All(e => e is D ed && string.Join(",", ed.Keys.OrderBy(k => k, StringComparer.Ordinal)) == "kind,target" && IsStr(ed["target"], 128) && In(ed["kind"], Effects)))
                    return "side_effects must be {target, kind} entries";
            }
            if (x.ContainsKey("idempotency"))
            {
                if (x["idempotency"] is not D i || i.Keys.Any(k => k is not ("mode" or "param")) || !In(G(i, "mode"), IdempotencyModes)) return "idempotency must be {mode, param?}";
                bool bad = (string)i["mode"]! == "key_param" ? !(G(i, "param") is string ip && nameSet.Contains(ip)) : i.ContainsKey("param");
                if (bad) return "idempotency.param is required for key_param (a declared parameter) and forbidden otherwise";
            }
            if (x.ContainsKey("context") && !StrList(x["context"], MaxDefContext, s => IsContextKey(s))) return "context must be distinct known context keys";
            if (x.ContainsKey("traits") && !StrList(x["traits"], MaxDefTraits, s => TraitIdRe.IsMatch(s))) return "traits must be distinct trait ids";
            if (x.ContainsKey("audience") && !(x["audience"] is string au && au == "resource")) return "audience must be 'resource'";
            if (x.ContainsKey("compensates") && !(x["compensates"] is string cp && VerbRe.IsMatch(cp))) return "compensates must be a verb";
            if (x.ContainsKey("bindings")) { var be = BindingsError(x["bindings"]); if (be != null) return be; }
            if (x.ContainsKey("examples"))
            {
                if (x["examples"] is not L ex || ex.Count > 32) return "examples must be an array of up to 32 entries";
                foreach (var e in ex)
                    if (e is not D ed || ed.Keys.Any(k => k is not ("params" or "under" or "expect")) || G(ed, "params") is not D || !(G(ed, "expect") is string xp && (xp == "allow" || xp == "escalate" || xp == "deny")))
                        return "example must be {params, under?, expect}";
            }
            var re = ReviewError(G(x, "review"));
            if (re != null) return re;
            if (x.ContainsKey("source"))
            {
                if (x["source"] is not D s || s.Keys.Any(k => k is not ("kind" or "uri" or "spec_digest" or "licence" or "imported_at")) || !IsStr(G(s, "kind"), 64) || !IsStr(G(s, "uri"), 2048)
                    || !IsStr(G(s, "spec_digest"), 128) || !IsStr(G(s, "licence"), 128) || (s.ContainsKey("imported_at") && !IsNonNeg(s["imported_at"])))
                    return "source must be {kind, uri, spec_digest, licence, imported_at?}";
            }
            if (x.ContainsKey("since") && !IsStr(x["since"], 64)) return "since must be a string";
            return null;
        }
        catch (Exception e) { return "malformed def: " + e.Message; }
    }

    // ---- profile lattice + trait registry --------------------------------------------------------------------------------------
    public static D Profile(long risk = 0, string rev = "reversible", long blastPpm = 0, long esc = 0, IEnumerable<string>? caveats = null, IEnumerable<string>? context = null, IEnumerable<string>? prules = null) => new()
    {
        ["risk"] = risk, ["rev"] = rev, ["blast_ppm"] = blastPpm, ["esc"] = esc,
        ["caveats"] = ToL(SortUniq(caveats)), ["context"] = ToL(SortUniq(context)), ["prules"] = ToL(SortUniq(prules)),
    };
    static readonly D Bottom = Profile();

    static bool IntIn(object? x, long lo, long hi) => IsInt(x) && I(x) >= lo && I(x) <= hi;

    internal static string? ProfileError(object? po)
    {
        if (po is not D p) return "profile must be an object";
        foreach (var k in p.Keys) if (k is not ("risk" or "rev" or "blast_ppm" or "esc" or "caveats" or "context" or "prules")) return $"profile: unknown member '{k}'";
        if (!IntIn(G(p, "risk"), 0, 3)) return "profile.risk must be an integer in 0..3";
        if (!In(G(p, "rev"), Reversibility)) return "profile.rev is not a reversibility class";
        if (!IntIn(G(p, "blast_ppm"), 0, PpmMax)) return "profile.blast_ppm must be an integer in 0..1000000";
        if (!IntIn(G(p, "esc"), 0, 3)) return "profile.esc must be an integer in 0..3";
        foreach (var (name, ok) in new (string, Func<object?, bool>)[] { ("caveats", x => In(x, CaveatKinds)), ("context", IsContextKey), ("prules", x => In(x, ParamRuleIds)) })
        {
            if (G(p, name) is not L a || a.Count > 64 || !a.All(ok)) return $"profile.{name} must be an array of known {name} entries";
            for (int i = 1; i < a.Count; i++) if (string.CompareOrdinal((string)a[i - 1]!, (string)a[i]!) >= 0) return $"profile.{name} must be sorted and distinct";
        }
        return null;
    }

    static string RevOf(D p) => (string)p["rev"]!;
    public static D Join(D p, D q) => new()
    {
        ["risk"] = Math.Max(I(p["risk"]), I(q["risk"])),
        ["rev"] = RevRank[RevOf(p)] >= RevRank[RevOf(q)] ? RevOf(p) : RevOf(q),
        ["blast_ppm"] = Math.Max(I(p["blast_ppm"]), I(q["blast_ppm"])),
        ["esc"] = Math.Max(I(p["esc"]), I(q["esc"])),
        ["caveats"] = ToL(SortUniq(Strs(p["caveats"]).Concat(Strs(q["caveats"])))),
        ["context"] = ToL(SortUniq(Strs(p["context"]).Concat(Strs(q["context"])))),
        ["prules"] = ToL(SortUniq(Strs(p["prules"]).Concat(Strs(q["prules"])))),
    };
    static D JoinAll(IEnumerable<D> ps) { var o = Bottom; foreach (var p in ps) o = Join(o, p); return o; }

    public static bool Leq(D p, D q) =>
        I(p["risk"]) <= I(q["risk"]) && RevRank[RevOf(p)] <= RevRank[RevOf(q)] && I(p["blast_ppm"]) <= I(q["blast_ppm"]) && I(p["esc"]) <= I(q["esc"])
        && Subset(Strs(p["caveats"]), Strs(q["caveats"])) && Subset(Strs(p["context"]), Strs(q["context"])) && Subset(Strs(p["prules"]), Strs(q["prules"]));

    /// <summary>Null if <paramref name="defsO"/> form a valid registry, else the first reason (ids, distinct, pca. reserved, implies resolve, T5, no cycle, depth &lt;= 8).</summary>
    public static string? RegistryError(IReadOnlyList<object?> defs, bool core = false)
    {
        if (defs.Count > MaxRegistryTraits) return $"a registry holds at most {MaxRegistryTraits} traits";
        var by = new Dictionary<string, D>();
        foreach (var to in defs)
        {
            if (to is not D t) return "trait must be an object";
            if (G(t, "id") is not string tid || !TraitIdRe.IsMatch(tid)) return $"trait id '{G(t, "id")}' is malformed";
            if (tid.StartsWith("pca.", StringComparison.Ordinal) && !core) return $"trait '{tid}': the pca. namespace is reserved for core traits";
            if (by.ContainsKey(tid)) return $"trait '{tid}' is defined twice";
            if (G(t, "implies") is not L im || im.Count > 8 || im.Any(u => u is not string) || im.Select(u => (string)u!).Distinct(StringComparer.Ordinal).Count() != im.Count) return $"trait '{tid}': implies must be up to 8 distinct trait ids";
            var pe = ProfileError(G(t, "floor"));
            if (pe != null) return $"trait '{tid}': {pe}";
            if (!(G(t, "card_phrase") is string cp && cp.Length >= 1 && cp.Length <= 120)) return $"trait '{tid}': card_phrase must be a non-empty string up to 120 characters";
            by[tid] = t;
        }
        foreach (var to in defs)
        {
            var t = (D)to!;
            foreach (var u in Strs(t["implies"]))
            {
                if (!by.TryGetValue(u, out var ud)) return $"trait '{t["id"]}' implies unknown trait '{u}'";
                if (!Leq((D)ud["floor"]!, (D)t["floor"]!)) return $"trait '{t["id"]}': floor is below the floor of implied '{u}'";
            }
        }
        var depth = new Dictionary<string, int>();
        var visiting = new HashSet<string>();
        int Walk(string i)
        {
            if (depth.TryGetValue(i, out var kn)) return kn;
            if (!visiting.Add(i)) return -1;
            int d = 1;
            foreach (var u in Strs(by[i]["implies"])) { var du = Walk(u); if (du < 0) return -1; d = Math.Max(d, du + 1); }
            visiting.Remove(i);
            depth[i] = d;
            return d;
        }
        foreach (var to in defs)
        {
            var id = (string)((D)to!)["id"]!;
            var d = Walk(id);
            if (d < 0) return $"trait '{id}': implies cycle";
            if (d > MaxTraitImpliesDepth) return $"trait '{id}': implies depth {d} exceeds {MaxTraitImpliesDepth}";
        }
        return null;
    }

    public static Dictionary<string, D> BuildRegistry(IReadOnlyList<object?> defs, bool core = false)
    {
        var e = RegistryError(defs, core);
        if (e != null) throw new ActionKitError("bad_registry", e);
        return defs.ToDictionary(t => (string)((D)t!)["id"]!, t => (D)t!);
    }

    /// <summary>Core registry extended with custom traits (which must not use <c>pca.</c> and must extend what they imply).</summary>
    public static Dictionary<string, D> ExtendRegistry(Dictionary<string, D> baseReg, IReadOnlyList<object?> custom)
    {
        foreach (var c in custom)
            if (c is not D cd || cd.GetValueOrDefault("id") is not string id || baseReg.ContainsKey(id) || id.StartsWith("pca.", StringComparison.Ordinal))
                throw new ActionKitError("bad_registry", "custom trait may not redefine a core trait");
        return BuildRegistry(baseReg.Values.Cast<object?>().Concat(custom).ToList(), true);
    }

    public static List<string> Closure(Dictionary<string, D> reg, IEnumerable<object?> ids)
    {
        var seen = new HashSet<string>();
        var stack = new Stack<object?>(ids.Reverse());
        while (stack.Count > 0)
        {
            var i = stack.Pop();
            if (i is string s && seen.Contains(s)) continue;
            if (i is not string id || !reg.TryGetValue(id, out var t)) throw new ActionKitError("unknown_trait", $"unknown trait '{i}'");
            seen.Add(id);
            foreach (var u in Strs(t["implies"])) stack.Push(u);
        }
        return SortUniq(seen);
    }

    public static D FloorOf(Dictionary<string, D> reg, IEnumerable<object?> ids) => JoinAll(Closure(reg, ids).Select(i => (D)reg[i]["floor"]!));

    /// <summary>FloorDecision(G, call, rho): deny if rho.esc &gt; G.max_esc; escalate if a caveat/context is missing or rho.esc &gt; G.preauth_esc; else allow.</summary>
    public static string FloorDecision(D g, D call, D rho)
    {
        if (I(rho["esc"]) > I(g["max_esc"])) return "deny";
        if (!Subset(Strs(rho["caveats"]), Strs(g["caveats"])) || !Subset(Strs(rho["context"]), Strs(call["context"])) || I(rho["esc"]) > I(g["preauth_esc"])) return "escalate";
        return "allow";
    }

    static readonly (string Id, string[] Implies, D Own, string Phrase)[] Table =
    {
        ("money_moving", new string[0], Profile(3, "rate_limited", 700_000, 2, new[] { "amount_cap", "count_cap", "window" }, new[] { "idempotency" }, new[] { "money_has_currency", "money_amount_bounded", "pay_has_idempotency" }), "moves money"),
        ("destructive", new string[0], Profile(2, "rate_limited", 0, 1, new[] { "resource_scope" }, null, new[] { "id_not_wildcard" }), "deletes or destroys data"),
        ("irreversible", new string[0], Profile(2, "irreversible", 0, 1, null, new[] { "fresh_revocation" }), "cannot be undone"),
        ("external_communication", new string[0], Profile(2, "irreversible", 0, 0, new[] { "recipient_scope", "rate_cap" }, null, new[] { "recipient_param_declared" }), "sends to people outside your organisation"),
        ("data_export", new string[0], Profile(2, "reversible", 0, 0, new[] { "resource_scope", "count_cap" }, null, new[] { "export_bounded" }), "exports data"),
        ("privilege_change", new string[0], Profile(3, "reversible", 0, 3, new[] { "resource_scope", "short_expiry" }), "changes who can do what"),
        ("code_execution", new string[0], Profile(3, "irreversible", 0, 2, new[] { "resource_scope" }, new[] { "sandbox_attested" }), "runs code or commands"),
        ("credential_access", new string[0], Profile(3, "reversible", 0, 3, null, null, new[] { "secret_not_logged" }), "reads or handles credentials"),
        ("bulk", new string[0], Profile(2, "reversible", 0, 0, new[] { "count_cap" }, null, new[] { "array_bounded" }), "acts on many items at once"),
        ("pii_access", new string[0], Profile(1, "reversible", 0, 0, new[] { "resource_scope" }), "touches personal data"),
        ("public_exposure", new string[0], Profile(2, "irreversible", 0, 1), "makes content public"),
        ("persistence", new string[0], Profile(2, "reversible", 0, 0, new[] { "short_expiry" }, new[] { "revocable" }), "creates standing access or infrastructure"),
        ("infra_mutation", new string[0], Profile(2, "rate_limited", 0, 0, new[] { "resource_scope" }), "changes infrastructure"),
        ("cost_incurring", new string[0], Profile(1, "reversible", 0, 0, new[] { "amount_cap" }), "incurs cost"),
        ("legal_binding", new string[0], Profile(3, "irreversible", 0, 3), "legally or cryptographically binds you"),
        ("impersonation", new[] { "external_communication" }, Profile(2, "reversible", 0, 1), "acts as a person"),
        ("network_egress", new string[0], Profile(1, "reversible", 0, 0, new[] { "recipient_scope" }), "reaches out to the network"),
        ("financial_data_read", new string[0], Profile(1, "reversible", 0, 0, new[] { "resource_scope" }), "reads financial data"),
        ("regulated_data", new string[0], Profile(2, "reversible", 0, 1), "handles regulated data"),
        ("scheduled", new string[0], Profile(2, "reversible", 0, 0, new[] { "short_expiry", "count_cap" }), "runs later or repeatedly"),
        ("unreviewed", new string[0], Profile(3, "irreversible", 1_000_000, 2, new[] { "approval_ref", "resource_scope" }, new[] { "dry_run_first" }), "has not been reviewed yet"),
        ("agent_spawning", new string[0], Profile(2, "reversible", 0, 0, new[] { "count_cap" }), "starts another agent"),
    };

    static List<object?> BuildCoreDefs()
    {
        var floors = new Dictionary<string, D>();
        var o = new List<object?>();
        foreach (var (name, implies, own, phrase) in Table)
        {
            var id = "pca." + name;
            var imp = implies.Select(n => "pca." + n).ToList();
            var fl = own;
            foreach (var u in imp) fl = Join(fl, floors[u]);
            floors[id] = fl;
            o.Add(new D { ["id"] = id, ["implies"] = ToL(imp), ["floor"] = fl, ["card_phrase"] = phrase });
        }
        return o;
    }

    public static readonly Dictionary<string, D> CoreRegistry = BuildRegistry(BuildCoreDefs(), true);

    static readonly Dictionary<string, string[]> EffectTraits = new()
    {
        ["read"] = new string[0], ["create"] = new string[0], ["update"] = new string[0], ["delete"] = new[] { "pca.destructive" }, ["send"] = new[] { "pca.external_communication" },
        ["pay"] = new[] { "pca.money_moving" }, ["exec"] = new[] { "pca.code_execution" }, ["privilege"] = new[] { "pca.privilege_change" }, ["export"] = new[] { "pca.data_export" },
        ["publish"] = new[] { "pca.public_exposure" }, ["provision"] = new[] { "pca.persistence", "pca.scheduled" }, ["sign"] = new[] { "pca.legal_binding" },
    };
    static readonly Dictionary<string, string[]> TagTraits = new()
    {
        ["pii"] = new[] { "pca.pii_access" }, ["phi"] = new[] { "pca.pii_access", "pca.regulated_data" }, ["pci"] = new[] { "pca.regulated_data" },
        ["secret"] = new[] { "pca.credential_access" }, ["credential"] = new[] { "pca.credential_access" },
    };
    static readonly Dictionary<string, string[]> RoleTraits = new()
    {
        ["credential.secret"] = new[] { "pca.credential_access" }, ["credential.token"] = new[] { "pca.credential_access" }, ["credential.key"] = new[] { "pca.credential_access" },
        ["url.target"] = new[] { "pca.network_egress" },
    };
    static readonly Dictionary<string, string> RoleSensFloor = new()
    {
        ["money.amount"] = "critical", ["money.currency"] = "material", ["money.fee"] = "material", ["party.payee"] = "critical", ["party.payer"] = "material",
        ["contact.email"] = "material", ["contact.phone"] = "material", ["contact.address"] = "material", ["person.name"] = "material", ["person.dob"] = "material",
        ["person.national_id"] = "critical", ["credential.secret"] = "critical", ["credential.token"] = "critical", ["credential.key"] = "critical",
        ["code.command"] = "critical", ["query.sql"] = "critical", ["text.message"] = "material",
    };
    static readonly Dictionary<string, string> TagSensFloor = new()
    {
        ["pii"] = "material", ["phi"] = "material", ["pci"] = "material", ["secret"] = "critical", ["credential"] = "critical",
        ["free_text_outbound"] = "material", ["code"] = "material", ["path"] = "material", ["sql"] = "material",
    };

    static D ListMap(Dictionary<string, string[]> m) => m.ToDictionary(kv => kv.Key, kv => (object?)ToL(kv.Value));
    static D StrMap(Dictionary<string, string> m) => m.ToDictionary(kv => kv.Key, kv => (object?)kv.Value);

    /// <summary>Digest of a trait registry (sorted by id): what a pack pins as <c>traits_digest</c>.</summary>
    public static string TraitsDigest(Dictionary<string, D> reg)
    {
        var ts = reg.Values.OrderBy(t => (string)t["id"]!, StringComparer.Ordinal).Select(t => (object?)new D
        {
            ["id"] = t["id"], ["implies"] = ToL(SortUniq(Strs(t["implies"]))), ["floor"] = t["floor"], ["card_phrase"] = t["card_phrase"],
        }).ToList();
        return Pca.HashCanonical(new D { ["d"] = TraitsDigestDomain, ["traits"] = ts });
    }

    public static string TablesDigest() => Pca.HashCanonical(new D
    {
        ["d"] = RolesDigestDomain, ["roles"] = ToL(CoreRoles), ["effect_traits"] = ListMap(EffectTraits), ["role_traits"] = ListMap(RoleTraits),
        ["tag_traits"] = ListMap(TagTraits), ["role_sensitivity"] = StrMap(RoleSensFloor), ["tag_sensitivity"] = StrMap(TagSensFloor),
    });

    // ---- normalize + digest ---------------------------------------------------------------------------------------------------
    static bool IsReadOnly(IEnumerable<string> effects) { var l = effects.ToList(); return l.Count > 0 && l.All(e => e == "read"); }
    static string MaxSens(string a, string b) => SensRank[a] >= SensRank[b] ? a : b;

    static string SensitivityFloor(D p)
    {
        var f = "free";
        if (G(p, "role") is string r && RoleSensFloor.TryGetValue(r, out var rf)) f = MaxSens(f, rf);
        foreach (var t in Strs(G(p, "tags"))) if (TagSensFloor.TryGetValue(t, out var tf)) f = MaxSens(f, tf);
        return f;
    }
    static string EffectiveParamSensitivity(D p) => MaxSens(G(p, "sensitivity") as string ?? "free", SensitivityFloor(p));

    static object? DeclaredReversibility(D d) => d.ContainsKey("reversibility") ? d["reversibility"] : IsReadOnly(Strs(d["effects"])) ? "reversible" : "irreversible";

    static string MaxRev(IEnumerable<object?> xs)
    {
        var o = "reversible";
        foreach (var b in xs) if (b is string s && RevRank.TryGetValue(s, out var rk) && rk > RevRank[o]) o = s;
        return o;
    }

    /// <summary>Conservative class of a (possibly value-dependent) reversibility declaration: the worst class any call can have.</summary>
    static string WorstReversibility(object? r, Dictionary<string, D> prms)
    {
        if (r is string s) return s;
        var rd = (D)r!;
        D? d = prms.GetValueOrDefault((string)rd["by"]!);
        var map = (D)rd["map"]!;
        var mapped = map.Values.ToList();
        List<string>? domain = null;
        if (d != null)
        {
            if (G(d, "type") as string == "boolean") domain = new() { "true", "false" };
            else if (G(d, "type") as string == "string" && d.TryGetValue("values", out var vs) && vs != null) domain = Strs(vs);
        }
        bool covered = domain != null && domain.All(map.ContainsKey);
        return MaxRev(covered ? mapped : mapped.Append(rd.TryGetValue("default", out var df) ? df : "irreversible"));
    }

    static D NormalizeParam(D p)
    {
        var o = new D(p);
        o["required"] = p.TryGetValue("required", out var rq) ? rq : true;
        if (p.ContainsKey("tags")) o["tags"] = ToL(SortUniq(Strs(p["tags"])));
        if (p.ContainsKey("values")) o["values"] = new L((L)p["values"]!);
        o["sensitivity"] = EffectiveParamSensitivity(p);
        if (p.ContainsKey("accumulates")) o["accumulates"] = ToL(SortUniq(Strs(p["accumulates"])));
        else if (G(p, "role") as string == "money.amount" && G(p, "unit") is D u && G(u, "kind") as string == "money" && G(u, "ccy") is string ccy)
            o["accumulates"] = new L { "money." + ccy.ToLowerInvariant() };
        return o;
    }

    static object? JsonCopy(object? v) => v switch { D d => d.ToDictionary(kv => kv.Key, kv => JsonCopy(kv.Value)), L l => new L(l.Select(JsonCopy)), _ => v };

    /// <summary>The authoring-independent form of a def (assumes ValidateDef passed): defaults filled, sets sorted, review/examples/source/since removed.</summary>
    public static D Normalize(D d)
    {
        var rev = DeclaredReversibility(d);
        var res = (D)d["resource"]!;
        var radius = d.ContainsKey("blast") ? (string)G(d["blast"], "radius")! : ScopeBlast[(string)res["scope"]!];
        var prms = new D();
        foreach (var k in ((D)d["params"]!).Keys.OrderBy(k => k, StringComparer.Ordinal)) prms[k] = NormalizeParam((D)((D)d["params"]!)[k]!);
        object? nrev;
        if (rev is string) nrev = rev;
        else
        {
            var rd = (D)rev!;
            var n = new D { ["by"] = rd["by"], ["map"] = new D((D)rd["map"]!) };
            if (rd.ContainsKey("default")) n["default"] = rd["default"];
            nrev = n;
        }
        var idem = new D { ["mode"] = d.ContainsKey("idempotency") ? G(d["idempotency"], "mode") : "none" };
        if (d.ContainsKey("idempotency") && Has(d["idempotency"], "param")) idem["param"] = G(d["idempotency"], "param");
        long ppm = Math.Max(BlastPpm[radius], d.ContainsKey("blast") && Has(d["blast"], "ppm") ? I(G(d["blast"], "ppm")) : 0);
        var se = d.ContainsKey("side_effects")
            ? ((L)d["side_effects"]!).Select(s => (Target: (string)G(s, "target")!, Kind: (string)G(s, "kind")!)).OrderBy(s => s.Target, StringComparer.Ordinal).ThenBy(s => s.Kind, StringComparer.Ordinal)
                .Select(s => (object?)new D { ["target"] = s.Target, ["kind"] = s.Kind }).ToList()
            : new List<object?>();
        var o = new D
        {
            ["v"] = 1L, ["kind"] = d["kind"], ["verb"] = d["verb"], ["aliases"] = ToL(SortUniq(Strs(G(d, "aliases")))), ["title"] = d["title"],
            ["effects"] = ToL(SortUniq(Strs(d["effects"]))),
            ["resource"] = new D { ["type"] = res["type"], ["id"] = res["id"], ["scope"] = res["scope"] },
            ["params"] = prms, ["reversibility"] = nrev, ["blast"] = new D { ["radius"] = radius, ["ppm"] = ppm },
            ["side_effects"] = se, ["idempotency"] = idem, ["context"] = ToL(SortUniq(Strs(G(d, "context")))), ["traits"] = ToL(SortUniq(Strs(G(d, "traits")))),
            ["bindings"] = d.ContainsKey("bindings") ? JsonCopy(d["bindings"]) : new D(),
        };
        if (d.ContainsKey("description")) o["description"] = d["description"];
        if (d.ContainsKey("audience")) o["audience"] = d["audience"];
        if (d.ContainsKey("compensates")) o["compensates"] = d["compensates"];
        return o;
    }

    public const string VerbFactsDomain = "atlas-pca/action-verb-facts/v1";

    /// <summary>b64u(sha256(strictCanonical({d, verb}))) over the verb WITHOUT traits, floors, confirmation and def: the facts a reviewer saw.</summary>
    public static string FactsDigest(D verb) => Pca.HashCanonical(new D
    {
        ["d"] = VerbFactsDomain,
        ["verb"] = verb.Where(kv => kv.Key is not ("traits" or "floors" or "confirmation" or "def")).ToDictionary(kv => kv.Key, kv => kv.Value),
    });

    /// <summary>b64u(sha256(strictCanonical({d, def: normalize(def)}))). Review state, examples, source and since do not enter it.</summary>
    public static string DefDigest(D d) => Pca.HashCanonical(new D { ["d"] = DefDigestDomain, ["def"] = Normalize(d) });

    // ---- pack Merkle root + inclusion proof ----------------------------------------------------------------------------------------
    static D Leaf(string digest) => new() { ["d"] = PackDigestDomain, ["def"] = digest };
    static List<string> SortedDigests(IReadOnlyList<string> digests)
    {
        var s = SortUniq(digests);
        if (s.Count != digests.Count) throw new ActionKitError("duplicate_def", "a pack lists a def digest twice");
        if (s.Count == 0) throw new ActionKitError("empty_pack", "a pack has at least one def");
        return s;
    }
    public static string PackRoot(IReadOnlyList<string> digests) => Pca.MerkleRoot(SortedDigests(digests).Select(x => (object?)Leaf(x)).ToList());

    static int Split(int n) { int k = 1; while (k * 2 < n) k *= 2; return k; }
    static byte[] Node(byte[] l, byte[] r) => SHA256.HashData(new byte[] { 1 }.Concat(l).Concat(r).ToArray());
    static byte[] SubRoot(List<byte[]> hs)
    {
        if (hs.Count == 1) return hs[0];
        int k = Split(hs.Count);
        return Node(SubRoot(hs.GetRange(0, k)), SubRoot(hs.GetRange(k, hs.Count - k)));
    }

    /// <summary>RFC 6962 inclusion proof of <paramref name="digest"/> in the pack made of <paramref name="digests"/>: {index, size, path: [{side, hash}]} bottom-up.</summary>
    public static D PackProof(IReadOnlyList<string> digests, string digest)
    {
        var s = SortedDigests(digests);
        int i = s.IndexOf(digest);
        if (i < 0) throw new ActionKitError("not_in_pack", "the digest is not in the pack");
        var seg = s.Select(x => SHA256.HashData(new byte[] { 0 }.Concat(Encoding.UTF8.GetBytes(Pca.Canonicalize(Leaf(x)))).ToArray())).ToList();
        var path = new List<object?>();
        int idx = i;
        while (seg.Count > 1)
        {
            int k = Split(seg.Count);
            if (idx < k) { path.Add(new D { ["side"] = "R", ["hash"] = Pca.B64u(SubRoot(seg.GetRange(k, seg.Count - k))) }); seg = seg.GetRange(0, k); }
            else { path.Add(new D { ["side"] = "L", ["hash"] = Pca.B64u(SubRoot(seg.GetRange(0, k))) }); seg = seg.GetRange(k, seg.Count - k); idx -= k; }
        }
        path.Reverse();
        return new D { ["index"] = IntentJs.OfLong(i), ["size"] = IntentJs.OfLong(s.Count), ["path"] = path };
    }

    /// <summary>Does <paramref name="proof"/> show <paramref name="digest"/> is in the pack with root <paramref name="root"/>?</summary>
    public static bool VerifyPackProof(string root, D proof, string digest) => Pca.VerifyInclusion(root, proof, Leaf(digest));

    // ---- T(d), decl(d), eff(d) ----------------------------------------------------------------------------------------------------
    /// <summary>Traits implied by effects, roles, tags, scope and reversibility. <paramref name="prms"/>: dicts with type/role/tags/max_items.</summary>
    public static List<string> ImpliedFromFacts(IEnumerable<string> effects, IEnumerable<D> prms, string? scope, string worstRev)
    {
        var o = new List<string>();
        var eff = effects.ToList();
        foreach (var e in eff) o.AddRange(EffectTraits[e]); // KeyNotFoundException on an unknown effect (callers treat it as a forged document)
        bool ro = IsReadOnly(eff);
        foreach (var p in prms)
        {
            if (G(p, "role") is string r)
            {
                if (RoleTraits.TryGetValue(r, out var rt)) o.AddRange(rt);
                if (ro && r.StartsWith("money.", StringComparison.Ordinal)) o.Add("pca.financial_data_read");
            }
            foreach (var t in Strs(G(p, "tags"))) if (TagTraits.TryGetValue(t, out var tt)) o.AddRange(tt);
            if (G(p, "type") as string == "array" && G(p, "max_items") == null) o.Add("pca.bulk");
        }
        if (scope != null && scope != "one") o.Add("pca.bulk");
        if (worstRev == "irreversible") o.Add("pca.irreversible");
        return SortUniq(o);
    }

    static Dictionary<string, D> ParamsOf(D n) => ((D)n["params"]!).ToDictionary(kv => kv.Key, kv => (D)kv.Value!);

    // ---- human confirmation: "unconfirmed means maximally dangerous" --------------------------------------------------------------
    // The ONLY thing that sets an action's effective traits below the top of the registry is a valid signed confirmation by a key
    // pinned with the reviewer role. Every failure of any check (absent, malformed, stale, unpinned, bad signature) is a reason string
    // and the action stays unconfirmed; nothing here throws.
    public const string ReviewDomain = "atlas-pca/action-review/v2\0";
    static readonly string[] KeyRoles = { "reviewer", "importer", "model", "publisher" };

    /// <summary>Null if the reviewer pin set <c>{keys, traits_digests?}</c> is sound: distinct kids, canonical keys, known roles, no key that is both a reviewer and a machine.</summary>
    public static string? ReviewerPinsError(object? po)
    {
        if (po is not D p || G(p, "keys") is not L keys) return "pins must be {keys: [...]}";
        var kids = new HashSet<string>();
        var machinePks = new HashSet<string>();
        foreach (var ko in keys)
        {
            if (ko is not D k || G(k, "kid") is not string kid || kid.Length == 0 || kid.Length > 128) return "a pinned key needs a kid";
            if (!kids.Add(kid)) return $"kid '{kid}' is pinned twice";
            if (Pca.B64uDecode(G(k, "pk"), 32) == null) return $"key '{kid}': pk is not canonical base64url (32 bytes)";
            if (G(k, "roles") is not L roles || roles.Count == 0 || roles.Any(r => !In(r, KeyRoles)) || roles.Distinct().Count() != roles.Count) return $"key '{kid}': roles must be distinct known roles";
            bool machine = roles.Contains("importer") || roles.Contains("model");
            if (roles.Contains("reviewer") && machine) return $"key '{kid}': an importer or model key cannot hold the reviewer role";
            foreach (var t in new[] { "not_before", "not_after" })
                if (k.ContainsKey(t) && !IsNonNeg(k[t])) return $"key '{kid}': {t} must be a non-negative integer";
            if (machine) machinePks.Add((string)k["pk"]!);
        }
        // the same key material under a second kid must not smuggle a machine key into the reviewer role
        foreach (var ko in keys)
        {
            var k = (D)ko!;
            if (((L)k["roles"]!).Contains("reviewer") && machinePks.Contains((string)k["pk"]!)) return $"key '{k["kid"]}': the same key material is pinned as an importer or model key";
        }
        return null;
    }

    // JS String.prototype.trim().length === 0 (its whitespace set differs from char.IsWhiteSpace)
    static bool JsBlank(string s) => s.All(c => c is '\t' or '\n' or '\v' or '\f' or '\r' or ' ' or '\u00a0' or '\u1680' or (>= '\u2000' and <= '\u200a')
        or '\u2028' or '\u2029' or '\u202f' or '\u205f' or '\u3000' or '\ufeff');

    static bool DigestAccepted(object? td, Dictionary<string, D> reg, D pins)
    {
        var extra = G(pins, "traits_digests");
        if (extra != null && extra is not L) return false;
        return td is string s && (s == TraitsDigest(reg) || (extra is L l && l.Contains(s)));
    }

    /// <summary>The checks both levels share: dismissed entries, the pinned reviewer key (role, validity window) and the Ed25519 signature
    /// over <c>ReviewDomain ++ strictCanonical(body)</c>. <paramref name="final"/> is the attestation's final_traits. Null = counts.</summary>
    static string? ReviewSigError(D a, D pins, List<string> final)
    {
        if (G(a, "dismissed") is not L dm) return "malformed confirmation";
        var fin = new HashSet<string>(final);
        foreach (var d in dm)
            if (d is not D dd || G(dd, "trait") is not string dt || G(dd, "reason") is not string dr || fin.Contains(dt) || JsBlank(dr)) return "a dismissed trait is also final, or has no reason";
        if (G(a, "reviewer_kid") is not string kid || !IsInt(G(a, "ts")) || G(a, "sig") is not string sig) return "malformed confirmation";
        var key = ((L)pins["keys"]!).Select(x => x as D).FirstOrDefault(x => x != null && G(x, "kid") as string == kid);
        if (key == null) return $"no pinned key '{kid}'";
        if (!((L)key["roles"]!).Contains("reviewer")) return $"key '{kid}' does not hold the reviewer role";
        var ts = I(a["ts"]);
        if ((key.ContainsKey("not_before") && ts < I(key["not_before"])) || (key.ContainsKey("not_after") && ts > I(key["not_after"]))) return "the confirmation time is outside the key validity";
        var body = new D
        {
            ["def_digest"] = a["def_digest"], ["traits_digest"] = a["traits_digest"], ["facts_digest"] = a["facts_digest"], ["final_traits"] = ToL(SortUniq(final)),
            ["dismissed"] = new L(dm.Cast<D>().OrderBy(x => (string)x["trait"]!, StringComparer.Ordinal).Select(x => (object?)new D { ["trait"] = x["trait"], ["reason"] = x["reason"] })),
            ["reviewer_kid"] = kid, ["ts"] = a["ts"],
        };
        return IntentJs.VerifyEd(key["pk"], IntentJs.Message(ReviewDomain, body), sig) ? null : "the confirmation signature is invalid";
    }

    /// <summary>Null iff the DEF carries a valid human confirmation: state <c>confirmed</c>, an attestation bound to this def digest and an accepted
    /// registry digest whose final traits are the def's declared traits, signed by a pinned reviewer key. Else the reason (the def is unconfirmed).</summary>
    public static string? AttestationError(D def, Dictionary<string, D> reg, object? pins)
    {
        try
        {
            if (pins is not D p) return "no reviewer keys are pinned";
            var pe = ReviewerPinsError(p);
            if (pe != null) return "bad pins: " + pe;
            if (G(G(def, "review"), "state") as string != "confirmed") return "review.state is not confirmed";
            if (G(G(def, "review"), "attestation") is not D a) return "a confirmed def carries an attestation";
            if (G(a, "sig") is not string) return "the attestation is unsigned";
            if (G(a, "def_digest") as string != DefDigest(def)) return "the def changed after it was reviewed";
            if (!DigestAccepted(G(a, "traits_digest"), reg, p)) return "the trait registry changed since the review";
            if (G(a, "final_traits") is not L ft || ft.Any(x => x is not string)) return "malformed attestation";
            var final = ft.Cast<string>().ToList();
            if (!SortUniq(final).SequenceEqual(SortUniq(Strs(G(def, "traits"))))) return "the attested final traits are not the def's declared traits";
            return ReviewSigError(a, p, final);
        }
        catch (Exception e) { return "malformed attestation: " + e.Message; }
    }

    /// <summary>Null iff the schema VERB's <c>confirmation</c> counts: it covers exactly the verb's <c>def</c> digest and an accepted registry digest, every
    /// final trait is carried by the verb, and a pinned reviewer key signed it. Else the reason (the verb is unconfirmed).</summary>
    public static string? VerbConfirmationError(D v, Dictionary<string, D> reg, object? pins)
    {
        try
        {
            if (pins is not D p) return "no reviewer keys are pinned";
            var pe = ReviewerPinsError(p);
            if (pe != null) return "bad pins: " + pe;
            if (!v.TryGetValue("confirmation", out var ao)) return "no confirmation";
            if (ao is not D a) return "confirmation is not an object";
            if (G(a, "sig") is not string) return "the confirmation is unsigned";
            if (G(v, "def") is not string vd || G(a, "def_digest") as string != vd) return "the confirmation covers a different def digest";
            if (!DigestAccepted(G(a, "traits_digest"), reg, p)) return "the confirmation was made against a different trait registry";
            if (G(a, "facts_digest") is not string fd || fd != FactsDigest(v)) return "the verb facts differ from the facts the reviewer confirmed";
            if (G(a, "final_traits") is not L ft || G(a, "dismissed") is not L) return "malformed confirmation";
            var carried = G(v, "traits") is L tl ? tl.OfType<string>().ToHashSet() : new HashSet<string>();
            if (ft.Any(x => x is not string xs || !carried.Contains(xs))) return "the verb does not carry every trait the reviewer signed";
            return ReviewSigError(a, p, ft.Cast<string>().ToList());
        }
        catch (Exception e) { return "malformed confirmation: " + e.Message; }
    }

    /// <summary>Every trait id of the registry (core and custom), sorted: what an unconfirmed action is treated as having.</summary>
    public static List<string> TopTraits(Dictionary<string, D> reg) => SortUniq(reg.Keys);

    /// <summary>Declared + implied-by-facts traits: what the def would have if a reviewer signed it as it stands. A hint; never enforcement.</summary>
    public static List<string> HintTraits(D d)
    {
        var n = Normalize(d);
        var ps = ParamsOf(n);
        return SortUniq(Strs(n["traits"]).Concat(ImpliedFromFacts(Strs(n["effects"]), ps.Values, (string)((D)n["resource"]!)["scope"]!, WorstReversibility(n["reversibility"], ps))));
    }

    /// <summary>T(d), the EFFECTIVE traits: <see cref="HintTraits"/> iff the def has a valid signed confirmation under <paramref name="pins"/>, else <see cref="TopTraits"/>.</summary>
    public static List<string> TraitsOf(D d, Dictionary<string, D> reg, object? pins = null) => AttestationError(d, reg, pins) == null ? HintTraits(d) : TopTraits(reg);

    public static D DeclProfile(D d)
    {
        var n = Normalize(d);
        var ps = ParamsOf(n);
        bool critical = ps.Values.Any(p => SensRank[EffectiveParamSensitivity(p)] >= SensRank["critical"]);
        return Profile(critical ? 2 : IsReadOnly(Strs(n["effects"])) ? 0 : 1, WorstReversibility(n["reversibility"], ps), I(((D)n["blast"]!)["ppm"]), 0, null, Strs(n["context"]));
    }

    /// <summary>{confirmed, traits, closure, floor, decl, eff}: eff = decl join F(T(d)); an unconfirmed def has every trait of the registry.</summary>
    public static D Effective(D d, Dictionary<string, D> reg, object? pins = null)
    {
        var confirmed = AttestationError(d, reg, pins) == null;
        var tr = confirmed ? HintTraits(d) : TopTraits(reg);
        var fl = FloorOf(reg, tr);
        var dp = DeclProfile(d);
        return new D { ["confirmed"] = confirmed, ["traits"] = ToL(tr), ["closure"] = ToL(Closure(reg, tr)), ["floor"] = fl, ["decl"] = dp, ["eff"] = Join(dp, fl) };
    }

    // ---- rule 22: whole-document integrity of the carried traits and floors ----------------------------------------------------------
    const string Pfx = "action.params.";
    static string Tail(string path) => path.Length >= Pfx.Length ? path.Substring(Pfx.Length) : "";

    /// <summary>Recompute from the verb's own visible facts that its <c>traits</c> contain every implied trait and that its <c>floors</c> are at least the
    /// floor of the traits' closure and of the declared reversibility. Null = consistent; else "&lt;code&gt;: &lt;reason&gt;". Never throws.</summary>
    public static string? SchemaVerbFloorError(D v, Dictionary<string, D> reg, object? pins = null)
    {
        try
        {
            if (G(v, "effects") is not L effects || G(v, "traits") is not L traits || !v.ContainsKey("floors")) return "schema_floor_forged: not a v2 verb";
            var ps = ((D)v["params"]!).Select(kv => (Name: Tail(kv.Key), P: (D)kv.Value!)).ToList();
            var byName = new Dictionary<string, D>();
            foreach (var (name, p) in ps)
            {
                var e = new D { ["type"] = G(p, "type") };
                if (p.ContainsKey("values")) e["values"] = p["values"];
                byName[name] = e;
            }
            object? decl;
            if (G(v, "reversibility_by") is D rb && rb.Count > 0)
            {
                var dd = new D { ["by"] = Tail((string)rb["param"]!), ["map"] = rb["map"] };
                if (rb.ContainsKey("default")) dd["default"] = rb["default"];
                decl = dd;
            }
            else decl = v.ContainsKey("reversibility") ? v["reversibility"] : G(v, "kind") as string == "read" ? "reversible" : "irreversible";
            var worst = WorstReversibility(decl, byName);
            var implied = ImpliedFromFacts(effects.Select(e => (string)e!), ps.Select(x => x.P), null, worst);
            var tset = Strs(traits);
            foreach (var t in implied) if (!tset.Contains(t)) return $"schema_traits_forged: missing implied trait {t}";
            // unconfirmed means maximally dangerous: no valid signed confirmation => the verb must carry EVERY trait of the registry
            if (VerbConfirmationError(v, reg, pins) != null)
                foreach (var t in TopTraits(reg)) if (!tset.Contains(t)) return $"schema_traits_forged: unconfirmed action must carry every trait (missing {t})";
            var fl = FloorOf(reg, traits);
            var floors = (D)v["floors"]!;
            if (!Leq(fl, floors)) return "schema_floor_forged: floors are below the floor of the carried traits";
            if (RevRank.GetValueOrDefault(floors["rev"] as string ?? "", -1) < RevRank.GetValueOrDefault(worst, -1)) return "schema_floor_forged: floors.rev is below the declared reversibility";
            return null;
        }
        catch (ActionKitError e) { return $"{e.Code}: {e.Message}"; }
        catch (Exception e) { return "schema_floor_forged: " + e.Message; }
    }

    /// <summary>Core + the document's own <c>trait_defs</c> (checked); when it carries <c>traits_digest</c> the registry must hash to it.</summary>
    public static Dictionary<string, D> RegistryOfSchema(D doc)
    {
        var reg = G(doc, "trait_defs") is L td && td.Count > 0 ? ExtendRegistry(CoreRegistry, td) : CoreRegistry;
        if (doc.ContainsKey("traits_digest") && doc["traits_digest"] as string != TraitsDigest(reg)) throw new ActionKitError("traits_digest_mismatch", "the document's traits_digest does not match its trait registry");
        return reg;
    }

    /// <summary>Rule 22's integrity half for a whole v2 document. Null = consistent. Never throws.</summary>
    public static string? SchemaFloorError(D doc, object? pins = null)
    {
        try
        {
            var reg = RegistryOfSchema(doc);
            foreach (var v in (L)doc["verbs"]!)
            {
                var e = SchemaVerbFloorError((D)v!, reg, pins);
                if (e != null) return $"{G(v, "verb")}: {e}";
            }
            return null;
        }
        catch (ActionKitError e) { return $"{e.Code}: {e.Message}"; }
        catch (Exception e) { return "bad_registry: " + e.Message; }
    }
}
