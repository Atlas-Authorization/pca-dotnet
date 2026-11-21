// The wallet side of the PCA Intent Layer v2: the principal-signed answer, friction tiers scaled by harm, cell coordinates over the
// wallet's own outcome space, the statistics behind the noise estimates, attention canaries and the approval-fatigue model.
// Values are JSON trees (Dictionary / List / Num / string / bool / null); doubles are binary64 in the reference's operation order.
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.IntentPkg;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Wallet;

/// <summary>A refusal the reference raises as an Error.</summary>
public sealed class WalletException(string message) : Exception(message);

public static class WalletCore
{
    public const string IntentAnswerSigDomain = "atlas-pca/intent-obs/v2\0";
    public const string IntentAnswerRefDomain = "atlas-pca/intent-answer-ref/v1";
    public const string IntentTypedDomain = "atlas-pca/intent-typed/v1";
    public const string IntentDeviceChallengeDomain = "atlas-pca/intent-device/v1";
    public const string IntentActionDomain = "atlas-pca/intent-action/v1";
    public const int MinHoldMs = 2000;

    public static readonly string[] FrictionOrder = { "tap", "hold", "typed", "device" };
    public static readonly string[] ProvenanceOrder = { "trusted", "first_party", "tool", "web", "agent" };
    public static D DefaultFrictionThresholds() => new() { ["hTap"] = new Num("5"), ["hDevice"] = new Num("100000") };
    public static D EmptyNoise() => new() { ["falseYes"] = new Num("0"), ["correctNo"] = new Num("0"), ["falseNo"] = new Num("0"), ["correctYes"] = new Num("0") };
    public static D NoisePrior() => new() { ["a"] = new Num("1"), ["b"] = new Num("9") };
    public static D DefaultFatigue() => new()
    {
        ["betaF"] = new Num("0.005"), ["etaStop"] = new Num("0.15"), ["deltaC"] = new Num("0.05"), ["freezeOn"] = "mean", ["assumeNoiseFree"] = false, ["delta"] = new Num("0.05"),
    };

    // ---- small JS helpers ----
    static readonly object U = JsX.Undef;
    internal static object? N(double d) => IntentOmega.N(d);
    internal static double Dn(object? o) => IntentJs.NumOf(o) ?? double.NaN;
    internal static bool IsNum(object? o) => IntentJs.NumOf(o) != null;
    internal static bool IsFin(object? o) => IntentJs.NumOf(o) is double d && double.IsFinite(d);
    internal static bool IsIntegral(object? o) => IntentJs.NumOf(o) is double d && double.IsFinite(d) && d == Math.Floor(d);
    internal static bool IsNegZero(object? o) => IntentJs.NumOf(o) is double d && IntentJs.IsNegZero(d);
    /// <summary>Property read of a JSON object; the sentinel for a missing member or a non-object.</summary>
    internal static object? G(object? o, string k) => o is D m && m.TryGetValue(k, out var v) ? v : U;
    internal static bool Has(object? o, string k) => o is D m && m.ContainsKey(k);
    internal static object? Nul(object? v) => ReferenceEquals(v, U) ? null : v;
    internal static bool IsObj(object? v) => v is D;

    /// <summary>Object.entries of a JSON value (strings and arrays yield their indices; null throws).</summary>
    internal static List<(string K, object? V)> Entries(object? v)
    {
        if (v == null || ReferenceEquals(v, U)) throw JsX.TypeError("Cannot convert undefined or null to object");
        return JsX.Keys(v).Select(k => (k, JsX.ValueOf(v, k))).ToList();
    }

    // ---- friction (wire.ts, friction.ts) ----
    public static bool IsFrictionTier(object? x) => x is string s && Array.IndexOf(FrictionOrder, s) >= 0;
    public static int FrictionRank(object? t) => t is string s ? Array.IndexOf(FrictionOrder, s) : -1;
    public static string MaxFriction(params object?[] ts)
    {
        var best = "tap";
        foreach (var t in ts) if (FrictionRank(t) > FrictionRank(best)) best = (string)t!;
        return best;
    }
    public static bool SatisfiesTier(object? given, object? required) => FrictionRank(given) >= FrictionRank(required);
    public static bool IsProvenanceLevel(object? x) => x is string s && Array.IndexOf(ProvenanceOrder, s) >= 0;

    /// <summary>The least trusted level of a set; "agent" for an empty or unknown set (fail closed).</summary>
    public static string WorstProvenance(object? levels)
    {
        IEnumerable<object?> items = levels switch
        {
            L l => l,
            string s => s.Select(c => (object?)c.ToString()),
            _ => throw JsX.TypeError("levels is not iterable"),
        };
        int best = -1;
        foreach (var lv in items)
        {
            if (!IsProvenanceLevel(lv)) return "agent";
            best = Math.Max(best, Array.IndexOf(ProvenanceOrder, (string)lv!));
        }
        return best < 0 ? "agent" : ProvenanceOrder[best];
    }

    static double ThNum(D th, string k) => th.TryGetValue(k, out var v) ? Dn(v) : double.NaN;

    public static D FrictionFor(D inp, D? th = null)
    {
        th ??= DefaultFrictionThresholds();
        var harmO = G(inp, "expectedHarm");
        if (!(IsFin(harmO) && Dn(harmO) >= 0)) return new D { ["tier"] = "device", ["rules"] = new L { "harm-unknown" } };
        double harm = Dn(harmO);
        var rules = new L();
        string tier = "tap";
        void Raise(object? t, string why)
        {
            if (FrictionRank(t) >= FrictionRank(tier)) rules.Add(why);
            tier = MaxFriction(tier, t);
        }
        var rev = G(inp, "reversibility") as string;
        if (rev == "rate_limited") Raise("hold", "rate-limited");
        if (harm >= ThNum(th, "hTap")) Raise("hold", "harm>=h_tap");
        if (rev == "irreversible") Raise("typed", "irreversible");
        var prov = G(inp, "provenance");
        bool taintedCritical = false;
        if (prov != null && !ReferenceEquals(prov, U))
        {
            if (prov is not L pl) throw JsX.TypeError("provenance is not iterable");
            foreach (var p in pl)
            {
                if (p == null) throw JsX.TypeError("cannot read properties of null");
                if (G(p, "sensitivity") is string se && se == "critical" && (WorstProvenance(G(p, "levels")) is "web" or "agent")) taintedCritical = true;
            }
        }
        if (taintedCritical) Raise("typed", "tainted-critical");
        if (JsX.Truthy(Nul(G(inp, "widensCriticalIdentity"))) && rev == "irreversible") Raise("device", "critical-irreversible");
        if (harm >= ThNum(th, "hDevice")) Raise("device", "harm>=h_device");
        if (JsX.Truthy(Nul(G(inp, "singleSource")))) Raise(FrictionOrder[Math.Min(FrictionOrder.Length - 1, FrictionRank(tier) + 1)], "single-source");
        if (Has(inp, "siteMin")) Raise(inp["siteMin"], "site-minimum");
        return new D { ["tier"] = tier, ["rules"] = rules };
    }

    // ---- helpers (wire.ts) ----
    public static bool IsB64u32(object? v) => Pca.B64uDecode(v, 32) != null;
    public static string? CoordsError(object? c) => Signers.CellCoordsError(c);

    /// <summary>The action digest of an attempted action (what intent_required.action_digest and a JIT consent bind to).</summary>
    public static string PcaActionDigest(object? a)
    {
        var act = new D();
        foreach (var (k, v0) in new (string, object?)[]
        {
            ("verb", G(a, "verb")), ("resource", G(a, "resource")),
            ("params_digest", Pca.ParamsDigest(Nul(G(a, "params")))), ("reversibility_class", G(a, "reversibility_class")),
        })
        {
            if (ReferenceEquals(v0, U)) throw new WalletException("canonicalize: undefined");
            act[k] = v0;
        }
        return Pca.HashCanonical(new D { ["d"] = IntentActionDomain, ["action"] = act });
    }

    /// <summary>The default projection of an attempted action onto Omega paths: the resource and every scalar param.</summary>
    public static D ActionValuesOf(object? a)
    {
        var values = new D();
        var res = G(a, "resource");
        if (!ReferenceEquals(res, U)) values["action.resource"] = res;
        foreach (var (k, v) in Entries(G(a, "params")))
            if (v is string || IsFin(v)) values["action.params." + k] = v;
        var o = new D { ["values"] = values };
        var verb = G(a, "verb");
        if (!ReferenceEquals(verb, U)) o["verb"] = verb;
        // the reference builds {verb?, values}: verb first
        if (o.ContainsKey("verb")) return new D { ["verb"] = o["verb"], ["values"] = values };
        return o;
    }

    // ---- the signed answer ----
    static readonly string[] AnsKeys = { "v", "kind", "map_digest", "session", "question_id", "verb", "cell", "y", "partial", "source", "observed_at", "ux", "signer", "alg", "sig" };
    static readonly string[] UxKeys = { "tier", "rendered_digest", "typed_digest", "hold_ms", "webauthn", "canary", "action_digest", "consent_for_action" };
    static readonly string[] WaKeys = { "credential_id", "authenticator_data", "client_data_json", "signature" };
    static readonly Regex QidRe = new(@"\A[A-Za-z0-9_-]{1,64}\z", RegexOptions.CultureInvariant);

    static bool NumEq(object? v, double n) => IntentJs.NumOf(v) is double d && d == n;
    static string? OnlyKeys(object? o, string[] allowed)
    {
        foreach (var k in ((D)o!).Keys) if (Array.IndexOf(allowed, k) < 0) return $"unknown member \"{k}\"";
        return null;
    }
    static bool IsInt(object? v) => IntentJs.IsInt(v);

    static string? PartialError(object? p)
    {
        if (p is not D m || G(p, "path") is not string path || path.Length == 0) return "partial.path must be a non-empty string";
        var keys = m.Keys.Where(k => k != "path").ToList();
        if (keys.Count != 1) return "partial must carry exactly one of upTo / from / except / notFor";
        var k0 = keys[0]; var v = m[k0];
        if ((k0 == "upTo" || k0 == "from") && !IsInt(v)) return $"partial.{k0} must be an integer";
        if (k0 == "except" && !(v is L e && e.Count > 0 && e.All(IsInt))) return "partial.except must be a non-empty integer array";
        if (k0 == "notFor" && !(v is L n && n.Count > 0 && n.All(x => x is string s && s.Length > 0))) return "partial.notFor must be a non-empty string array";
        if (k0 != "upTo" && k0 != "from" && k0 != "except" && k0 != "notFor") return $"unknown partial member \"{k0}\"";
        return null;
    }

    public static string? AnswerShapeError(object? a)
    {
        if (a is not D am) return "not an object";
        if (OnlyKeys(a, AnsKeys) is { } extra) return extra;
        if (!NumEq(G(a, "v"), 2) || !(G(a, "kind") is string kd && kd == "pca-intent-observation")) return "not a pca-intent-observation v2";
        foreach (var k in new[] { "map_digest", "session", "signer" })
            if (!IsB64u32(G(a, k))) return $"{k} is not canonical base64url (32 bytes)";
        if (G(a, "question_id") is not string qid || !QidRe.IsMatch(qid)) return "question_id must match [A-Za-z0-9_-]{1,64}";
        if (G(a, "verb") is not string vb || vb.Length == 0) return "verb must be a non-empty string";
        if (CoordsError(Nul(G(a, "cell"))) is { } ce) return "cell: " + ce;
        var y = G(a, "y");
        if (!(NumEq(y, 0) || NumEq(y, 1))) return "y must be 0 or 1";
        if (am.ContainsKey("partial"))
        {
            if (PartialError(am["partial"]) is { } pe) return pe;
            if (!NumEq(y, 1)) return "a partial answer carries y = 1 (yes for the part)";
        }
        if (!(G(a, "source") is string src && (src == "elicitation" || src == "clarification"))) return "source must be elicitation or clarification";
        var obs = G(a, "observed_at");
        if (!IsInt(obs) || Dn(obs) < 0) return "observed_at must be a non-negative safe integer";
        if (!(G(a, "alg") is string alg && alg == "ed25519")) return "alg must be ed25519";
        var ux = G(a, "ux");
        if (ux is not D um) return "ux must be an object";
        if (OnlyKeys(ux, UxKeys) is { } ue) return "ux: " + ue;
        if (!IsFrictionTier(G(ux, "tier"))) return "ux.tier is not a friction tier";
        if (!IsB64u32(G(ux, "rendered_digest"))) return "ux.rendered_digest is not canonical base64url (32 bytes)";
        if (G(ux, "canary") is not bool canary) return "ux.canary must be a boolean";
        if (um.ContainsKey("typed_digest") && !IsB64u32(um["typed_digest"])) return "ux.typed_digest is not canonical base64url (32 bytes)";
        if (um.ContainsKey("hold_ms") && !(IsInt(um["hold_ms"]) && Dn(um["hold_ms"]) >= 0)) return "ux.hold_ms must be a non-negative integer";
        if (um.ContainsKey("action_digest") && !IsB64u32(um["action_digest"])) return "ux.action_digest is not canonical base64url (32 bytes)";
        if (um.ContainsKey("consent_for_action") && um["consent_for_action"] is not bool) return "ux.consent_for_action must be a boolean";
        bool consent = G(ux, "consent_for_action") is true;
        if (consent && (!um.ContainsKey("action_digest") || !NumEq(y, 1) || am.ContainsKey("partial"))) return "consent_for_action needs action_digest and a plain yes";
        if (consent && canary) return "a canary never consents to an action";
        if (um.ContainsKey("webauthn"))
        {
            var wa = um["webauthn"];
            if (wa is not D || OnlyKeys(wa, WaKeys) != null || !WaKeys.All(k => G(wa, k) is string)) return "ux.webauthn is malformed";
        }
        if (NumEq(y, 1) && !canary)
        {
            var tier = (string)um["tier"]!;
            if (tier == "hold" && !(IsInt(G(ux, "hold_ms")) && Dn(G(ux, "hold_ms")) >= MinHoldMs)) return $"hold tier needs hold_ms >= {MinHoldMs}";
            if (tier == "typed" && !um.ContainsKey("typed_digest")) return "typed tier needs typed_digest";
            if (tier == "device" && !um.ContainsKey("webauthn")) return "device tier needs a WebAuthn assertion";
        }
        return null;
    }

    static D AnswerBody(D a)
    {
        var body = new D();
        foreach (var k in new[] { "v", "kind", "map_digest", "session", "question_id", "verb", "cell", "y", "partial", "source", "observed_at", "ux", "signer", "alg" })
            if (a.TryGetValue(k, out var v)) body[k] = v;
        return (D)Plain(IntentJs.Normalize(body))!;
    }

    /// <summary>The reference's <c>JSON.parse(JSON.stringify(v))</c> of the answer body: a negative zero comes back as 0.</summary>
    static object? Plain(object? v) => v switch
    {
        Num n when IntentJs.NumOf(n) is double d && IntentJs.IsNegZero(d) => new Num("0"),
        D m => m.ToDictionary(e => e.Key, e => Plain(e.Value)),
        L l => l.Select(Plain).ToList(),
        _ => v,
    };

    static byte[] DomainMessage(string domain, object? body) => Pca.Cat(Encoding.UTF8.GetBytes(domain), Pca.Canon(body));

    /// <summary>Wallet side: sign the principal's answer with the principal key (Ed25519, domain-separated, over the canonical body).</summary>
    public static D SignIntentAnswer(D a, byte[] principalSecret)
    {
        using var key = EdKey.FromSeed(principalSecret);
        var b = new D(a) { ["v"] = new Num("2"), ["kind"] = "pca-intent-observation", ["signer"] = key.Id, ["alg"] = "ed25519" };
        var body = AnswerBody(b);
        if (AnswerShapeError(body) is { } bad) throw new WalletException("signIntentAnswer: " + bad);
        var o = new D(body) { ["sig"] = Pca.B64u(key.Sign(DomainMessage(IntentAnswerSigDomain, body))) };
        return o;
    }

    /// <summary>Verify a signed answer; <paramref name="principals"/> restricts the signer. Never throws.</summary>
    public static D VerifyIntentAnswer(object? a, IReadOnlyCollection<string>? principals = null)
    {
        D Fail(string r) => new() { ["ok"] = false, ["reason"] = r };
        try
        {
            if (AnswerShapeError(a) is { } bad) return Fail(bad);
            var am = (D)a!;
            if (principals != null && !principals.Contains((string)am["signer"]!)) return Fail("signer is not a principal of the session");
            if (G(a, "sig") is not string sig) return Fail("bad signature");
            var pk = Pca.B64uDecode(am["signer"], 32); var sg = Pca.B64uDecode(sig, 64);
            if (pk == null || sg == null || !Pca.VerifyEd25519Strict(pk, DomainMessage(IntentAnswerSigDomain, AnswerBody(am)), sg)) return Fail("bad signature");
            return new D { ["ok"] = true };
        }
        catch (Exception e) { return Fail("malformed answer: " + e.Message); }
    }

    public static string AnswerRef(object? a) => Pca.HashCanonical(new D { ["d"] = IntentAnswerRefDomain, ["a"] = a });
    public static string TypedDigest(object? questionId, object? normalizedValue) => Pca.HashCanonical(new D { ["d"] = IntentTypedDomain, ["q"] = questionId, ["v"] = normalizedValue });

    /// <summary>The 32-byte WebAuthn challenge of a device-tier answer: binds the question, the card the human saw, y and the action.</summary>
    public static string DeviceChallenge(object? questionId, object? renderedDigest, object? y, object? actionDigest = null) =>
        Pca.HashCanonical(new D { ["d"] = IntentDeviceChallengeDomain, ["q"] = questionId, ["r"] = renderedDigest, ["y"] = y, ["a"] = actionDigest });

    // ---- cell coordinates <-> the wallet's own Omega (box.ts) ----
    static readonly Regex Acc = new(@"\Aenv\.acc\.([A-Za-z0-9_.-]+)\.post\z", RegexOptions.CultureInvariant);
    static readonly Regex Mon = new(@"\Aenv\.mon\.([A-Za-z0-9_.-]+)\.state\z", RegexOptions.CultureInvariant);
    static readonly Regex Prov = new("\\Aenv\\.prov\\.([^\n\r\u2028\u2029]+)\\z", RegexOptions.CultureInvariant);
    static readonly Regex World = new(@"\Aenv\.world\.([A-Za-z0-9_.-]+)\z", RegexOptions.CultureInvariant);

    public static string CoordKeyOf(string path)
    {
        Match m;
        if ((m = Acc.Match(path)).Success) return m.Groups[1].Value;
        if ((m = Mon.Match(path)).Success) return "mon:" + m.Groups[1].Value;
        if ((m = Prov.Match(path)).Success) return "prov:" + m.Groups[1].Value;
        if ((m = World.Match(path)).Success) return m.Groups[1].Value;
        return path;
    }

    public static string CatLabel(IntentOmega.CatDim d, int i) => d.Values[i].Value;

    /// <summary>The outcome of <see cref="ResolveCoords"/>: a box of cells of the verb's space, or a reason.</summary>
    public sealed record Resolved(bool Ok, IntentOmega.VerbSpace? Vs, List<List<int>>? Box, string? Reason);

    /// <summary>Resolve coordinates to a box of cells of the verb's space. Every dimension must be named exactly once; anything the wallet cannot resolve exactly is refused.</summary>
    public static Resolved ResolveCoords(IntentOmega.Omega omega, object? verb, object? coords)
    {
        var vs = omega.Verbs.Find(v => verb is string s && s == v.Verb);
        if (vs == null) return new(false, null, null, $"verb {JsX.Str(verb)} is not in the wallet's outcome space");
        var byKey = new Dictionary<string, int>();
        for (int k = 0; k < vs.Dims.Count; k++) { byKey[vs.Dims[k].Path] = k; byKey[CoordKeyOf(vs.Dims[k].Path)] = k; }
        var named = new HashSet<int>();
        foreach (var (key, _) in Entries(coords))
        {
            if (!byKey.TryGetValue(key, out var k)) return new(false, null, null, $"unknown dimension {key}");
            if (!named.Add(k)) return new(false, null, null, $"dimension {vs.Dims[k].Path} is named twice");
        }
        var box = new List<List<int>>();
        foreach (var d in vs.Dims)
        {
            var c = G(coords, d.Path);
            if (ReferenceEquals(c, U) || c == null) c = G(coords, CoordKeyOf(d.Path));
            if (ReferenceEquals(c, U)) return new(false, null, null, $"coordinates leave out dimension {d.Path}");
            if (c == null) throw JsX.TypeError("Cannot read properties of null");
            if (d is IntentOmega.NumDim nd)
            {
                if (!(c is L cl && cl.Count == 2 && IsNum(cl[0]) && IsNum(cl[1]))) return new(false, null, null, $"dimension {d.Path} is numeric: expected an index range");
                double lo = Dn(cl[0]), hi = Dn(cl[1]);
                if (!(IsIntegral(cl[0]) && IsIntegral(cl[1]) && !IsNegZero(cl[0]) && !IsNegZero(cl[1]) && lo >= 0 && lo <= hi && hi < IntentOmega.NumCells(nd).Count))
                    return new(false, null, null, $"index range of {d.Path} is out of range");
                var r = new List<int>();
                for (long i = (long)lo; i <= (long)hi; i++) r.Add((int)i);
                box.Add(r);
            }
            else
            {
                var cd = (IntentOmega.CatDim)d;
                if (c is not L labels) throw JsX.TypeError("c.every is not a function");
                if (!labels.All(x => x is string)) return new(false, null, null, $"dimension {d.Path} is categorical: expected a value set");
                var ids = new SortedSet<int>();
                foreach (string label in labels)
                {
                    var hits = new List<int>();
                    for (int j = 0; j < cd.Values.Count; j++) if (cd.Values[j].Value == label) hits.Add(j);
                    if (hits.Count == 0) return new(false, null, null, $"unknown value {JsJson.Quote(label)} for {d.Path}");
                    if (hits.Count > 1) return new(false, null, null, $"value {JsJson.Quote(label)} names two cells of {d.Path}");
                    ids.Add(hits[0]);
                }
                box.Add(ids.ToList());
            }
        }
        return new(true, vs, box, null);
    }

    /// <summary>The coordinates of a box (the inverse of ResolveCoords; numeric sides must be contiguous).</summary>
    public static D CoordsOfBox(IntentOmega.VerbSpace vs, IReadOnlyList<IReadOnlyList<int>> box)
    {
        var o = new D();
        for (int k = 0; k < vs.Dims.Count; k++)
        {
            var d = vs.Dims[k]; var ids = box[k];
            if (d is IntentOmega.NumDim)
            {
                int lo = ids.Min(), hi = ids.Max();
                if (hi - lo + 1 != ids.Count) throw new WalletException($"coordsOfBox: numeric side of {d.Path} is not contiguous");
                o[d.Path] = new L { new Num(lo.ToString(CultureInfo.InvariantCulture)), new Num(hi.ToString(CultureInfo.InvariantCulture)) };
            }
            else o[d.Path] = ids.Select(i => (object?)CatLabel((IntentOmega.CatDim)d, i)).ToList();
        }
        return o;
    }

    public static D CoordsOfCell(IntentOmega.VerbSpace vs, IReadOnlyList<int> idx) => CoordsOfBox(vs, idx.Select(i => (IReadOnlyList<int>)new[] { i }).ToList());

    public static bool CellInBox(IReadOnlyList<IReadOnlyList<int>> box, IReadOnlyList<int> idx)
    {
        if (box.Count != idx.Count) return false;
        for (int k = 0; k < box.Count; k++) if (!box[k].Contains(idx[k])) return false;
        return true;
    }

    public static List<List<int>> BoxCells(IReadOnlyList<IReadOnlyList<int>> box)
    {
        var o = new List<List<int>> { new() };
        foreach (var ids in box) o = o.SelectMany(pre => ids.Select(i => new List<int>(pre) { i })).ToList();
        return o;
    }

    public static double BoxSize(IReadOnlyList<IReadOnlyList<int>> box) { double n = 1; foreach (var ids in box) n *= ids.Count; return n; }

    /// <summary>The cell of a concrete action in the wallet's Omega; null when it falls outside it (fail closed).</summary>
    public static (IntentOmega.VerbSpace Vs, int[] Idx)? CellOfAction(IntentOmega.Omega omega, object? a)
    {
        var verb = G(a, "verb");
        var vs = omega.Verbs.Find(v => verb is string s && s == v.Verb);
        if (vs == null) return null;
        var values = G(a, "values");
        if (values is not D vm) { if (values is L) return null; throw JsX.TypeError("Cannot use 'in' operator"); }
        foreach (var d in vs.Dims) if (!vm.ContainsKey(d.Path)) return null;
        var idx = IntentOmega.CellOf(vs, new IntentOmega.Outcome(vs.Verb, vm.ToDictionary(e => e.Key, e => IntentOmega.Value(e.Value))));
        return idx == null ? null : (vs, idx);
    }

    public static double FlatIndex(IntentOmega.VerbSpace vs, IReadOnlyList<int> idx)
    {
        double f = 0;
        for (int k = 0; k < vs.Dims.Count; k++) f = f * IntentOmega.CellCount(vs.Dims[k]) + idx[k];
        return f;
    }

    // ---- stats (stats.ts) ----
    static readonly double[] Lanczos =
    {
        676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059, 12.507343278686905,
        -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7,
    };

    public static double LnGamma(double x)
    {
        if (x < 0.5) return IntentMath.Log(Math.PI / Math.Sin(Math.PI * x)) - LnGamma(1 - x);
        double z = x - 1, a = 0.99999999999980993, t = z + 7.5;
        for (int i = 0; i < Lanczos.Length; i++) a += Lanczos[i] / (z + i + 1);
        return 0.5 * IntentMath.Log(2 * Math.PI) + (z + 0.5) * IntentMath.Log(t) - t + IntentMath.Log(a);
    }

    /// <summary>The continued fraction of I_x(a, b) (modified Lentz; a zero denominator is replaced by 1e-300, never divided by).</summary>
    public static double Betacf(double a, double b, double x)
    {
        const double tiny = 1e-300;
        double qab = a + b, qap = a + 1, qam = a - 1, c = 1, d = 1 - qab * x / qap;
        if (Math.Abs(d) < tiny) d = tiny;
        d = 1 / d;
        double h = d;
        for (int m = 1; m <= 300; m++)
        {
            int m2 = 2 * m;
            double aa = m * (b - m) * x / ((qam + m2) * (a + m2));
            d = 1 + aa * d;
            if (Math.Abs(d) < tiny) d = tiny;
            c = 1 + aa / c;
            if (Math.Abs(c) < tiny) c = tiny;
            d = 1 / d;
            h *= d * c;
            aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
            d = 1 + aa * d;
            if (Math.Abs(d) < tiny) d = tiny;
            c = 1 + aa / c;
            if (Math.Abs(c) < tiny) c = tiny;
            d = 1 / d;
            double dl = d * c;
            h *= dl;
            if (Math.Abs(dl - 1) < 1e-15) break;
        }
        return h;
    }

    /// <summary>Regularized incomplete beta I_x(a, b), a, b &gt; 0, x in [0, 1].</summary>
    public static double BetaInc(double x, double a, double b)
    {
        if (!(a > 0 && b > 0)) throw new WalletException("betaInc: a and b must be > 0");
        if (x <= 0) return 0;
        if (x >= 1) return 1;
        double lbt = LnGamma(a + b) - LnGamma(a) - LnGamma(b) + a * IntentMath.Log(x) + b * IntentMath.Log(1 - x);
        double bt = IntentMath.Exp(lbt);
        if (x < (a + 1) / (a + b + 2)) return bt * Betacf(a, b, x) / a;
        return 1 - bt * Betacf(b, a, 1 - x) / b;
    }

    /// <summary>The q-quantile of Beta(a, b) by bisection (200 steps).</summary>
    public static double BetaQuantile(double q, double a, double b)
    {
        if (!(q >= 0 && q <= 1)) throw new WalletException("betaQuantile: q must be in [0, 1]");
        if (q == 0) return 0;
        if (q == 1) return 1;
        double lo = 0, hi = 1;
        for (int i = 0; i < 200; i++)
        {
            double mid = (lo + hi) / 2;
            if (BetaInc(mid, a, b) < q) lo = mid; else hi = mid;
        }
        return hi;
    }

    /// <summary>Binary entropy in bits.</summary>
    public static double BinEnt(double p)
    {
        if (p <= 0 || p >= 1) return 0;
        return -(p * Math.Log2(p) + (1 - p) * Math.Log2(1 - p));
    }

    public static double ClopperPearsonUpper(object? k, object? n, object? alpha)
    {
        if (!(IsIntegral(k) && IsIntegral(n) && Dn(k) >= 0 && Dn(n) >= 0 && Dn(k) <= Dn(n))) throw new WalletException("clopperPearsonUpper: need integers 0 <= k <= n");
        if (!(IsNum(alpha) && Dn(alpha) > 0 && Dn(alpha) < 1)) throw new WalletException("clopperPearsonUpper: alpha must be in (0, 1)");
        return IntentStats.ClopperPearsonUpper(Dn(k), Dn(n), Dn(alpha));
    }

    // ---- canaries (canary.ts) ----
    static double C(D n, string k) => n.TryGetValue(k, out var v) ? Dn(v) : double.NaN;

    /// <summary>Fold one canary answer into the counts (pure).</summary>
    public static D RecordCanary(D n, object? expected, object? y)
    {
        var o = new D(n);
        if (NumEq(expected, 0))
        {
            if (NumEq(y, 1)) o["falseYes"] = N(C(n, "falseYes") + 1); else o["correctNo"] = N(C(n, "correctNo") + 1);
        }
        else if (NumEq(y, 0)) o["falseNo"] = N(C(n, "falseNo") + 1);
        else o["correctYes"] = N(C(n, "correctYes") + 1);
        return o;
    }

    public static D EstimateNoise(D n, double deltaC = 0.05)
    {
        if (!(deltaC > 0 && deltaC < 1)) throw new WalletException("estimateNoise: deltaC must be in (0, 1)");
        double fy = C(n, "falseYes"), cn = C(n, "correctNo"), fn = C(n, "falseNo"), cy = C(n, "correctYes");
        double ap = 1 + fy, bp = 9 + cn, an = 1 + fn, bn = 9 + cy;
        double knownNo = fy + cn, knownYes = fn + cy;
        return new D
        {
            ["etaPos"] = N(ap / (ap + bp)),
            ["etaNeg"] = N(an / (an + bn)),
            ["etaPosUpper"] = N(BetaQuantile(1 - deltaC, ap, bp)),
            ["etaNegUpper"] = N(BetaQuantile(1 - deltaC, an, bn)),
            ["etaPosCP"] = N(knownNo == 0 ? 1 : ClopperPearsonUpper(N(fy), N(knownNo), N(deltaC))),
            ["etaNegCP"] = N(knownYes == 0 ? 1 : ClopperPearsonUpper(N(fn), N(knownYes), N(deltaC))),
            ["asked"] = N(knownNo + knownYes),
        };
    }

    public static string CellKey(object? verb, IEnumerable<object?> idx) =>
        JsX.Str(verb) + "|" + string.Join(",", idx.Select(i => JsX.Str(i)));
    public static string CellKey(string verb, IEnumerable<int> idx) => verb + "|" + string.Join(",", idx.Select(i => i.ToString(CultureInfo.InvariantCulture)));

    public sealed record CellRef(string Verb, int[] Idx);
    public sealed record Canary(string Verb, int[] Idx, int Expected, string Source);

    /// <summary>Cells one step outside the confirmed region in exactly one dimension (deterministic order).</summary>
    public static List<CellRef> BoundaryNeighbours(IntentOmega.Omega omega, IReadOnlyList<CellRef> confirmed)
    {
        var inside = new HashSet<string>(confirmed.Select(c => CellKey(c.Verb, c.Idx)));
        var o = new Dictionary<string, CellRef>();
        foreach (var c in confirmed)
        {
            var vs = omega.Verbs.Find(v => v.Verb == c.Verb);
            if (vs == null) continue;
            for (int k = 0; k < vs.Dims.Count; k++)
            {
                int n = IntentOmega.CellCount(vs.Dims[k]);
                var alts = vs.Dims[k] is IntentOmega.NumDim ? new List<int> { c.Idx[k] - 1, c.Idx[k] + 1 } : Enumerable.Range(0, n).ToList();
                foreach (var a in alts)
                {
                    if (a < 0 || a >= n || a == c.Idx[k]) continue;
                    var idx = (int[])c.Idx.Clone();
                    idx[k] = a;
                    var key = CellKey(c.Verb, idx);
                    if (!inside.Contains(key)) o[key] = new CellRef(c.Verb, idx);
                }
            }
        }
        return o.OrderBy(e => e.Key, StringComparer.Ordinal).Select(e => e.Value).ToList();
    }

    /// <summary>The inputs of <see cref="PickCanary"/>.</summary>
    public sealed class CanaryCtx
    {
        public required IntentOmega.Omega Omega { get; init; }
        public required IReadOnlyList<CellRef> Confirmed { get; init; }
        /// <summary>"ceiling" | "veto" | null for a cell.</summary>
        public required Func<string, int[], string?> KnownNo { get; init; }
        public required IReadOnlyList<CellRef> KnownYes { get; init; }
        public required HashSet<string> Exclude { get; init; }
        public required Func<double> Rand { get; init; }
        public double? Rho { get; init; }
        public bool LowHarmSession { get; init; }
        public double CanariesSoFar { get; init; }
    }

    /// <summary>Decide whether to insert a canary now, and which (null: none this time).</summary>
    public static Canary? PickCanary(CanaryCtx ctx)
    {
        double rho = ctx.Rho ?? 0.1;
        if (!(rho >= 0 && rho <= 1)) throw new WalletException("pickCanary: rho must be in [0, 1]");
        if (ctx.LowHarmSession && ctx.CanariesSoFar >= 1) return null;
        if (!(ctx.Rand() < rho)) return null;
        var no = new List<Canary>();
        foreach (var c in BoundaryNeighbours(ctx.Omega, ctx.Confirmed))
        {
            if (ctx.Exclude.Contains(CellKey(c.Verb, c.Idx))) continue;
            var why = ctx.KnownNo(c.Verb, c.Idx);
            if (!string.IsNullOrEmpty(why)) no.Add(new Canary(c.Verb, c.Idx, 0, why));
        }
        var yes = ctx.KnownYes.Where(c => !ctx.Exclude.Contains(CellKey(c.Verb, c.Idx))).Select(c => new Canary(c.Verb, (int[])c.Idx.Clone(), 1, "confirmed-yes")).ToList();
        if (no.Count == 0 && yes.Count == 0) return null;
        List<Canary> pool = no.Count > 0 && yes.Count > 0 ? (ctx.Rand() < 0.5 ? no : yes) : (no.Count > 0 ? no : yes);
        return pool[(int)Math.Min(pool.Count - 1, Math.Floor(ctx.Rand() * pool.Count))];
    }

    // ---- approval fatigue (fatigue.ts) ----
    const double BelowHalf = 0.5 - 1e-9;
    static double M(D m, string k) => m.TryGetValue(k, out var v) ? Dn(v) : double.NaN;

    /// <summary>eta+ under load: base + beta_f * n_recent, capped at 1/2.</summary>
    public static double EtaUnderLoad(object? bas, object? betaF, object? nRecent)
    {
        if (!(Dn(bas) >= 0 && Dn(betaF) >= 0 && IsIntegral(nRecent) && Dn(nRecent) >= 0)) throw new WalletException("etaUnderLoad: bad arguments");
        return Math.Min(0.5, Dn(bas) + Dn(betaF) * Dn(nRecent));
    }

    public static D NoiseState(D counts, object? nRecent, D? model = null)
    {
        model ??= DefaultFatigue();
        var e = EstimateNoise(counts, M(model, "deltaC"));
        double etaPos = EtaUnderLoad(e["etaPos"], model["betaF"], nRecent);
        double etaPosBar = EtaUnderLoad(e["etaPosUpper"], model["betaF"], nRecent);
        double stat = model.TryGetValue("freezeOn", out var f) && f is string fs && fs == "mean" ? etaPos : etaPosBar;
        return new D { ["etaPos"] = N(etaPos), ["etaPosBar"] = N(etaPosBar), ["etaNegBar"] = N(Math.Min(0.5, Dn(e["etaNegUpper"]))), ["frozen"] = stat > M(model, "etaStop") };
    }

    public static D AdmissionPolicy(D state, D? model = null)
    {
        model ??= DefaultFatigue();
        if (model.TryGetValue("assumeNoiseFree", out var nf) && JsX.Truthy(nf))
            return new D { ["tau"] = new Num("1"), ["etaPos"] = new Num("0"), ["etaNeg"] = new Num("0"), ["doubleConfirmIrreversible"] = false, ["falseAdmitBound"] = new Num("0") };
        double delta = M(model, "delta");
        if (!(delta > 0 && delta < 1)) throw new WalletException("admissionPolicy: delta must be in (0, 1)");
        double ep = Math.Min(BelowHalf, M(state, "etaPosBar")), en = Math.Min(BelowHalf, M(state, "etaNegBar"));
        return new D { ["tau"] = N(1 - delta), ["etaPos"] = N(ep), ["etaNeg"] = N(en), ["doubleConfirmIrreversible"] = ep > 0, ["falseAdmitBound"] = N(ep * ep) };
    }

    /// <summary>Sliding-window question counter shared across sessions: keeps only timestamps inside the window.</summary>
    public sealed class SlidingWindowCounter
    {
        readonly double _window;
        readonly List<double> _times = new();
        public SlidingWindowCounter(double windowMs = 3_600_000)
        {
            if (!(double.IsFinite(windowMs) && windowMs == Math.Floor(windowMs) && windowMs > 0)) throw new WalletException("SlidingWindowCounter: windowMs must be a positive integer");
            _window = windowMs;
        }
        void Prune(double now) { while (_times.Count > 0 && _times[0] <= now - _window) _times.RemoveAt(0); }
        public int Count(double now) { Prune(now); return _times.Count; }
        /// <summary>Record one event at <paramref name="now"/> if the count is below <paramref name="cap"/>; false (nothing recorded) otherwise.</summary>
        public bool TryAdd(double now, double cap)
        {
            Prune(now);
            if (_times.Count >= cap) return false;
            if (_times.Count > 0 && now < _times[^1]) throw new WalletException("SlidingWindowCounter: time went backwards");
            _times.Add(now);
            return true;
        }
    }

    /// <summary>Two "yes" answers at typed or device tier, on different screens, with at least one other screen between them.</summary>
    public static bool DoubleConfirmed(L records)
    {
        var strong = records.Where(r => G(r, "tier") is string t && (t == "typed" || t == "device")).Select(r => Dn(G(r, "screen"))).OrderBy(x => x).ToList();
        for (int i = 0; i < strong.Count; i++)
            for (int j = i + 1; j < strong.Count; j++)
                if (strong[j] - strong[i] >= 2) return true;
        return false;
    }
}
