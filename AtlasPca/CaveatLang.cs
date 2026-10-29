// Caveat language v2 (track K1): a port of packages/pca/src/caveat-lang.ts (security contract C-220 to C-229). Six verifier-side
// features, all of them RESTRICTIONS: needs_discharge (third-party caveat + signed discharge from a key THE VERIFIER pinned),
// sealed, narrow (holder-signed self-attenuation that rides beside the PCActn), max_uses (n atomic first-use slots in the
// verifier's replay store), derive (bounded Kleene three-valued fact check) and spiffe_bound. Everything here is total: a
// malformed caveat, discharge, narrow block or context is a refusal, never an exception and never an allow.
// Values are the parsed JSON tree (Dictionary<string, object?>, List<object?>, Num, string, bool, null).
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>A verifier-side pin for a discharge issuer. <c>Label</c> is what caveats name; the keys never appear in a token.</summary>
public sealed record DischargePin(string Label, string Class, string Pk, string? PqPk = null, string? SpiffeId = null);

/// <summary>A caveat of the leaf hop with the hop that introduced it (0 = the root grant) and that hop's capability hash.</summary>
public sealed record BoundCaveat(object? Caveat, int Hop, string CapHash);

/// <summary>What a discharge is verified against. <c>Now</c> must be a safe integer (anything else refuses).</summary>
public sealed record DischargeBinding(string CapHash, IReadOnlyList<DischargePin>? Pins, long Now, string? ActionDigest = null, IReadOnlyList<string>? Revoked = null);

/// <summary>Ok with the discharge digest and its claims, or a refusal reason.</summary>
public sealed record DischargeVerdict(bool Ok, string? Digest = null, Dictionary<string, object?>? Claims = null, string? Reason = null);

/// <summary>What a narrow block is verified against.</summary>
public sealed record NarrowBinding(long Now, string? ActionDigest = null);

/// <summary>Ok with the narrow block's caveats, or a refusal reason.</summary>
public sealed record NarrowVerdict(bool Ok, IReadOnlyList<object?>? Caveats = null, string? Reason = null);

/// <summary>Ok with the number of uses spent, or a refusal reason.</summary>
public sealed record UsesVerdict(bool Ok, int Spent = 0, string? Reason = null);

/// <summary>The evaluation clock and the action under decision (<c>{verb, resource, params}</c>).</summary>
public sealed record K1Context(long Now, Dictionary<string, object?>? Action = null);

/// <summary>The verifier-side K1 input. Nothing in it comes from the request except the presented discharges and narrow block.</summary>
public sealed class K1Input
{
    /// <summary>The verifier's pins for discharge issuers.</summary>
    public IReadOnlyList<DischargePin>? Pins { get; init; }
    /// <summary>Discharges presented with the action.</summary>
    public IReadOnlyList<object?>? Discharges { get; init; }
    /// <summary>The digest of the PCActn being decided (<see cref="CaveatLang.DischargeActionDigest"/>).</summary>
    public string? ActionDigest { get; init; }
    /// <summary>Discharge digests the verifier has revoked.</summary>
    public IReadOnlyList<string>? RevokedDischarges { get; init; }
    /// <summary>The SPIFFE ID of the presenting workload, from an SVID the verifier verified.</summary>
    public string? SpiffeId { get; init; }
    /// <summary>The verifier's own record of this holder's admitted actions (<c>{t, verb, resource}</c>).</summary>
    public IReadOnlyList<object?>? History { get; init; }

    object? _narrow;
    /// <summary>A narrow block presented with the action. Setting it (null included) marks it present: a present malformed
    /// block is refused, an absent one is not.</summary>
    public object? Narrow { get => _narrow; init { _narrow = value; HasNarrow = true; } }
    public bool HasNarrow { get; private set; }

    /// <summary>A copy with <see cref="ActionDigest"/> replaced (the verifier computes the digest itself and ignores a caller-supplied one).</summary>
    public K1Input WithActionDigest(string? digest) => HasNarrow
        ? new K1Input { Pins = Pins, Discharges = Discharges, RevokedDischarges = RevokedDischarges, SpiffeId = SpiffeId, History = History, ActionDigest = digest, Narrow = _narrow }
        : new K1Input { Pins = Pins, Discharges = Discharges, RevokedDischarges = RevokedDischarges, SpiffeId = SpiffeId, History = History, ActionDigest = digest };
}

/// <summary>The verdict of <see cref="CaveatLang.EvaluateK1"/>.</summary>
public sealed record K1Result(bool Ok, IReadOnlyList<string> Failed, IReadOnlyList<string> Reasons, IReadOnlyList<object?> Plain, IReadOnlyList<BoundCaveat> Bound);

/// <summary>The facts a <c>derive</c> caveat may read.</summary>
public sealed record DeriveInput(long Now, Dictionary<string, object?>? Action, IReadOnlyList<object?>? History, IReadOnlyDictionary<string, Dictionary<string, object?>> Claims);

/// <summary>What a request presents for the caveat language: <see cref="Discharges"/> (null: none) and a narrow block
/// (<see cref="HasNarrow"/>; any JSON value). <see cref="Ok"/> is false, with a <see cref="Reason"/>, when a header is unreadable.</summary>
public sealed record PresentedK1(bool Ok, IReadOnlyList<object?>? Discharges = null, bool HasNarrow = false, object? Narrow = null, string? Reason = null);

public static class CaveatLang
{
    public const string DischargesHeader = "PCA-Discharges";
    public const string NarrowHeader = "PCA-Narrow";

    // one header value by case-insensitive name; several spellings with different values are ambiguous, so absent
    static string? HeaderValue(IEnumerable<KeyValuePair<string, string>> headers, string name)
    {
        var vals = headers.Where(kv => string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase)).Select(kv => kv.Value).Distinct(StringComparer.Ordinal).ToList();
        return vals.Count == 1 ? vals[0] : null;
    }

    static object? ParseHeaderJson(string value)
    {
        var text = Pca.DecodePcaHeader(value) ?? throw new FormatException("not canonical base64url");
        if (System.Text.Encoding.UTF8.GetByteCount(text) > Pca.MaxArtifactBytes) throw new FormatException(Pca.ArtifactSizeReason);
        return Pca.ParseStrict(text);
    }

    /// <summary>Discharges and a narrow block as presented with a request: header <c>PCA-Discharges</c> (strict base64url of a JSON
    /// array) and <c>PCA-Narrow</c> (strict base64url of any JSON value). An empty value is absent; names are case-insensitive.
    /// Unreadable text is <c>Ok = false</c> (the guard then presents nothing, so the K1 caveat stays unsatisfied). Total.</summary>
    public static PresentedK1 PresentedK1Of(IEnumerable<KeyValuePair<string, string>>? headers)
    {
        try
        {
            if (headers == null) return new PresentedK1(true);
            IReadOnlyList<object?>? discharges = null;
            var d = HeaderValue(headers, DischargesHeader);
            if (!string.IsNullOrEmpty(d))
                discharges = ParseHeaderJson(d) as JL ?? throw new FormatException("PCA-Discharges must be a JSON array");
            var n = HeaderValue(headers, NarrowHeader);
            return string.IsNullOrEmpty(n) ? new PresentedK1(true, discharges) : new PresentedK1(true, discharges, true, ParseHeaderJson(n));
        }
        catch (Exception ex) { return new PresentedK1(false, Reason: ex.Message); }
    }

    /// <summary>The K1 input to hand to the evaluator: what the request presented, overridden by what the verifier supplies itself
    /// (<paramref name="own"/> wins member by member). Unreadable headers present nothing.</summary>
    public static K1Input MergePresented(PresentedK1 presented, K1Input? own)
    {
        var pr = presented.Ok ? presented : new PresentedK1(true);
        own ??= new K1Input();
        var discharges = own.Discharges ?? pr.Discharges;
        bool narrow = own.HasNarrow || pr.HasNarrow;
        var nv = own.HasNarrow ? own.Narrow : pr.Narrow;
        return narrow
            ? new K1Input { Pins = own.Pins, Discharges = discharges, RevokedDischarges = own.RevokedDischarges, SpiffeId = own.SpiffeId, History = own.History, ActionDigest = own.ActionDigest, Narrow = nv }
            : new K1Input { Pins = own.Pins, Discharges = discharges, RevokedDischarges = own.RevokedDischarges, SpiffeId = own.SpiffeId, History = own.History, ActionDigest = own.ActionDigest };
    }

    public const string NeedsDischarge = "needs_discharge";
    public const string Sealed = "sealed";
    public const string MaxUses = "max_uses";
    public const string Derive = "derive";
    public const string SpiffeBound = "spiffe_bound";
    public static readonly IReadOnlyList<string> K1CaveatTypes = new[] { NeedsDischarge, Sealed, MaxUses, Derive, SpiffeBound };

    public const string DischargeDomain = "atlas-pca/discharge/v1\0";
    public const string DischargeRefDomain = "atlas-pca/discharge-ref/v1";
    public const string DischargeActionDomain = "atlas-pca/discharge-action/v1";
    public const string NarrowDomain = "atlas-pca/narrow/v1\0";
    public const string MaxUsesDomain = "atlas-pca/max-uses/v1\0";
    /// <summary>A discharge or narrow block lives at most 24 hours.</summary>
    public const long MaxLifetimeMs = 86_400_000;
    public const int MaxUsesLimit = 256;
    public const int NarrowMaxCaveats = 16;
    public const int DeriveMaxDefs = 8;
    public const int DeriveMaxNodes = 32;
    public const int DeriveMaxDepth = 4;
    public const long DeriveMaxWindowMs = 30L * 86_400_000;
    public const int DeriveMaxHistory = 10_000;
    public const int SpiffeMaxIdBytes = 2048;

    static readonly Regex IdRe = new(@"^[a-z0-9][a-z0-9_.-]{0,63}\z", RegexOptions.CultureInvariant);
    static readonly Regex NameRe = new(@"^[a-z][a-z0-9_]{0,63}\z", RegexOptions.CultureInvariant);
    static readonly Regex TrustDomainRe = new(@"^[a-z0-9._-]+\z", RegexOptions.CultureInvariant);
    static readonly Regex SpiffeSegmentRe = new(@"^[A-Za-z0-9._-]+\z", RegexOptions.CultureInvariant);
    static readonly string[] IssuerClasses = { "human", "org", "workload", "model", "artifact" };
    static readonly string[] Ops = { "eq", "neq", "gte", "lte", "in" };
    const string ClockReason = "the verifier clock is not a safe integer (fail closed)";

    static bool IsId(object? v) => v is string s && IdRe.IsMatch(s);
    static bool IsName(object? v) => v is string s && NameRe.IsMatch(s);
    static bool IsStr256(object? v) => IntentArtifacts.IsBoundedString(v, 256);
    static bool IsScalarClaim(object? v) => IntentArtifacts.IsScalar(v) && (v is not string || IsStr256(v));
    static bool IsInt(object? v) => IntentJs.IsInt(v);
    static double Dbl(object? v) => IntentJs.NumOf(v)!.Value;
    static bool ClockOk(long now) => Math.Abs(now) <= Pca.MaxSafeInt;
    static JL HopsOf(object? grant, object? chain) => chain is JL { Count: > 0 } c ? c : new JL { grant };

    /// <summary>True iff the caveat is an object whose string <c>type</c> is one this module evaluates.</summary>
    public static bool IsK1Caveat(object? c) => c is JD d && d.GetValueOrDefault("type") is string t && K1CaveatTypes.Contains(t);

    // ====================================================================================================
    // SPIFFE ID syntax (SPIFFE-ID.md)
    // ====================================================================================================

    /// <summary>Null when <paramref name="s"/> is a valid SPIFFE ID: <c>spiffe://</c> + a trust domain over <c>[a-z0-9._-]</c> (at most 255)
    /// + an optional path of non-empty segments over <c>[A-Za-z0-9._-]</c> that are not <c>.</c> or <c>..</c>, no trailing slash, at
    /// most 2048 bytes.</summary>
    public static string? SpiffeIdError(object? s)
    {
        try
        {
            if (s is not string id || id.Length == 0) return "SPIFFE ID must be a non-empty string";
            if (IntentJs.U8Len(id) > SpiffeMaxIdBytes) return "SPIFFE ID is too long";
            if (!id.StartsWith("spiffe://", StringComparison.Ordinal)) return "SPIFFE ID must begin with spiffe://";
            var rest = id.Substring(9);
            int slash = rest.IndexOf('/');
            var td = slash == -1 ? rest : rest.Substring(0, slash);
            var path = slash == -1 ? "" : rest.Substring(slash);
            if (td.Length == 0 || td.Length > 255 || !TrustDomainRe.IsMatch(td)) return "invalid trust domain";
            if (path == "") return null;
            if (path.EndsWith('/')) return "path must not end with a slash";
            foreach (var seg in path.Split('/').Skip(1))
                if (seg.Length == 0 || seg == "." || seg == ".." || !SpiffeSegmentRe.IsMatch(seg)) return "invalid path segment";
            return null;
        }
        catch (Exception) { return "SPIFFE ID is malformed"; }
    }

    // ====================================================================================================
    // Hop analysis: which hop introduced a caveat
    // ====================================================================================================

    /// <summary>Every caveat of the leaf hop with the hop that introduced it. Caveat lists are cumulative and append-only, so the
    /// caveat at position <c>p</c> was introduced by the first hop whose list is longer than <c>p</c>. Null for a malformed chain.</summary>
    public static List<BoundCaveat>? BoundCaveats(object? grant, object? chain = null)
    {
        try
        {
            var hops = HopsOf(grant, chain);
            if (hops[^1] is not JD leaf || leaf.GetValueOrDefault("caveats") is not JL lcs) return null;
            var hashes = new Dictionary<int, string>();
            var output = new List<BoundCaveat>();
            for (int p = 0; p < lcs.Count; p++)
            {
                int q = p;
                int h = hops.FindIndex(x => x is JD xm && xm.GetValueOrDefault("caveats") is JL xc && xc.Count > q);
                if (h < 0) h = hops.Count - 1;
                if (!hashes.TryGetValue(h, out var ch)) { ch = Pca.CapHash(hops[h]); hashes[h] = ch; }
                output.Add(new BoundCaveat(lcs[p], h, ch));
            }
            return output;
        }
        catch (Exception) { return null; }
    }

    // ====================================================================================================
    // needs_discharge
    // ====================================================================================================

    static string? RequireError(object? r)
    {
        if (r is not JD m) return "requirement must be an object";
        var e = IntentArtifacts.ClosedMembers(m, new[] { "claim", "op", "value" }, Array.Empty<string>(), "require");
        if (e != null) return e;
        if (!IsName(m["claim"])) return "claim name is malformed";
        if (m["op"] is not string op || !Ops.Contains(op)) return "op must be eq, neq, gte, lte or in";
        var value = m["value"];
        if (op == "in")
        {
            if (value is not JL vl || vl.Count == 0 || vl.Count > 16 || !vl.All(IsScalarClaim)) return "'in' needs 1..16 scalar values";
        }
        else if (op == "gte" || op == "lte")
        {
            if (!IsInt(value)) return $"'{op}' needs a safe integer";
        }
        else if (!IsScalarClaim(value)) return "value must be a scalar";
        return null;
    }

    /// <summary>Null when the caveat is well-formed: closed members, canonical names, bounded sizes.</summary>
    public static string? NeedsDischargeError(object? c)
    {
        try
        {
            if (c is not JD m) return "caveat must be an object";
            var e = IntentArtifacts.ClosedMembers(m, new[] { "type", "id", "issuer", "issuer_class", "bind", "ttl_ms", "require" }, new[] { "issuer_spiffe" }, "needs_discharge");
            if (e != null) return e;
            if (m["type"] is not NeedsDischarge) return "not a needs_discharge caveat";
            if (!IsId(m["id"])) return "id is malformed";
            if (!IsId(m["issuer"])) return "issuer label is malformed";
            if (m["issuer_class"] is not string ic || !IssuerClasses.Contains(ic)) return "issuer_class must be human, org, workload, model or artifact";
            if (m["bind"] is not ("chain_hop" or "action")) return "bind must be 'chain_hop' or 'action'";
            if (!(IsInt(m["ttl_ms"]) && Dbl(m["ttl_ms"]) >= 1 && Dbl(m["ttl_ms"]) <= MaxLifetimeMs)) return "ttl_ms must be 1..86400000";
            if (m["require"] is not JL req || req.Count > 16) return "require must be an array of at most 16 requirements";
            foreach (var r in req)
            {
                var re = RequireError(r);
                if (re != null) return re;
            }
            if (m.ContainsKey("issuer_spiffe"))
            {
                var se = SpiffeIdError(m["issuer_spiffe"]);
                if (se != null) return $"issuer_spiffe: {se}";
            }
            return null;
        }
        catch (Exception ex) { return "caveat error: " + ex.Message; }
    }

    /// <summary>The digest of the exact PCActn (counter and signature included): a bind-<c>action</c> discharge authorises that one action.</summary>
    public static string DischargeActionDigest(object? pcactn) =>
        Pca.HashCanonical(new JD { ["d"] = DischargeActionDomain, ["pcactn"] = pcactn });

    /// <summary>Content address of a discharge (signature included); what a revocation list names.</summary>
    public static string DischargeDigest(object? discharge) =>
        Pca.HashCanonical(new JD { ["d"] = DischargeRefDomain, ["discharge"] = discharge });

    static readonly string[] DRequired = { "v", "kind", "caveat_id", "issuer", "cap_hash", "bind", "claims", "iat", "not_after", "nonce", "sig" };
    static readonly string[] DOptional = { "action_digest", "alg", "pq_pk", "pq_sig" };

    static bool IsNonNegInt(object? v) => IsInt(v) && Dbl(v) >= 0;
    static bool IsVersion1(object? v) => IsInt(v) && Dbl(v) == 1;

    /// <summary>Null = well-formed.</summary>
    public static string? DischargeShapeError(object? discharge)
    {
        try
        {
            if (discharge is not JD a) return "not an object";
            var e = IntentArtifacts.ClosedMembers(a, DRequired, DOptional, "discharge");
            if (e != null) return e;
            if (!IsVersion1(a["v"]) || a["kind"] is not "pca-discharge") return "not a pca-discharge v1";
            if (!IsId(a["caveat_id"])) return "caveat_id is malformed";
            if (!IsId(a["issuer"])) return "issuer label is malformed";
            if (!IntentArtifacts.IsDigest(a["cap_hash"])) return "cap_hash must be canonical base64url (32 bytes)";
            if (a["bind"] is not ("chain_hop" or "action")) return "bind must be 'chain_hop' or 'action'";
            if ((a["bind"] is "action") ? !(a.ContainsKey("action_digest") && IntentArtifacts.IsDigest(a["action_digest"])) : a.ContainsKey("action_digest"))
                return "action_digest is required for bind action and forbidden for chain_hop";
            if (a["claims"] is not JD claims || claims.Count > 16) return "claims must be an object of at most 16 members";
            foreach (var (k, v) in claims) if (!NameRe.IsMatch(k) || !IsScalarClaim(v)) return $"claim '{k}' is malformed";
            if (!IsNonNegInt(a["iat"]) || !IsNonNegInt(a["not_after"])) return "iat and not_after must be non-negative safe integers";
            if (!(Dbl(a["not_after"]) > Dbl(a["iat"]))) return "not_after must be greater than iat";
            if (Dbl(a["not_after"]) - Dbl(a["iat"]) > MaxLifetimeMs) return $"a discharge lives at most {MaxLifetimeMs} ms";
            var nb = a["nonce"] is string ns ? Pca.B64uDecode(ns) : null;
            if (nb == null || nb.Length < 16) return "nonce must be canonical base64url of at least 16 bytes";
            if (a["sig"] is not string) return "sig must be a string";
            return IntentArtifacts.ArtifactSuiteError(a);
        }
        catch (Exception ex) { return "discharge error: " + ex.Message; }
    }

    static bool ClaimHolds(JD r, JD claims)
    {
        if (!claims.TryGetValue((string)r["claim"]!, out var v)) return false;
        var want = r["value"];
        switch ((string)r["op"]!)
        {
            case "eq": return IntentArtifacts.ScalarEq(v, want);
            case "neq": return !IntentArtifacts.ScalarEq(v, want);
            case "gte": return IsInt(v) && Dbl(v) >= Dbl(want);
            case "lte": return IsInt(v) && Dbl(v) <= Dbl(want);
            case "in": return ((JL)want!).Any(x => IntentArtifacts.ScalarEq(v, x));
            default: return false;
        }
    }

    static DischargeVerdict No(string reason) => new(false, Reason: reason);

    /// <summary>Verify one discharge against one caveat. The verifier's own pins decide the key; the discharge is bound to the hop
    /// carrying the caveat (and for <c>action</c> to the PCActn); it must be inside its window and within the caveat's
    /// <c>ttl_ms</c>; and its claims must satisfy every requirement. Total.</summary>
    public static DischargeVerdict VerifyDischarge(object? discharge, object? caveat, DischargeBinding bind)
    {
        try
        {
            if (!ClockOk(bind.Now)) return No(ClockReason);
            var ce = NeedsDischargeError(caveat);
            if (ce != null) return No($"malformed needs_discharge caveat: {ce}");
            var c = (JD)caveat!;
            var de = DischargeShapeError(discharge);
            if (de != null) return No($"malformed discharge: {de}");
            var d = (JD)discharge!;
            var issuer = (string)c["issuer"]!;
            if (!Equals(d["caveat_id"], c["id"])) return No("the discharge is for another caveat");
            if (!Equals(d["issuer"], c["issuer"])) return No("the discharge names another issuer");
            if (bind.Pins == null) return No("no issuer is pinned");
            var pins = bind.Pins.Where(p => p != null && p.Label == issuer).ToList();
            if (pins.Count == 0) return No("the issuer is not pinned by this verifier");
            if (pins.Count > 1) return No("the issuer label is pinned more than once (ambiguous)");
            var pin = pins[0];
            if (pin.Class != (string)c["issuer_class"]!) return No("the pinned issuer is not of the class the caveat requires");
            if (c.TryGetValue("issuer_spiffe", out var want) && pin.SpiffeId != (string?)want) return No("the pinned issuer does not carry the SPIFFE ID the caveat requires");
            if (!IntentArtifacts.VerifyArtifactSig(DischargeDomain, d, pin.Pk, pin.PqPk)) return No("discharge signature invalid");
            if (!Equals(d["bind"], c["bind"])) return No("the discharge binds differently than the caveat requires");
            if (!Equals(d["cap_hash"], bind.CapHash)) return No("the discharge is bound to another hop");
            if (c["bind"] is "action" && !Equals(d["action_digest"], bind.ActionDigest)) return No("the discharge is bound to another action");
            if (bind.Now < Dbl(d["iat"])) return No("the discharge is from the future");
            if (bind.Now > Dbl(d["not_after"])) return No("the discharge has expired");
            if (Dbl(d["not_after"]) - Dbl(d["iat"]) > Dbl(c["ttl_ms"])) return No("the discharge lives longer than the caveat allows");
            var digest = DischargeDigest(d);
            if (bind.Revoked != null && bind.Revoked.Contains(digest)) return No("the discharge is revoked");
            var claims = (JD)d["claims"]!;
            foreach (var r in (JL)c["require"]!)
            {
                var rm = (JD)r!;
                if (!ClaimHolds(rm, claims)) return No($"claim '{(string)rm["claim"]!}' does not satisfy the caveat");
            }
            return new DischargeVerdict(true, digest, claims);
        }
        catch (Exception ex) { return No("discharge error (fail closed): " + ex.Message); }
    }

    // ====================================================================================================
    // narrow: holder-signed per-action self-attenuation (no new hop)
    // ====================================================================================================

    static readonly HashSet<string> NarrowForbidden = new() { "envelope", Sealed, "budget_alloc", "intent_session" };
    static readonly string[] NRequired = { "v", "kind", "cap_hash", "holder", "caveats", "iat", "not_after", "nonce", "sig" };
    static readonly string[] NOptional = { "action_digest", "alg", "pq_pk", "pq_sig" };

    /// <summary>Null = well-formed.</summary>
    public static string? NarrowShapeError(object? narrow)
    {
        try
        {
            if (narrow is not JD a) return "not an object";
            var e = IntentArtifacts.ClosedMembers(a, NRequired, NOptional, "narrow");
            if (e != null) return e;
            if (!IsVersion1(a["v"]) || a["kind"] is not "pca-narrow") return "not a pca-narrow v1";
            if (!IntentArtifacts.IsDigest(a["cap_hash"])) return "cap_hash must be canonical base64url (32 bytes)";
            if (!IntentArtifacts.IsBoundedString(a["holder"], 64) || Pca.B64uDecode(a["holder"], 32) == null) return "holder must be canonical base64url (32 bytes)";
            if (a["caveats"] is not JL cs || cs.Count < 1 || cs.Count > NarrowMaxCaveats) return $"caveats must be 1..{NarrowMaxCaveats} caveats";
            foreach (var c in cs)
            {
                if (c is not JD cm || cm.GetValueOrDefault("type") is not string t) return "every caveat must be an object with a string type";
                if (NarrowForbidden.Contains(t)) return $"a narrow block cannot carry a '{t}' caveat";
            }
            if (a.ContainsKey("action_digest") && !IntentArtifacts.IsDigest(a["action_digest"])) return "action_digest must be canonical base64url (32 bytes)";
            if (!IsNonNegInt(a["iat"]) || !IsNonNegInt(a["not_after"])) return "iat and not_after must be non-negative safe integers";
            if (!(Dbl(a["not_after"]) > Dbl(a["iat"]))) return "not_after must be greater than iat";
            if (Dbl(a["not_after"]) - Dbl(a["iat"]) > MaxLifetimeMs) return $"a narrow block lives at most {MaxLifetimeMs} ms";
            var nb = a["nonce"] is string ns ? Pca.B64uDecode(ns) : null;
            if (nb == null || nb.Length < 16) return "nonce must be canonical base64url of at least 16 bytes";
            if (a["sig"] is not string) return "sig must be a string";
            return IntentArtifacts.ArtifactSuiteError(a);
        }
        catch (Exception ex) { return "narrow error: " + ex.Message; }
    }

    static NarrowVerdict NoNarrow(string reason) => new(false, Reason: reason);

    /// <summary>Verify a narrow block against the chain's leaf: signed by the leaf holder (a non-Ed25519 suite only under the PQ key the
    /// leaf's <c>holder_pq</c> commits to), bound to the leaf hop and, when it names one, to this PCActn, inside its window. The
    /// caveats it carries then join the chain's. A narrow block can only ADD restrictions. Total.</summary>
    public static NarrowVerdict VerifyNarrow(object? narrow, object? grant, object? chain, NarrowBinding bind)
    {
        try
        {
            if (!ClockOk(bind.Now)) return NoNarrow(ClockReason);
            var e = NarrowShapeError(narrow);
            if (e != null) return NoNarrow($"malformed narrow block: {e}");
            var n = (JD)narrow!;
            var hops = HopsOf(grant, chain);
            var leaf = hops[^1];
            var holder = (string)n["holder"]!;
            if (IntentJs.Get(leaf, "holder") is not string lh || lh != holder) return NoNarrow("the narrow block is not signed by the leaf holder");
            if (!Equals(n["cap_hash"], Pca.CapHash(leaf))) return NoNarrow("the narrow block is bound to another hop");
            string? pq = n.GetValueOrDefault("pq_pk") is string pk && IntentJs.Get(leaf, "holder_pq") is string hp && Pca.HolderPqCommitment(pk) == hp ? pk : null;
            if (!IntentArtifacts.VerifyArtifactSig(NarrowDomain, n, holder, pq)) return NoNarrow("narrow signature invalid");
            if (n.ContainsKey("action_digest") && !Equals(n["action_digest"], bind.ActionDigest)) return NoNarrow("the narrow block is bound to another action");
            if (bind.Now < Dbl(n["iat"])) return NoNarrow("the narrow block is from the future");
            if (bind.Now > Dbl(n["not_after"])) return NoNarrow("the narrow block has expired");
            return new NarrowVerdict(true, (JL)n["caveats"]!);
        }
        catch (Exception ex) { return NoNarrow("narrow error (fail closed): " + ex.Message); }
    }

    // ====================================================================================================
    // max_uses: n atomic first-use slots in the verifier's replay store
    // ====================================================================================================

    /// <summary>Null when the caveat is well-formed.</summary>
    public static string? MaxUsesError(object? c)
    {
        try
        {
            if (c is not JD m) return "caveat must be an object";
            var e = IntentArtifacts.ClosedMembers(m, new[] { "type", "id", "n", "until" }, Array.Empty<string>(), "max_uses");
            if (e != null) return e;
            if (m["type"] is not MaxUses) return "not a max_uses caveat";
            if (!IsId(m["id"])) return "id is malformed";
            if (!(IsInt(m["n"]) && Dbl(m["n"]) >= 1 && Dbl(m["n"]) <= MaxUsesLimit)) return $"n must be 1..{MaxUsesLimit}";
            if (!IsNonNegInt(m["until"])) return "until must be a non-negative safe integer";
            return null;
        }
        catch (Exception ex) { return "caveat error: " + ex.Message; }
    }

    /// <summary>The store key of use slot <c>i</c> of caveat <c>id</c> carried by hop <c>capHashOfHop</c>:
    /// <c>b64u(sha256(domain NUL cap NUL id NUL i))</c>.</summary>
    public static string MaxUsesSlotKey(string capHashOfHop, string id, int i) =>
        Pca.B64u(Pca.Sha256Of(IntentJs.Utf8($"{MaxUsesDomain}{capHashOfHop}\0{id}\0{i}")));

    static UsesVerdict NoUses(string reason) => new(false, 0, reason);

    /// <summary>Spend one use of every <c>max_uses</c> caveat in <paramref name="bound"/>, in order, after the rest of the decision
    /// allows. Each caveat takes the first free slot of its <c>n</c>: slot <c>i</c> is the atomic first consume of its key in the replay
    /// store (<see cref="IStateStore.ConsumeOnce"/>, remembered until the caveat's <c>until</c>), so concurrent actions never share a
    /// slot, across processes when the store is durable and shared. The first exhausted, expired or malformed caveat refuses; slots
    /// already taken stay spent (fail closed).</summary>
    public static UsesVerdict ReserveMaxUses(IStateStore store, IEnumerable<BoundCaveat> bound, long now)
    {
        try
        {
            if (!ClockOk(now)) return NoUses(ClockReason);
            int spent = 0;
            var ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var b in bound)
            {
                if (IntentJs.Get(b.Caveat, "type") is not MaxUses) continue;
                var err = MaxUsesError(b.Caveat);
                if (err != null) return NoUses($"malformed max_uses caveat: {err}");
                var c = (JD)b.Caveat!;
                var id = (string)c["id"]!;
                if (!ids.Add(b.CapHash + "\0" + id)) return NoUses($"duplicate max_uses id '{id}'");
                if (now >= Dbl(c["until"])) return NoUses($"max_uses '{id}' has expired");
                bool took = false;
                int n = (int)Dbl(c["n"]);
                long until = (long)Dbl(c["until"]);
                for (int i = 0; i < n && !took; i++) took = store.ConsumeOnce(MaxUsesSlotKey(b.CapHash, id, i), until, now);
                if (!took) return NoUses($"max_uses '{id}' is exhausted");
                spent += 1;
            }
            return new UsesVerdict(true, spent);
        }
        catch (Exception ex) { return NoUses("max_uses error (fail closed): " + ex.Message); }
    }

    // ====================================================================================================
    // derive: bounded derived facts in Kleene three-valued logic
    // ====================================================================================================

    static string? ExprError(object? x, HashSet<string> names, int depth, int[] count)
    {
        if (depth > DeriveMaxDepth) return $"expression nests deeper than {DeriveMaxDepth}";
        if (++count[0] > DeriveMaxNodes) return $"more than {DeriveMaxNodes} expression nodes";
        if (x is not JD m) return "expression must be an object";
        if (m.ContainsKey("ref"))
        {
            var e = IntentArtifacts.ClosedMembers(m, new[] { "ref" }, Array.Empty<string>(), "ref");
            if (e != null) return e;
            return m["ref"] is string r && names.Contains(r) ? null : "ref names no earlier def";
        }
        if (m.ContainsKey("const"))
        {
            var e = IntentArtifacts.ClosedMembers(m, new[] { "const" }, Array.Empty<string>(), "const");
            if (e != null) return e;
            return IsScalarClaim(m["const"]) ? null : "const must be a scalar";
        }
        var op = m.GetValueOrDefault("op") as string;
        if (op == "and" || op == "or")
        {
            var e = IntentArtifacts.ClosedMembers(m, new[] { "op", "args" }, Array.Empty<string>(), op);
            if (e != null) return e;
            if (m["args"] is not JL args || args.Count < 1 || args.Count > 8) return $"{op} needs 1..8 arguments";
            foreach (var a in args)
            {
                var r = ExprError(a, names, depth + 1, count);
                if (r != null) return r;
            }
            return null;
        }
        if (op == "not")
        {
            var e = IntentArtifacts.ClosedMembers(m, new[] { "op", "arg" }, Array.Empty<string>(), "not");
            return e ?? ExprError(m["arg"], names, depth + 1, count);
        }
        if (op is "eq" or "neq" or "lt" or "lte" or "gt" or "gte")
        {
            var e = IntentArtifacts.ClosedMembers(m, new[] { "op", "a", "b" }, Array.Empty<string>(), op);
            return e ?? ExprError(m["a"], names, depth + 1, count) ?? ExprError(m["b"], names, depth + 1, count);
        }
        return "unknown expression";
    }

    /// <summary>Null when the caveat is well-formed: bounded, closed, and non-recursive (a def refers only to defs before it).</summary>
    public static string? DeriveError(object? c)
    {
        try
        {
            if (c is not JD m) return "caveat must be an object";
            var e = IntentArtifacts.ClosedMembers(m, new[] { "type", "id", "defs", "check" }, Array.Empty<string>(), "derive");
            if (e != null) return e;
            if (m["type"] is not Derive) return "not a derive caveat";
            if (!IsId(m["id"])) return "id is malformed";
            if (m["defs"] is not JL defs || defs.Count > DeriveMaxDefs) return $"defs must be an array of at most {DeriveMaxDefs}";
            var names = new HashSet<string>(StringComparer.Ordinal);
            var count = new[] { 0 };
            foreach (var dv in defs)
            {
                if (dv is not JD d || !d.TryGetValue("name", out var nv) || !IsName(nv)) return "def name is malformed";
                var name = (string)nv!;
                if (names.Contains(name)) return $"def '{name}' is defined twice";
                string? de;
                switch (d.GetValueOrDefault("kind"))
                {
                    case "count":
                        de = IntentArtifacts.ClosedMembers(d, new[] { "name", "kind", "window_ms" }, new[] { "verb", "resource_prefix" }, "count");
                        if (de == null && !(IsInt(d["window_ms"]) && Dbl(d["window_ms"]) >= 1 && Dbl(d["window_ms"]) <= DeriveMaxWindowMs)) de = "window_ms out of range";
                        if (de == null && d.ContainsKey("verb") && !IsStr256(d["verb"])) de = "verb must be a non-empty string";
                        if (de == null && d.ContainsKey("resource_prefix") && !IsStr256(d["resource_prefix"])) de = "resource_prefix must be a non-empty string";
                        break;
                    case "param":
                        de = IntentArtifacts.ClosedMembers(d, new[] { "name", "kind", "path" }, Array.Empty<string>(), "param");
                        if (de == null && !(d["path"] is string path && path.Split('.').Length <= 4 && path.Split('.').All(IntentArtifacts.IsPathSegment))) de = "param path is malformed";
                        break;
                    case "action":
                        de = IntentArtifacts.ClosedMembers(d, new[] { "name", "kind", "field" }, Array.Empty<string>(), "action");
                        if (de == null && d["field"] is not ("verb" or "resource")) de = "field must be 'verb' or 'resource'";
                        break;
                    case "claim":
                        de = IntentArtifacts.ClosedMembers(d, new[] { "name", "kind", "caveat_id", "claim" }, Array.Empty<string>(), "claim");
                        if (de == null && !(IsId(d["caveat_id"]) && IsName(d["claim"]))) de = "claim reference is malformed";
                        break;
                    case "expr":
                        de = IntentArtifacts.ClosedMembers(d, new[] { "name", "kind", "expr" }, Array.Empty<string>(), "expr") ?? ExprError(d["expr"], names, 1, count);
                        break;
                    default:
                        de = "unknown def kind";
                        break;
                }
                if (de != null) return $"def '{name}': {de}";
                names.Add(name);
            }
            return ExprError(m["check"], names, 1, count);
        }
        catch (Exception ex) { return "caveat error: " + ex.Message; }
    }

    // A value is a scalar (string, bool, Num) or null = unknown.
    static object? EvalExpr(JD x, Dictionary<string, object?> env)
    {
        if (x.ContainsKey("ref")) return env.TryGetValue((string)x["ref"]!, out var rv) ? rv : null;
        if (x.ContainsKey("const")) return x["const"];
        var op = (string)x["op"]!;
        if (op == "not") return EvalExpr((JD)x["arg"]!, env) is bool nb ? !nb : null;
        if (op == "and" || op == "or")
        {
            bool stop = op == "or";
            bool unknown = false;
            foreach (var a in (JL)x["args"]!)
            {
                var v = EvalExpr((JD)a!, env);
                if (v is not bool b) unknown = true;
                else if (b == stop) return stop;
            }
            return unknown ? null : !stop;
        }
        var l = EvalExpr((JD)x["a"]!, env);
        var r = EvalExpr((JD)x["b"]!, env);
        if (l == null || r == null) return null;
        if (op == "eq") return IntentArtifacts.ScalarEq(l, r);
        if (op == "neq") return !IntentArtifacts.ScalarEq(l, r);
        if (!IsInt(l) || !IsInt(r)) return null;
        double dl = Dbl(l), dr = Dbl(r);
        return op == "lt" ? dl < dr : op == "lte" ? dl <= dr : op == "gt" ? dl > dr : dl >= dr;
    }

    /// <summary>Evaluate a WELL-FORMED derive caveat (see <see cref="DeriveError"/>): true only when <c>check</c> is exactly true
    /// (false and unknown, here null, both refuse).</summary>
    public static bool? EvaluateDerive(JD c, DeriveInput inp)
    {
        var env = new Dictionary<string, object?>(StringComparer.Ordinal);
        var act = inp.Action;
        foreach (var dv in (JL)c["defs"]!)
        {
            var d = (JD)dv!;
            object? v = null;
            switch ((string)d["kind"]!)
            {
                case "count":
                {
                    var h = inp.History;
                    if (h == null || h.Count > DeriveMaxHistory) break;
                    long n = 0;
                    bool bad = false;
                    long window = (long)Dbl(d["window_ms"]);
                    d.TryGetValue("verb", out var verb);
                    d.TryGetValue("resource_prefix", out var prefix);
                    foreach (var ev in h)
                    {
                        if (ev is not JD e || !IsInt(e.GetValueOrDefault("t")) || e.GetValueOrDefault("verb") is not string ev1 || e.GetValueOrDefault("resource") is not string ev2)
                        {
                            bad = true;
                            break;
                        }
                        double t = Dbl(e["t"]);
                        if (t > inp.Now - window && t <= inp.Now && (verb == null || ev1 == (string)verb) && (prefix == null || ev2.StartsWith((string)prefix, StringComparison.Ordinal))) n += 1;
                    }
                    v = bad ? null : IntentJs.OfLong(n);
                    break;
                }
                case "param":
                {
                    var r = IntentArtifacts.ResolveParamPath(IntentJs.Get(act, "params"), "action.params." + (string)d["path"]!);
                    v = r.Found && IsScalarClaim(r.Value) ? r.Value : null;
                    break;
                }
                case "action":
                {
                    var f = IntentJs.Get(act, (string)d["field"]!);
                    v = IsStr256(f) ? f : null;
                    break;
                }
                case "claim":
                    v = inp.Claims.TryGetValue((string)d["caveat_id"]!, out var cl) ? cl.GetValueOrDefault((string)d["claim"]!) : null;
                    break;
                case "expr":
                    v = EvalExpr((JD)d["expr"]!, env);
                    break;
            }
            env[(string)d["name"]!] = v;
        }
        return EvalExpr((JD)c["check"]!, env) is bool res ? res : null;
    }

    // ====================================================================================================
    // spiffe_bound
    // ====================================================================================================

    /// <summary>Null when the caveat is well-formed: exactly one of <c>spiffe_id</c> and <c>spiffe_prefix</c>, a valid SPIFFE ID.</summary>
    public static string? SpiffeBoundError(object? c)
    {
        try
        {
            if (c is not JD m) return "caveat must be an object";
            var e = IntentArtifacts.ClosedMembers(m, new[] { "type" }, new[] { "spiffe_id", "spiffe_prefix" }, "spiffe_bound");
            if (e != null) return e;
            if (m["type"] is not SpiffeBound) return "not a spiffe_bound caveat";
            if (m.ContainsKey("spiffe_id") == m.ContainsKey("spiffe_prefix")) return "exactly one of spiffe_id and spiffe_prefix";
            return SpiffeIdError(m.ContainsKey("spiffe_id") ? m["spiffe_id"] : m["spiffe_prefix"]);
        }
        catch (Exception ex) { return "caveat error: " + ex.Message; }
    }

    // spiffe_id: the peer must equal it. spiffe_prefix: the peer must equal it or lie below it (prefix + "/").
    static bool SpiffeSatisfied(JD c, object? peer)
    {
        if (SpiffeBoundError(c) != null || SpiffeIdError(peer) != null) return false;
        var p = (string)peer!;
        if (c.TryGetValue("spiffe_id", out var id)) return p == (string?)id;
        var pre = (string)c["spiffe_prefix"]!;
        return p == pre || p.StartsWith(pre + "/", StringComparison.Ordinal);
    }

    // ====================================================================================================
    // The K1 evaluator
    // ====================================================================================================

    /// <summary>Evaluate the K1 caveat types of the leaf hop (and of a verified narrow block). Non-K1 caveats are left to the stock
    /// evaluators. <c>needs_discharge</c>, <c>sealed</c> and <c>max_uses</c> ids must be unique over the chain and narrow block: a
    /// duplicate fails every caveat that shares it. <c>max_uses</c> is only checked for well-formedness and expiry here;
    /// <see cref="ReserveMaxUses"/> spends it. Two passes: every <c>needs_discharge</c> first (derive reads their claims), then the
    /// rest in order. Total.</summary>
    public static K1Result EvaluateK1(object? grant, object? chain, K1Input? k1, K1Context ctx)
    {
        var failed = new List<string>();
        var reasons = new List<string>();
        void Fail(string type, string why) { failed.Add(type); reasons.Add(why); }
        K1Result Result(List<object?> plain, List<BoundCaveat> bound) => new(failed.Count == 0, failed, reasons, plain, bound);
        try
        {
            var bs = BoundCaveats(grant, chain);
            if (bs == null || ctx == null || !ClockOk(ctx.Now))
            {
                Fail("<malformed>", bs == null ? "malformed capability chain" : ClockReason);
                return Result(new List<object?>(), new List<BoundCaveat>());
            }
            // No K1 input at all (not even an empty one): every K1 caveat is refused, whatever its type.
            if (k1 == null)
            {
                var mine = bs.Where(b => IsK1Caveat(b.Caveat)).ToList();
                foreach (var b in mine) Fail((string)((JD)b.Caveat!)["type"]!, "the caveat language is not configured (no k1 input)");
                return Result(new List<object?>(), mine);
            }
            var bound = bs;
            var hops = HopsOf(grant, chain);
            int leafIndex = hops.Count - 1;
            var plain = new List<object?>();
            if (k1.HasNarrow)
            {
                var nv = VerifyNarrow(k1.Narrow, grant, chain, new NarrowBinding(ctx.Now, k1.ActionDigest));
                if (!nv.Ok)
                {
                    Fail("narrow", nv.Reason!);
                    return Result(new List<object?>(), bound.Where(b => IsK1Caveat(b.Caveat)).ToList());
                }
                var leafHash = Pca.CapHash(hops[leafIndex]);
                bound = bound.Concat(nv.Caveats!.Select(c => new BoundCaveat(c, leafIndex, leafHash))).ToList();
                foreach (var c in nv.Caveats!) if (!IsK1Caveat(c)) plain.Add(c);
            }
            var k1Bound = bound.Where(b => IsK1Caveat(b.Caveat)).ToList();
            // ids are unique per type across the chain and narrow block
            var seen = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var b in k1Bound)
            {
                var cv = (JD)b.Caveat!;
                if (cv.GetValueOrDefault("id") is string sid)
                {
                    var key = (string)cv["type"]! + "\0" + sid;
                    seen[key] = seen.GetValueOrDefault(key) + 1;
                }
            }
            int Seen(JD cv, string type) => cv.GetValueOrDefault("id") is string sid ? seen.GetValueOrDefault(type + "\0" + sid) : 0;
            long now = ctx.Now;
            var claims = new Dictionary<string, Dictionary<string, object?>>(StringComparer.Ordinal);
            var discharges = k1.Discharges ?? Array.Empty<object?>();
            // pass 1: discharges (derive reads their claims)
            foreach (var b in k1Bound)
            {
                var c = (JD)b.Caveat!;
                if (c["type"] is not NeedsDischarge) continue;
                var bad = NeedsDischargeError(c);
                if (bad != null) { Fail(NeedsDischarge, bad); continue; }
                var cid = (string)c["id"]!;
                if (Seen(c, NeedsDischarge) > 1) { Fail(NeedsDischarge, $"duplicate needs_discharge id '{cid}'"); continue; }
                string why = "no discharge presented";
                DischargeVerdict? okd = null;
                foreach (var d in discharges)
                {
                    if (d is not JD dm || !Equals(dm.GetValueOrDefault("caveat_id"), cid)) continue;
                    var v = VerifyDischarge(dm, c, new DischargeBinding(b.CapHash, k1.Pins ?? Array.Empty<DischargePin>(), now, k1.ActionDigest, k1.RevokedDischarges));
                    if (v.Ok) { okd = v; break; }
                    why = v.Reason!;
                }
                if (okd != null) claims[cid] = okd.Claims!;
                else Fail(NeedsDischarge, why);
            }
            // pass 2: everything else, in order
            foreach (var b in k1Bound)
            {
                var c = (JD)b.Caveat!;
                switch ((string)c["type"]!)
                {
                    case Sealed:
                    {
                        var e = IntentArtifacts.ClosedMembers(c, new[] { "type" }, Array.Empty<string>(), "sealed");
                        if (e != null) Fail(Sealed, e);
                        else if (b.Hop != leafIndex) Fail(Sealed, "a hop was appended below a sealed hop");
                        break;
                    }
                    case MaxUses:
                    {
                        var e = MaxUsesError(c);
                        if (e != null) Fail(MaxUses, e);
                        else if (Seen(c, MaxUses) > 1) Fail(MaxUses, $"duplicate max_uses id '{(string)c["id"]!}'");
                        else if (now >= Dbl(c["until"])) Fail(MaxUses, $"max_uses '{(string)c["id"]!}' has expired");
                        break;
                    }
                    case Derive:
                    {
                        var e = DeriveError(c);
                        if (e != null) Fail(Derive, e);
                        else if (Seen(c, Derive) > 1) Fail(Derive, $"duplicate derive id '{(string)c["id"]!}'");
                        else
                        {
                            var r = EvaluateDerive(c, new DeriveInput(now, ctx.Action, k1.History, claims));
                            if (r != true) Fail(Derive, r == null ? "derive check is unknown (a fact is missing)" : "derive check is false");
                        }
                        break;
                    }
                    case SpiffeBound:
                        if (!SpiffeSatisfied(c, k1.SpiffeId)) Fail(SpiffeBound, "the presenting workload does not carry the required SPIFFE ID");
                        break;
                }
            }
            return Result(plain, k1Bound);
        }
        catch (Exception ex)
        {
            Fail("<malformed>", "caveat language error (fail closed): " + ex.Message);
            return Result(new List<object?>(), new List<BoundCaveat>());
        }
    }

    /// <summary>The decision for a grant and chain with K1 input: the K1 caveat types by <see cref="EvaluateK1"/>, every other
    /// caveat of <see cref="Caveats.PolicyCaveats"/> plus the verified narrow block's plain caveats by the agent caveat evaluator
    /// (<see cref="Pca.EvaluateAgentCaveats"/>). <paramref name="context"/> uses the stock names: <c>now</c>, <c>delegation_depth</c>,
    /// <c>recent_action_times</c>, <c>action</c> (<c>{verb, resource, params}</c>). <c>Failed</c> = stock failures + K1 failures, sorted.
    /// Total.</summary>
    public static (bool Allow, List<string> Failed) EvaluateCaveatsK1(object? grant, object? chain, K1Input? k1, Dictionary<string, object?> context)
    {
        try
        {
            var nowObj = IntentJs.Get(context, "now");
            long now = IsInt(nowObj) ? IntentJs.Lng(nowObj) : long.MaxValue; // a non-integer clock fails closed in EvaluateK1
            var action = IntentJs.Get(context, "action") as JD;
            var k = EvaluateK1(grant, chain, k1, new K1Context(now, action));
            var policy = Caveats.PolicyCaveats(grant, chain);
            object? stock = policy is JL pl ? pl.Where(x => !IsK1Caveat(x)).Concat(k.Plain).ToList() : policy;
            var actionCtx = action != null ? new JD { ["action"] = action } : null;
            var s = Pca.EvaluateAgentCaveats(stock, new JD(context), actionCtx);
            var all = s.Failed.Concat(k.Failed).ToList();
            all.Sort(StringComparer.Ordinal);
            return (s.Ok && k.Ok, all);
        }
        catch (Exception) { return (false, new List<string> { "<malformed>" }); }
    }
}
