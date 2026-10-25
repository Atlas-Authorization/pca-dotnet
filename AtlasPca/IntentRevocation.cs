// Rule 13 step 7: session revocation (packages/pca/src/intent-revocation.ts checkSessionRevocation), mirroring
// IntentRevocation.java: ONE dedicated revocation authority (S.revocation.key, never a principal) signs epochs that carry the
// FULL revoked list (sorted, distinct, its revset root the signed root, its length set_size == epoch); the verifier needs an
// epoch at most max_age old that lists none of the ids the action relies on and that extends the tracked last epoch
// append-only (no rollback, no drop, no equivocation).
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class IntentRevocation
{
    public const string RevepochDomain = "atlas-pca/revepoch/v1\0";
    static readonly byte[] RevsetPrefix = Encoding.UTF8.GetBytes("pca-revset/v1\0");

    public static string SessionRevocationId(string session) => "pca-intent:session:" + session;
    public static string MapRevocationId(string mapDigest) => "pca-intent:map:" + mapDigest;
    public static string DeltaRevocationId(string grantId) => "pca-intent:delta:" + grantId;
    public static string ProfileRevocationId(string profile, string version) => "pca-intent:profile:" + profile + "@" + version;
    public static string SessionRevocationScope(string session) => "pca-intent-session:" + session;

    /// <summary>The template-literal text of a JSON value (<c>`${x}`</c>).</summary>
    internal static string JsText(object? x, bool present) => !present ? "undefined" : x switch
    {
        null => "null",
        Num n => n.Raw == "-0" ? "0" : n.Raw,
        bool b => b ? "true" : "false",
        string s => s,
        L l => string.Join(",", l.Select(e => e == null ? "" : JsText(e, true))),
        D => "[object Object]",
        _ => x.ToString() ?? "",
    };

    static string BindRoot(object? size, string treeRoot) =>
        Pca.B64u(Pca.Sha256Of(RevsetPrefix, IntentJs.CanonBytes(new D { ["size"] = size, ["tree"] = treeRoot })));

    static readonly string EmptyTree = Pca.B64u(Pca.Sha256Of(Array.Empty<byte>()));

    /// <summary><c>revset_root(L)</c>: <c>base64url(SHA-256("pca-revset/v1\0" || canonical({size: |L|, tree})))</c> over the RFC 6962
    /// Merkle root of <c>L</c> in order (leaf <c>SHA-256(0x00 || canonical(id))</c>, node <c>SHA-256(0x01 || l || r)</c>),
    /// <c>tree = base64url(SHA-256(""))</c> for the empty list.</summary>
    internal static string RevsetRoot(IReadOnlyList<string> ids) =>
        BindRoot(IntentJs.OfLong(ids.Count), ids.Count == 0 ? EmptyTree : Pca.MerkleRoot(ids.Cast<object?>().ToList()));

    /// <summary>JavaScript truthiness of a JSON value.</summary>
    internal static bool Truthy(object? v) => v switch
    {
        null => false,
        bool b => b,
        string s => s.Length > 0,
        _ when IntentJs.NumOf(v) is double d => d != 0 && !double.IsNaN(d),
        _ => true,
    };

    /// <summary>The revoked list is well-formed and is exactly what the epoch signs: an array of strings strictly ascending in
    /// UTF-8 byte order, <c>length == set_size == epoch</c>, <c>revset_root(revoked) == root</c>. Null = ok.</summary>
    internal static string? RevokedListError(D ep, object? revoked)
    {
        if (revoked is not L rl || rl.Any(x => x is not string)) return "revoked must be an array of ids";
        var r = rl.Cast<string>().ToList();
        for (int i = 1; i < r.Count; i++) if (IntentJs.CompareUtf8(r[i - 1], r[i]) >= 0) return "revoked must be sorted by UTF-8 bytes and distinct";
        if (r.Count != IntentJs.NumOf(ep["set_size"]) || IntentJs.NumOf(ep["epoch"]) != IntentJs.NumOf(ep["set_size"]))
            return "the epoch must be numbered by its set size and list exactly set_size ids";
        if (RevsetRoot(r) != ep["root"] as string) return "the revoked list is not the signed set (root mismatch)";
        return null;
    }

    /// <summary>The revocation epoch, strictly typed before any comparison. Null = well-formed.</summary>
    internal static string? RevocationEpochShapeError(object? epO)
    {
        if (epO is not D ep) return "the revocation epoch must be an object";
        foreach (var k in new[] { "instance_id", "grant_ref", "root", "guardian", "sig" }) if (IntentJs.Get(ep, k) is not string) return $"revocation epoch {k} must be a string";
        foreach (var k in new[] { "epoch", "set_size", "issued_at", "not_after" }) if (!IntentJs.IsNonNeg(IntentJs.Get(ep, k))) return $"revocation epoch {k} must be a non-negative safe integer";
        if (ep.ContainsKey("guardian_epoch") && !IntentJs.IsNonNeg(ep["guardian_epoch"])) return "revocation epoch guardian_epoch must be a non-negative safe integer";
        var se = IntentJs.SuiteError(IntentJs.Get(ep, "alg"), ep.ContainsKey("alg"));
        if (se != null) return "revocation epoch alg: " + se;
        foreach (var k in new[] { "pq_pk", "pq_sig" }) if (ep.ContainsKey(k) && ep[k] is not string) return $"revocation epoch {k} must be a string";
        return null;
    }

    /// <summary>The signed epoch (shape already checked): signature under the guardian (a PQ epoch only under the PQ key pinned
    /// for it), grant binding, <c>now &lt;= not_after</c>, issued at most 60 s ahead.</summary>
    internal static string? CheckRevocationEpoch(D ep, string guardian, double now, string grantRef, IReadOnlyDictionary<string, string>? pqPins)
    {
        try
        {
            if (IntentJs.Get(ep, "guardian") as string != guardian || IntentJs.SuiteOf(ep) == null) return "revocation epoch not signed by the pinned guardian";
            var body = new D();
            foreach (var k in new[] { "instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after" }) body[k] = ep[k];
            var msg = Pca.Concat(Encoding.UTF8.GetBytes(RevepochDomain),
                IntentJs.CanonBytes(IntentJs.BindSuiteFields(body, IntentJs.Get(ep, "alg"), ep.ContainsKey("alg"), IntentJs.Get(ep, "pq_pk"), ep.ContainsKey("pq_pk"))));
            if (!IntentJs.VerifyPinnedSuite(IntentJs.Get(ep, "alg"), ep.ContainsKey("alg"), guardian, IntentJs.Get(ep, "pq_pk"), msg, IntentJs.Get(ep, "sig"), IntentJs.Get(ep, "pq_sig"), pqPins))
                return "revocation epoch signature invalid";
            if (ep["grant_ref"] as string != grantRef) return "revocation epoch is for a different grant";
            if (!(now <= IntentJs.NumOf(ep["not_after"])!.Value)) return "revocation epoch expired (stale revocation root)";
            if (!(IntentJs.NumOf(ep["issued_at"])!.Value <= now + 60_000)) return "revocation epoch issued in the future";
            return null;
        }
        catch (Exception) { return "revocation epoch check error"; }
    }

    /// <summary>The session revocation step (rule 13 step 7). First failure wins: a. <paramref name="maxAgeMs"/> a safe integer
    /// &gt;= 0, the clock a safe integer, <paramref name="ids"/> a list, the authority a string; b. the evidence an object with a
    /// well-formed epoch whose guardian is the dedicated <paramref name="authority"/>; c. the epoch verifies for the scope (PQ only
    /// under <paramref name="pqPins"/>); d. it is at most <paramref name="maxAgeMs"/> old; e. <c>revoked</c> is the full signed
    /// set; f. APPEND-ONLY against the tracked <paramref name="last"/> when present; g. no id of <paramref name="ids"/> is
    /// revoked. Null = ok.</summary>
    public static string? CheckSessionRevocation(object? ev, string? session, object? authority, IReadOnlyList<object?>? ids, double now, double maxAgeMs,
        string? scope, IReadOnlyDictionary<string, string>? pqPins, bool lastPresent, object? last)
    {
        try
        {
            if (!(double.IsFinite(maxAgeMs) && maxAgeMs == Math.Round(maxAgeMs) && maxAgeMs <= IntentJs.MaxSafe && maxAgeMs >= 0 && !IntentJs.IsNegZero(maxAgeMs)))
                return "revocation max age misconfigured (fail closed)";
            if (!(double.IsFinite(now) && now == Math.Round(now) && Math.Abs(now) <= IntentJs.MaxSafe && !IntentJs.IsNegZero(now))) return "the verifier clock is not a safe integer (fail closed)";
            if (ids == null || authority is not string auth) return "ids must be an array and the authority a key";
            if (ev is not D) return "no session revocation epoch supplied";
            if (ClosedEvidenceError((D)ev) is string ce) return "the revocation evidence " + ce;
            var epO = IntentJs.Get(ev, "epoch");
            var shape = RevocationEpochShapeError(epO);
            if (shape != null) return shape;
            var ep = (D)epO!;
            if (ep["guardian"] as string != auth) return "the revocation epoch is not signed by the session revocation authority";
            var r = CheckRevocationEpoch(ep, auth, now, scope ?? SessionRevocationScope(session ?? "null"), pqPins);
            if (r != null) return r;
            if (!(now - IntentJs.NumOf(ep["issued_at"])!.Value <= maxAgeMs)) return $"the session revocation epoch is older than {(long)maxAgeMs} ms";
            var revoked = IntentJs.Get(ev, "revoked");
            var le = RevokedListError(ep, revoked);
            if (le != null) return le;
            var cur = new HashSet<string>(((L)revoked!).Cast<string>(), StringComparer.Ordinal);
            if (lastPresent)
            {
                var lep = IntentJs.Get(last, "epoch");
                if (last is not D ld || ClosedEvidenceError(ld) != null || RevocationEpochShapeError(lep) != null || RevokedListError((D)lep!, IntentJs.Get(last, "revoked")) != null)
                    return "the tracked last epoch is malformed (fail closed)";
                if (IntentJs.NumOf(ep["epoch"])!.Value < IntentJs.NumOf(IntentJs.Get(lep, "epoch"))!.Value) return "revocation epoch rollback (older than the last accepted)";
                foreach (var id in ((L)IntentJs.Get(last, "revoked")!).Cast<string>())
                    if (!cur.Contains(id)) return $"the epoch drops '{id}', revoked in the last accepted epoch (not append-only)";
                if (IntentJs.NumOf(ep["epoch"]) == IntentJs.NumOf(IntentJs.Get(lep, "epoch")) && ep["root"] as string != IntentJs.Get(lep, "root") as string)
                    return "two different revocation sets under one epoch number (equivocation)";
            }
            foreach (var id in ids) if (id is not string s || cur.Contains(s)) return $"'{JsText(id, true)}' is revoked";
            return null;
        }
        catch (Exception e) { return "session revocation check error (fail closed): " + e.GetType().Name; }
    }

    /// <summary>The evidence is CLOSED: exactly the members <c>epoch</c> and <c>revoked</c> (an extra member is malformed). Null = ok.</summary>
    internal static string? ClosedEvidenceError(D ev)
    {
        foreach (var k in ev.Keys) if (k is not ("epoch" or "revoked")) return $"has the unknown member '{k}' (it is exactly {{epoch, revoked}})";
        return null;
    }

    /// <summary>The parameters of <c>primitives.intent_revocation</c>; every other input member belongs to the (closed) evidence.</summary>
    static readonly string[] PrimitiveParams = { "session", "scope", "authority", "ids", "now", "max_age_ms", "last" };

    /// <summary>The <c>primitives.intent_revocation</c> entry point: <c>{epoch, revoked, session, authority, ids, now, max_age_ms,
    /// last?}</c> with the scope <c>"pca-intent-session:" + session</c>.</summary>
    public static bool CheckPrimitive(object? input) => PrimitiveReason(input) == null;

    /// <summary>As <see cref="CheckPrimitive"/>, with the refusal reason (null = ok).</summary>
    public static string? PrimitiveReason(object? input)
    {
        try
        {
            var inp = (D)IntentJs.Normalize(input)!;
            var ev = new D(inp);
            foreach (var k in PrimitiveParams) ev.Remove(k);
            double maxAge = IntentJs.IsInt(IntentJs.Get(inp, "max_age_ms")) ? IntentJs.NumOf(inp["max_age_ms"])!.Value : double.NaN;
            double now = IntentJs.IsInt(IntentJs.Get(inp, "now")) ? IntentJs.NumOf(inp["now"])!.Value : double.NaN;
            return CheckSessionRevocation(ev, IntentJs.Get(inp, "session") as string, IntentJs.Get(inp, "authority"), IntentJs.Get(inp, "ids") as L, now, maxAge,
                null, null, inp.ContainsKey("last"), IntentJs.Get(inp, "last"));
        }
        catch (Exception) { return "session revocation check error (fail closed)"; }
    }
}
