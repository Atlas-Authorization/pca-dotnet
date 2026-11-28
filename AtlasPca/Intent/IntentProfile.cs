// Portable, revocable intent profiles (pca-intent-profile v1): the principal's signed, versioned, append-only record of standing rules (deny wins;
// permit is explicit, scoped and expiring) and prior answers (negative answers become vetoes, positive ones never feed the learner). Profiles, scopes,
// rules and uses are JSON trees. Signing is Ed25519 (the default suite); verification honours every suite the SDK implements.
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentProfile
{
    public const string IntentProfileKind = "pca-intent-profile";
    public const string IntentProfileSigDomain = "atlas-pca/intent-profile/v1\0";
    public const string IntentProfileRefDomain = "atlas-pca/intent-profile-ref/v1";
    public const int MaxProfileRules = 256;
    public const int MaxProfileObservations = 2000;

    static readonly string[] Keys = { "v", "kind", "profile_id", "version", "owner", "scope", "standing", "prior", "expires_at", "revocation", "prev", "alg", "pq_pk", "sig", "pq_sig" };
    static readonly Regex IdRe = new(@"^[A-Za-z0-9_.-]{1,128}\z", RegexOptions.CultureInvariant);

    static object? Get(object? o, string k) => o is D m ? m.GetValueOrDefault(k) : null;
    static bool Has(object? o, string k) => o is D m && m.ContainsKey(k);
    static bool IsInt(object? v) => IntentJs.IsInt(v);
    static double DblOr(object? v) => IntentJs.NumOf(v) ?? double.NaN;
    static bool B32(object? v) => IntentJs.B32(v);

    static bool StrList(object? v)
    {
        if (v is not L l || l.Count > 256) return false;
        foreach (var x in l) if (x is not string s || s.Length == 0) return false;
        return true;
    }

    static bool PredOk(object? p)
    {
        if (p is not D) return false;
        var verb = Get(p, "verb");
        if (verb is string) return true;
        if (verb is not L vl) return false;
        foreach (var x in vl) if (x is not string) return false;
        return true;
    }

    static string SortedKeys(object? o) => string.Join(",", new SortedSet<string>(((D)o!).Keys, StringComparer.Ordinal));

    /// <summary>The first reason a profile is malformed, or null. signed = false skips the suite / signature members.</summary>
    public static string? IntentProfileShapeError(object? p, bool signed = true)
    {
        try
        {
            if (p is not D pm) return "profile is not an object";
            foreach (var k in pm.Keys) if (!Keys.Contains(k)) return "profile: unknown member '" + k + "'";
            if (!(IntentJs.NumOf(Get(p, "v")) != null && DblOr(Get(p, "v")) == 1) || (Get(p, "kind") as string) != IntentProfileKind) return "not a pca-intent-profile v1";
            var pid = Get(p, "profile_id");
            if (pid is not string ps || !IdRe.IsMatch(ps)) return "profile_id must match [A-Za-z0-9_.-]{1,128}";
            if (!(IsInt(Get(p, "version")) && DblOr(Get(p, "version")) >= 1)) return "version must be a safe integer >= 1";
            if (!B32(Get(p, "owner"))) return "owner must be canonical base64url (32 bytes)";
            var scope = Get(p, "scope");
            if (scope is not D sc) return "scope must be {sites?, verbs?, semantic_types?}";
            foreach (var k in sc.Keys) if (k is not ("sites" or "verbs" or "semantic_types")) return "scope must be {sites?, verbs?, semantic_types?}";
            foreach (var k in new[] { "sites", "verbs", "semantic_types" }) if (Has(scope, k) && !StrList(Get(scope, k))) return "scope." + k + " must be a list of strings";
            var standing = Get(p, "standing");
            if (standing is not D || SortedKeys(standing) != "deny,permit") return "standing must be {deny, permit}";
            foreach (var k in new[] { "deny", "permit" })
            {
                var r = Get(standing, k);
                if (r is not L rl || rl.Count > MaxProfileRules) return "standing." + k + " must be at most " + MaxProfileRules + " predicates";
                foreach (var x in rl) if (!PredOk(x)) return "standing." + k + " must be at most " + MaxProfileRules + " predicates";
            }
            var prior = Get(p, "prior");
            if (prior is not D || SortedKeys(prior) != "maps,observations") return "prior must be {observations, maps}";
            if (Get(prior, "observations") is not L obs || obs.Count > MaxProfileObservations) return "prior.observations must be at most " + MaxProfileObservations;
            foreach (var o in obs)
            {
                var y = Get(o, "y");
                bool yOk = IntentJs.NumOf(y) != null && (DblOr(y) == 0 || DblOr(y) == 1);
                if (o is not D || SortedKeys(o) != "at,values,verb,y" || Get(o, "verb") is not string || Get(o, "values") is not D || !yOk || !(IsInt(Get(o, "at")) && DblOr(Get(o, "at")) >= 0))
                    return "prior.observations entries are {verb, values, y, at}";
            }
            if (Get(prior, "maps") is not L maps) return "prior.maps must be 32-byte digests";
            foreach (var x in maps) if (!B32(x)) return "prior.maps must be 32-byte digests";
            if (!(IsInt(Get(p, "expires_at")) && DblOr(Get(p, "expires_at")) >= 0)) return "expires_at must be a non-negative safe integer";
            var rev = Get(p, "revocation");
            if (rev is not D rv) return "revocation must be {epoch_uri, key?}";
            foreach (var k in rv.Keys) if (k != "epoch_uri" && k != "key") return "revocation must be {epoch_uri, key?}";
            if (!(Get(rev, "epoch_uri") is string eu && eu.Length > 0)) return "revocation must be {epoch_uri, key?}";
            if (Has(rev, "key") && !B32(Get(rev, "key"))) return "revocation.key (the revocation authority; absent = the owner) must be canonical base64url (32 bytes)";
            bool v1 = DblOr(Get(p, "version")) == 1;
            if (v1 != !Has(p, "prev")) return "prev is required exactly when version > 1";
            if (Has(p, "prev") && !B32(Get(p, "prev"))) return "prev must be canonical base64url (32 bytes)";
            if (signed)
            {
                if (Has(p, "alg") && Get(p, "alg") is not string) return "alg must be a string";
                var suite = IntentJs.SuiteOf(Get(p, "alg"), Has(p, "alg"));
                if (suite == null) return "alg: unsupported_suite: '" + JsX.Str(Get(p, "alg")) + "'";
                if (suite == "ed25519" && (Has(p, "pq_pk") || Has(p, "pq_sig"))) return "an ed25519 profile must not carry pq_pk / pq_sig";
                if (Get(p, "sig") is not string) return "sig must be a string";
            }
            Pca.Canonicalize(ProfileBody(pm));
            return null;
        }
        catch (Exception e)
        {
            return "malformed profile: " + e.Message;
        }
    }

    static D ProfileBody(D p)
    {
        var b = new D();
        foreach (var k in new[] { "v", "kind", "profile_id", "version", "owner", "scope", "standing", "prior", "expires_at", "revocation", "prev" })
            if (p.ContainsKey(k)) b[k] = p[k];
        return b;
    }

    static byte[] Message(D body) => IntentJs.Message(IntentProfileSigDomain, body);

    /// <summary>Sign a profile version as its owner with the owner's Ed25519 seed (the owner identity must be the signer's key).</summary>
    public static D SignIntentProfile(D body, byte[] ownerSeed) => SignIntentProfile(body, SuiteKey.Ed25519(EdKey.FromSeed(ownerSeed)));

    /// <summary>Sign under any registry suite (ML-DSA, hybrid, ...): alg and pq_pk are signed into the profile.</summary>
    public static D SignIntentProfile(D body, SuiteKey key)
    {
        var owner = key.Ed?.Id ?? throw new ArgumentException("signIntentProfile: signer needs an Ed25519 identity key");
        if (body.ContainsKey("owner") && !(body["owner"] is string bo && bo == owner)) throw new ArgumentException("signIntentProfile: owner does not match the signing key");
        var withOwner = new D(body) { ["owner"] = owner };
        var b = ProfileBody(withOwner);
        var bad = IntentProfileShapeError(b, false);
        if (bad != null) throw new ArgumentException("signIntentProfile: " + bad);
        return IntentStatement.SignSuite(b, key, IntentProfileSigDomain);
    }

    static D Result(string? reason)
    {
        var r = new D { ["ok"] = reason == null };
        if (reason != null) r["reason"] = reason;
        return r;
    }

    /// <summary>{ok: true} or {ok: false, reason}; pin maps an identity to the PQ key the verifier pins for it. Never throws.</summary>
    public static D VerifyIntentProfile(object? p, D? pin = null)
    {
        try
        {
            var bad = IntentProfileShapeError(p);
            if (bad != null) return Result(bad);
            var r = (D)p!;
            var body = IntentJs.BindSuiteFields(ProfileBody(r), r.GetValueOrDefault("alg"), r.ContainsKey("alg"), r.GetValueOrDefault("pq_pk"), r.ContainsKey("pq_pk"));
            if (!IntentJs.VerifyPinnedSuite(r.GetValueOrDefault("alg"), r.ContainsKey("alg"), (string)r["owner"]!, r.GetValueOrDefault("pq_pk"), Message(body), r.GetValueOrDefault("sig"), r.GetValueOrDefault("pq_sig"), Pins(pin)))
                return Result("profile signature invalid");
            return Result(null);
        }
        catch (Exception e)
        {
            return Result("malformed profile: " + e.Message);
        }
    }

    static Dictionary<string, string>? Pins(D? pin)
    {
        if (pin == null) return null;
        var o = new Dictionary<string, string>();
        foreach (var e in pin) if (e.Value is string pv) o[e.Key] = pv;
        return o;
    }

    /// <summary>The content address of a signed profile version.</summary>
    public static string IntentProfileDigest(object? p) => Pca.HashCanonical(new D { ["d"] = IntentProfileRefDomain, ["p"] = p });

    /// <summary>Append-only succession: same id and owner, version + 1, prev = digest(previous).</summary>
    public static D VerifyProfileSuccession(object? prev, object? next)
    {
        var both = new[] { prev, next };
        var names = new[] { "previous", "next" };
        for (int i = 0; i < 2; i++)
        {
            var v = VerifyIntentProfile(both[i]);
            if (!(v["ok"] is true)) return Result(names[i] + " version: " + v.GetValueOrDefault("reason"));
        }
        if (!Equals(Get(next, "profile_id"), Get(prev, "profile_id")) || !Equals(Get(next, "owner"), Get(prev, "owner"))) return Result("a profile version cannot change its id or owner");
        if (!(DblOr(Get(next, "version")) == DblOr(Get(prev, "version")) + 1)) return Result("versions are append-only: next.version must be previous + 1");
        if (!(Get(next, "prev") is string np && IntentProfileDigest(prev) == np)) return Result("next.prev is not the digest of the previous version");
        return Result(null);
    }

    static bool Includes(object? list, object? x)
    {
        foreach (var e in (L)list!) if (e != null && IntentJs.JsonEquals(e, x)) return true;
        return false;
    }

    /// <summary>Is the profile in scope (and unexpired) for this use ({aud, verb, now, semantics?})?</summary>
    public static bool ProfileApplies(D p, D u)
    {
        if (!(DblOr(u.GetValueOrDefault("now")) < DblOr(p.GetValueOrDefault("expires_at")))) return false;
        var scope = p.GetValueOrDefault("scope");
        if (Get(scope, "sites") != null && !Includes(Get(scope, "sites"), u.GetValueOrDefault("aud"))) return false;
        if (Get(scope, "verbs") != null && !Includes(Get(scope, "verbs"), u.GetValueOrDefault("verb"))) return false;
        if (Get(scope, "semantic_types") != null)
        {
            bool any = false;
            if (u.GetValueOrDefault("semantics") != null) foreach (var s in (L)u["semantics"]!) if (Includes(Get(scope, "semantic_types"), s)) any = true;
            if (!any) return false;
        }
        return true;
    }

    static bool AnyRuleMatches(object? rules, D action)
    {
        foreach (var r in (L)rules!) if (Predicates.PredicateMatches(r, action)) return true;
        return false;
    }

    /// <summary>G^std membership: an in-scope action is OUTSIDE the standing layer iff a deny rule matches it (deny wins).</summary>
    public static bool StandingAdmits(D p, D u, D action)
    {
        if (!ProfileApplies(p, u)) return true;
        return !AnyRuleMatches(Get(p.GetValueOrDefault("standing"), "deny"), action);
    }

    /// <summary>The explicit standing-permission layer: true iff an in-scope permit rule matches.</summary>
    public static bool StandingPermits(D p, D u, D action) => ProfileApplies(p, u) && AnyRuleMatches(Get(p.GetValueOrDefault("standing"), "permit"), action);

    /// <summary>The cells that the profile's negative observations veto: [{verb, cell}], de-duplicated in order.</summary>
    public static List<D> ProfileVetoCells(D p, Omega omega)
    {
        var o = new List<D>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var ob in (L)Get(p.GetValueOrDefault("prior"), "observations")!)
        {
            if (DblOr(Get(ob, "y")) != 0) continue;
            var verb = (string)Get(ob, "verb")!;
            var vs = VerbSpaceOf(omega, verb);
            var vals = new Dictionary<string, object?>();
            foreach (var e in (D)Get(ob, "values")!) vals[e.Key] = IsNum(e.Value) ? Dbl(e.Value) : e.Value;
            var cell = vs == null ? null : CellOf(vs, new Outcome(verb, vals));
            if (vs == null || cell == null) continue;
            if (seen.Add(verb + "|" + string.Join(",", cell))) o.Add(new D { ["verb"] = verb, ["cell"] = cell.Select(x => (object?)N(x)).ToList() });
        }
        return o;
    }

    /// <summary>A ceiling function (for a visit decision) from the profile's standing deny rules over outcomes.</summary>
    public static Func<VerbSpace, Outcome, bool> ProfileCeiling(D p, D u) => (vs, o) =>
    {
        var a = IntentPolicyKit.OutcomeToAction(vs, o);
        var act = new D { ["verb"] = a["verb"], ["resource"] = a["resource"], ["params"] = a.GetValueOrDefault("params") };
        var ctx = new D { ["action"] = act };
        if (a.ContainsKey("env")) ctx["env"] = a["env"];
        if (a.ContainsKey("subject")) ctx["subject"] = a["subject"];
        var use = new D(u) { ["verb"] = o.Verb };
        return StandingAdmits(p, use, ctx);
    };

    /// <summary>Is this profile version usable now: signed, unexpired and not revoked per a fresh epoch of its revocation authority? c members: now, maxAgeMs, revocation?, last?, pin?.</summary>
    public static D ProfileUsable(D p, D c)
    {
        var pin = c.GetValueOrDefault("pin") as D;
        var v = VerifyIntentProfile(p, pin);
        if (!(v["ok"] is true)) return v;
        if (!(DblOr(c.GetValueOrDefault("now")) < DblOr(p.GetValueOrDefault("expires_at")))) return Result("the profile has expired");
        var id = (string)p["profile_id"]!;
        var revKey = Get(p.GetValueOrDefault("revocation"), "key");
        var authority = revKey ?? p.GetValueOrDefault("owner");
        var ids = new L { IntentRevocation.ProfileRevocationId(id, JsX.JsNumString(DblOr(p.GetValueOrDefault("version")))) };
        var r = IntentRevocation.CheckSessionRevocation(c.GetValueOrDefault("revocation"), id, authority, ids, DblOr(c.GetValueOrDefault("now")), DblOr(c.GetValueOrDefault("maxAgeMs")),
            "pca-intent-profile:" + id, Pins(pin), c.GetValueOrDefault("last") != null, c.GetValueOrDefault("last"));
        return r == null ? Result(null) : Result("profile revocation: " + r);
    }
}
