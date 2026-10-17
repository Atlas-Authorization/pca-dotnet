// Rule 16: intent world facts, relational dimensions and offer sets (packages/pca/src/oracle-facts.ts decideIntentWorld and
// offer-set.ts decideOfferSet), mirroring OracleFacts.java. The verifier computes env.world; the agent only commits the
// artifacts (intent_session.facts / offer_set). First failure wins, every failure is ok: false; never throws.
using System.Numerics;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class OracleFacts
{
    public const string FactDomain = "atlas-pca/fact/v1\0";
    public const string FactRefDomain = "atlas-pca/fact-ref/v1";
    public const string OfferSetDomain = "atlas-pca/offer-set/v1\0";
    public const string OfferSetRefDomain = "atlas-pca/offer-set-ref/v1";
    public const int MaxCommittedFacts = 16;
    public const int MaxWorlds = 16;
    public const int MaxRelational = 16;
    public const long DefaultWorldSkewMs = 60_000L;
    public const int MaxOffers = 256;
    public const int MaxOfferAttrs = 32;
    public const int MaxQueryKeys = 32;

    /// <summary>The rule-16 verdict: <c>World</c> (world names, then relational names, then the offers name) and <c>SingleSource</c>.</summary>
    public sealed record WorldResult(bool Ok, string? Reason, D? World, List<string>? SingleSource)
    {
        internal static WorldResult Fail(string reason) => new(false, "facts: " + reason, null, null);
    }

    internal static bool IsOne(object? v) => IntentJs.NumOf(v) is double d && d == 1.0;

    internal static string? ValidateFactWire(object? fo)
    {
        if (fo is not D f) return "fact must be an object";
        var m = IntentArtifacts.ClosedMembers(f, new[] { "v", "kind", "name", "subject", "value", "t_obs", "oracle", "sig" }, IntentArtifacts.SuiteMembers, "fact");
        if (m != null) return m;
        if (!IsOne(f["v"]) || f["kind"] as string != "pca-fact") return "fact must be {v: 1, kind: \"pca-fact\"}";
        if (!IntentArtifacts.IsName(f["name"])) return "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$";
        if (!IntentArtifacts.IsBoundedString(f["subject"], 256)) return "'fact.subject' must be a non-empty string (<= 256 bytes)";
        if (!IntentJs.IsInt(f["value"]) && !IntentArtifacts.IsBoundedString(f["value"], 256)) return "'fact.value' must be a safe integer or a non-empty string (<= 256 bytes)";
        if (!IntentJs.IsNonNeg(f["t_obs"])) return "'fact.t_obs' must be a non-negative safe integer";
        if (!IntentArtifacts.IsBoundedString(f["oracle"], 64)) return "'fact.oracle' must be a non-empty string (<= 64 bytes)";
        if (f["sig"] is not string) return "'fact.sig' must be a string";
        return null;
    }

    public static string FactRef(D f) => IntentArtifacts.ArtifactRef(FactRefDomain, "f", f);
    public static string OfferSetRef(D o) => IntentArtifacts.ArtifactRef(OfferSetRefDomain, "o", o);

    internal static long? RatioPpm(long a, long b)
    {
        if (!(b > 0) || a < 0) return null;
        var q = new BigInteger(a) * 1_000_000 / new BigInteger(b);
        return q <= new BigInteger(9007199254740991L) ? (long)q : null;
    }

    /// <summary>A non-empty ARRAY (strict typing: nothing else makes a check active).</summary>
    internal static bool NonEmpty(object? x) => x is L l && l.Count > 0;

    static string? Claim(HashSet<string> names, object? n)
    {
        if (!IntentArtifacts.IsName(n)) return $"dimension name '{n}' must match ^[a-z][a-z0-9_]{{0,63}}$";
        var s = (string)n!;
        if (!names.Add(s)) return $"duplicate dimension name '{s}'";
        return null;
    }

    internal static string? ValidateWorldPolicy(object? po)
    {
        if (po is not D p) return "world policy must be an object";
        var cm = IntentArtifacts.ClosedMembers(p, Array.Empty<string>(), new[] { "skew_ms", "worlds", "relational", "offers" }, "policy");
        if (cm != null) return cm;
        if (p.ContainsKey("skew_ms") && !IntentJs.IsNonNeg(p["skew_ms"])) return "skew_ms must be a non-negative safe integer";
        var names = new HashSet<string>();
        if (IntentJs.Opt(p, "worlds", new L()) is not L worlds || worlds.Count > MaxWorlds) return $"worlds must be a list of at most {MaxWorlds}";
        foreach (var wo in worlds)
        {
            if (wo is not D w) return "world entry must be an object";
            var wm = IntentArtifacts.ClosedMembers(w, new[] { "name", "subject_path", "oracles", "freshness_ms", "min_oracles", "max_faulty" }, Array.Empty<string>(), "world");
            if (wm != null) return wm;
            var e = Claim(names, IntentJs.Get(w, "name"));
            if (e != null) return e;
            var n = w["name"];
            if (IntentJs.Get(w, "subject_path") is not string sp || !sp.StartsWith("action.", StringComparison.Ordinal)) return $"world '{n}': subject_path must be rooted at action.";
            if (!IntentJs.IsNonNeg(IntentJs.Get(w, "freshness_ms"))) return $"world '{n}': freshness_ms must be a non-negative safe integer";
            if (!IntentJs.IsNonNeg(IntentJs.Get(w, "max_faulty"))) return $"world '{n}': max_faulty must be a non-negative safe integer";
            if (!IntentJs.IsInt(IntentJs.Get(w, "min_oracles")) || IntentJs.NumOf(w["min_oracles"])!.Value < 2 * IntentJs.NumOf(w["max_faulty"])!.Value + 1)
                return $"world '{n}': min_oracles must be a safe integer >= 2*max_faulty+1";
            if (IntentJs.Get(w, "oracles") is not L oracles || oracles.Count < IntentJs.NumOf(w["min_oracles"])!.Value) return $"world '{n}': fewer pinned oracles than min_oracles";
            var kids = new HashSet<string>();
            foreach (var o in oracles)
            {
                if (o is not D od || IntentArtifacts.ClosedMembers(od, new[] { "kid", "pk" }, new[] { "pq_pk" }, "oracle") != null
                    || !IntentArtifacts.IsBoundedString(IntentJs.Get(od, "kid"), 64) || !IntentArtifacts.IsDigest(IntentJs.Get(od, "pk"))
                    || !IntentArtifacts.PinPqOk(od) || !kids.Add((string)od["kid"]!)) return $"world '{n}': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk";
            }
        }
        if (IntentJs.Opt(p, "relational", new L()) is not L rel || rel.Count > MaxRelational) return $"relational must be a list of at most {MaxRelational}";
        foreach (var ro in rel)
        {
            if (ro is not D r) return "relational entry must be an object";
            var rm = IntentArtifacts.ClosedMembers(r, new[] { "name", "fn", "a", "b" }, Array.Empty<string>(), "relational");
            if (rm != null) return rm;
            var e = Claim(names, IntentJs.Get(r, "name"));
            if (e != null) return e;
            var n = (string)r["name"]!;
            var fn = IntentJs.Get(r, "fn") as string;
            if (fn != "sub" && fn != "ratio_ppm") return $"relational '{n}': fn must be \"sub\" or \"ratio_ppm\"";
            foreach (var op in new[] { IntentJs.Get(r, "a"), IntentJs.Get(r, "b") })
            {
                bool ok = IntentArtifacts.IsParamPath(op);
                if (!ok && op is string os && os.StartsWith("env.world.", StringComparison.Ordinal))
                {
                    var rest = os.Substring("env.world.".Length);
                    ok = names.Contains(rest) && rest != n;
                }
                if (!ok) return $"relational '{n}': operand '{op}' must be an action.params path or an earlier env.world dimension";
            }
        }
        if (p.ContainsKey("offers"))
        {
            var e = ValidateOfferPolicy(p["offers"]) ?? Claim(names, IntentJs.Get(p["offers"], "name"));
            if (e != null) return e;
        }
        return null;
    }

    internal static string? ValidateOfferPolicy(object? po)
    {
        if (po is not D p) return "offers policy must be an object";
        var cm = IntentArtifacts.ClosedMembers(p, new[] { "name", "site_keys", "max_age_ms", "offer_param", "filter" }, Array.Empty<string>(), "offers");
        if (cm != null) return cm;
        if (IntentJs.Get(p, "name") is not string) return "offers policy needs a name";
        if (IntentJs.Get(p, "site_keys") is not L keys || keys.Count == 0) return "offers policy needs at least one pinned site key";
        var kids = new HashSet<string>();
        foreach (var k in keys)
        {
            if (k is not D kd || IntentArtifacts.ClosedMembers(kd, new[] { "kid", "pk" }, new[] { "pq_pk" }, "site_key") != null
                || !IntentArtifacts.IsBoundedString(IntentJs.Get(kd, "kid"), 64) || !IntentArtifacts.IsDigest(IntentJs.Get(kd, "pk"))
                || !IntentArtifacts.PinPqOk(kd) || !kids.Add((string)kd["kid"]!)) return "offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk";
        }
        if (!IntentJs.IsNonNeg(IntentJs.Get(p, "max_age_ms"))) return "offers policy: max_age_ms must be a non-negative safe integer";
        if (IntentJs.Get(p, "offer_param") is not string param || !param.StartsWith("action.params.", StringComparison.Ordinal)) return "offers policy: offer_param must be an action.params.* path";
        if (IntentJs.Get(p, "filter") is not D f || IntentArtifacts.ClosedMembers(f, new[] { "query", "offer" }, Array.Empty<string>(), "filter") != null
            || IntentJs.Get(f, "query") is not D fq || IntentJs.Get(f, "offer") is not D fo) return "offers policy: filter must be exactly {query: {}, offer: {}}";
        foreach (var v in fq.Values.Concat(fo.Values)) if (!IntentArtifacts.IsScalar(v)) return "offers policy: filter values must be scalars";
        return null;
    }

    /// <summary>True iff rule 16 is active: <c>facts</c> a non-empty array, <c>offer_set</c> a string, <c>worlds</c> /
    /// <c>relational</c> a non-empty array, or <c>offers</c> a plain object.</summary>
    public static bool IntentWorldActive(object? committed, object? policy) =>
        NonEmpty(IntentJs.Get(committed, "facts")) || IntentJs.Get(committed, "offer_set") is string
        || NonEmpty(IntentJs.Get(policy, "worlds")) || NonEmpty(IntentJs.Get(policy, "relational")) || IntentJs.Get(policy, "offers") is D;

    static object? Prop(object? o, string k) => o == null ? throw new ArgumentException("cannot read '" + k + "' of null") : IntentJs.Get(o, k);

    static string? SubjectOf(object? action, string path)
    {
        if (path == "action.resource") return Prop(action, "resource") as string;
        if (path == "action.verb") return Prop(action, "verb") as string;
        if (action == null) throw new ArgumentException("no action");
        var r = IntentArtifacts.ResolveParamPath(IntentArtifacts.ActionParams(action), path);
        return r.Found ? r.Value as string : null;
    }

    /// <summary>The <c>primitives.intent_world</c> entry point: normalizes <paramref name="input"/>, then decides.</summary>
    public static WorldResult DecideIntentWorld(object? input)
    {
        try { return Decide((D)IntentJs.Normalize(input)!); }
        catch (Exception e) { return WorldResult.Fail("evaluation error (fail closed): " + e.GetType().Name); }
    }

    /// <summary>Rule 16 over an already normalized input <c>{now, aud, session, action, committed, facts?, offer_set?, policy}</c>.</summary>
    internal static WorldResult Decide(D input)
    {
        try
        {
            var policyO = IntentJs.Opt(input, "policy", new D());
            var pe = ValidateWorldPolicy(policyO);
            if (pe != null) return WorldResult.Fail("policy misconfigured (fail closed): " + pe);
            var policy = (D)policyO!;
            // CLOCK: a `now` that is not a safe integer is never coerced: every fact and every offer set is stale
            bool clock = IntentJs.IsInt(IntentJs.Get(input, "now"));
            double now = clock ? IntentJs.NumOf(input["now"])!.Value : double.NaN;
            double skew = policy.ContainsKey("skew_ms") ? IntentJs.NumOf(policy["skew_ms"])!.Value : DefaultWorldSkewMs;
            if (IntentJs.Get(input, "action") is not D act) return WorldResult.Fail("action must be an object");
            if (IntentJs.Opt(act, "params", new D()) is not D) return WorldResult.Fail("action.params must be an object");
            if (IntentJs.Opt(input, "committed", new D()) is not D committed) return WorldResult.Fail("committed must be an object");
            if (IntentJs.Opt(committed, "facts", new L()) is not L committedFacts || committedFacts.Count > MaxCommittedFacts)
                return WorldResult.Fail($"committed facts must be a list of at most {MaxCommittedFacts} digests");
            var seen = new HashSet<string>();
            foreach (var d in committedFacts)
            {
                if (!IntentArtifacts.IsDigest(d)) return WorldResult.Fail("a committed fact digest is not canonical base64url (32 bytes)");
                if (!seen.Add((string)d!)) return WorldResult.Fail("duplicate committed fact digest");
            }
            bool offerCommitted = committed.ContainsKey("offer_set");
            var committedOffer = IntentJs.Get(committed, "offer_set");
            if (offerCommitted && !IntentArtifacts.IsDigest(committedOffer)) return WorldResult.Fail("the committed offer_set is not canonical base64url (32 bytes)");

            if (IntentJs.Opt(input, "facts", new L()) is not L supplied) return WorldResult.Fail("facts must be an array");
            if (input.ContainsKey("offer_set") && input["offer_set"] is not D) return WorldResult.Fail("offer_set must be an object");
            var byRef = new Dictionary<string, D>();
            foreach (var f in supplied)
            {
                if (ValidateFactWire(f) != null) continue;
                try { byRef[FactRef((D)f!)] = (D)f!; } catch (Exception) { /* no reference */ }
            }
            var worlds = (L)IntentJs.Opt(policy, "worlds", new L())!;
            var accepted = new List<D>();
            var pairs = new HashSet<string>();
            foreach (var d in committedFacts)
            {
                if (!byRef.TryGetValue((string)d!, out var fact)) return WorldResult.Fail("a committed fact was not supplied (or is malformed)");
                var se = IntentArtifacts.ArtifactSuiteError(fact);
                if (se != null) return WorldResult.Fail("fact signature suite: " + se);
                var w = worlds.Select(x => x as D).FirstOrDefault(x => x != null && Equals(fact["name"], IntentJs.Get(x, "name")));
                if (w == null) return WorldResult.Fail($"fact for undeclared world '{fact["name"]}'");
                var pin = ((L)w["oracles"]!).Select(x => x as D).FirstOrDefault(x => x != null && Equals(fact["oracle"], IntentJs.Get(x, "kid")));
                if (pin == null) return WorldResult.Fail($"oracle '{fact["oracle"]}' is not pinned for world '{w["name"]}'");
                if (!IntentArtifacts.VerifyArtifactSig(FactDomain, fact, pin["pk"], IntentJs.Get(pin, "pq_pk"))) return WorldResult.Fail($"bad oracle signature on a '{w["name"]}' fact");
                var subject = SubjectOf(IntentJs.Get(input, "action"), (string)w["subject_path"]!);
                if (subject == null || (string)fact["subject"]! != subject) return WorldResult.Fail($"a '{w["name"]}' fact names another subject");
                if (!pairs.Add(w["name"] + "\u0000" + fact["oracle"])) return WorldResult.Fail($"two facts from oracle '{fact["oracle"]}' for world '{w["name"]}'");
                accepted.Add(fact);
            }

            var world = new D();
            var singleSource = new List<string>();
            foreach (var wo in worlds)
            {
                var w = (D)wo!;
                var name = (string)w["name"]!;
                double freshness = IntentJs.NumOf(w["freshness_ms"])!.Value;
                var fresh = accepted.Where(f =>
                {
                    double t = IntentJs.NumOf(f["t_obs"])!.Value;
                    return clock && (string)f["name"]! == name && t <= now + skew && now - t <= freshness;
                }).ToList();
                double minOracles = IntentJs.NumOf(w["min_oracles"])!.Value;
                if (fresh.Count < minOracles) return WorldResult.Fail($"world '{name}' has {fresh.Count} fresh fact(s), needs {IntentJs.Lng(w["min_oracles"])}");
                var nums = fresh.Where(f => IntentJs.IsNumber(f["value"])).Select(f => IntentJs.Lng(f["value"])).ToList();
                if (nums.Count == fresh.Count)
                {
                    nums.Sort();
                    world[name] = IntentJs.OfLong(nums[(nums.Count - 1) / 2]);
                }
                else if (nums.Count == 0)
                {
                    var v = (string)fresh[0]["value"]!;
                    if (fresh.Any(f => f["value"] as string != v)) return WorldResult.Fail($"world '{name}': string facts disagree");
                    world[name] = v;
                }
                else return WorldResult.Fail($"world '{name}': facts mix integer and string values");
                if (minOracles == 1) singleSource.Add(name);
            }

            foreach (var ro in (L)IntentJs.Opt(policy, "relational", new L())!)
            {
                var r = (D)ro!;
                var a = Operand(world, input, (string)r["a"]!);
                var b = Operand(world, input, (string)r["b"]!);
                if (a == null || b == null) return WorldResult.Fail($"relational '{r["name"]}': an operand is missing or not a safe integer");
                long? v = r["fn"] as string == "sub" ? a.Value - b.Value : RatioPpm(a.Value, b.Value);
                if (v == null || Math.Abs(v.Value) > 9007199254740991L) return WorldResult.Fail($"relational '{r["name"]}': result undefined or outside the safe integer range");
                world[(string)r["name"]!] = IntentJs.OfLong(v.Value);
            }

            if (policy.ContainsKey("offers"))
            {
                var op = (D)policy["offers"]!;
                var (why, excess) = DecideOfferSet(op, offerCommitted ? (string)committedOffer! : null, input.ContainsKey("offer_set"), IntentJs.Get(input, "offer_set"),
                    ActionParamsOf(input), IntentJs.Get(input, "aud"), IntentJs.Get(input, "session"), clock, now, skew);
                if (why != null) return WorldResult.Fail(why);
                world[(string)op["name"]!] = IntentJs.OfLong(excess);
            }
            return new WorldResult(true, null, world, singleSource);
        }
        catch (Exception e) { return WorldResult.Fail("evaluation error (fail closed): " + e.GetType().Name); }
    }

    /// <summary><c>input.action.params</c> (absent = {}); a missing action or a present non-object params fails closed.</summary>
    static D ActionParamsOf(D input) =>
        IntentArtifacts.ActionParams(IntentJs.Get(input, "action") ?? throw new ArgumentException("no action"));

    static long? Operand(D world, D input, string path)
    {
        if (path.StartsWith("env.world.", StringComparison.Ordinal))
        {
            var v = world.TryGetValue(path.Substring("env.world.".Length), out var x) ? x : null;
            return IntentJs.IsInt(v) ? IntentJs.Lng(v) : null;
        }
        var r = IntentArtifacts.ResolveParamPath(ActionParamsOf(input), path);
        return r.Found && IntentJs.IsInt(r.Value) ? IntentJs.Lng(r.Value) : null;
    }

    internal static string? ValidateOfferSetWire(object? oo)
    {
        if (oo is not D o) return "offer set must be an object";
        var m = IntentArtifacts.ClosedMembers(o, new[] { "v", "kind", "site", "session", "query", "rank", "complete", "offers", "issued_at", "kid", "sig" }, IntentArtifacts.SuiteMembers, "offer_set");
        if (m != null) return m;
        if (!IsOne(o["v"]) || o["kind"] as string != "pca-offer-set") return "offer set must be {v: 1, kind: \"pca-offer-set\"}";
        if (!IntentArtifacts.IsBoundedString(o["site"], 256)) return "'offer_set.site' must be a non-empty string (<= 256 bytes)";
        if (!IntentArtifacts.IsDigest(o["session"])) return "'offer_set.session' must be canonical base64url (32 bytes)";
        if (o["query"] is not D q || q.Count > MaxQueryKeys) return $"'offer_set.query' must be an object with <= {MaxQueryKeys} keys";
        foreach (var (k, v) in q) if (!IntentArtifacts.IsBoundedString(k, 64) || !IntentArtifacts.IsScalar(v)) return $"'offer_set.query.{k}' must be a scalar";
        if (o["rank"] as string != "price_asc") return "'offer_set.rank' must be \"price_asc\"";
        if (o["complete"] is not bool) return "'offer_set.complete' must be a boolean";
        if (o["offers"] is not L offers || offers.Count == 0 || offers.Count > MaxOffers) return $"'offer_set.offers' must hold 1..{MaxOffers} offers";
        var ids = new HashSet<string>();
        for (int i = 0; i < offers.Count; i++)
        {
            if (offers[i] is not D x) return $"offer {i} must be an object";
            if (!IntentArtifacts.IsBoundedString(IntentJs.Get(x, "offer_id"), 128)) return $"offer {i}: 'offer_id' must be a non-empty string (<= 128 bytes)";
            if (!ids.Add((string)x["offer_id"]!)) return $"offer {i}: duplicate offer_id";
            if (!IntentJs.IsNonNeg(IntentJs.Get(x, "price"))) return $"offer {i}: 'price' must be a non-negative safe integer";
            var attrs = x.Keys.Where(k => k != "offer_id" && k != "price").ToList();
            if (attrs.Count > MaxOfferAttrs) return $"offer {i}: more than {MaxOfferAttrs} attributes";
            foreach (var k in attrs) if (!IntentArtifacts.IsBoundedString(k, 64) || !IntentArtifacts.IsScalar(x[k])) return $"offer {i}: attribute '{k}' must be a scalar";
        }
        if (!IntentJs.IsNonNeg(o["issued_at"])) return "'offer_set.issued_at' must be a non-negative safe integer";
        if (!IntentArtifacts.IsBoundedString(o["kid"], 64)) return "'offer_set.kid' must be a non-empty string (<= 64 bytes)";
        if (o["sig"] is not string) return "'offer_set.sig' must be a string";
        return null;
    }

    internal static bool OfferMatches(D offer, D f) => f.All(e => offer.TryGetValue(e.Key, out var v) && IntentArtifacts.ScalarEq(v, e.Value));
    internal static bool QueryCovers(D query, D fq) => query.All(e => fq.TryGetValue(e.Key, out var v) && IntentArtifacts.ScalarEq(v, e.Value));

    /// <summary>(reason, 0) on failure, (null, excess) on success.</summary>
    internal static (string? Why, long Excess) DecideOfferSet(D policy, string? committed, bool supplied, object? o, D parameters, object? aud,
        object? session, bool clock, double now, double skewMs)
    {
        if (committed == null) return ("offers: the PCActn commits no offer set but the policy requires one", 0);
        if (!supplied) return ("offers: the committed offer set was not supplied", 0);
        var w = ValidateOfferSetWire(o);
        if (w != null) return ("offers: " + w, 0);
        var os = (D)o!;
        string reference;
        try { reference = OfferSetRef(os); } catch (Exception) { return ("offers: the offer set is not strictly canonical", 0); }
        if (reference != committed) return ("offers: the supplied offer set does not match the committed reference", 0);
        var se = IntentArtifacts.ArtifactSuiteError(os);
        if (se != null) return ("offers: signature suite: " + se, 0);
        var key = ((L)policy["site_keys"]!).Select(k => k as D).FirstOrDefault(k => k != null && Equals(os["kid"], IntentJs.Get(k, "kid")));
        if (key == null) return ($"offers: signing key '{os["kid"]}' is not pinned", 0);
        if (!IntentArtifacts.VerifyArtifactSig(OfferSetDomain, os, key["pk"], IntentJs.Get(key, "pq_pk"))) return ("offers: bad site signature", 0);
        if (!Equals(os["site"], aud)) return ("offers: the offer set was issued for another audience", 0);
        if (!Equals(os["session"], session)) return ("offers: the offer set is bound to another session", 0);
        if (!clock) return ("offers: no usable clock (now must be a safe integer): the offer set counts as stale", 0);
        double issued = IntentJs.NumOf(os["issued_at"])!.Value;
        if (issued > now + skewMs) return ("offers: the offer set is issued in the future", 0);
        if (now - issued > IntentJs.NumOf(policy["max_age_ms"])!.Value) return ("offers: the offer set is stale", 0);
        if (os["complete"] is not true) return ("offers: the offer set is not declared complete", 0);
        var filter = (D)policy["filter"]!;
        if (!QueryCovers((D)os["query"]!, (D)filter["query"]!)) return ("offers: the search was narrowed beyond the intent filter (coverage)", 0);
        var id = IntentArtifacts.ResolveParamPath(parameters, policy["offer_param"]);
        if (!id.Found || id.Value is not string chosenId) return ("offers: the action names no offer id at the declared parameter", 0);
        var offers = ((L)os["offers"]!).Cast<D>().ToList();
        var chosen = offers.FirstOrDefault(x => x["offer_id"] as string == chosenId);
        if (chosen == null) return ("offers: the chosen offer is not in the signed offer set", 0);
        var fo = (D)filter["offer"]!;
        if (!OfferMatches(chosen, fo)) return ("offers: the chosen offer does not satisfy the intent filter", 0);
        long price = IntentJs.Lng(chosen["price"]);
        long min = price;
        foreach (var x in offers) { long px = IntentJs.Lng(x["price"]); if (OfferMatches(x, fo) && px < min) min = px; }
        return (null, price - min);
    }
}
