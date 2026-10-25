// Rule 15: accumulators, monitors, sequencer reservation receipts and the sequencer's root-signed key sets
// (packages/pca/src/intent-acc.ts), mirroring IntentAcc.java. The verifier never takes an accumulator value from the agent:
// it recomputes the post-action value from its own pre-state (site-local) or from a sequencer-signed receipt.
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class IntentAcc
{
    public const int MaxSessionAccumulators = 16;
    public const int MaxSessionMonitors = 16;
    public const int MaxMonitorWithin = 64;
    public const string AccReceiptDomain = "atlas-pca/acc-receipt/v1\0";
    public const string AccReceiptRefDomain = "atlas-pca/acc-receipt-ref/v1";
    public const string AccReserveDomain = "atlas-pca/acc-reserve/v1";
    public const string SequencerKeysDomain = "atlas-pca/sequencer-keys/v1\0";
    public const string SequencerKeysRefDomain = "atlas-pca/sequencer-keys-ref/v1";
    public const long ReceiptSkewMs = 60_000L;
    /// <summary>A receipt lives at most this long: <c>issued_at &lt;= expires_at &lt;= issued_at + 900000</c> (15 min).</summary>
    public const long MaxReceiptLifetimeMs = 900_000L;
    /// <summary>Default bound on a receipt's age at verification, policy <c>acc.max_receipt_age_s</c> (15 min).</summary>
    public const long DefaultMaxReceiptAgeMs = 900_000L;
    /// <summary>Default bound on a key set's age, policy <c>acc.max_keyset_age_s</c> (1 h).</summary>
    public const long DefaultMaxKeySetAgeMs = 3_600_000L;
    static readonly string[] AccAggs = { "sum", "count", "distinct", "max" };
    static readonly string[] MonitorKinds = { "requires_prior", "precedes", "never", "always", "responds_within" };
    static readonly Regex KidRe = new(@"^[A-Za-z0-9_.:-]{1,64}\z", RegexOptions.CultureInvariant);
    static readonly Regex ParamPathRe = new(@"^action\.params\.[A-Za-z0-9_]{1,64}\z", RegexOptions.CultureInvariant);
    static readonly Regex UnitRe = new(@"^[a-z0-9_]+(?:\.[a-z0-9_]+)*\z", RegexOptions.CultureInvariant);
    static readonly string[] ReceiptKeys = { "v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at",
        "expires_at", "kid", "ledger", "signer", "alg", "pq_pk", "sig", "pq_sig" };

    static bool IdOk(object? v) => v is string s && IntentSession.AccIdRe.IsMatch(s);
    static bool DeclIdOk(object? v) => IdOk(v) && !ActionSchema.ReservedNames.Contains((string)v!);
    static bool ExactKeys(object? o, params string[] keys) => o is D m && m.Count == keys.Length && keys.All(m.ContainsKey);

    /// <summary>The state set Q of a monitor.</summary>
    internal static List<string> MonitorStates(D m)
    {
        switch (IntentJs.Get(m, "kind") as string)
        {
            case "requires_prior": case "precedes": return new() { "unmet", "met" };
            case "never": return new() { "clean", "seen" };
            case "always": return new() { "ok", "broken" };
            case "responds_within":
                {
                    long w = IntentJs.IsInt(IntentJs.Get(m, "within")) ? IntentJs.Lng(m["within"]) : 0;
                    var output = new List<string> { "idle" };
                    for (long i = 1; i <= w; i++) output.Add("pending:" + i);
                    output.Add("missed");
                    return output;
                }
            default: return new();
        }
    }

    static bool PredicateShapeOk(object? p) =>
        p is D d && (IntentJs.Get(d, "verb") is string || (IntentJs.Get(d, "verb") is L vl && vl.Count > 0 && vl.All(x => x is string)));

    /// <summary>Shape of an accumulator declaration in S. Null = well-formed.</summary>
    internal static string? AccumulatorDeclError(object? aO)
    {
        if (aO is not D a) return "accumulator must be an object";
        foreach (var k in a.Keys) if (k is not ("id" or "agg" or "val" or "unit" or "sel" or "win" or "key" or "domain_max" or "cap" or "holder")) return $"accumulator: unknown member '{k}'";
        if (!DeclIdOk(IntentJs.Get(a, "id"))) return "accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype";
        var at = $"accumulator '{a["id"]}'";
        var agg = IntentJs.Get(a, "agg") as string;
        if (agg == null || !AccAggs.Contains(agg)) return at + ": unknown agg";
        if (a.ContainsKey("val") && (a["val"] is not string vs || !ParamPathRe.IsMatch(vs))) return at + ": val must be action.params.<name>";
        if (a.ContainsKey("unit") && (a["unit"] is not string us || us.Length > 64 || !UnitRe.IsMatch(us))) return at + ": unit must be a unit id";
        if (IntentJs.Get(a, "sel") is not D sel) return at + ": sel must be an object";
        foreach (var k in sel.Keys) if (k is not ("verbs" or "accumulates_into" or "event")) return $"{at}: sel has unknown member '{k}'";
        if (sel.ContainsKey("verbs") && (sel["verbs"] is not L verbs || verbs.Count == 0 || verbs.Count > 64 || verbs.Any(x => x is not string xs || xs.Length == 0)))
            return at + ": sel.verbs must be 1..64 verb names";
        if (sel.ContainsKey("accumulates_into") && (sel["accumulates_into"] is not string ai || !UnitRe.IsMatch(ai))) return at + ": sel.accumulates_into must be a unit id";
        if (sel.ContainsKey("event") && sel["event"] as string is not ("intent_required" or "question" or "clarification")) return at + ": unknown sel.event";
        bool actionSel = sel.ContainsKey("verbs") || sel.ContainsKey("accumulates_into");
        if (actionSel == sel.ContainsKey("event")) return at + ": sel names actions (verbs / accumulates_into) or a wallet event, exactly one kind";
        if (IntentJs.Get(a, "win") is not D w) return at + ": win must be an object";
        switch (IntentJs.Get(w, "kind") as string)
        {
            case "task":
                if (w.Count != 1) return at + ": win {kind: task} has no other member";
                break;
            case "sliding":
                if (!ExactKeys(w, "kind", "ms") || !(IntentJs.IsInt(w["ms"]) && IntentJs.NumOf(w["ms"]) > 0)) return at + ": win sliding needs a positive ms";
                break;
            case "period":
                if (!ExactKeys(w, "kind", "ms", "t0") || !(IntentJs.IsInt(w["ms"]) && IntentJs.NumOf(w["ms"]) > 0) || !IntentJs.IsNonNeg(w["t0"])) return at + ": win period needs a positive ms and t0 >= 0";
                break;
            default:
                return at + ": unknown win kind";
        }
        bool keyNull = a.ContainsKey("key") && a["key"] == null;
        if (!keyNull && (IntentJs.Get(a, "key") is not string ks || !ParamPathRe.IsMatch(ks))) return at + ": key must be null or action.params.<name>";
        if (a.ContainsKey("domain_max") && !IntentJs.IsNonNeg(a["domain_max"])) return at + ": domain_max must be a non-negative safe integer";
        if (a.ContainsKey("cap") && !IntentJs.IsNonNeg(a["cap"])) return at + ": cap must be a non-negative safe integer";
        if (IntentJs.Get(a, "holder") is not D h) return at + ": holder must be an object";
        var hk = IntentJs.Get(h, "kind") as string;
        if (hk is "site_local" or "wallet")
        {
            if (h.Count != 1) return $"{at}: holder {hk} has no other member";
        }
        else if (hk == "sequenced")
        {
            foreach (var k in h.Keys) if (k is not ("kind" or "uri" or "root" or "root_alg" or "root_pq_pk" or "keys_uri")) return $"{at}: holder sequenced has unknown member '{k}'";
            if (IntentJs.Get(h, "uri") is not string uri || uri.Length == 0) return at + ": holder sequenced needs a uri";
            if (!IntentJs.B32(IntentJs.Get(h, "root"))) return at + ": holder.root is not canonical base64url (32 bytes)";
            var rse = IntentJs.SuiteError(h.GetValueOrDefault("root_alg"), h.ContainsKey("root_alg"));
            if (rse != null) return at + ": holder.root_alg: " + rse;
            if (h.ContainsKey("root_pq_pk") && !IntentJs.B64Any(h["root_pq_pk"])) return at + ": holder.root_pq_pk is not canonical base64url";
            if (h.ContainsKey("keys_uri") && (h["keys_uri"] is not string ku || ku.Length == 0)) return at + ": holder.keys_uri must be a non-empty string";
        }
        else return at + ": unknown holder kind";
        bool wallet = hk == "wallet";
        if (wallet != sel.ContainsKey("event")) return at + ": wallet events are wallet-held and only wallet events are";
        if (!wallet)
        {
            if (agg != "count" && !a.ContainsKey("val") && !sel.ContainsKey("accumulates_into")) return $"{at}: {agg} needs val (or sel.accumulates_into for a sum)";
            if (agg != "sum" && agg != "count" && !a.ContainsKey("val")) return $"{at}: {agg} needs val";
            if (agg == "count" && a.ContainsKey("val")) return at + ": count takes no val";
        }
        return null;
    }

    /// <summary>Shape of a monitor declaration in S. Null = well-formed.</summary>
    internal static string? MonitorDeclError(object? mO)
    {
        if (mO is not D m) return "monitor must be an object";
        foreach (var k in m.Keys) if (k is not ("id" or "kind" or "p" or "q" or "status" or "within")) return $"monitor: unknown member '{k}'";
        if (!DeclIdOk(IntentJs.Get(m, "id"))) return "monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype";
        var at = $"monitor '{m["id"]}'";
        var kind = IntentJs.Get(m, "kind") as string;
        if (kind == null || !MonitorKinds.Contains(kind)) return at + ": unknown kind";
        if (!PredicateShapeOk(IntentJs.Get(m, "p"))) return at + ": p must be a predicate";
        bool needsQ = kind is "requires_prior" or "precedes" or "responds_within";
        if (needsQ != m.ContainsKey("q")) return at + ": q is required exactly for requires_prior / precedes / responds_within";
        if (m.ContainsKey("q") && !PredicateShapeOk(m["q"])) return at + ": q must be a predicate";
        if (m.ContainsKey("status") && m["status"] as string is not ("admitted" or "committed")) return at + ": status must be admitted or committed";
        if ((kind == "responds_within") != m.ContainsKey("within")) return at + ": within is required exactly for responds_within";
        if (m.ContainsKey("within") && !(IntentJs.IsInt(m["within"]) && IntentJs.NumOf(m["within"]) >= 1 && IntentJs.NumOf(m["within"]) <= MaxMonitorWithin))
            return $"{at}: within must be an integer in 1..{MaxMonitorWithin}";
        return null;
    }

    /// <summary>The action is selected: its verb is listed, or its schema verb has a parameter feeding <c>sel.accumulates_into</c>.</summary>
    internal static bool AccSelects(D a, string verb, object? schema)
    {
        var sel = (D)a["sel"]!;
        if (sel.ContainsKey("event")) return false;
        if (IntentJs.Get(sel, "verbs") is L verbs && verbs.Any(x => x as string == verb)) return true;
        if (sel.ContainsKey("accumulates_into") && schema != null)
        {
            var v = ActionSchema.SchemaVerb(schema, verb);
            return v != null && ActionSchema.AccumulationParams(v, (string)sel["accumulates_into"]!).Count > 0;
        }
        return false;
    }

    /// <summary>val(omega): a reason, or the value and (distinct) key.</summary>
    internal sealed record AccValue(string? Reason, long Val, string? Key);

    internal static string? DistinctKey(object? x)
    {
        if (x is string || IntentJs.IsInt(x))
        {
            try { return IntentJs.Canon(x); } catch (Exception) { return null; }
        }
        return null;
    }

    internal static AccValue AccValueOf(D a, string verb, D parameters, object? schema)
    {
        var agg = IntentJs.Get(a, "agg") as string;
        if (agg == "count") return new(null, 1, null);
        if (agg == "distinct")
        {
            var name = ((string)a["val"]!).Substring("action.params.".Length);
            var k = parameters.TryGetValue(name, out var dv) ? DistinctKey(dv) : null;
            return k == null ? new(a["val"] + " must be a string or a safe integer", 0, null) : new(null, 1, k);
        }
        if (a.ContainsKey("val"))
        {
            var name = ((string)a["val"]!).Substring("action.params.".Length);
            return parameters.TryGetValue(name, out var x) && IntentJs.IsNonNeg(x) ? new(null, IntentJs.Lng(x), null) : new(a["val"] + " must be a non-negative safe integer", 0, null);
        }
        var v = schema != null ? ActionSchema.SchemaVerb(schema, verb) : null;
        if (v == null) return new($"no schema entry for '{verb}' to read accumulates_into", 0, null);
        long s = 0;
        foreach (var p in ActionSchema.AccumulationParams(v, (string)((D)a["sel"]!)["accumulates_into"]!))
        {
            var name = p.Substring("action.params.".Length);
            if (!parameters.TryGetValue(name, out var x)) continue;
            if (!IntentJs.IsNonNeg(x)) return new(p + " must be a non-negative safe integer", 0, null);
            s += IntentJs.Lng(x);
            if (s > 9007199254740991L) return new("accumulated value exceeds 2^53-1", 0, null);
        }
        return new(null, s, null);
    }

    static string Want(string? agg) => agg switch { "sum" => "sum", "count" => "count", "max" => "max", _ => "values" };

    internal static string? PreStateError(string? agg, object? sO)
    {
        if (sO is not D s) return "pre-state must be an object";
        var want = Want(agg);
        if (s.Count != 1 || !s.ContainsKey(want)) return $"pre-state of a {agg} accumulator is {{{want}}}";
        if (want == "values")
        {
            if (s["values"] is not L vs || vs.Any(x => x is not string)) return "pre-state values must be strings";
            if (vs.Cast<string>().Distinct().Count() != vs.Count) return "pre-state values must be distinct";
            return null;
        }
        return IntentJs.IsNonNeg(s[want]) ? null : $"pre-state {want} must be a non-negative safe integer";
    }

    /// <summary>The post-action value (null when it leaves the safe-integer range).</summary>
    internal static long? CombineAcc(string? agg, D pre, AccValue v)
    {
        long post = agg switch
        {
            "sum" => IntentJs.Lng(pre["sum"]) + v.Val,
            "count" => IntentJs.Lng(pre["count"]) + 1,
            "max" => Math.Max(IntentJs.Lng(pre["max"]), v.Val),
            _ => ((L)pre["values"]!).Count + (((L)pre["values"]!).Any(x => x as string == v.Key) ? 0 : 1),
        };
        return post <= 9007199254740991L ? post : null;
    }

    internal static long PreValue(string? agg, D pre) => agg switch
    {
        "sum" => IntentJs.Lng(pre["sum"]),
        "count" => IntentJs.Lng(pre["count"]),
        "max" => IntentJs.Lng(pre["max"]),
        _ => ((L)pre["values"]!).Count,
    };

    /// <summary>The digest a reservation binds: the PCActn without sig, pq_sig, threshold and intent_session.</summary>
    public static string PcactnReservationDigest(D p)
    {
        var body = new D(p);
        foreach (var k in new[] { "sig", "pq_sig", "threshold", "intent_session" }) body.Remove(k);
        return IntentJs.Ref(AccReserveDomain, "b", body);
    }

    internal static string? ReceiptShapeError(object? rO)
    {
        if (rO is not D r) return "receipt is not an object";
        foreach (var k in r.Keys) if (!ReceiptKeys.Contains(k)) return $"receipt: unknown member '{k}'";
        if (!OracleFacts.IsOne(IntentJs.Get(r, "v")) || IntentJs.Get(r, "kind") as string != "pca-acc-receipt") return "not a pca-acc-receipt v1";
        if (!IntentJs.B32(IntentJs.Get(r, "session"))) return "receipt.session is not canonical base64url (32 bytes)";
        if (!IdOk(IntentJs.Get(r, "acc"))) return "receipt.acc is not an accumulator id";
        if (!(IntentJs.IsInt(IntentJs.Get(r, "seq")) && IntentJs.NumOf(r["seq"]) >= 1)) return "receipt.seq must be a safe integer >= 1";
        if (!IntentJs.IsNonNeg(IntentJs.Get(r, "pre")) || !IntentJs.IsNonNeg(IntentJs.Get(r, "delta")) || !IntentJs.IsNonNeg(IntentJs.Get(r, "post"))) return "receipt pre / delta / post must be non-negative safe integers";
        if (!IntentJs.B32(IntentJs.Get(r, "pcactn_digest"))) return "receipt.pcactn_digest is not canonical base64url (32 bytes)";
        if (IntentJs.Get(r, "aud") is not string aud || aud.Length == 0) return "receipt.aud must be a non-empty string";
        if (!IntentJs.IsNonNeg(IntentJs.Get(r, "issued_at")) || !IntentJs.IsNonNeg(IntentJs.Get(r, "expires_at"))) return "receipt.issued_at / expires_at must be non-negative safe integers";
        double ia = IntentJs.NumOf(IntentJs.Get(r, "issued_at"))!.Value, ea = IntentJs.NumOf(IntentJs.Get(r, "expires_at"))!.Value;
        if (!(ea >= ia && ea - ia <= MaxReceiptLifetimeMs)) return $"receipt.expires_at must be within {MaxReceiptLifetimeMs} ms after issued_at";
        if (IntentJs.Get(r, "kid") is not string kid || !KidRe.IsMatch(kid)) return "receipt.kid must match [A-Za-z0-9_.:-]{1,64}";
        var l = IntentJs.Get(r, "ledger");
        if (!ExactKeys(l, "head", "index") || !IntentJs.IsNonNeg(IntentJs.Get(l, "index")) || !IntentJs.B32(IntentJs.Get(l, "head"))) return "receipt.ledger must be {index, head}";
        if (!IntentJs.B32(IntentJs.Get(r, "signer"))) return "receipt.signer is not canonical base64url (32 bytes)";
        var rse = IntentJs.SuiteError(IntentJs.Get(r, "alg"), r.ContainsKey("alg"));
        if (rse != null) return "receipt.alg: " + rse;
        var suite = IntentJs.SuiteOf(r);
        if (suite == "ed25519" && (r.ContainsKey("pq_pk") || r.ContainsKey("pq_sig"))) return "an ed25519 receipt must not carry pq_pk / pq_sig";
        if (IntentJs.Get(r, "sig") is not string) return "receipt.sig must be a string";
        return null;
    }

    static D ReceiptBody(D r)
    {
        var b = new D();
        foreach (var k in new[] { "v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at", "kid" }) b[k] = IntentJs.Get(r, k);
        b["ledger"] = new D { ["index"] = IntentJs.Get(r["ledger"], "index"), ["head"] = IntentJs.Get(r["ledger"], "head") };
        b["signer"] = IntentJs.Get(r, "signer");
        return b;
    }

    internal static bool VerifyReceiptSignature(D r, string expectedSigner, IReadOnlyDictionary<string, string>? pin)
    {
        try
        {
            if (ReceiptShapeError(r) != null || r["signer"] as string != expectedSigner) return false;
            var msg = IntentJs.Message(AccReceiptDomain, IntentJs.BindSuiteFields(ReceiptBody(r), IntentJs.Get(r, "alg"), r.ContainsKey("alg"), IntentJs.Get(r, "pq_pk"), r.ContainsKey("pq_pk")));
            return IntentJs.VerifyPinnedSuite(IntentJs.Get(r, "alg"), r.ContainsKey("alg"), (string)r["signer"]!, IntentJs.Get(r, "pq_pk"), msg, IntentJs.Get(r, "sig"), IntentJs.Get(r, "pq_sig"), pin);
        }
        catch (Exception) { return false; }
    }

    /// <summary>The receipt's content address (what <c>intent_session.acc[].receipt</c> carries).</summary>
    public static string ReceiptDigest(object? r) => IntentJs.Ref(AccReceiptRefDomain, "r", r);

    internal static bool ReceiptArithmeticOk(string? agg, D r, long val)
    {
        long pre = IntentJs.Lng(r["pre"]), delta = IntentJs.Lng(r["delta"]), post = IntentJs.Lng(r["post"]);
        return agg switch
        {
            "sum" => delta == val && post == pre + delta,
            "count" => delta == 1 && post == pre + 1,
            "max" => delta == val && post == Math.Max(pre, delta),
            _ => (delta == 0 || delta == 1) && post == pre + delta,
        };
    }

    internal static string? KeySetShapeError(object? kO)
    {
        if (kO is not D k) return "key set is not an object";
        foreach (var x in k.Keys) if (x is not ("v" or "kind" or "sequencer" or "version" or "issued_at" or "keys" or "alg" or "pq_pk" or "sig" or "pq_sig")) return $"key set: unknown member '{x}'";
        if (!OracleFacts.IsOne(IntentJs.Get(k, "v")) || IntentJs.Get(k, "kind") as string != "pca-sequencer-keys") return "not a pca-sequencer-keys v1";
        if (!IntentJs.B32(IntentJs.Get(k, "sequencer"))) return "sequencer is not canonical base64url (32 bytes)";
        if (!(IntentJs.IsNonNeg(IntentJs.Get(k, "version")) && IntentJs.NumOf(IntentJs.Get(k, "version"))!.Value >= 1)) return "version must be a safe integer >= 1";
        if (!IntentJs.IsNonNeg(IntentJs.Get(k, "issued_at"))) return "issued_at must be a non-negative safe integer";
        if (IntentJs.Get(k, "keys") is not L keys || keys.Count == 0 || keys.Count > 256) return "keys must be 1..256 entries";
        var kids = new HashSet<string>();
        foreach (var eO in keys)
        {
            if (eO is not D e || e.Keys.Any(x => x is not ("kid" or "pk" or "alg" or "pq_pk" or "not_before" or "not_after"))) return "keys entries are {kid, pk, alg?, pq_pk?, not_before, not_after?}";
            if (IntentJs.Get(e, "kid") is not string kid || !KidRe.IsMatch(kid) || !kids.Add(kid)) return "key kids must match [A-Za-z0-9_.:-]{1,64} and be distinct";
            if (!IntentJs.B32(IntentJs.Get(e, "pk"))) return "key pk is not canonical base64url (32 bytes)";
            var kse = IntentJs.SuiteError(e.GetValueOrDefault("alg"), e.ContainsKey("alg"));
            if (kse != null) return "key alg: " + kse;
            if (e.ContainsKey("pq_pk") && !IntentJs.B64Any(e["pq_pk"])) return "key pq_pk is not canonical base64url";
            if (!IntentJs.IsNonNeg(IntentJs.Get(e, "not_before"))
                || (e.ContainsKey("not_after") && !(IntentJs.IsNonNeg(e["not_after"]) && IntentJs.NumOf(e["not_after"]) >= IntentJs.NumOf(e["not_before"]))))
                return "key validity must be 0 <= not_before <= not_after";
        }
        var ase = IntentJs.SuiteError(IntentJs.Get(k, "alg"), k.ContainsKey("alg"));
        if (ase != null) return "alg: " + ase;
        var suite = IntentJs.SuiteOf(k);
        if (suite == "ed25519" && (k.ContainsKey("pq_pk") || k.ContainsKey("pq_sig"))) return "an ed25519 key set must not carry pq_pk / pq_sig";
        if (IntentJs.Get(k, "sig") is not string) return "sig must be a string";
        return null;
    }

    internal static bool VerifyKeySet(object? kO, string root, object? rootPqPk, bool rootPqPresent)
    {
        try
        {
            if (KeySetShapeError(kO) != null) return false;
            var k = (D)kO!;
            if (k["sequencer"] as string != root) return false;
            var pin = rootPqPresent ? IntentJs.Pin(root, rootPqPk) : null;
            var body = new D();
            foreach (var x in new[] { "v", "kind", "sequencer", "version", "issued_at", "keys" }) body[x] = IntentJs.Get(k, x);
            var msg = IntentJs.Message(SequencerKeysDomain, IntentJs.BindSuiteFields(body, IntentJs.Get(k, "alg"), k.ContainsKey("alg"), IntentJs.Get(k, "pq_pk"), k.ContainsKey("pq_pk")));
            return IntentJs.VerifyPinnedSuite(IntentJs.Get(k, "alg"), k.ContainsKey("alg"), root, IntentJs.Get(k, "pq_pk"), msg, IntentJs.Get(k, "sig"), IntentJs.Get(k, "pq_sig"), pin);
        }
        catch (Exception) { return false; }
    }

    /// <summary>A key set's content address: <c>base64url(sha256(strictCanonical({"d":"atlas-pca/sequencer-keys-ref/v1","k":set})))</c>.</summary>
    public static string KeySetDigest(object? ks) => IntentJs.Ref(SequencerKeysRefDomain, "k", ks);

    /// <summary><c>acc.keyset_versions[root]</c> is exactly <c>{version, digest}</c>: version a safe integer &gt;= 1, digest 32-byte base64url. Null = ok.</summary>
    internal static string? TrackedKeySetError(object? t)
    {
        if (t is not D m) return "a tracked key set must be an object {version, digest}";
        foreach (var k in m.Keys) if (k is not ("version" or "digest")) return $"a tracked key set has the unknown member '{k}'";
        if (!IntentJs.IsInt(IntentJs.Get(m, "version")) || IntentJs.NumOf(m["version"])!.Value < 1) return "a tracked key set version must be a safe integer >= 1";
        if (!IntentJs.B32(IntentJs.Get(m, "digest"))) return "a tracked key set digest must be canonical base64url (32 bytes)";
        return null;
    }

    static bool NonNegSafe(double d) => double.IsFinite(d) && d == Math.Round(d) && d >= 0 && d <= IntentJs.MaxSafe && !IntentJs.IsNegZero(d);

    /// <summary>Verify a receipt against the sequenced holder of S (rule 15 step 3, sequenced). False unless ALL hold: the clock
    /// and every bound are safe integers; the receipt is well-formed (lifetime at most 15 min), <c>issued_at &lt;= now + 60 s</c>
    /// and <c>now - issued_at &lt;= maxReceiptAgeMs</c>; SOME presented key set verifies under <c>holder.root</c> (PQ: pinned by
    /// <c>holder.root_pq_pk</c>), and, when the verifier tracks <c>{version, digest}</c> for the root, <c>version &gt;= tracked.version</c> (no
    /// rollback) and at <c>version == tracked.version</c> the same key-set digest (no equivocation), <c>issued_at &lt;= now + 60 s</c> and
    /// <c>now - issued_at &lt;= maxKeySetAgeMs</c>, and lists <c>receipt.kid</c> with <c>pk == receipt.signer</c>,
    /// <c>not_before &lt;= receipt.issued_at</c> and, when <c>not_after</c> is set, <c>receipt.issued_at &lt;= not_after</c> AND
    /// <c>not_after &gt;= now - 60 s</c> (a retired key stops verifying), the entry's suite equal to the receipt's; and the
    /// receipt verifies under that entry (its PQ key pinned by the entry).</summary>
    internal static bool VerifyReceiptAgainstHolder(D r, D holder, object? keySets, double now, double maxReceiptAgeMs, double maxKeySetAgeMs, object? tracked)
    {
        if (!(double.IsFinite(now) && now == Math.Round(now) && Math.Abs(now) <= IntentJs.MaxSafe && !IntentJs.IsNegZero(now))) return false;
        if (!NonNegSafe(maxReceiptAgeMs) || !NonNegSafe(maxKeySetAgeMs) || (tracked != null && TrackedKeySetError(tracked) != null)) return false;
        if (keySets is not L sets || ReceiptShapeError(r) != null) return false;
        double issued = IntentJs.NumOf(r["issued_at"])!.Value;
        if (!(issued <= now + ReceiptSkewMs) || !(now - issued <= maxReceiptAgeMs)) return false;
        var rs = IntentJs.SuiteOf(r);
        foreach (var kO in sets)
        {
            if (!VerifyKeySet(kO, (string)holder["root"]!, IntentJs.Get(holder, "root_pq_pk"), holder.ContainsKey("root_pq_pk"))) continue;
            var ks = (D)kO!;
            if (tracked != null)
            {
                double v = IntentJs.NumOf(ks["version"])!.Value, tv = IntentJs.NumOf(IntentJs.Get(tracked, "version"))!.Value;
                if (v < tv || (v == tv && KeySetDigest(ks) != IntentJs.Get(tracked, "digest") as string)) continue; // rollback / equivocation
            }
            double ksIssued = IntentJs.NumOf(ks["issued_at"])!.Value;
            if (!(ksIssued <= now + ReceiptSkewMs) || !(now - ksIssued <= maxKeySetAgeMs)) continue;
            var e = ((L)ks["keys"]!).Cast<D>().FirstOrDefault(x => Equals(x["kid"], r["kid"]));
            if (e == null || e["pk"] as string != r["signer"] as string || issued < IntentJs.NumOf(e["not_before"])!.Value) continue;
            if (e.ContainsKey("not_after") && (issued > IntentJs.NumOf(e["not_after"])!.Value || IntentJs.NumOf(e["not_after"])!.Value < now - ReceiptSkewMs)) continue;
            var es = IntentJs.SuiteOf(e);
            if ((es ?? "ed25519") != (rs ?? "x")) continue;
            var pin = e.ContainsKey("pq_pk") ? IntentJs.Pin((string)e["pk"]!, e["pq_pk"]) : null;
            if (VerifyReceiptSignature(r, (string)e["pk"]!, pin)) return true;
        }
        return false;
    }
}
