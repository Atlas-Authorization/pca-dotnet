using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Evidence;

/// <summary>The dispute evidence bundle <c>pca-intent-evidence</c> v1: closed-member shape validation, the deterministic normal form, the
/// commitments-only form and its digest. A bundle is a JSON tree (maps, lists, strings, <see cref="Num"/>, bool, null); it is evidence to be
/// re-verified by every reader, never trusted. Reads follow JavaScript property semantics: a missing member is "undefined", reading a member
/// of null/undefined throws, and an undefined value inside a hashed object refuses (strict canonical form).</summary>
public static class EvidenceBundle
{
    public const string EvidenceDomain = "atlas-pca/intent-evidence/v1";

    static readonly object Undef = new();

    static readonly string[] TopKeys =
    {
        "v", "kind", "subject", "statement", "session_root", "schema", "root_grant", "maps", "answers", "canary_labels", "canaries",
        "deltas", "pcactns", "verdicts", "accumulator", "facts", "classifier", "offer_sets", "labels", "effects", "settlements", "revocation_epochs", "anchors",
    };

    // ---- JavaScript-flavoured tree helpers ----------------------------------------------------------------------------------

    static bool IsObj(object? v) => v is D;

    /// <summary>obj.k: null / undefined throw (TypeError), a non-object yields undefined.</summary>
    static object? P(object? o, string k)
    {
        if (o == null || ReferenceEquals(o, Undef)) throw new InvalidOperationException($"Cannot read properties of {(o == null ? "null" : "undefined")} (reading '{k}')");
        return o is D d && d.TryGetValue(k, out var v) ? v : Undef;
    }

    static bool Has(D d, string k) => d.ContainsKey(k);
    static bool IsStr(object? v) => v is string;
    static bool IsNumEq(object? v, double x) => v is Num && JsJson.ToJsNumber(v) == x;

    static bool Truthy(object? v) => v switch
    {
        null => false,
        bool b => b,
        string s => s.Length > 0,
        Num => JsJson.ToJsNumber(v) is var x && x != 0 && !double.IsNaN(x),
        _ => !ReferenceEquals(v, Undef),
    };

    /// <summary>JSON.parse(JSON.stringify(v)): a deep copy whose numbers are re-printed the way JavaScript prints them (-0 prints 0).</summary>
    static object? Plain(object? v)
    {
        switch (v)
        {
            case D m:
                var d = new D();
                foreach (var kv in m) d[kv.Key] = Plain(kv.Value);
                return d;
            case L l: return l.Select(Plain).ToList();
            case Num n: return new Num(JsJson.NumberToString(JsJson.ToJsNumber(n)));
            default: return v;
        }
    }

    static string? Closed(object? o, string[] keys, string where)
    {
        if (o is not D m) return $"{where} must be an object";
        foreach (var k in IntentJs.JsKeys(m.Keys)) if (!keys.Contains(k)) return $"{where}: unknown member \"{k}\"";
        return null;
    }

    // ---- shape -------------------------------------------------------------------------------------------------------------

    /// <summary>Closed-member shape validation (unknown members are refused at every level the bundle owns). Null when well-formed.</summary>
    public static string? BundleShapeError(object? b)
    {
        var top = Closed(b, TopKeys, "bundle");
        if (top != null) return top;
        var x = (D)b!;
        object? G(string k) => x.TryGetValue(k, out var v) ? v : Undef;
        if (!IsNumEq(G("v"), 1) || !(G("kind") is string kind && kind == "pca-intent-evidence")) return "not a pca-intent-evidence v1 bundle";
        var subj = Closed(G("subject"), new[] { "pcactn_digest", "aud", "session" }, "subject");
        if (subj != null) return subj;
        var s = (D)G("subject")!;
        if (!IsStr(s.GetValueOrDefault("pcactn_digest")) || !IsStr(s.GetValueOrDefault("aud")) || !IsStr(s.GetValueOrDefault("session"))) return "subject members must be strings";
        var st = Closed(G("statement"), new[] { "commit", "opening" }, "statement");
        if (st != null) return st;
        if (!IsStr(((D)G("statement")!).GetValueOrDefault("commit"))) return "statement.commit must be a string";
        if (G("session_root") is not D sr || !IsNumEq(sr.GetValueOrDefault("v"), 1) || !(sr.GetValueOrDefault("kind") is string sk && sk == "pca-intent-session")) return "session_root is not a pca-intent-session v1";
        if (!IsStr(sr.GetValueOrDefault("session")) || !IsStr(sr.GetValueOrDefault("intent_ref")) || !IntentJs.IsInt(sr.GetValueOrDefault("expires_at"))) return "session_root is missing session / intent_ref / expires_at";
        if (sr.GetValueOrDefault("principals") is not L pl || pl.Count == 0 || !pl.All(p => p is D pd && IsStr(pd.GetValueOrDefault("key")))) return "session_root.principals must be a non-empty key list";
        var sc = Closed(G("schema"), new[] { "doc", "anchor" }, "schema");
        if (sc != null) return sc;
        if (((D)G("schema")!).GetValueOrDefault("doc") is not D doc || !(doc.GetValueOrDefault("kind") is string dk && dk == "pca-action-schema") || doc.GetValueOrDefault("sig") is not D) return "schema.doc is not a signed pca-action-schema";
        if (!IsObj(G("root_grant"))) return "root_grant must be a capability";
        foreach (var k in new[] { "maps", "answers", "canary_labels", "deltas", "pcactns", "verdicts", "effects", "revocation_epochs", "anchors" })
            if (G(k) is not L) return $"{k} must be an array";
        foreach (var k in new[] { "facts", "classifier", "offer_sets", "labels", "settlements" })
            if (Has(x, k) && x[k] is not L) return $"{k} must be an array";
        var maps = (L)G("maps")!;
        for (int i = 0; i < maps.Count; i++)
        {
            var e = Closed(maps[i], new[] { "seq", "commit", "map", "disclosed" }, $"maps[{i}]");
            if (e != null) return e;
            var mm = (D)maps[i]!;
            if (!IntentJs.IsInt(mm.GetValueOrDefault("seq")) || JsJson.ToJsNumber(mm["seq"]) < 0 || !IsStr(mm.GetValueOrDefault("commit"))) return $"maps[{i}] needs an integer seq and a commit";
        }
        var cl = (L)G("canary_labels")!;
        for (int i = 0; i < cl.Count; i++)
        {
            var e = Closed(cl[i], new[] { "question_id", "label" }, $"canary_labels[{i}]");
            if (e != null) return e;
            var cc = (D)cl[i]!;
            var lab = cc.GetValueOrDefault("label");
            if (!IsStr(cc.GetValueOrDefault("question_id")) || !(IsNumEq(lab, 0) || IsNumEq(lab, 1))) return $"canary_labels[{i}] is malformed";
        }
        var cs = Closed(G("canaries"), new[] { "asked", "false_yes", "false_no" }, "canaries");
        if (cs != null) return cs;
        var cn = (D)G("canaries")!;
        if (!new[] { "asked", "false_yes", "false_no" }.All(k => IntentJs.IsNonNeg(cn.GetValueOrDefault(k)))) return "canaries counts must be non-negative integers";
        var ac = Closed(G("accumulator"), new[] { "holder", "events", "receipts", "sequencer_keys" }, "accumulator");
        if (ac != null) return ac;
        var acc = (D)G("accumulator")!;
        if (!(acc.GetValueOrDefault("holder") is string h && (h == "site_local" || h == "sequenced"))) return "accumulator.holder must be site_local or sequenced";
        if (acc.GetValueOrDefault("events") is not L events) return "accumulator.events must be an array";
        for (int i = 0; i < events.Count; i++)
        {
            var e = Closed(events[i], new[] { "acc", "post", "pcactn_digest", "delta", "status" }, $"accumulator.events[{i}]");
            if (e != null) return e;
            var ev = (D)events[i]!;
            if (!IsStr(ev.GetValueOrDefault("acc")) || !IntentJs.IsNonNeg(ev.GetValueOrDefault("post")) || !IsStr(ev.GetValueOrDefault("pcactn_digest"))) return $"accumulator.events[{i}] is malformed";
            if (Has(ev, "delta") && !IntentJs.IsNonNeg(ev["delta"])) return $"accumulator.events[{i}].delta must be a non-negative integer";
        }
        if (Has(acc, "receipts") && acc["receipts"] is not L) return "accumulator.receipts must be an array";
        if (Has(acc, "sequencer_keys") && acc["sequencer_keys"] is not L) return "accumulator.sequencer_keys must be an array";
        var eps = (L)G("revocation_epochs")!;
        for (int i = 0; i < eps.Count; i++)
        {
            var e = Closed(eps[i], new[] { "epoch", "revoked" }, $"revocation_epochs[{i}]");
            if (e != null) return e;
            var rr = (D)eps[i]!;
            if (rr.GetValueOrDefault("epoch") is not D || rr.GetValueOrDefault("revoked") is not L) return $"revocation_epochs[{i}] needs an epoch and its revoked list";
        }
        var anchors = (L)G("anchors")!;
        for (int i = 0; i < anchors.Count; i++)
        {
            var e = Closed(anchors[i], new[] { "kind", "digest", "index", "proof", "signed_tree_head" }, $"anchors[{i}]");
            if (e != null) return e;
        }
        var effects = (L)G("effects")!;
        for (int i = 0; i < effects.Count; i++)
            if (effects[i] is not D ef || !IsStr(ef.GetValueOrDefault("pcactn_digest"))) return $"effects[{i}] needs a pcactn_digest";
        return null;
    }

    // ---- normal form -------------------------------------------------------------------------------------------------------

    static double N(object? v) => ReferenceEquals(v, Undef) ? double.NaN : JsJson.ToJsNumber(v);

    /// <summary>A numeric comparator term (<c>a - b</c>); NaN counts as equal, as an Array.prototype.sort comparator does.</summary>
    static int Diff(object? a, object? b)
    {
        var d = N(a) - N(b);
        return double.IsNaN(d) || d == 0 ? 0 : d < 0 ? -1 : 1;
    }

    /// <summary>The string comparator <c>a &lt; b ? -1 : a &gt; b ? 1 : 0</c> (JavaScript relational operators).</summary>
    static int Cmp(object? a, object? b)
    {
        if (a is string x && b is string y) { var c = string.CompareOrdinal(x, y); return c < 0 ? -1 : c > 0 ? 1 : 0; }
        var p = N(a); var q = N(b);
        return p < q ? -1 : p > q ? 1 : 0;
    }

    static int Then(int first, Func<int> next) => first != 0 ? first : next();

    /// <summary>In-place STABLE sort (Array.prototype.sort is stable; List.Sort is not). The list must be an array.</summary>
    static void Sort(object? list, Func<object?, object?, int> cmp)
    {
        var l = list as L;
        if (l is null) throw new InvalidOperationException("sort is not a function");
        var sorted = l.OrderBy(e => e, Comparer<object?>.Create((a, c) => cmp(a, c))).ToList();
        l.Clear();
        l.AddRange(sorted);
    }

    static string Key(object? v) => Pca.HashCanonical(v);

    static double SeqOf(object? cap)
    {
        var cvs = P(cap, "caveats") as L;
        if (cvs is null) throw new InvalidOperationException("c.caveats.find is not a function");
        var cv = cvs.FirstOrDefault(k => P(k, "type") is string t && t == "intent_session");
        if (cv != null && IntentJs.IsInt(P(cv, "seq"))) return N(P(cv, "seq"));
        return 9007199254740991.0;
    }

    static D EffectWithoutParams(object? e)
    {
        var m = e as D;
        if (m is null) throw new InvalidOperationException("Cannot destructure a non-object");
        var d = new D();
        foreach (var kv in m) if (kv.Key != "params") d[kv.Key] = kv.Value;
        return d;
    }

    /// <summary>Deterministic normal form: the members that are SETS are sorted by a content key; <c>accumulator.events</c> is a sequence
    /// and is never reordered.</summary>
    public static D NormalizeBundle(object? b)
    {
        var x = Plain(b);
        Sort(P(x, "maps"), (a, c) => Then(Diff(P(a, "seq"), P(c, "seq")), () => Cmp(P(a, "commit"), P(c, "commit"))));
        Sort(P(x, "answers"), (a, c) => Then(Diff(P(a, "observed_at"), P(c, "observed_at")), () => Then(Cmp(P(a, "question_id"), P(c, "question_id")), () => Cmp(P(a, "sig"), P(c, "sig")))));
        Sort(P(x, "canary_labels"), (a, c) => Then(Cmp(P(a, "question_id"), P(c, "question_id")), () => Diff(P(a, "label"), P(c, "label"))));
        Sort(P(x, "deltas"), (a, c) => Then(Math.Sign(SeqOf(a) - SeqOf(c)), () => Cmp(P(a, "id"), P(c, "id"))));
        Sort(P(x, "pcactns"), (a, c) => Then(Diff(P(a, "iat"), P(c, "iat")), () => Then(Diff(P(a, "counter"), P(c, "counter")), () => Cmp(Key(a), Key(c)))));
        Sort(P(x, "verdicts"), (a, c) => Then(Cmp(P(a, "pcactn_digest"), P(c, "pcactn_digest")), () => Cmp(Key(a), Key(c))));
        // Sorted without the params opening, so withholding an opening never reorders the commitments-only form.
        Sort(P(x, "effects"), (a, c) => Then(Cmp(P(a, "pcactn_digest"), P(c, "pcactn_digest")), () => Cmp(Key(EffectWithoutParams(a)), Key(EffectWithoutParams(c)))));
        // Issue order (not epoch number): a rollback, an epoch issued later with a lower number, must stay visible.
        Sort(P(x, "revocation_epochs"), (a, c) => Then(Diff(P(P(a, "epoch"), "issued_at"), P(P(c, "epoch"), "issued_at")),
            () => Then(Diff(P(P(a, "epoch"), "epoch"), P(P(c, "epoch"), "epoch")), () => Cmp(Key(a), Key(c)))));
        Sort(P(x, "anchors"), (a, c) => Then(Cmp(P(a, "kind"), P(c, "kind")), () => Then(Diff(P(a, "index"), P(c, "index")), () => Cmp(P(a, "digest"), P(c, "digest")))));
        foreach (var k in new[] { "facts", "classifier", "offer_sets", "labels", "settlements" })
        {
            var v = P(x, k);
            if (v == null || ReferenceEquals(v, Undef)) continue; // arr?.sort
            Sort(v, (a, c) => Cmp(Key(a), Key(c)));
        }
        var receipts = P(P(x, "accumulator"), "receipts");
        if (Truthy(receipts)) Sort(receipts, (a, c) => Cmp(Key(a), Key(c)));
        return (D)x!;
    }

    /// <summary>Assemble a bundle in normal form. Throws on a malformed part (the exporter's bug, not evidence).</summary>
    public static D BuildEvidenceBundle(object? parts)
    {
        var all = new D { ["v"] = new Num("1"), ["kind"] = "pca-intent-evidence" };
        if (parts is D pm) foreach (var kv in pm) all[kv.Key] = kv.Value;
        var b = NormalizeBundle(all);
        var bad = BundleShapeError(b);
        if (bad != null) throw new InvalidOperationException($"buildEvidenceBundle: {bad}");
        return b;
    }

    /// <summary>The commitments-only normal form: no anchors, no statement opening, no full maps, no effect params. Everything else stays in.</summary>
    public static D CommitmentForm(object? b)
    {
        var n = NormalizeBundle(b);
        var rest = new D();
        foreach (var kv in n) if (kv.Key != "anchors") rest[kv.Key] = kv.Value;
        rest["statement"] = new D { ["commit"] = P(P(n, "statement"), "commit") };
        rest["maps"] = ((L)P(n, "maps")!).Select(m =>
        {
            var d = new D { ["seq"] = P(m, "seq"), ["commit"] = P(m, "commit") };
            var disclosed = P(m, "disclosed");
            if (!ReferenceEquals(disclosed, Undef)) d["disclosed"] = disclosed;
            return (object?)d;
        }).ToList();
        rest["effects"] = ((L)P(n, "effects")!).Select(e => (object?)EffectWithoutParams(e)).ToList();
        return rest;
    }

    /// <summary>The bundle's content address: H over the commitments-only normal form.</summary>
    public static string EvidenceDigest(object? b) => Pca.HashCanonical(new D { ["d"] = EvidenceDomain, ["b"] = CommitmentForm(b) });
}
