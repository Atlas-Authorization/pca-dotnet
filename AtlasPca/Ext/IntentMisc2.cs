// The leftovers of five intent modules of the reference, over the JSON tree: the signed "ask the principal" question and its RFC 9457 problem (intent-required.ts), the signing and digest helpers of the
// strict artifacts (intent-artifacts.ts), classifier verdict signing and the attestation gate (intent-classifier.ts), the signing and digest half of accumulator receipts and sequencer key sets (intent-acc.ts)
// and admission and settlement through a session store (intent-history.ts). The shape checks, the verdicts and the pure history functions are the rest of the intent module (IntentArtifacts, IntentClassifier,
// IntentAcc, IntentHistory); this adds what signs, hashes and stores.
using System.Text.RegularExpressions;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The session store port: every operation on one session runs under that session's lock.</summary>
public interface IIntentSessionTx
{
    L Events();
    void Append(D ev);
    /// <summary>Set the status of an event; false when the session has no such event.</summary>
    bool SetStatus(string id, string status);
}

/// <summary>A session store. <see cref="Durable"/> must be exactly <c>true</c> for a store that survives a restart (admission refuses any other store unless told otherwise).</summary>
public interface IIntentSessionStore
{
    object? Durable { get; }
    T WithSession<T>(string session, Func<IIntentSessionTx, T> fn);
}

/// <summary>The in-process session store (tests and single-process sites): its histories die with the process.</summary>
public sealed class MemoryIntentSessionStore(object? durable = null) : IIntentSessionStore
{
    readonly Dictionary<string, L> _events = new(StringComparer.Ordinal);
    readonly object _lock = new();
    public object? Durable => durable;

    sealed class Tx(L list) : IIntentSessionTx
    {
        public L Events() => new(list.Select(e => (object?)new D((D)e!)));
        public void Append(D ev) => list.Add(new D(ev));
        public bool SetStatus(string id, string status)
        {
            var ev = list.Cast<D>().FirstOrDefault(e => Equals(e.GetValueOrDefault("id"), id));
            if (ev == null) return false;
            ev["status"] = status;
            return true;
        }
    }

    public T WithSession<T>(string session, Func<IIntentSessionTx, T> fn)
    {
        lock (_lock)
        {
            if (!_events.TryGetValue(session, out var l)) _events[session] = l = new L();
            return fn(new Tx(l));
        }
    }
}

public static class IntentRequired
{
    public const string ProblemBase = "https://atlasauth.net/pca/problems/";
    public const string RequiredDomain = "atlas-pca/intent-required/v1\0";
    public const string ActionDomain = "atlas-pca/intent-action/v1";
    public static readonly IReadOnlyList<string> ProblemKinds = ["intent-required", "intent-denied", "schema-violation", "ceiling"];
    public static readonly IReadOnlyList<string> Frictions = ["tap", "hold", "typed", "device"];
    static readonly string[] BodyKeys = ["v", "kind", "session", "map_digest", "schema", "pcactn_digest", "action_digest", "cell", "reason", "question_id", "friction", "delivered_to", "expires_at", "sig"];
    static readonly Regex QuestionId = new(@"\A[A-Za-z0-9_-]{1,64}\z", RegexOptions.CultureInvariant);

    static object? Need(D d, string k) => d.TryGetValue(k, out var v) ? v : throw new InvalidOperationException("canonicalize: unsupported type undefined");
    static string? SuiteErr(object? alg, bool present) => IntentJs.SuiteError(alg, present);

    /// <summary>The digest every question and verdict binds to: the strict hash of <c>{d, action: {verb, resource, params_digest, reversibility_class}}</c>.</summary>
    public static string IntentActionDigest(D action) => Pca.HashCanonical(new D
    {
        ["d"] = ActionDomain, ["action"] = new D { ["verb"] = Need(action, "verb"), ["resource"] = Need(action, "resource"), ["params_digest"] = Need(action, "params_digest"), ["reversibility_class"] = Need(action, "reversibility_class") },
    });

    /// <summary>Why the cell coordinates are malformed, or null: 1..64 dimensions, each an index range <c>[lo, hi]</c> (0 &lt;= lo &lt;= hi) or a set of 1..256 distinct strings.</summary>
    public static string? CellCoordsError(object? c)
    {
        if (c is not D d || d.Count == 0 || d.Count > 64) return "coords must be an object of 1..64 dimensions";
        foreach (var (k, v) in d)
        {
            if (k.Length == 0 || k.Length > 256) return "a coordinate path must be 1..256 characters";
            if (v is L { Count: 2 } r && r.All(x => IntentJs.IsInt(x)))
            {
                if (!(IntentJs.NumOf(r[0])!.Value >= 0 && IntentJs.NumOf(r[0])!.Value <= IntentJs.NumOf(r[1])!.Value)) return $"coords '{k}': need 0 <= lo <= hi";
            }
            else if (v is L { Count: >= 1 and <= 256 } s && s.All(x => x is string))
            {
                if (s.Cast<string>().Distinct(StringComparer.Ordinal).Count() != s.Count) return $"coords '{k}': values must be distinct";
            }
            else return $"coords '{k}': an index range [lo, hi] or a value set";
        }
        return null;
    }

    /// <summary>Why a question body is malformed, or null. <paramref name="signed"/> false: an unsigned body (it must not carry <c>sig</c>).</summary>
    public static string? IntentRequiredShapeError(object? bo, bool signed = true)
    {
        if (bo is not D b) return "not an object";
        foreach (var k in b.Keys) if (!BodyKeys.Contains(k)) return $"unknown member '{k}'";
        if (IntentJs.NumOf(b.GetValueOrDefault("v")) != 1 || b.GetValueOrDefault("kind") is not "pca-intent-required") return "not a pca-intent-required v1";
        foreach (var k in new[] { "session", "map_digest", "schema", "pcactn_digest", "action_digest" }) if (!IntentJs.B32(b.GetValueOrDefault(k))) return $"{k} must be canonical base64url (32 bytes)";
        if (b.GetValueOrDefault("cell") is not D cell || string.Join(",", cell.Keys.OrderBy(x => x, StringComparer.Ordinal)) != "coords,verb" || cell["verb"] is not string { Length: > 0 }) return "cell must be {verb, coords}";
        var ce = CellCoordsError(cell["coords"]);
        if (ce != null) return ce;
        if (b.GetValueOrDefault("reason") is not "uncertain") return "reason must be 'uncertain'";
        if (b.GetValueOrDefault("question_id") is not string qid || !QuestionId.IsMatch(qid)) return "question_id must match [A-Za-z0-9_-]{1,64}";
        if (b.GetValueOrDefault("friction") is not string fr || !Frictions.Contains(fr)) return "unknown friction tier";
        if (b.GetValueOrDefault("delivered_to") is not ("wallet" or "agent")) return "delivered_to must be 'wallet' or 'agent'";
        if (!(IntentJs.IsInt(b.GetValueOrDefault("expires_at")) && IntentJs.NumOf(b["expires_at"])!.Value >= 0)) return "expires_at must be a non-negative safe integer";
        if (signed)
        {
            var s = b.GetValueOrDefault("sig") as D;
            if (s != null && SuiteErr(s.GetValueOrDefault("alg"), s.ContainsKey("alg")) is { } se) return $"sig.alg: {se}";
            if (s != null && s.TryGetValue("pq_value", out var pv) && pv is not string) return "sig.pq_value must be a string";
            if (s == null || s.Keys.Any(k => k is not ("alg" or "kid" or "value" or "pq_value")) || IntentJs.SuiteOf(s.GetValueOrDefault("alg"), s.ContainsKey("alg")) == null
                || s.GetValueOrDefault("kid") is not string || s.GetValueOrDefault("value") is not string) return "sig must be {alg, kid, value, pq_value?}";
        }
        else if (b.ContainsKey("sig")) return "an unsigned body must not carry sig";
        return null;
    }

    static byte[] Message(D b)
    {
        var body = new D(b);
        body.Remove("sig");
        return IntentJs.Message(RequiredDomain, body);
    }

    /// <summary>Sign a question as the site: <c>{...body, sig: {alg, kid, value, pq_value?}}</c> (<paramref name="alg"/> null is ed25519). An invalid unsigned body is never signed.</summary>
    public static D SignIntentRequired(D body, string kid, byte[] siteSecret, string? alg = null, SuiteSecretKeys? keys = null)
    {
        var e = IntentRequiredShapeError(body, signed: false);
        if (e != null) throw new InvalidOperationException("signIntentRequired: " + e);
        if (IntentJs.SuiteOf(alg ?? "ed25519", true) is not { } resolved) throw new InvalidOperationException($"signIntentRequired: unknown signature alg '{alg}'");
        var parts = PqSuites.SignSuiteArtifact(alg, PqSuites.SuiteKeysOf(siteSecret, keys), Message(body));
        var sig = new D { ["alg"] = resolved, ["kid"] = kid, ["value"] = parts.Sig };
        if (parts.PqSig != null) sig["pq_value"] = parts.PqSig;
        return new D(body) { ["sig"] = sig };
    }

    static D Verdict(string? reason) => reason == null ? new D { ["ok"] = true } : new D { ["ok"] = false, ["reason"] = reason };

    /// <summary>Verify a question against the site's discovery keys at <paramref name="now"/>: the shape, a listed key, the suite pinned by that key, the signature and the expiry. The clock must be a safe integer
    /// (else a denial). Returns <c>{ok}</c> or <c>{ok: false, reason}</c>; never throws.</summary>
    public static D VerifyIntentRequired(object? b, object? keys, object? now)
    {
        try
        {
            if (!IntentJs.IsSafeInteger(now)) return Verdict("the verifier clock is not a safe integer (fail closed)");
            var e = IntentRequiredShapeError(b);
            if (e != null) return Verdict(e);
            var s = (D)b!;
            var sig = (D)s["sig"]!;
            if (keys is not L kl) return Verdict("the site keys must be an array");
            var key = kl.OfType<D>().FirstOrDefault(k => Equals(k.GetValueOrDefault("kid"), sig["kid"]));
            if (key == null) return Verdict($"no site key with kid '{sig["kid"]}'");
            var kse = SuiteErr(key.GetValueOrDefault("alg"), key.ContainsKey("alg"));
            if (kse != null) return Verdict($"site key: {kse}");
            if (IntentJs.SuiteOf(key.GetValueOrDefault("alg"), key.ContainsKey("alg")) != IntentJs.SuiteOf(sig.GetValueOrDefault("alg"), sig.ContainsKey("alg"))) return Verdict("sig.alg does not match the pinned key suite");
            var pk = key.GetValueOrDefault("pk") as string ?? "";
            var pins = key.ContainsKey("pq_pk") ? new Dictionary<string, string> { [pk] = key["pq_pk"] as string ?? "" } : null;
            if (!IntentJs.VerifyPinnedSuite(key.GetValueOrDefault("alg"), key.ContainsKey("alg"), pk, key.GetValueOrDefault("pq_pk"), Message(s), sig["value"], sig.GetValueOrDefault("pq_value"), pins)) return Verdict("site signature invalid");
            if (!(IntentJs.NumOf(now)!.Value <= IntentJs.NumOf(s["expires_at"])!.Value)) return Verdict("the question has expired");
            return Verdict(null);
        }
        catch (Exception err) { return Verdict("malformed intent_required: " + err.Message); }
    }

    /// <summary>As <see cref="VerifyIntentRequired"/>; the clock gate is explicit.</summary>
    public static D VerifyIntentRequiredAt(object? b, object? keys, object? now) =>
        !IntentJs.IsSafeInteger(now) ? Verdict("the verifier clock is not a safe integer (fail closed)") : VerifyIntentRequired(b, keys, now);

    static string Title(string kind) => kind switch
    {
        "intent-required" => "Principal confirmation required for this action",
        "intent-denied" => "The principal does not intend this action",
        "schema-violation" => "The action does not conform to the site action schema",
        _ => "The action is outside a ceiling the principal cannot widen",
    };

    /// <summary>The RFC 9457 problem of a refused action: <c>{status: 403, headers: {WWW-Authenticate, Content-Type}, body}</c>. <c>intent-required</c> needs the signed question in <c>opts.body</c>.</summary>
    public static D IntentProblem(string? kind, D? opts = null)
    {
        // as the reference: an unknown kind is not refused; it answers error="undefined", no title, type = base + String(kind)
        var known = kind != null && ProblemKinds.Contains(kind);
        var error = known ? kind!.Replace('-', '_') : "undefined";
        var ps = new List<string> { $"error=\"{error}\"" };
        var body = opts?.GetValueOrDefault("body") as D;
        if (kind == "intent-required")
        {
            if (body == null) throw new InvalidOperationException("intentProblem: intent-required needs the signed body");
            ps.Add($"session=\"{AttestationSoft.Js(body.TryGetValue("session", out var se) ? se : AttestationSoft.Undef)}\"");
            ps.Add($"question=\"{AttestationSoft.Js(body.TryGetValue("question_id", out var q) ? q : AttestationSoft.Undef)}\"");
        }
        var pb = new D { ["type"] = ProblemBase + AttestationSoft.Js(kind) };
        if (known) pb["title"] = Title(kind!);
        pb["status"] = IntentJs.OfLong(403);
        if (opts != null && opts.TryGetValue("detail", out var detail)) pb["detail"] = detail;
        if (body != null) pb["pca"] = body;
        return new D
        {
            ["status"] = IntentJs.OfLong(403),
            ["headers"] = new D { ["WWW-Authenticate"] = "PCA " + string.Join(", ", ps), ["Content-Type"] = "application/problem+json" },
            ["body"] = pb,
        };
    }
}

public static class IntentMisc2
{
    static L Strs(params string[] xs) => xs.Cast<object?>().ToList();
    static D Re(string source) => new() { ["$regex"] = source };
    static object Num(long n) => IntentJs.OfLong(n);

    /// <summary>Every exported constant of the five modules (regexes as <c>{"$regex": source}</c>).</summary>
    public static D Constants() => new()
    {
        ["DATA_CLASS_RE"] = Re(@"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$"), ["INTENT_NAME_RE"] = Re("^[a-z][a-z0-9_]{0,63}$"), ["PARAM_SEGMENT_RE"] = Re("^[A-Za-z0-9_-]{1,64}$"), ["SUITE_MEMBERS"] = Strs("alg", "pq_pk", "pq_sig"),
        ["FRICTIONS"] = Strs("tap", "hold", "typed", "device"), ["INTENT_ACTION_DOMAIN"] = IntentRequired.ActionDomain, ["INTENT_PROBLEM_KINDS"] = Strs("intent-required", "intent-denied", "schema-violation", "ceiling"),
        ["INTENT_REQUIRED_DOMAIN"] = IntentRequired.RequiredDomain, ["PROBLEM_BASE"] = IntentRequired.ProblemBase, ["INTENT_CLASSIFIER_DOMAIN"] = IntentClassifier.IntentClassifierDomain,
        ["INTENT_CLASSIFIER_REF_DOMAIN"] = IntentClassifier.IntentClassifierRefDomain, ["MAX_CLASSIFIER_LABELS"] = Num(IntentClassifier.MaxClassifierLabels), ["MAX_COMMITTED_CLASSES"] = Num(IntentClassifier.MaxCommittedClasses),
        ["ACC_AGGS"] = Strs("sum", "count", "distinct", "max"), ["ACC_ID_RE"] = Re("^[A-Za-z0-9_]{1,64}$"), ["ACC_RECEIPT_CORE_DOMAIN"] = AccReceiptCoreDomain, ["ACC_RECEIPT_DOMAIN"] = IntentAcc.AccReceiptDomain,
        ["ACC_RECEIPT_REF_DOMAIN"] = IntentAcc.AccReceiptRefDomain, ["ACC_RESERVE_DOMAIN"] = IntentAcc.AccReserveDomain, ["ACC_SCOPES"] = Strs("session", "principal", "org", "fleet"),
        ["DEFAULT_MAX_KEYSET_AGE_MS"] = Num(IntentAcc.DefaultMaxKeySetAgeMs), ["DEFAULT_MAX_RECEIPT_AGE_MS"] = Num(IntentAcc.DefaultMaxReceiptAgeMs), ["KID_RE"] = Re("^[A-Za-z0-9_.:-]{1,64}$"),
        ["MAX_MONITOR_WITHIN"] = Num(IntentAcc.MaxMonitorWithin), ["MAX_RECEIPT_LIFETIME_MS"] = Num(IntentAcc.MaxReceiptLifetimeMs), ["MAX_SESSION_ACCUMULATORS"] = Num(IntentAcc.MaxSessionAccumulators),
        ["MAX_SESSION_MONITORS"] = Num(IntentAcc.MaxSessionMonitors), ["MONITOR_KINDS"] = Strs("requires_prior", "precedes", "never", "always", "responds_within"), ["RECEIPT_SKEW_MS"] = Num(IntentAcc.ReceiptSkewMs),
        ["SEQUENCER_KEYS_DOMAIN"] = IntentAcc.SequencerKeysDomain, ["SEQUENCER_KEYS_REF_DOMAIN"] = IntentAcc.SequencerKeysRefDomain, ["COUNTED_STATUSES"] = Strs("reserved", "committed"),
        ["EVENT_STATUSES"] = Strs("reserved", "committed", "released", "reverted"),
    };

    public const string AccReceiptCoreDomain = "atlas-pca/acc-receipt-core/v1";

    static object? Need(D d, string k) => d.TryGetValue(k, out var v) ? v : throw new InvalidOperationException("canonicalize: unsupported type undefined");

    // ---- strict artifacts ----

    /// <summary>Sign an artifact body under <paramref name="domain"/>: <c>{...body, sig, pq_sig?}</c>; a non-ed25519 suite binds <c>alg</c> and <c>pq_pk</c> into the signed body. Throws on an unknown alg.</summary>
    public static D SignArtifact(string domain, D body, byte[] secret, string? alg = null, SuiteSecretKeys? keys = null)
    {
        if (IntentJs.SuiteOf(alg ?? "ed25519", true) is not { } resolved) throw new InvalidOperationException($"signArtifact: unknown signature alg '{alg}'");
        var full = new D(body);
        if (resolved != "ed25519")
        {
            full["alg"] = resolved;
            full["pq_pk"] = PqSuites.SuitePqPublicKey(alg, keys) ?? throw new InvalidOperationException("canonicalize: unsupported type undefined");
        }
        var f = PqSuites.SignSuiteArtifact(alg, PqSuites.SuiteKeysOf(secret, keys), IntentArtifacts.ArtifactMessage(domain, full));
        var o = new D(full) { ["sig"] = f.Sig };
        if (f.PqSig != null) o["pq_sig"] = f.PqSig;
        return o;
    }

    /// <summary>The artifact's signature under a pinned signer: <paramref name="pin"/> a b64u key, or <c>{pk, pq_pk?}</c>. Never throws.</summary>
    public static bool VerifyArtifactSig(string domain, D artifact, object? pin)
    {
        try
        {
            var pk = pin is string ps ? ps : (pin as D)?.GetValueOrDefault("pk");
            var pq = pin is D pd ? pd.GetValueOrDefault("pq_pk") : null;
            return IntentArtifacts.VerifyArtifactSig(domain, artifact, pk, pq is string ? pq : null);
        }
        catch (Exception) { return false; }
    }

    public static string PublicKeyB64u(byte[] secret) { using var k = EdKey.FromSeed(secret); return k.Id; }

    // ---- the classifier ----

    /// <summary>A classifier verdict signed by <paramref name="secret"/>: <c>{v: 1, kind, ...body, judge, sig, ...}</c> (the judge is the signer's key).</summary>
    public static D SignClassifierVerdict(D body, byte[] secret, string? alg = null, SuiteSecretKeys? keys = null)
    {
        var o = new D { ["v"] = Num(1), ["kind"] = "pca-intent-classification" };
        foreach (var (k, v) in body) o[k] = v;
        o["judge"] = PublicKeyB64u(secret);
        return SignArtifact(IntentClassifier.IntentClassifierDomain, o, secret, alg, keys);
    }

    /// <summary>The attestation gate of a classifier verdict: its <c>measurement</c> must equal the attested enclave measurement (see <see cref="SemanticThreshold.VerifyJudgeAttestation"/>). A non-object verdict is refused.</summary>
    public static D VerifyClassifierAttestation(object? v, object? attestation, object? approved)
    {
        if (v is not D vd) return new D { ["ok"] = false, ["reason"] = "verdict must be an object" };
        try { return SemanticThreshold.VerifyJudgeAttestation(vd.GetValueOrDefault("measurement"), attestation, approved); }
        catch (Exception e) { return new D { ["ok"] = false, ["reason"] = "attestation check error (fail closed): " + (string.IsNullOrEmpty(e.Message) ? "unknown" : e.Message) }; }
    }

    // ---- accumulator receipts and sequencer key sets ----

    static D ReceiptBodyOf(D r, string signer)
    {
        var b = new D();
        foreach (var k in new[] { "v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at", "kid" }) b[k] = Need(r, k);
        var l = Need(r, "ledger") as D ?? throw new InvalidOperationException("Cannot read properties of undefined (reading 'index')");
        b["ledger"] = new D { ["index"] = Need(l, "index"), ["head"] = Need(l, "head") };
        b["signer"] = signer;
        return b;
    }

    /// <summary>Sign an accumulator receipt as the sequencer: <c>{...body, signer, sig, ...}</c>. Throws on a body that is not a well-formed receipt.</summary>
    public static D SignAccReceipt(D body, byte[] sequencerSecret, string? alg = null, SuiteSecretKeys? keys = null)
    {
        var signer = PublicKeyB64u(sequencerSecret);
        var bas = ReceiptBodyOf(body, signer);
        var pqPk = PqSuites.SuitePqPublicKey(alg, keys);
        var f = PqSuites.SignSuiteArtifact(alg, PqSuites.SuiteKeysOf(sequencerSecret, keys), IntentJs.Message(IntentAcc.AccReceiptDomain, IntentJs.BindSuiteFields(bas, alg, alg != null, pqPk, pqPk != null)));
        var o = new D(bas) { ["sig"] = f.Sig };
        if (f.Alg != null) o["alg"] = f.Alg;
        if (f.PqPk != null) o["pq_pk"] = f.PqPk;
        if (f.PqSig != null) o["pq_sig"] = f.PqSig;
        var bad = IntentAcc.ReceiptShapeError(o);
        if (bad != null) throw new InvalidOperationException("signAccReceipt: " + bad);
        return o;
    }

    /// <summary>The receipt's log-leaf content: the strict hash of its core (without the ledger position, the key id and the signature fields).</summary>
    public static string AccReceiptCoreDigest(D r)
    {
        var core = new D();
        foreach (var k in new[] { "v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at" }) core[k] = Need(r, k);
        return Pca.HashCanonical(new D { ["d"] = AccReceiptCoreDomain, ["r"] = core });
    }

    /// <summary>Sign a sequencer key set as the root: <c>{v, kind, sequencer, version, issued_at, keys, sig, ...}</c>. Throws on a body that is not a well-formed key set.</summary>
    public static D SignSequencerKeySet(D body, byte[] rootSecret, string? alg = null, SuiteSecretKeys? keys = null)
    {
        var bas = new D();
        foreach (var k in new[] { "v", "kind" }) bas[k] = Need(body, k);
        bas["sequencer"] = PublicKeyB64u(rootSecret);
        foreach (var k in new[] { "version", "issued_at", "keys" }) bas[k] = Need(body, k);
        var pqPk = PqSuites.SuitePqPublicKey(alg, keys);
        var f = PqSuites.SignSuiteArtifact(alg, PqSuites.SuiteKeysOf(rootSecret, keys), IntentJs.Message(IntentAcc.SequencerKeysDomain, IntentJs.BindSuiteFields(bas, alg, alg != null, pqPk, pqPk != null)));
        var o = new D(bas) { ["sig"] = f.Sig };
        if (f.Alg != null) o["alg"] = f.Alg;
        if (f.PqPk != null) o["pq_pk"] = f.PqPk;
        if (f.PqSig != null) o["pq_sig"] = f.PqSig;
        var bad = IntentAcc.KeySetShapeError(o);
        if (bad != null) throw new InvalidOperationException("signSequencerKeySet: " + bad);
        return o;
    }

    /// <summary>The distinct strings in UTF-8 byte order.</summary>
    public static L SortedDistinct(IEnumerable<string> keys) => IntentJs.SortedUtf8(keys.Distinct(StringComparer.Ordinal)).Cast<object?>().ToList();

    // ---- admission and settlement through a session store ----

    /// <summary>Admit one action atomically against the session's accumulators (site-local holder): under the session lock, compute the pre-states and monitor states from the history, run <paramref name="verify"/>
    /// with them and, on <c>allow</c>, append the event as <c>reserved</c>. The store must report <c>durable === true</c> unless <paramref name="requireDurable"/> is false (a restart would reset every cap).
    /// <paramref name="args"/>: <c>{session, root, schema?, event}</c>.</summary>
    public static D AdmitIntentAction(IIntentSessionStore store, D args, Func<D, D> verify, bool requireDurable = true)
    {
        if (requireDurable && store.Durable is not true) throw new InvalidOperationException("admitIntentAction: the session store is not durable (a restart would reset every cap); use a durable IntentSessionStore");
        var ev = (D)args["event"]!;
        return store.WithSession((string)args["session"]!, tx =>
        {
            var history = tx.Events();
            var acc = IntentHistory.AccContextFor((D)args["root"]!, history, (D)ev["params"]!, ev.GetValueOrDefault("t"), args.GetValueOrDefault("schema"));
            var v = verify(acc);
            if (v.GetValueOrDefault("allow") is true) tx.Append(new D(ev) { ["status"] = "reserved" });
            return v;
        });
    }

    /// <summary>Settle an event after its effect: <c>committed</c>, <c>released</c> or <c>reverted</c>. False when the session has no such event.</summary>
    public static bool SettleIntentEvent(IIntentSessionStore store, string session, string id, string status) => store.WithSession(session, tx => tx.SetStatus(id, status));
}
