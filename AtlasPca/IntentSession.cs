// Rule 13: the PCActn member `intent_session` (wire), the `intent_session` grant caveat and the principal-signed session root
// S (`pca-intent-session` v1), mirroring IntentSession.java (packages/pca/src/intent-session.ts, intent-session-caveat.ts).
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class IntentSession
{
    public const string IntentSessionKind = "pca-intent-session";
    public const string IntentSessionSigDomain = "atlas-pca/intent-session/v1\0";
    public const string IntentSessionRefDomain = "atlas-pca/intent-session-ref/v1";
    public const string IntentSessionCaveat = "intent_session";
    public const string IntentGoalV2Prefix = "pca-intent:v2:";
    /// <summary>Session grants over a COMMITTED map (rule 19): <c>pca-intent:v2c:&lt;session&gt;:&lt;map_commit&gt;</c>.</summary>
    public const string IntentGoalV2cPrefix = "pca-intent:v2c:";
    public const long MaxSessionSeq = 2_147_483_647L;
    public const int MaxIsAcc = 16, MaxIsFacts = 16, MaxIsProvPaths = 32, MaxIsProvRefs = 8, MaxIsClasses = 8, MaxIsLabels = 16, MaxIsStringBytes = 256;
    public const int MaxSessionPrincipals = 16;
    static readonly string[] IntentSessionFields = { "session", "root", "seq", "schema", "acc", "facts", "offer_set", "prov", "classes", "labels", "map_form" };
    internal static readonly Regex AccIdRe = new(@"^[A-Za-z0-9_]{1,64}\z", RegexOptions.CultureInvariant);
    static readonly Regex ProvKeyRe = new(@"^action\.params\.[A-Za-z0-9_]{1,64}\z", RegexOptions.CultureInvariant);
    static readonly string[] RootKeys = { "v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors",
        "question_uri", "revocation", "flows", "expires_at", "signer", "alg", "pq_pk", "sig", "pq_sig" };

    static bool ShortStr(object? v) => v is string s && s.Length > 0 && !Pca.HasLoneSurrogate(s) && IntentJs.U8Len(s) <= MaxIsStringBytes;

    static string? DigestList(object? v, string name, int max)
    {
        if (v is not L l || l.Count > max) return $"'intent_session.{name}' must be an array of at most {max} digests";
        if (l.Any(x => !IntentJs.B32(x))) return $"'intent_session.{name}' entries must be canonical base64url (32 bytes)";
        if (l.Cast<string>().Distinct().Count() != l.Count) return $"'intent_session.{name}' entries must be distinct";
        return null;
    }

    /// <summary>Wire validation of <c>intent_session</c> (part of the terminal <c>wire</c> check). Null = well-formed.</summary>
    public static string? ValidateWire(object? vO)
    {
        if (vO is not D v) return "'intent_session' must be an object";
        foreach (var k in v.Keys) if (!IntentSessionFields.Contains(k)) return $"unknown field 'intent_session.{k}'";
        foreach (var k in new[] { "session", "root", "seq", "schema" }) if (!v.ContainsKey(k)) return $"missing field 'intent_session.{k}'";
        foreach (var k in new[] { "session", "root", "schema" }) if (!IntentJs.B32(v[k])) return $"'intent_session.{k}' is not canonical base64url (32 bytes)";
        if (!IntentJs.IsNonNeg(v["seq"]) || IntentJs.NumOf(v["seq"]) > MaxSessionSeq) return "'intent_session.seq' must be a safe integer in [0, 2147483647]";
        if (v.ContainsKey("acc"))
        {
            if (v["acc"] is not L acc || acc.Count > MaxIsAcc) return $"'intent_session.acc' must be an array of at most {MaxIsAcc} entries";
            var ids = new HashSet<string>();
            for (int i = 0; i < acc.Count; i++)
            {
                if (acc[i] is not D a) return $"'intent_session.acc[{i}]' must be an object";
                foreach (var k in a.Keys) if (k != "id" && k != "post" && k != "receipt") return $"unknown field 'intent_session.acc[{i}].{k}'";
                if (IntentJs.Get(a, "id") is not string id || !AccIdRe.IsMatch(id)) return $"'intent_session.acc[{i}].id' must match [A-Za-z0-9_]{{1,64}}";
                if (!ids.Add(id)) return "'intent_session.acc' ids must be distinct";
                if (!IntentJs.IsNonNeg(IntentJs.Get(a, "post"))) return $"'intent_session.acc[{i}].post' must be a non-negative safe integer";
                if (a.ContainsKey("receipt") && !IntentJs.B32(a["receipt"])) return $"'intent_session.acc[{i}].receipt' is not canonical base64url (32 bytes)";
            }
        }
        if (v.ContainsKey("facts")) { var e = DigestList(v["facts"], "facts", MaxIsFacts); if (e != null) return e; }
        if (v.ContainsKey("offer_set") && !IntentJs.B32(v["offer_set"])) return "'intent_session.offer_set' is not canonical base64url (32 bytes)";
        if (v.ContainsKey("prov"))
        {
            if (v["prov"] is not D prov || prov.Count > MaxIsProvPaths) return $"'intent_session.prov' must be an object of at most {MaxIsProvPaths} entries";
            foreach (var (path, refs) in prov)
            {
                if (!ProvKeyRe.IsMatch(path)) return $"'intent_session.prov' key '{path}' is not action.params.<name>";
                if (refs is not L rl || rl.Count == 0 || rl.Count > MaxIsProvRefs || !rl.All(ShortStr))
                    return $"'intent_session.prov.{path}' must be 1..{MaxIsProvRefs} non-empty strings of at most {MaxIsStringBytes} UTF-8 bytes";
            }
        }
        if (v.ContainsKey("classes")) { var e = DigestList(v["classes"], "classes", MaxIsClasses); if (e != null) return e; }
        if (v.ContainsKey("labels")) { var e = DigestList(v["labels"], "labels", MaxIsLabels); if (e != null) return e; }
        if (v.ContainsKey("map_form") && v["map_form"] as string != IntentMap.MapFormCommit) return "'intent_session.map_form' must be \"commit\" when present";
        return null;
    }

    /// <summary>The goal a session grant commits to: <c>pca-intent:v2:&lt;session&gt;:&lt;map_digest&gt;</c>.</summary>
    public static string IntentGoalV2(string session, string mapDigest) => IntentGoalV2Prefix + session + ":" + mapDigest;

    /// <summary>The goal a session grant over a COMMITTED map commits to (rule 19): <c>pca-intent:v2c:&lt;session&gt;:&lt;map_commit&gt;</c>.</summary>
    public static string IntentGoalV2c(string session, string mapCommit) => IntentGoalV2cPrefix + session + ":" + mapCommit;

    /// <summary>The FIRST caveat of <paramref name="grant"/> whose type is <c>intent_session</c> (as is), or null.</summary>
    internal static D? GrantSessionCaveat(object? grant) =>
        grant is D g && IntentJs.Get(g, "caveats") is L cs ? cs.Select(c => c as D).FirstOrDefault(c => c != null && IntentJs.Get(c, "type") as string == IntentSessionCaveat) : null;

    /// <summary>Shape of an <c>intent_session</c> grant caveat: exactly {type, session, seq, root, prev?}, prev present iff seq &gt; 0.</summary>
    public static string? CaveatError(object? cO)
    {
        if (cO is not D c || IntentJs.Get(c, "type") as string != IntentSessionCaveat) return "not an intent_session caveat";
        foreach (var k in c.Keys) if (k is not ("type" or "session" or "seq" or "root" or "prev")) return $"intent_session caveat: unknown member '{k}'";
        if (!IntentJs.B32(IntentJs.Get(c, "session")) || !IntentJs.B32(IntentJs.Get(c, "root"))) return "intent_session caveat: session and root must be canonical base64url (32 bytes)";
        if (!IntentJs.IsNonNeg(IntentJs.Get(c, "seq")) || IntentJs.NumOf(c["seq"]) > MaxSessionSeq) return "intent_session caveat: seq must be a safe integer in [0, 2147483647]";
        if ((IntentJs.NumOf(c["seq"]) == 0) != !c.ContainsKey("prev")) return "intent_session caveat: prev is present exactly when seq > 0";
        if (c.ContainsKey("prev") && !IntentJs.B32(c["prev"])) return "intent_session caveat: prev must be canonical base64url (32 bytes)";
        return null;
    }

    static bool KeysAre(object? o, params string[] keys) => o is D m && m.Count == keys.Length && keys.All(m.ContainsKey);

    /// <summary>Structural validation of a signed session root. Null = well-formed. Never throws.</summary>
    public static string? RootShapeError(object? sO)
    {
        try
        {
            if (sO is not D s) return "session root is not an object";
            foreach (var k in s.Keys) if (!RootKeys.Contains(k)) return $"session root: unknown member '{k}'";
            if (!OracleFacts.IsOne(IntentJs.Get(s, "v")) || IntentJs.Get(s, "kind") as string != IntentSessionKind) return "not a pca-intent-session v1";
            if (!IntentJs.B32(IntentJs.Get(s, "session")) || !IntentJs.B32(IntentJs.Get(s, "intent_ref"))) return "session and intent_ref must be canonical base64url (32 bytes)";
            if (IntentJs.Get(s, "principals") is not L ps || ps.Count == 0 || ps.Count > MaxSessionPrincipals) return $"principals must be 1..{MaxSessionPrincipals} keys";
            var keys = new HashSet<string>();
            foreach (var p in ps)
            {
                if (p is not D pd || !IntentJs.B32(IntentJs.Get(pd, "key")) || pd.Keys.Any(k => k is not ("key" or "alg" or "pq_pk"))) return "principals entries are {key, alg?, pq_pk?} with a 32-byte key";
                var pse = IntentJs.SuiteError(IntentJs.Get(pd, "alg"), pd.ContainsKey("alg"));
                if (pse != null) return "principal alg: " + pse;
                if (pd.ContainsKey("pq_pk") && !IntentJs.B64Any(pd["pq_pk"])) return "principal pq_pk is not canonical base64url";
                if (!keys.Add((string)pd["key"]!)) return "principal keys must be distinct";
            }
            var sc = IntentJs.Get(s, "schema");
            if (!KeysAre(sc, "aud", "digest") || IntentJs.Get(sc, "aud") is not string scAud || scAud.Length == 0 || !IntentJs.B32(IntentJs.Get(sc, "digest"))) return "schema must be {aud, digest}";
            if (IntentJs.Get(s, "layers") is not D layers) return "layers must be an object";
            foreach (var k in layers.Keys) if (k is not ("org" or "std" or "task")) return $"layers: unknown member '{k}'";
            var task = IntentJs.Get(layers, "task");
            if (!KeysAre(task, "map_digest") || !IntentJs.B32(IntentJs.Get(task, "map_digest"))) return "layers.task must be {map_digest}";
            if (layers.TryGetValue("org", out var org) && (org is not D || !IntentJs.B32(IntentJs.Get(org, "digest")))) return "layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)";
            if (layers.TryGetValue("std", out var std))
            {
                if (!KeysAre(std, "digest", "profile", "version") || IntentJs.Get(std, "profile") is not string prof || prof.Length == 0 || IntentJs.U8Len(prof) > 128
                    || !(IntentJs.IsInt(IntentJs.Get(std, "version")) && IntentJs.NumOf(IntentJs.Get(std, "version")) >= 1) || !IntentJs.B32(IntentJs.Get(std, "digest")))
                    return "layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)";
            }
            if (IntentJs.Get(s, "accumulators") is not L accs || accs.Count > IntentAcc.MaxSessionAccumulators) return $"accumulators must be an array of at most {IntentAcc.MaxSessionAccumulators}";
            var ids = new HashSet<string>();
            foreach (var a in accs)
            {
                var e = IntentAcc.AccumulatorDeclError(a);
                if (e != null) return e;
                if (!ids.Add((string)((D)a!)["id"]!)) return "accumulator and monitor ids must be distinct";
            }
            if (IntentJs.Get(s, "monitors") is not L mons || mons.Count > IntentAcc.MaxSessionMonitors) return $"monitors must be an array of at most {IntentAcc.MaxSessionMonitors}";
            var mids = new HashSet<string>();
            foreach (var m in mons)
            {
                var e = IntentAcc.MonitorDeclError(m);
                if (e != null) return e;
                if (!mids.Add((string)((D)m!)["id"]!)) return "monitor ids must be distinct";
            }
            if (IntentJs.Get(s, "question_uri") is not string q || q.Length == 0 || IntentJs.U8Len(q) > 2048) return "question_uri must be a non-empty string";
            if (s.ContainsKey("revocation"))
            {
                if (s["revocation"] is not D r || r.Keys.Any(k => k is not ("epoch_uri" or "max_age_s" or "key" or "pq_pk"))) return "revocation must be {epoch_uri, max_age_s, key, pq_pk?}";
                if (IntentJs.Get(r, "epoch_uri") is not string eu || eu.Length == 0) return "revocation.epoch_uri must be a non-empty string";
                if (!IntentJs.IsNonNeg(IntentJs.Get(r, "max_age_s"))) return "revocation.max_age_s must be a non-negative safe integer";
                if (!IntentJs.B32(IntentJs.Get(r, "key"))) return "revocation.key (the dedicated revocation authority) is required: canonical base64url (32 bytes)";
                if (keys.Contains((string)r["key"]!)) return "revocation.key must not be a session principal (a dedicated revocation authority)";
                if (r.ContainsKey("pq_pk") && !IntentJs.B64Any(r["pq_pk"])) return "revocation.pq_pk must be canonical base64url";
            }
            if (s.ContainsKey("flows") && s["flows"] is not D) return "flows must be an object";
            if (!IntentJs.IsNonNeg(IntentJs.Get(s, "expires_at"))) return "expires_at must be a non-negative safe integer (epoch ms)";
            if (!IntentJs.B32(IntentJs.Get(s, "signer"))) return "signer must be canonical base64url (32 bytes)";
            if (!keys.Contains((string)s["signer"]!)) return "signer is not one of the session principals";
            var ase = IntentJs.SuiteError(IntentJs.Get(s, "alg"), s.ContainsKey("alg"));
            if (ase != null) return "alg: " + ase;
            var suite = IntentJs.SuiteOf(s);
            if (suite == "ed25519" && (s.ContainsKey("pq_pk") || s.ContainsKey("pq_sig"))) return "an ed25519 session root must not carry pq_pk / pq_sig";
            if (IntentJs.Get(s, "sig") is not string) return "sig must be a string";
            IntentJs.CanonBytes(RootBody(s));
            return null;
        }
        catch (Exception e) { return "malformed session root: " + e.Message; }
    }

    static D RootBody(D s)
    {
        var b = new D();
        foreach (var k in new[] { "v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors", "question_uri" }) b[k] = IntentJs.Get(s, k);
        if (s.ContainsKey("revocation")) b["revocation"] = s["revocation"];
        if (s.ContainsKey("flows")) b["flows"] = s["flows"];
        b["expires_at"] = IntentJs.Get(s, "expires_at");
        return b;
    }

    /// <summary>Verify S: shape, signer listed, suite signature. Null = valid. R3-01 (fail closed): a non-ed25519 root verifies
    /// only under the VERIFIER's pin for its signer (<paramref name="pqPins"/> = context <c>session.pq_pins</c>, an object
    /// whose member for the signer is a string), never under the root's own <c>principals[].pq_pk</c>; the signer's own entry,
    /// when it declares a <c>pq_pk</c>, must agree. An ed25519 root never consults the pins.</summary>
    public static string? VerifyRoot(object? sO, object? pqPins = null)
    {
        try
        {
            var bad = RootShapeError(sO);
            if (bad != null) return bad;
            var s = (D)sO!;
            var signer = (string)s["signer"]!;
            var p = ((L)s["principals"]!).Cast<D>().First(x => x["key"] as string == signer);
            IReadOnlyDictionary<string, string>? pin = null;
            var suite = IntentJs.SuiteOf(IntentJs.Get(s, "alg"), s.ContainsKey("alg"));
            if (suite != null && Pq.Suites[suite].NeedsPqPk)
            {
                if (pqPins is not D pins || !pins.TryGetValue(signer, out var pv) || pv is not string pinned)
                    return $"session root suite '{suite}' needs the signer's PQ key pinned by the verifier (pq_pins); the root's own principals entry proves nothing about who signed it";
                if (IntentJs.Get(s, "pq_pk") as string != pinned || !s.ContainsKey("pq_pk"))
                    return "session root pq_pk does not match the verifier's pin for the signer";
                if (p.ContainsKey("pq_pk") && p["pq_pk"] as string != pinned)
                    return "session root pq_pk does not match the signer's principals entry";
                pin = IntentJs.Pin(signer, pinned);
            }
            var body = RootBody(s);
            body["signer"] = signer;
            var msg = IntentJs.Message(IntentSessionSigDomain, IntentJs.BindSuiteFields(body, IntentJs.Get(s, "alg"), s.ContainsKey("alg"), IntentJs.Get(s, "pq_pk"), s.ContainsKey("pq_pk")));
            if (!IntentJs.VerifyPinnedSuite(IntentJs.Get(s, "alg"), s.ContainsKey("alg"), signer, IntentJs.Get(s, "pq_pk"), msg, IntentJs.Get(s, "sig"), IntentJs.Get(s, "pq_sig"), pin))
                return "session root signature invalid";
            return null;
        }
        catch (Exception e) { return "malformed session root: " + e.Message; }
    }

    /// <summary>digest(S): the content address of the whole signed session root.</summary>
    public static string RootDigest(object? s) => IntentJs.Ref(IntentSessionRefDomain, "s", s);
}
