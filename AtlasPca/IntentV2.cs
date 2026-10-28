// The Intent Layer v2 checks of the core verifier (packages/pca/src/intent-v2.ts decideIntentV2), mirroring IntentV2.java, in
// their normative order after `intent` (rule 12): schema (rule 14) -> intent_session (rule 13) -> layers (V5) -> accumulators
// (rule 15) -> facts / provenance / classes (rules 16-18, IntentWB). REPORTING: `schema` iff the PCActn carries intent_session
// or the policy sets schema.closed_world: true; `intent_session` iff the PCActn carries it or session.require is true;
// `layers` iff the PCActn carries intent_session and the verifier configured layers; `accumulators` iff the PCActn carries
// intent_session; the W-B checks iff the PCActn carries intent_session and IntentWB reports them. Checks 1-4 are independent;
// the W-B checks are one unit. A rule-17 `question` fails `provenance` with reason `intent_required: ...`. Never throws.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The verifier state the v2 checks read (verifier-held, never the agent's): <c>{policy?, params?, schema?: {docs, keys},
/// session?: {root?, grants?, revocation?}, layers?, wb?: {artifacts?, policy?}, acc?: {state?, monitors?, receipts?, last_seq?,
/// sequencer_keys?}}</c> as a JSON tree (the <c>context.intent_v2</c> object of the vectors).</summary>
public sealed class IntentV2Context
{
    internal readonly D Raw;
    /// <summary>False for a PRESENT context that is not a JSON object (null included): every reportable v2 check fails.</summary>
    internal readonly bool WellFormed;
    IntentV2Context(D raw, bool wellFormed) { Raw = raw; WellFormed = wellFormed; }

    /// <summary>From the parsed JSON value of a PRESENT <c>intent_v2</c> member (normalized to binary64 number semantics). A
    /// non-object (JSON null included) is a malformed context, never "no context": pass null only when the member is absent.</summary>
    public static IntentV2Context FromJson(object? o) => IntentJs.Normalize(o) is D d ? new IntentV2Context(d, true) : new IntentV2Context(new D(), false);

    /// <summary>From raw JSON text (lenient parse).</summary>
    public static IntentV2Context FromJsonText(string text) => FromJson(Pca.ParseJson(text));

    /// <summary>A copy with <c>params</c> replaced (a host supplying the plaintext params it parsed from the request).</summary>
    public IntentV2Context WithParams(object? parameters) => new(new D(Raw) { ["params"] = IntentJs.Normalize(parameters) }, WellFormed);

    /// <summary>A copy with the verifier defaults of <c>authorize</c> (TypeScript <c>intentV2.params ?? ctx.params</c>, <c>intentV2.env ?? ctx.env</c>):
    /// a missing or null <c>params</c> is the operation's, a missing or null <c>env</c> is the authorize context's (absent when that has none).</summary>
    internal IntentV2Context WithDefaults(object? parameters, object? hostEnv)
    {
        var raw = new D(Raw);
        if (raw.GetValueOrDefault("params") == null) raw["params"] = IntentJs.Normalize(parameters);
        if (raw.GetValueOrDefault("env") == null)
        {
            raw.Remove("env");
            if (hostEnv != null) raw["env"] = IntentJs.Normalize(hostEnv);
        }
        return new IntentV2Context(raw, WellFormed);
    }

    internal object? Get(params string[] path)
    {
        object? cur = Raw;
        foreach (var k in path) cur = IntentJs.Get(cur, k);
        return cur;
    }

    internal bool Has(params string[] path)
    {
        object? cur = Raw;
        for (int i = 0; i < path.Length - 1; i++) cur = IntentJs.Get(cur, path[i]);
        return IntentJs.Own(cur, path[^1]);
    }
}

public static class IntentV2
{
    /// <summary>One reported v2 check.</summary>
    public sealed record Check(string Name, bool Ok, string? Reason);

    /// <summary>The checks in reporting order and the verifier-computed predicate env (<c>canon</c>, <c>acc</c>, <c>mon</c>, <c>world</c>, <c>prov</c>, <c>class</c>).</summary>
    public sealed class Decision
    {
        public List<Check> Checks { get; } = new();
        public D Env { get; } = new();
        /// <summary>The action schema the action was checked against (when the schema check passed).</summary>
        public object? Schema { get; internal set; }
        /// <summary>The worlds decided by a single oracle (their <c>env.world.&lt;name&gt;</c> is model-derived, rule 21).</summary>
        public List<string> SingleSource { get; internal set; } = new();
        /// <summary>Rule 21's compatibility mode is in effect and a grant reads a model-derived path (reported degraded).</summary>
        public bool Legacy { get; internal set; }
    }

    /// <summary>True iff any v2 check would be reported (a malformed present context fails closed, so it counts).</summary>
    public static bool Active(D p, IntentV2Context? ctx) => p.ContainsKey("intent_session") || ContextError(ctx) != null || ClosedWorld(ctx) || SessionRequired(ctx) || MapRequired(ctx);
    static bool MapRequired(IntentV2Context? ctx) => ctx?.Get("policy", "map", "require") is true;
    /// <summary>The PCActn's <c>intent_session.map_form</c> is <c>"commit"</c> (rule 19).</summary>
    static bool MapCommitted(D p) => IntentJs.Get(IntentJs.Get(p, "intent_session"), "map_form") as string == IntentMap.MapFormCommit;
    static bool ClosedWorld(IntentV2Context? ctx) => ctx?.Get("policy", "schema", "closed_world") is true;
    static bool SessionRequired(IntentV2Context? ctx) => ctx?.Get("policy", "session", "require") is true;

    static object? CGet(IntentV2Context? ctx, params string[] path) => ctx?.Get(path);

    static bool OptD(object? o, string k) => !IntentJs.Own(o, k) || IntentJs.Get(o, k) is D;
    static bool OptL(object? o, string k) => !IntentJs.Own(o, k) || IntentJs.Get(o, k) is L;

    /// <summary>The verifier context is closed and typed at the top level (README "absent vs null", "the v2 policy is closed and
    /// typed"): a malformed member fails every reportable v2 check. Null = well-formed.</summary>
    internal static string? ContextError(IntentV2Context? ctx)
    {
        if (ctx == null) return null;
        if (!ctx.WellFormed) return "the v2 verifier context must be an object";
        var c = ctx.Raw;
        if (!OptD(c, "policy")) return "policy must be an object";
        if (c.TryGetValue("policy", out var pol))
        {
            var pr = (D)pol!;
            foreach (var k in pr.Keys) if (k is not ("session" or "schema" or "acc" or "map" or "model_polarity")) return $"policy: unknown member '{k}'";
            if (pr.TryGetValue("model_polarity", out var mpol) && mpol is not ("strict" or "legacy")) return "policy.model_polarity must be 'strict' or 'legacy'";
            if (!OptD(pr, "session")) return "policy.session must be an object";
            if (pr.TryGetValue("session", out var ps))
            {
                var o = (D)ps!;
                foreach (var k in o.Keys) if (k is not ("require" or "max_revocation_age_s")) return $"policy.session: unknown member '{k}'";
                if (o.ContainsKey("require") && o["require"] is not bool) return "policy.session.require must be a boolean";
                if (o.ContainsKey("max_revocation_age_s") && !IntentJs.IsNonNeg(o["max_revocation_age_s"])) return "policy.session.max_revocation_age_s must be a non-negative safe integer";
            }
            if (!OptD(pr, "schema")) return "policy.schema must be an object";
            if (pr.TryGetValue("schema", out var pc))
            {
                var o = (D)pc!;
                foreach (var k in o.Keys) if (k != "closed_world") return $"policy.schema: unknown member '{k}'";
                if (o.ContainsKey("closed_world") && o["closed_world"] is not bool) return "policy.schema.closed_world must be a boolean";
            }
            if (!OptD(pr, "acc")) return "policy.acc must be an object";
            if (pr.TryGetValue("acc", out var pa))
            {
                var o = (D)pa!;
                foreach (var k in o.Keys) if (k is not ("max_receipt_age_s" or "max_keyset_age_s")) return $"policy.acc: unknown member '{k}'";
                foreach (var k in new[] { "max_receipt_age_s", "max_keyset_age_s" })
                    if (o.ContainsKey(k) && !IntentJs.IsNonNeg(o[k])) return $"policy.acc.{k} must be a non-negative safe integer";
            }
            if (!OptD(pr, "map")) return "policy.map must be an object";
            if (pr.TryGetValue("map", out var pm))
            {
                var o = (D)pm!;
                foreach (var k in o.Keys) if (k is not ("require" or "max_residual_risk_ppm")) return $"policy.map: unknown member '{k}'";
                if (o.ContainsKey("require") && o["require"] is not bool) return "policy.map.require must be a boolean";
                if (o.ContainsKey("max_residual_risk_ppm") && !IntentJs.IsNonNeg(o["max_residual_risk_ppm"])) return "policy.map.max_residual_risk_ppm must be a non-negative safe integer";
            }
        }
        if (!OptD(c, "params")) return "params must be an object";
        if (!OptD(c, "env")) return "env must be an object";
        foreach (var k in new[] { "schema", "session", "acc" }) if (!OptD(c, k)) return k + " must be an object";
        if (!OptD(c, "map")) return "map must be an object";
        if (c.TryGetValue("map", out var mc)) foreach (var k in ((D)mc!).Keys) if (k != "disclosure") return $"map: unknown member '{k}'";
        if (c.TryGetValue("layers", out var layers))
        {
            if (layers is not D ld) return "layers must be an object";
            foreach (var (k, v) in ld)
            {
                if (k is not ("org" or "site" or "std")) return $"layers: unknown member '{k}'";
                if (v is not D vd || IntentJs.Get(vd, "predicates") is not L) return $"layers.{k} must be {{predicates: [...]}}";
            }
        }
        if (c.TryGetValue("wb", out var wb))
        {
            if (wb is not D) return "wb must be an object";
            if (!OptD(wb, "artifacts")) return "wb.artifacts must be an object";
            if (IntentJs.Own(wb, "artifacts"))
            {
                var a = IntentJs.Get(wb, "artifacts");
                foreach (var k in new[] { "facts", "labels", "verdicts" }) if (!OptL(a, k)) return $"wb.artifacts.{k} must be an array";
                if (!OptD(a, "offer_set")) return "wb.artifacts.offer_set must be an object";
            }
            if (!OptD(wb, "policy")) return "wb.policy must be an object";
            if (IntentJs.Own(wb, "policy"))
            {
                var p = IntentJs.Get(wb, "policy");
                if (!OptD(p, "world") || !OptD(p, "provenance")) return "wb.policy.world / provenance must be objects";
                if (!OptL(p, "classifiers")) return "wb.policy.classifiers must be an array";
            }
        }
        return null;
    }

    static string? SchemaCtxError(IntentV2Context? ctx)
    {
        if (ctx == null || !ctx.Has("schema")) return null;
        var sc = ctx.Get("schema");
        return sc is D && IntentJs.Get(sc, "docs") is L && IntentJs.Get(sc, "keys") is L ? null : "the schema context must be {docs: [...], keys: [...]}";
    }

    static string? SessionCtxError(IntentV2Context? ctx)
    {
        if (ctx == null || !ctx.Has("session")) return null;
        var se = ctx.Get("session");
        if (se is not D) return "the session context must be an object";
        if (!OptL(se, "grants")) return "the session grants must be an array";
        if (!OptD(se, "revocation")) return "the session revocation evidence must be an object";
        if (!OptD(se, "revocation_last")) return "the tracked last revocation epoch must be an object";
        if (se is D sd && sd.TryGetValue("pq_pins", out var pp) && (pp is not D pm || pm.Values.Any(x => x is not string)))
            return "the session pq_pins must be an object of strings";
        return null;
    }

    static string? AccCtxError(IntentV2Context? ctx)
    {
        if (ctx == null || !ctx.Has("acc")) return null;
        var a = ctx.Get("acc");
        if (a is not D) return "the accumulator context must be an object";
        foreach (var k in new[] { "state", "monitors", "last_seq", "keyset_versions" }) if (!OptD(a, k)) return $"acc.{k} must be an object";
        if (IntentJs.Get(a, "keyset_versions") is D kvs)
            foreach (var v in kvs.Values) if (IntentAcc.TrackedKeySetError(v) is string te) return "acc.keyset_versions: " + te;
        foreach (var k in new[] { "receipts", "sequencer_keys" }) if (!OptL(a, k)) return $"acc.{k} must be an array";
        if (IntentJs.Get(a, "last_seq") is D ls && ls.Values.Any(v => !IntentJs.IsNonNeg(v))) return "acc.last_seq values must be non-negative safe integers";
        return null;
    }

    static string VerbOf(D p) => IntentRevocation.JsText(IntentJs.Get(IntentJs.Get(p, "action"), "verb"), IntentJs.Own(IntentJs.Get(p, "action"), "verb"));
    static string ResourceOf(D p) => IntentRevocation.JsText(IntentJs.Get(IntentJs.Get(p, "action"), "resource"), IntentJs.Own(IntentJs.Get(p, "action"), "resource"));

    static object? SchemaByDigest(object? docs, object? want)
    {
        if (docs is not L l) return null;
        foreach (var d in l)
        {
            bool hit;
            try { hit = ActionSchema.Digest(d) == want as string; } catch (Exception) { hit = false; }
            if (hit) return d;
        }
        return null;
    }

    static string? SchemaStep(D p, IntentV2Context? ctx, out object? matched)
    {
        matched = null;
        var ce = SchemaCtxError(ctx);
        if (ce != null) return ce;
        if (CGet(ctx, "schema", "docs") is not L docs || docs.Count == 0) return "this verifier has no action schema configured";
        object? doc;
        if (p.ContainsKey("intent_session"))
        {
            doc = SchemaByDigest(docs, IntentJs.Get(p["intent_session"], "schema"));
            if (doc == null) return "intent_session.schema names no schema this verifier accepts";
        }
        else doc = docs[0];
        var v = ActionSchema.Verify(doc, ctx!.Get("schema", "keys"));
        if (v != null) return "schema does not verify: " + v;
        if (IntentJs.Get(doc, "aud") as string != IntentJs.Get(p, "aud") as string) return "schema aud does not match the PCActn aud";
        if (CGet(ctx, "params") is not D parameters) return "no plaintext params to check against the schema (closed world needs them)";
        if (Pca.ParamsDigest(parameters) != IntentJs.Get(IntentJs.Get(p, "action"), "params_digest") as string) return "params do not hash to action.params_digest";
        var c = ActionSchema.ConformAction(doc, VerbOf(p), parameters);
        if (!c.Ok) return $"schema_violation: {c.Code}: {c.Reason}";
        matched = doc;
        return null;
    }

    static string? BoundRoot(D isw, IntentV2Context? ctx, double now, out D? root)
    {
        root = null;
        if (ctx == null || !ctx.Has("session", "root")) return "no session root for this session";
        var S = ctx.Get("session", "root");
        // a PQ / hybrid root verifies only under the VERIFIER's pin for its signer (session.pq_pins), never its own principals
        var v = IntentSession.VerifyRoot(S, ctx.Has("session", "pq_pins") ? ctx.Get("session", "pq_pins") : null);
        if (v != null) return "session root: " + v;
        if (IntentSession.RootDigest(S) != isw["root"] as string) return "intent_session.root is not the digest of the session root";
        if (IntentJs.Get(S, "session") as string != isw["session"] as string) return "the session root names another session";
        if (!(now < IntentJs.NumOf(IntentJs.Get(S, "expires_at"))!.Value)) return "the session root has expired";
        root = (D)S!;
        return null;
    }

    static string? SessionStep(D p, D grant, IntentV2Context? ctx, double now)
    {
        bool maxAgeSet = ctx != null && ctx.Has("policy", "session", "max_revocation_age_s");
        var maxAgeS = CGet(ctx, "policy", "session", "max_revocation_age_s");
        if (maxAgeSet && !IntentJs.IsNonNeg(maxAgeS)) return "session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)";
        if (!p.ContainsKey("intent_session")) return "this verifier requires an intent_session but the PCActn carries none";
        var ce = SessionCtxError(ctx);
        if (ce != null) return ce;
        var isw = (D)p["intent_session"]!;
        if (!p.ContainsKey("intent")) return "an intent_session needs the envelope.intent binding";
        var intent = (D)p["intent"]!;
        var e = BoundRoot(isw, ctx, now, out var S);
        if (e != null) return e;
        if (S!["intent_ref"] as string != intent["ref"] as string) return "intent.ref is not the session statement";
        if (IntentJs.Get(S["schema"], "digest") as string != isw["schema"] as string) return "intent_session.schema is not the session schema";
        if (IntentJs.Get(S["schema"], "aud") as string != IntentJs.Get(p, "aud") as string) return "the session schema is for another audience";
        long seq = IntentJs.Lng(isw["seq"]);
        if (seq == 0 && intent["map_digest"] as string != IntentJs.Get(IntentJs.Get(S["layers"], "task"), "map_digest") as string) return "a seq-0 action must use the session task map";
        var gc = IntentSession.GrantSessionCaveat(grant);
        var ge = IntentSession.CaveatError(gc);
        if (ge != null) return "admitting root: " + ge;
        if (gc!["session"] as string != isw["session"] as string || gc["root"] as string != isw["root"] as string || IntentJs.Lng(gc["seq"]) != seq)
            return "the admitting root is bound to another session, root or seq";
        var principals = ((L)S["principals"]!).Select(x => (string)((D)x!)["key"]!).ToList();
        if (IntentJs.Get(grant, "issuer") is not string gi || !principals.Contains(gi)) return "the admitting root is not signed by a session principal";
        var prior = ctx!.Has("session", "grants") ? (L)ctx.Get("session", "grants")! : new L();
        if (prior.Count < seq) return $"the verifier does not hold the {seq} earlier grants of this session";
        for (int i = 0; i < seq; i++)
        {
            var g = prior[i];
            if (g is not D gd || IntentJs.Get(gd, "id") is not string || IntentJs.Get(gd, "issuer") is not string) return $"session grant {i} is not a capability";
            var gse = IntentJs.SuiteError(IntentJs.Get(gd, "alg"), gd.ContainsKey("alg"));
            if (gse != null) return $"session grant {i}: {gse}";
            var c = IntentSession.GrantSessionCaveat(g);
            if (IntentSession.CaveatError(c) != null || c!["session"] as string != isw["session"] as string || c["root"] as string != isw["root"] as string || IntentJs.Lng(c["seq"]) != i)
                return $"session grant {i} does not belong to this session at seq {i}";
            if (IntentJs.Get(g, "issuer") is not string issuer || !principals.Contains(issuer)) return $"session grant {i} is not signed by a session principal";
            if (i > 0 && !IntentJs.JsonEquals(IntentJs.Get(c, "prev"), IntentJs.Get(prior[i - 1], "id"))) return $"session grant {i} does not chain to grant {i - 1}";
        }
        if (seq > 0 && !IntentJs.JsonEquals(IntentJs.Get(gc, "prev"), IntentJs.Get(prior[(int)seq - 1], "id"))) return $"the admitting root does not chain to grant {seq - 1}";
        bool sRev = S.ContainsKey("revocation");
        if (sRev || maxAgeSet)
        {
            double ages = double.PositiveInfinity;
            if (sRev) ages = Math.Min(ages, IntentJs.NumOf(IntentJs.Get(S["revocation"], "max_age_s"))!.Value);
            if (maxAgeSet) ages = Math.Min(ages, IntentJs.NumOf(maxAgeS)!.Value);
            double maxAgeMs = ages * 1000;
            if (!sRev) return "revocation: the policy requires a revocation epoch but the session root names no revocation authority";
            var authority = IntentJs.Get(S["revocation"], "key");
            var ids = new List<string>
            {
                IntentRevocation.SessionRevocationId((string)isw["session"]!),
                IntentRevocation.MapRevocationId((string)intent["map_digest"]!),
            };
            for (int i = 0; i < seq; i++) ids.Add(IntentRevocation.DeltaRevocationId(IntentRevocation.JsText(IntentJs.Get(prior[i], "id"), IntentJs.Own(prior[i], "id"))));
            ids.Add(IntentRevocation.DeltaRevocationId(IntentRevocation.JsText(IntentJs.Get(grant, "id"), grant.ContainsKey("id"))));
            var std = IntentJs.Get(S["layers"], "std");
            if (IntentRevocation.Truthy(std))
                ids.Add(IntentRevocation.ProfileRevocationId((string)IntentJs.Get(std, "profile")!, IntentRevocation.JsText(IntentJs.Get(std, "version"), true)));
            // only the dedicated authority S.revocation.key signs epochs; a PQ epoch verifies only under S.revocation.pq_pk
            var pqPins = new Dictionary<string, string>();
            if (authority is string rk && IntentJs.Get(S["revocation"], "pq_pk") is string rpk) pqPins[rk] = rpk;
            bool lastPresent = ctx != null && ctx.Has("session", "revocation_last");
            var rv = IntentRevocation.CheckSessionRevocation(CGet(ctx, "session", "revocation"), (string)isw["session"]!, authority, ids.Cast<object?>().ToList(), now, maxAgeMs, null, pqPins,
                lastPresent, lastPresent ? ctx!.Get("session", "revocation_last") : null);
            if (rv != null) return "revocation: " + rv;
        }
        return null;
    }

    static D PostOf(long post) => new() { ["post"] = IntentJs.OfLong(post) };
    static D? FindById(L xs, object? id) => xs.Select(x => x as D).FirstOrDefault(x => x != null && id is string s && IntentJs.Get(x, "id") as string == s);

    static string? AccStep(D p, IntentV2Context? ctx, double now, D accEnv, D monEnv)
    {
        var isw = (D)p["intent_session"]!;
        var e = BoundRoot(isw, ctx, now, out var S);
        if (e != null) return e;
        var ce = AccCtxError(ctx) ?? SchemaCtxError(ctx);
        if (ce != null) return ce;
        var verb = VerbOf(p);
        var claims = IntentJs.Get(isw, "acc") as L ?? new L();
        var accs = (L)S!["accumulators"]!;
        foreach (var c in claims)
        {
            var a = FindById(accs, IntentJs.Get(c, "id"));
            if (a == null) return $"claim '{IntentJs.Get(c, "id")}' names no accumulator of the session";
            if (IntentJs.Get(a["holder"], "kind") as string == "wallet") return $"accumulator '{IntentJs.Get(c, "id")}' is wallet-held and cannot be claimed at a site";
        }
        var schemaDoc = SchemaByDigest(CGet(ctx, "schema", "docs"), isw["schema"]);
        var parameters = CGet(ctx, "params");
        var state = ctx!.Has("acc", "state") ? (D)ctx.Get("acc", "state")! : new D();
        foreach (var aO in accs)
        {
            var a = (D)aO!;
            var id = (string)a["id"]!;
            var holder = (D)a["holder"]!;
            var hk = holder["kind"] as string;
            if (hk == "wallet") continue;
            var sel = (D)a["sel"]!;
            var agg = a["agg"] as string;
            if (sel.ContainsKey("accumulates_into") && schemaDoc == null) return $"accumulator '{id}' selects by accumulates_into but the session schema is not available";
            bool selected = IntentAcc.AccSelects(a, verb, schemaDoc);
            var claim = FindById(claims, id);
            bool hasPre = state.TryGetValue(id, out var pre);
            if (!selected)
            {
                if (claim != null) return $"claim '{id}' for an accumulator this action does not feed";
                if (hk == "site_local" && hasPre)
                {
                    var pe = IntentAcc.PreStateError(agg, pre);
                    if (pe != null) return $"accumulator '{id}': {pe}";
                    accEnv[id] = PostOf(IntentAcc.PreValue(agg, (D)pre!));
                }
                continue;
            }
            if (claim == null) return $"no claim for accumulator '{id}' that this action feeds";
            if (parameters is not D pm) return "no plaintext params to compute accumulator values";
            if (IntentJs.Get(a, "key") is string key)
            {
                var name = key.Substring("action.params.".Length);
                if (!pm.ContainsKey(name)) return $"accumulator '{id}': the key parameter {key} is missing";
                var verbDecl = schemaDoc != null ? ActionSchema.SchemaVerb(schemaDoc, verb) : null;
                var kd = verbDecl == null ? null : IntentJs.Get(verbDecl["params"], key);
                if (kd == null || ((string)IntentJs.Get(kd, "semantic")!).StartsWith("text.", StringComparison.Ordinal))
                    return $"accumulator '{id}': the key must be a schema-declared identity (not free text)";
            }
            var v = IntentAcc.AccValueOf(a, verb, pm, schemaDoc);
            if (v.Reason != null) return $"accumulator '{id}': {v.Reason}";
            long post;
            if (hk == "site_local")
            {
                if (claim.ContainsKey("receipt")) return $"accumulator '{id}' is site-local: a receipt is not accepted";
                if (!hasPre) return $"no state for site-local accumulator '{id}'";
                var pe = IntentAcc.PreStateError(agg, pre);
                if (pe != null) return $"accumulator '{id}': {pe}";
                var x = IntentAcc.CombineAcc(agg, (D)pre!, v);
                if (x == null) return $"accumulator '{id}' overflows 2^53-1";
                post = x.Value;
            }
            else
            {
                if (!claim.ContainsKey("receipt")) return $"accumulator '{id}' is sequenced: the claim needs a reservation receipt";
                var rcs = ctx.Has("acc", "receipts") ? (L)ctx.Get("acc", "receipts")! : new L();
                D? rc = null;
                foreach (var x in rcs)
                {
                    bool hit;
                    try { hit = IntentAcc.ReceiptDigest(x) == claim["receipt"] as string; } catch (Exception) { hit = false; }
                    if (hit && x is D xd) { rc = xd; break; }
                }
                if (rc == null) return $"the reservation receipt for '{id}' was not presented";
                var keySets = ctx.Has("acc", "sequencer_keys") ? ctx.Get("acc", "sequencer_keys") : new L();
                var pol = ctx.Get("policy", "acc");
                double maxReceiptAgeMs = IntentJs.Own(pol, "max_receipt_age_s") ? IntentJs.NumOf(IntentJs.Get(pol, "max_receipt_age_s"))!.Value * 1000 : IntentAcc.DefaultMaxReceiptAgeMs;
                double maxKeySetAgeMs = IntentJs.Own(pol, "max_keyset_age_s") ? IntentJs.NumOf(IntentJs.Get(pol, "max_keyset_age_s"))!.Value * 1000 : IntentAcc.DefaultMaxKeySetAgeMs;
                var kv = ctx.Get("acc", "keyset_versions");
                object? tracked = holder["root"] is string root && IntentJs.Own(kv, root) ? IntentJs.Get(kv, root) : null;
                if (!IntentAcc.VerifyReceiptAgainstHolder(rc, holder, keySets, now, maxReceiptAgeMs, maxKeySetAgeMs, tracked))
                {
                    if (IntentJs.SuiteError(IntentJs.Get(rc, "alg"), rc.ContainsKey("alg")) is string rse && rse.StartsWith(IntentJs.UnsupportedSuite, StringComparison.Ordinal)) return $"the reservation receipt for '{id}': {IntentJs.UnsupportedSuite}";
                    return $"the reservation receipt for '{id}' is not signed by a key the session sequencer's root-signed key set lists for its issue time";
                }
                if (rc["session"] as string != isw["session"] as string || rc["acc"] as string != id || rc["aud"] as string != IntentJs.Get(p, "aud") as string)
                    return $"the reservation receipt for '{id}' is for another session, accumulator or audience";
                if (rc["pcactn_digest"] as string != IntentAcc.PcactnReservationDigest(p)) return $"the reservation receipt for '{id}' is for another action";
                if (!(now <= IntentJs.NumOf(rc["expires_at"])!.Value)) return $"the reservation receipt for '{id}' has expired";
                var lastSeq = ctx.Has("acc", "last_seq") ? (D)ctx.Get("acc", "last_seq")! : new D();
                if (lastSeq.TryGetValue(id, out var last))
                {
                    if (!(IntentJs.NumOf(rc["seq"])!.Value > IntentJs.NumOf(last)!.Value)) return $"the reservation receipt for '{id}' replays seq {IntentJs.Lng(rc["seq"])} (last accepted {IntentJs.Lng(last)})";
                }
                if (!IntentAcc.ReceiptArithmeticOk(agg, rc, v.Val)) return $"the reservation receipt for '{id}' does not add up";
                post = IntentJs.Lng(rc["post"]);
            }
            if (a.ContainsKey("domain_max") && post > IntentJs.Lng(a["domain_max"])) return $"accumulator '{id}' post {post} is outside its domain (max {IntentJs.Lng(a["domain_max"])})";
            if (IntentJs.Lng(claim["post"]) != post) return $"claimed post {IntentJs.Lng(claim["post"])} for '{id}' differs from the verifier's {post}";
            accEnv[id] = PostOf(post);
        }
        var mons = ctx.Has("acc", "monitors") ? (D)ctx.Get("acc", "monitors")! : new D();
        foreach (var mO in (L)S["monitors"]!)
        {
            var m = (D)mO!;
            var id = (string)m["id"]!;
            var st = mons.TryGetValue(id, out var sv) ? sv : null;
            if (st is not string sts || !IntentAcc.MonitorStates(m).Contains(sts)) return $"no valid state for monitor '{id}'";
            monEnv[id] = new D { ["state"] = sts };
        }
        return null;
    }

    static void Run(Decision output, string name, bool clockOk, Func<string?> f)
    {
        string? why;
        try { why = clockOk ? f() : "the verifier clock is not a safe integer (fail closed)"; }
        catch (Exception e) { why = name + " error (fail closed): " + e.GetType().Name; }
        output.Checks.Add(new Check(name, why == null, why));
    }

    /// <summary>Run the v2 checks for a wire-valid PCActn <paramref name="p"/> under the verifier's root <paramref name="grant"/>
    /// (never throws: an internal error fails the check being evaluated).</summary>
    public static Decision Decide(D p, D grant, IntentV2Context? ctx, long nowL)
    {
        var output = new Decision();
        double now = nowL;
        bool present = p.ContainsKey("intent_session");
        bool clockOk = Math.Abs(nowL) <= 9007199254740991L;
        var ctxErr = ContextError(ctx);
        if (ctxErr != null)
        {
            // a malformed verifier context fails closed: every v2 check that could be reported fails with the reason
            output.Checks.Add(new Check("schema", false, "malformed v2 context: " + ctxErr));
            output.Checks.Add(new Check("intent_session", false, "malformed v2 context: " + ctxErr));
            if (present) output.Checks.Add(new Check("accumulators", false, "malformed v2 context: " + ctxErr));
            if (present && MapCommitted(p)) output.Checks.Add(new Check("map", false, "malformed v2 context: " + ctxErr));
            return output;
        }
        if (present || ClosedWorld(ctx))
        {
            Run(output, "schema", clockOk, () =>
            {
                var why = SchemaStep(p, ctx, out var matched);
                if (why == null) { output.Env["canon"] = ActionSchema.CanonProjection(matched, VerbOf(p), (D)ctx!.Get("params")!); output.Schema = matched; }
                return why;
            });
        }
        if (present || SessionRequired(ctx)) Run(output, "intent_session", clockOk, () => SessionStep(p, grant, ctx, now));
        bool mapActive = MapCommitted(p) || MapRequired(ctx);
        var parameters = CGet(ctx, "params");
        var action = new D { ["verb"] = VerbOf(p), ["resource"] = ResourceOf(p), ["params"] = parameters as D ?? new D() };
        if (present && ctx != null && ctx.Has("layers"))
        {
            Run(output, "layers", clockOk, () =>
            {
                var layers = (D)ctx.Get("layers")!;
                var env = new D();
                if (output.Env.TryGetValue("canon", out var canon)) env["canon"] = canon;
                var actx = new D { ["action"] = action, ["env"] = env };
                foreach (var k in new[] { "org", "site", "std" })
                {
                    if (!layers.TryGetValue(k, out var layer)) continue;
                    if (((D)layer!).Count != 1) return $"layers: the {k} ceiling is malformed (null or not {{predicates: [...]}})";
                    if (!Predicates.EvaluatePredicates(IntentJs.Get(layer, "predicates"), actx))
                        return $"layers: the action is outside the {k} ceiling (a ceiling is never a question)";
                }
                return null;
            });
        }
        if (present)
        {
            Run(output, "accumulators", clockOk, () =>
            {
                var acc = new D(); var mon = new D();
                var why = AccStep(p, ctx, now, acc, mon);
                if (why == null) { output.Env["acc"] = acc; output.Env["mon"] = mon; }
                return why;
            });
            if (mapActive) Run(output, "map", clockOk, () => MapStep(p, ctx));
            IntentWB.Result? wb = null;
            try
            {
                var input = new D
                {
                    ["now"] = IntentJs.OfLong(nowL),
                    ["aud"] = IntentRevocation.JsText(IntentJs.Get(p, "aud"), p.ContainsKey("aud")),
                    ["session"] = IntentJs.Get(p["intent_session"], "session"),
                    ["action"] = action,
                    ["intent_session"] = p["intent_session"],
                };
                if (ctx != null && ctx.Has("wb", "artifacts")) input["artifacts"] = ctx.Get("wb", "artifacts");
                if (ctx != null && ctx.Has("wb", "policy")) input["policy"] = ctx.Get("wb", "policy");
                wb = IntentWB.Decide(input);
            }
            catch (Exception e)
            {
                output.Checks.Add(new Check("facts", false, "W-B error (fail closed): " + e.GetType().Name));
            }
            if (wb != null)
            {
                foreach (var name in new[] { "facts", "provenance", "classes" })
                {
                    var c = wb.Check(name);
                    if (c == null) continue;
                    if (c == "pass") output.Checks.Add(new Check(name, true, null));
                    else output.Checks.Add(new Check(name, false, c == "question" ? "intent_required: " + (wb.Reason ?? "a question is required") : (wb.Reason ?? "rejected")));
                }
                if (wb.Outcome != "deny")
                {
                    if (wb.World != null) output.Env["world"] = wb.World;
                    if (wb.Prov != null) output.Env["prov"] = wb.Prov;
                    if (wb.Class != null) output.Env["class"] = wb.Class;
                }
                if (wb.SingleSource is { Count: > 0 }) output.SingleSource = new List<string>(wb.SingleSource);
            }
        }
        else if (mapActive)
        {
            Run(output, "map", clockOk, () => MapStep(p, ctx));
        }
        ModelRules(p, grant, ctx, output, clockOk, action);
        return output;
    }

    /// <summary>The predicate lists a model-derived path could widen: the grant's allow-list and the ceilings (V5 layers).</summary>
    static L AllowSidePredicates(D? env, IntentV2Context? ctx)
    {
        var lists = new L { env == null ? null : IntentJs.Get(env, "predicates") };
        if (ctx?.Get("layers") is D lm)
            foreach (var k in new[] { "org", "site", "std" }) lists.Add(IntentJs.Get(IntentJs.Get(lm, k), "predicates"));
        return lists;
    }

    /// <summary>Rules 20 and 21 (intent-v2.ts modelRules), evaluated last so the verifier-computed env is complete. Both read the signed
    /// ENVELOPE of the stored grant: <c>units</c> (20) is reported iff <c>envelope.units</c> is present; <c>tighten</c> (21) iff
    /// <c>envelope.tighten</c> or a <c>model_polarity</c> (envelope or policy) is present, or a grant-side <c>where</c> reads a
    /// model-derived env path (so that case is refused, never silently skipped). A PCActn with none of these verifies byte-identically to
    /// a verifier without the two rules.</summary>
    static void ModelRules(D p, D grant, IntentV2Context? ctx, Decision output, bool clockOk, D action)
    {
        var env = Pca.ReadEnvelope(grant);
        var preds = AllowSidePredicates(env, ctx);
        var verb = action["verb"] as string ?? "";
        if (env != null && env.ContainsKey("units"))
        {
            Run(output, "units", clockOk, () =>
            {
                var doc = output.Schema;
                if (doc == null)
                {
                    var why = SchemaStep(p, ctx, out var matched);
                    if (why != null) return why;
                    doc = matched;
                }
                var v = ActionSchema.SchemaVerb(doc, verb);
                var input = new D { ["units"] = env["units"], ["verb"] = verb, ["predicates"] = preds };
                if (IntentJs.Own(doc, "units")) input["schema_units"] = IntentJs.Get(doc, "units");
                if (v != null && v.ContainsKey("params")) input["verb_params"] = v["params"];
                var (ok, reason) = PcaDecision.DecideUnits(input);
                return ok ? null : reason;
            });
        }
        var single = output.SingleSource;
        bool polCtxP = ctx != null && ctx.Has("policy", "model_polarity");
        object? polCtx = polCtxP ? ctx!.Get("policy", "model_polarity") : null;
        object? polarity = null; bool hasPol = false;
        if (polCtxP && polCtx is "strict") { }
        else if (polCtxP) { polarity = polCtx; hasPol = true; }
        else if (env != null && env.ContainsKey("model_polarity")) { polarity = env["model_polarity"]; hasPol = true; }
        bool hasTighten = env != null && env.ContainsKey("tighten");
        if (hasTighten || hasPol || polCtxP || PcaDecision.ModelPathsRead(preds, single).Count > 0)
        {
            Run(output, "tighten", clockOk, () =>
            {
                var merged = new D();
                if (ctx?.Get("env") is D hostEnv) foreach (var (k, x) in hostEnv) merged[k] = x;
                foreach (var (k, x) in output.Env) merged[k] = x;
                var input = new D { ["predicates"] = preds, ["single_source"] = new L(single.Cast<object?>()), ["context"] = new D { ["action"] = action, ["env"] = merged } };
                if (hasTighten) input["tighten"] = env!["tighten"];
                if (hasPol) input["polarity"] = polarity;
                var r = PcaDecision.DecideTighten(input);
                if (r.Legacy) output.Legacy = true;
                return r.Outcome == "ok" ? null : r.Reason ?? "refused";
            });
        }
    }

    /// <summary>The grant's envelope carries units / tighten / model_polarity, or a grant-side where reads a model-derived path: the v2
    /// pipeline then needs the plaintext params and the host env even when the host configured no v2 context.</summary>
    internal static bool NeedsModelRules(D grant)
    {
        var env = Pca.ReadEnvelope(grant);
        if (env == null) return false;
        if (env.ContainsKey("units") || env.ContainsKey("tighten") || env.ContainsKey("model_polarity")) return true;
        return PcaDecision.ModelPathsRead(new L { IntentJs.Get(env, "predicates") }).Count > 0;
    }

    /// <summary>Rule 19 (<c>map</c>, V15 Z0): reported iff the PCActn's <c>intent_session.map_form</c> is <c>"commit"</c> or the
    /// policy sets <c>map.require: true</c>; evaluated after <c>accumulators</c> (independent of the earlier checks) and before W-B.</summary>
    static string? MapStep(D p, IntentV2Context? ctx)
    {
        if (!MapCommitted(p)) return "this verifier requires a committed map (intent_session.map_form \"commit\")";
        if (!p.ContainsKey("intent")) return "a committed map needs the envelope.intent binding";
        if (ctx == null || !ctx.Has("map", "disclosure")) return "no disclosure of the committed map was presented";
        double? eps = ctx.Has("policy", "map", "max_residual_risk_ppm") ? IntentJs.NumOf(ctx.Get("policy", "map", "max_residual_risk_ppm")) : null;
        var d = IntentMap.Decide(IntentJs.Get(p["intent"], "map_digest"), p.TryGetValue("action", out var a) ? a : new D(),
            ctx.Has("params"), ctx.Get("params"), ctx.Get("map", "disclosure"), eps);
        return d.Ok ? null : d.Reason;
    }
}
