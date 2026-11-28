// Lazy just-in-time elicitation: the ordered decision for a visited cell (schema violation, ceiling, intent denied, admit, intent required), the
// cell coordinates of an intent_required question, the wallet's check of one, and the delta grant minted from an answer.
using System.Text.RegularExpressions;
using AtlasPca.InteropJs;
using static AtlasPca.IntentPkg.IntentOmega;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.IntentPkg;

public static class IntentJit
{
    public const string IntentActionDomain = "atlas-pca/intent-action/v1";

    static VerbSpace? VerbOf(Omega o, string verb) => o.Verbs.Find(v => v.Verb == verb);

    static L Ints(IEnumerable<int> a) => a.Select(x => (object?)N(x)).ToList();

    static string JsStr(object? o) => o == null ? "undefined" : IsNum(o) ? JsX.JsNumString(Dbl(o)) : o is bool b ? (b ? "true" : "false") : o.ToString() ?? "undefined";

    /// <summary>The ordered decision of a visit. conform: {ok, code?, reason?} (the schema conformance of the plaintext action); ceilings: each must admit the
    /// lifted outcome (a deny anywhere wins); inEffective: is the cell in the effective grant. Returns {kind, ...}.</summary>
    public static D DecideVisit(IntentLearner learner, Outcome lifted, D conform, IEnumerable<Func<VerbSpace, Outcome, bool>>? ceilings, bool inEffective)
    {
        var r = new D();
        if (!(conform.GetValueOrDefault("ok") is true))
        {
            r["kind"] = "schema_violation";
            r["reason"] = JsStr(conform.GetValueOrDefault("code")) + ": " + JsStr(conform.GetValueOrDefault("reason"));
            return r;
        }
        var vs = VerbOf(learner.Omega, lifted.Verb);
        var cell = vs == null ? null : CellOf(vs, lifted);
        if (vs == null || cell == null)
        {
            r["kind"] = "schema_violation";
            r["reason"] = "the lifted action lies outside Ω̃";
            return r;
        }
        if (ceilings != null) foreach (var c in ceilings) if (!c(vs, lifted)) { r["kind"] = "ceiling"; return r; }
        bool vetoed = learner.IsVetoed(lifted);
        double p = learner.Acceptance(lifted);
        if (vetoed || p <= 0) { r["kind"] = "intent_denied"; r["vetoed"] = vetoed; return r; }
        if (inEffective) { r["kind"] = "admit"; r["cell"] = Ints(cell); return r; }
        r["kind"] = "intent_required";
        r["cell"] = Ints(cell);
        r["p"] = N(p);
        return r;
    }

    /// <summary>The coordinates of one cell (numeric: [i, i]; categorical: the cell's value).</summary>
    public static D CellCoords(VerbSpace vs, int[] cell)
    {
        var o = new D();
        for (int k = 0; k < vs.Dims.Count; k++)
        {
            var d = vs.Dims[k];
            var c = new L();
            if (d is NumDim) { c.Add(N(cell[k])); c.Add(N(cell[k])); }
            else c.Add(((CatDim)d).Values[cell[k]].Value);
            o[d.Path] = c;
        }
        return o;
    }

    /// <summary>Coordinates to per-dimension cell indices (the inverse of CellCoords for one cell), or null.</summary>
    public static double[]? CellFromCoords(VerbSpace vs, D coords)
    {
        if (coords.Count != vs.Dims.Count) return null;
        var o = new double[vs.Dims.Count];
        for (int k = 0; k < o.Length; k++)
        {
            var d = vs.Dims[k];
            if (!coords.TryGetValue(d.Path, out var cv) || cv is not L c) return null;
            if (d is NumDim)
            {
                if (c.Count == 0 || !IsNum(c[0]) || c.Count < 2 || !IsNum(c[1]) || Dbl(c[0]) != Dbl(c[1])) return null;
                o[k] = Dbl(c[0]);
            }
            else
            {
                if (c.Count != 1 || c[0] is not string cs) return null;
                int i = ((CatDim)d).Values.FindIndex(v => v.Value == cs);
                if (i < 0) return null;
                o[k] = i;
            }
        }
        return o;
    }

    /// <summary>The content address of the action an intent_required question is about.</summary>
    public static string IntentActionDigest(object? action)
    {
        var a = (D)action!;
        var act = new D();
        foreach (var k in new[] { "verb", "resource", "params_digest", "reversibility_class" }) act[k] = a.GetValueOrDefault(k);
        return Pca.HashCanonical(IntentJs.Normalize(new D { ["d"] = IntentActionDomain, ["action"] = act }));
    }

    /// <summary>The site's pca-intent-required body for a visited uncertain cell. input: session, mapDigest, schemaDigest, pcactn (JSON), questionId, friction,
    /// deliveredTo, expiresAt; vs and cell locate the cell.</summary>
    public static D IntentRequiredBody(D input, VerbSpace vs, int[] cell)
    {
        var pcactn = Obj(input.GetValueOrDefault("pcactn"));
        return new D
        {
            ["v"] = N(1),
            ["kind"] = "pca-intent-required",
            ["session"] = input.GetValueOrDefault("session"),
            ["map_digest"] = input.GetValueOrDefault("mapDigest"),
            ["schema"] = input.GetValueOrDefault("schemaDigest"),
            ["pcactn_digest"] = Pca.HashCanonical(IntentJs.Normalize(pcactn)),
            ["action_digest"] = IntentActionDigest(pcactn.GetValueOrDefault("action")),
            ["cell"] = new D { ["verb"] = vs.Verb, ["coords"] = CellCoords(vs, cell) },
            ["reason"] = "uncertain",
            ["question_id"] = input.GetValueOrDefault("questionId"),
            ["friction"] = input.GetValueOrDefault("friction"),
            ["delivered_to"] = input.GetValueOrDefault("deliveredTo"),
            ["expires_at"] = input.GetValueOrDefault("expiresAt"),
        };
    }

    public static D SignedIntentRequired(D input, VerbSpace vs, int[] cell, string kid, SuiteKey site) => Signers.SignIntentRequired(IntentRequiredBody(input, vs, cell), kid, site);

    static D Fail(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    static readonly string[] SignedKeys = { "v", "kind", "session", "map_digest", "schema", "pcactn_digest", "action_digest", "cell", "reason", "question_id", "friction", "delivered_to", "expires_at", "sig" };
    static readonly Regex QidRe = new(@"^[A-Za-z0-9_-]{1,64}\z", RegexOptions.CultureInvariant);

    /// <summary>The signed-body shape check of the reference's intentRequiredShapeError; null when well formed.</summary>
    static string? SignedShapeError(object? bo)
    {
        if (bo is not D b) return "not an object";
        foreach (var k in b.Keys) if (!SignedKeys.Contains(k)) return "unknown member '" + k + "'";
        if (!OracleFacts.IsOne(b.GetValueOrDefault("v")) || (b.GetValueOrDefault("kind") as string) != "pca-intent-required") return "not a pca-intent-required v1";
        foreach (var k in new[] { "session", "map_digest", "schema", "pcactn_digest", "action_digest" })
            if (!IntentJs.B32(b.GetValueOrDefault(k))) return k + " must be canonical base64url (32 bytes)";
        if (b.GetValueOrDefault("cell") is not D cell || cell.Count != 2 || !cell.ContainsKey("coords") || cell.GetValueOrDefault("verb") is not string { Length: > 0 }) return "cell must be {verb, coords}";
        var ce = Signers.CellCoordsError(cell["coords"]);
        if (ce != null) return ce;
        if ((b.GetValueOrDefault("reason") as string) != "uncertain") return "reason must be 'uncertain'";
        if (b.GetValueOrDefault("question_id") is not string q || !QidRe.IsMatch(q)) return "question_id must match [A-Za-z0-9_-]{1,64}";
        if (b.GetValueOrDefault("friction") is not ("tap" or "hold" or "typed" or "device")) return "unknown friction tier";
        if (b.GetValueOrDefault("delivered_to") is not ("wallet" or "agent")) return "delivered_to must be 'wallet' or 'agent'";
        if (!IntentJs.IsNonNeg(b.GetValueOrDefault("expires_at"))) return "expires_at must be a non-negative safe integer";
        var s = b.GetValueOrDefault("sig");
        if (s is D sm0)
        {
            var se = IntentJs.SuiteError(sm0.GetValueOrDefault("alg"), sm0.ContainsKey("alg"));
            if (se != null) return "sig.alg: " + se;
            if (sm0.ContainsKey("pq_value") && sm0["pq_value"] != null && sm0["pq_value"] is not string) return "sig.pq_value must be a string";
        }
        bool okSig = s is D;
        if (s is D sm)
        {
            foreach (var k in sm.Keys) if (k is not ("alg" or "kid" or "value" or "pq_value")) okSig = false;
            if (IntentJs.SuiteOf(sm.GetValueOrDefault("alg"), sm.ContainsKey("alg")) == null || sm.GetValueOrDefault("kid") is not string || sm.GetValueOrDefault("value") is not string) okSig = false;
        }
        if (!okSig) return "sig must be {alg, kid, value, pq_value?}";
        return null;
    }

    /// <summary>Verify a site-signed intent_required body against the site's discovery keys at now: null when valid, else the reason. The clock must be a safe integer.</summary>
    internal static string? VerifyIntentRequired(object? body, object? keys, long now)
    {
        try
        {
            if (!IntentJs.IsSafeInteger(now)) return "the verifier clock is not a safe integer (fail closed)";
            var e = SignedShapeError(body);
            if (e != null) return e;
            var s = (D)body!;
            var sig = (D)s["sig"]!;
            if (keys is not L kl) return "the site keys must be an array";
            D? key = null;
            foreach (var k in kl) if (k is D kd && Equals(sig["kid"], kd.GetValueOrDefault("kid"))) { key = kd; break; }
            if (key == null) return "no site key with kid '" + JsX.Str(sig["kid"]) + "'";
            var kse = IntentJs.SuiteError(key.GetValueOrDefault("alg"), key.ContainsKey("alg"));
            if (kse != null) return "site key: " + kse;
            var ka = IntentJs.SuiteOf(key);
            var sa = IntentJs.SuiteOf(sig);
            if (ka == null || ka != sa) return "sig.alg does not match the pinned key suite";
            var pk = (string)key["pk"]!;
            var pin = key.ContainsKey("pq_pk") && key["pq_pk"] != null ? IntentJs.Pin(pk, key["pq_pk"]) : null;
            var b = new D(s);
            b.Remove("sig");
            var msg = IntentJs.Message(Signers.IntentRequiredDomain, b);
            if (!IntentJs.VerifyPinnedSuite(ka, true, pk, key.GetValueOrDefault("pq_pk"), msg, sig.GetValueOrDefault("value"), sig.GetValueOrDefault("pq_value"), pin)) return "site signature invalid";
            if (!(now <= IntentJs.NumOf(s["expires_at"]))) return "the question has expired";
            return null;
        }
        catch (Exception err)
        {
            return "malformed intent_required: " + err.Message;
        }
    }

    /// <summary>The wallet's check of an intent_required: the site signature under its discovery keys, the expiry, the session and map, and the CELL, re-derived from
    /// the wallet's own space and the lifted action. Returns {ok: true, vs, cell} or {ok: false, reason}.</summary>
    public static D WalletCheckIntentRequired(object? body, L keys, long now, string session, string mapDigest, Omega omegaTilde, Outcome lifted, D pcactn)
    {
        var v = VerifyIntentRequired(body, keys, now);
        if (v != null) return Fail(v);
        var b = (D)body!;
        if (!(b["session"] is string bs && bs == session) || !(b["map_digest"] is string bm && bm == mapDigest)) return Fail("the question is for another session or map");
        if (!(b["pcactn_digest"] is string pd && Pca.HashCanonical(IntentJs.Normalize(pcactn)) == pd) || !(b["action_digest"] is string ad && IntentActionDigest(pcactn.GetValueOrDefault("action")) == ad))
            return Fail("the question is about another action");
        var vs = VerbOf(omegaTilde, lifted.Verb);
        var mine = vs == null ? null : CellOf(vs, lifted);
        var bc = (D)b["cell"]!;
        if (vs == null || mine == null || !(bc["verb"] is string bv && bv == vs.Verb)) return Fail("the wallet cannot place the action in Ω̃");
        var theirs = CellFromCoords(vs, (D)bc["coords"]!);
        if (theirs == null) return Fail("the site cell differs from the cell the wallet derives");
        for (int k = 0; k < theirs.Length; k++) if (theirs[k] != mine[k]) return Fail("the site cell differs from the cell the wallet derives");
        return new D { ["ok"] = true, ["vs"] = VerbSpaceToJson(vs), ["cell"] = Ints(mine) };
    }

    // ---- delta grants ----

    static string Join(int[] a) => string.Join(",", a);

    /// <summary>Per verb, the cells the next learner's grant adds over the previous one's (both over the same space); verbs with no new cell are absent.</summary>
    public static Dictionary<string, byte[]> DeltaCells(IntentLearner prev, IntentLearner next)
    {
        var o = new Dictionary<string, byte[]>();
        var prevIn = new HashSet<string>(StringComparer.Ordinal);
        foreach (var c in prev.Cells()) if (c.InGrant) prevIn.Add(c.Verb + "|" + Join(c.Cell));
        var nextCells = next.Cells();
        foreach (var vs in next.Omega.Verbs)
        {
            var a = new byte[(int)VerbCellCount(vs)];
            bool any = false;
            foreach (var c in nextCells)
            {
                if (c.Verb != vs.Verb || !c.InGrant || prevIn.Contains(c.Verb + "|" + Join(c.Cell))) continue;
                a[(int)EncodeCell(vs, c.Cell)] = 1;
                any = true;
            }
            if (any) o[vs.Verb] = a;
        }
        return o;
    }

    /// <summary>The predicates of a delta (one maximal box per covered region, per verb).</summary>
    public static List<D> DeltaPredicates(Omega omegaTilde, Dictionary<string, byte[]> delta)
    {
        var o = new List<D>();
        foreach (var vs in omegaTilde.Verbs) if (delta.TryGetValue(vs.Verb, out var cells)) o.AddRange(IntentLearner.BoxesToPredicates(vs, cells));
        return o;
    }

    /// <summary>Mint D_k from the k-th answer: null when the answer added no cell. a: holder, holderPq?, session, seq, prev?, root, mapDigest, mapForm?, caveats?, agentBinding?,
    /// riskPolicy?, salt?, and prevGrant (the previous session grant, JSON). Returns {grant, goalSalt, cells}.</summary>
    public static D? MintDelta(IntentLearner prev, IntentLearner next, D a, SuiteKey principal)
    {
        var delta = DeltaCells(prev, next);
        long cells = 0;
        foreach (var v in delta.Values) foreach (var x in v) cells += x;
        if (cells == 0) return null;
        var prevGrant = Obj(a.GetValueOrDefault("prevGrant"));
        if (a.GetValueOrDefault("prev") != null && !Equals(a["prev"], prevGrant.GetValueOrDefault("id"))) throw new ArgumentException("mintDelta: prev must be the id of the previous session grant");
        var preds = DeltaPredicates(next.Omega, delta).Select(x => (object?)x).ToList();
        var caveats = a.GetValueOrDefault("caveats") == null ? null : (L)a["caveats"]!;
        var binding = a.GetValueOrDefault("agentBinding") == null ? null : (D)a["agentBinding"]!;
        var risk = a.GetValueOrDefault("riskPolicy") == null ? null : (D)a["riskPolicy"]!;
        var g = Signers.MintSessionGrant(principal, (string)a["holder"]!, (string)a["session"]!, (long)Dbl(a.GetValueOrDefault("seq")), (string)a["root"]!, (string)a["mapDigest"]!, preds,
            (string?)prevGrant.GetValueOrDefault("id"), a.GetValueOrDefault("mapForm") as string, caveats, binding, risk, a.GetValueOrDefault("salt") as string, a.GetValueOrDefault("holderPq") as string);
        return new D { ["grant"] = g.Grant, ["goalSalt"] = g.GoalSalt, ["cells"] = N(cells) };
    }
}
