// K5 workflow (DAG) authorization: a principal signs ONE commitment to a whole workflow; each step is admitted only as part of that DAG,
// its inputs proven from the signed receipts of earlier steps. TOTAL and PURE (no clock, no store, no I/O): anything unknown, malformed,
// unsigned, out of order or unplanned DENIES; only a pipelined step with an unconstrained promise and an "ask a human" label ESCALATE.
// Integers only (a JSON number must be an exact safe integer lexeme). Port of packages/pca/src/workflow.ts; replays
// packages/pca/conformance/workflow-vectors.json. Inputs are the parsed JSON (Pca.ParseJson / ParseStrict) values.
using System.Globalization;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca;

/// <summary>decision is allow | deny | escalate. <c>At</c> is the offending receipt/edge index; <c>Pending</c> the edge indexes whose source receipt does not exist yet.</summary>
public sealed record WfResult(string Decision, string? Code, string? Step, int? At, IReadOnlyList<int> Pending)
{
    public JD ToJson() => new()
    {
        ["decision"] = Decision,
        ["code"] = Code,
        ["step"] = Step,
        ["at"] = At is int a ? (object?)(long)a : null,
        ["pending"] = Pending.Select(i => (object?)(long)i).ToList(),
    };
}

/// <param name="Workflow">the signed workflow {body, sig} (parsed JSON)</param>
/// <param name="Principal">the principal key the verifier pinned: a key named inside the workflow is never trusted</param>
/// <param name="RsSigner">the resource-server key the verifier pinned for step receipts</param>
/// <param name="Receipts">the receipt chain (a parsed JSON array; anything else denies)</param>
public sealed record AdmitInput(object? Workflow, string? Principal, string? RsSigner, object? Receipts, long Now, object? Request);

/// <summary>Strict shape helpers shared by <see cref="Workflow"/> and <see cref="ReadSide"/>.</summary>
internal static class K5Strict
{
    static readonly Regex IntRe = new(@"\A-?(0|[1-9][0-9]*)\z", RegexOptions.None);
    internal static readonly Regex IdRe = new(@"\A(?!__proto__\z)[A-Za-z0-9_.:-]{1,64}\z", RegexOptions.None);
    internal static readonly Regex LabelRe = new(@"\A(?!__proto__\z)[a-z0-9_.:-]{1,64}\z", RegexOptions.None);
    internal static readonly Regex NameRe = new(@"\A(?!__proto__\z)[A-Za-z0-9_.-]{1,64}\z", RegexOptions.None);
    internal static readonly Regex UnitRe = new(@"\A[A-Za-z0-9_.:-]{1,16}\z", RegexOptions.None);
    const long MaxSafe = 9007199254740991L;

    /// <summary>An exact safe-integer lexeme (no fraction, no exponent, no "-0", |n| &lt;= 2^53-1). A bool or string is not a number.</summary>
    internal static bool TryInt(object? x, out long n)
    {
        n = 0;
        if (x is not Num m || !IntRe.IsMatch(m.Raw) || m.Raw == "-0") return false;
        if (!long.TryParse(m.Raw, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out n)) return false;
        return n >= -MaxSafe && n <= MaxSafe;
    }
    internal static bool IsUint(object? x) => TryInt(x, out var n) && n >= 0;
    internal static long U(object? x) { TryInt(x, out var n); return n; }
    internal static bool IsObj(object? x) => x is JD;
    internal static bool IsStr(object? x, int max) => x is string s && s.Length >= 1 && s.Length <= max;
    internal static bool IsB32(object? x) => Pca.B64uDecode(x, 32) != null;
    internal static bool Rx(object? x, Regex re) => x is string s && re.IsMatch(s);
    internal static bool IsScalar(object? v) => v is string || v is bool || TryInt(v, out _);
    internal static bool IsScalarMap(object? x) => x is JD o && o.Count <= 32 && o.All(e => NameRe.IsMatch(e.Key) && IsScalar(e.Value));
    internal static bool OnlyKeys(JD o, params string[] keys) => o.Count == keys.Length && keys.All(o.ContainsKey);
    internal static bool NullOr(object? x, Func<object?, bool> ok) => x == null || ok(x);

    /// <summary>Strictly ascending (ordinal; every member is ASCII) with every member matching <paramref name="re"/>.</summary>
    internal static bool SortedUnique(object? x, Regex re, int max)
    {
        if (x is not List<object?> a || a.Count > max) return false;
        for (var i = 0; i < a.Count; i++)
        {
            if (a[i] is not string s || !re.IsMatch(s)) return false;
            if (i > 0 && string.CompareOrdinal((string)a[i - 1]!, s) >= 0) return false;
        }
        return true;
    }
    internal static List<string> Strs(object? x) => ((List<object?>)x!).Select(s => (string)s!).ToList();

    /// <summary>Same as the reference's verifyBody: a canonical 64-byte signature by <paramref name="signer"/> over exactly domain || canonical(body).</summary>
    internal static bool VerifyBody(string domain, object? body, object? signer, object? sig) => signer is string && sig is string && Pca.VerifyDomain(domain, body, signer, sig);

    internal static JD Pick(JD raw, params string[] keys)
    {
        var o = new JD();
        foreach (var k in keys) o[k] = raw[k];
        return o;
    }
}

public static class Workflow
{
    public const string WorkflowDomain = "atlas-pca/workflow/v1\0";
    public const string ReceiptDomain = "atlas-pca/wf-receipt/v1\0";
    const string WfRef = "atlas-pca/workflow-ref/v1";
    const string WrRef = "atlas-pca/wf-receipt-ref/v1";
    const string Val = "atlas-pca/wf-value/v1";

    static readonly string[] StepKeys = { "id", "verb", "resource", "params_digest", "deps", "sink", "deny_labels", "escalate_labels", "fresh_ms", "cost" };
    static readonly string[] EdgeKeys = { "from", "to", "op", "unit", "deny_labels", "promise" };
    static readonly string[] BodyKeys = { "v", "id", "principal", "goal_digest", "plan_root", "issued_at", "expires_at", "steps", "edges", "budget" };
    static readonly string[] ReceiptKeys = { "v", "wf", "step", "seq", "prev", "outcome", "params_digest", "outputs", "issued_at", "signer", "sig" };
    static readonly string[] ReceiptBodyKeys = { "v", "wf", "step", "seq", "prev", "outcome", "params_digest", "outputs", "issued_at", "signer" };
    static readonly string[] Ops = { "eq", "le", "ge", "lt", "gt" };

    // ---- typed views of an ALREADY VALIDATED document ----------------------------------------------------------------------
    sealed class Step
    {
        public string Id = "", Verb = "", Resource = "";
        public string? ParamsDigest;
        public List<string> Deps = new();
        public string? Sink;
        public List<string> DenyLabels = new(), EscalateLabels = new();
        public long? FreshMs;
        public Dictionary<string, long> Cost = new();
    }
    sealed class Edge
    {
        public string FromStep = "", FromField = "", ToStep = "", ToParam = "", Op = "";
        public string? Unit, Promise;
        public List<string> DenyLabels = new();
    }
    sealed class Body
    {
        public JD Raw = new();
        public string Principal = "";
        public string? GoalDigest, PlanRoot;
        public long IssuedAt, ExpiresAt, MaxSteps;
        public List<Step> Steps = new();
        public List<Edge> Edges = new();
        public Dictionary<string, long> Caps = new();
    }
    sealed class Out { public string Digest = ""; public long? Num; public string? Unit; public List<string> Labels = new(); }
    sealed class Rcpt
    {
        public JD Raw = new();
        public string Wf = "", Step = "", Outcome = "", ParamsDigest = "", Signer = "";
        public string? Prev;
        public long Seq, IssuedAt;
        public object? Sig;
        public Dictionary<string, Out> Outputs = new();
    }

    static Dictionary<string, long> UintMapOf(object? x) => ((JD)x!).ToDictionary(e => e.Key, e => K5Strict.U(e.Value));
    static string? StrOrNull(object? x) => x as string;

    static Body ParseBody(JD b)
    {
        var budget = (JD)b["budget"]!;
        var body = new Body
        {
            Raw = b,
            Principal = (string)b["principal"]!,
            GoalDigest = StrOrNull(b["goal_digest"]),
            PlanRoot = StrOrNull(b["plan_root"]),
            IssuedAt = K5Strict.U(b["issued_at"]),
            ExpiresAt = K5Strict.U(b["expires_at"]),
            MaxSteps = K5Strict.U(budget["max_steps"]),
            Caps = UintMapOf(budget["caps"]),
        };
        foreach (var so in (List<object?>)b["steps"]!)
        {
            var s = (JD)so!;
            body.Steps.Add(new Step
            {
                Id = (string)s["id"]!, Verb = (string)s["verb"]!, Resource = (string)s["resource"]!, ParamsDigest = StrOrNull(s["params_digest"]),
                Deps = K5Strict.Strs(s["deps"]), Sink = StrOrNull(s["sink"]), DenyLabels = K5Strict.Strs(s["deny_labels"]), EscalateLabels = K5Strict.Strs(s["escalate_labels"]),
                FreshMs = s["fresh_ms"] == null ? null : K5Strict.U(s["fresh_ms"]), Cost = UintMapOf(s["cost"]),
            });
        }
        foreach (var eo in (List<object?>)b["edges"]!)
        {
            var e = (JD)eo!;
            var f = (JD)e["from"]!;
            var t = (JD)e["to"]!;
            body.Edges.Add(new Edge
            {
                FromStep = (string)f["step"]!, FromField = (string)f["field"]!, ToStep = (string)t["step"]!, ToParam = (string)t["param"]!, Op = (string)e["op"]!,
                Unit = StrOrNull(e["unit"]), DenyLabels = K5Strict.Strs(e["deny_labels"]), Promise = StrOrNull(e["promise"]),
            });
        }
        return body;
    }

    // ---- validation --------------------------------------------------------------------------------------------------------
    static bool UintMap(object? x, int max) => x is JD o && o.Count <= max && o.All(e => K5Strict.NameRe.IsMatch(e.Key) && K5Strict.IsUint(e.Value));

    static bool ValidStep(object? so)
    {
        if (so is not JD s || !K5Strict.OnlyKeys(s, StepKeys)) return false;
        return K5Strict.Rx(s["id"], K5Strict.IdRe) && K5Strict.IsStr(s["verb"], 128) && K5Strict.IsStr(s["resource"], 512) && K5Strict.NullOr(s["params_digest"], K5Strict.IsB32) &&
            K5Strict.SortedUnique(s["deps"], K5Strict.IdRe, 16) && K5Strict.NullOr(s["sink"], x => K5Strict.Rx(x, K5Strict.IdRe)) &&
            K5Strict.SortedUnique(s["deny_labels"], K5Strict.LabelRe, 16) && K5Strict.SortedUnique(s["escalate_labels"], K5Strict.LabelRe, 16) &&
            K5Strict.NullOr(s["fresh_ms"], K5Strict.IsUint) && UintMap(s["cost"], 8);
    }

    static bool ValidEdge(object? eo)
    {
        if (eo is not JD e || !K5Strict.OnlyKeys(e, EdgeKeys)) return false;
        return e["from"] is JD f && K5Strict.OnlyKeys(f, "step", "field") && K5Strict.Rx(f["step"], K5Strict.IdRe) && K5Strict.Rx(f["field"], K5Strict.NameRe) &&
            e["to"] is JD t && K5Strict.OnlyKeys(t, "step", "param") && K5Strict.Rx(t["step"], K5Strict.IdRe) && K5Strict.Rx(t["param"], K5Strict.NameRe) &&
            e["op"] is string op && Ops.Contains(op) && K5Strict.NullOr(e["unit"], x => K5Strict.Rx(x, K5Strict.UnitRe)) &&
            K5Strict.SortedUnique(e["deny_labels"], K5Strict.LabelRe, 16) && K5Strict.NullOr(e["promise"], x => K5Strict.Rx(x, K5Strict.IdRe));
    }

    /// <summary>Shape of the body only (no signature, no DAG semantics).</summary>
    public static bool ValidWorkflowBody(object? bo)
    {
        if (bo is not JD b || !K5Strict.OnlyKeys(b, BodyKeys) || !(K5Strict.TryInt(b["v"], out var v) && v == 1)) return false;
        if (!K5Strict.Rx(b["id"], K5Strict.IdRe) || !K5Strict.IsB32(b["principal"]) || !K5Strict.NullOr(b["goal_digest"], K5Strict.IsB32) || !K5Strict.NullOr(b["plan_root"], K5Strict.IsB32) ||
            !K5Strict.IsUint(b["issued_at"]) || !K5Strict.IsUint(b["expires_at"])) return false;
        if (b["steps"] is not List<object?> steps || steps.Count == 0 || steps.Count > 64 || !steps.All(ValidStep)) return false;
        if (b["edges"] is not List<object?> edges || edges.Count > 256 || !edges.All(ValidEdge)) return false;
        if (b["budget"] is not JD bg || !K5Strict.OnlyKeys(bg, "max_steps", "caps") || !K5Strict.IsUint(bg["max_steps"]) || !UintMap(bg["caps"], 8)) return false;
        // every cost name must be capped: an uncapped cost is a budget that silently does not exist
        var caps = (JD)bg["caps"]!;
        return steps.All(s => ((JD)((JD)s!)["cost"]!).Keys.All(caps.ContainsKey));
    }

    /// <summary>DAG semantics: unique ids, deps exist, acyclic, every edge runs from a (transitive) dependency. null when fine.</summary>
    static string? DagError(Body b)
    {
        var ids = new Dictionary<string, Step>();
        foreach (var s in b.Steps)
        {
            if (ids.ContainsKey(s.Id)) return "duplicate step id";
            ids[s.Id] = s;
        }
        foreach (var s in b.Steps) foreach (var d in s.Deps) if (d == s.Id || !ids.ContainsKey(d)) return "bad dependency";
        var anc = Ancestors(b);
        if (anc == null) return "cycle";
        foreach (var e in b.Edges)
            if (!ids.ContainsKey(e.FromStep) || !ids.ContainsKey(e.ToStep) || !anc[e.ToStep].Contains(e.FromStep)) return "edge does not follow a dependency";
        return null;
    }

    /// <summary>The DAG error of a workflow body (producer side: refuse to sign a malformed or cyclic commitment). null when fine.</summary>
    internal static string? DagErrorOf(JD body) => ValidWorkflowBody(body) ? DagError(ParseBody(body)) : "malformed workflow";

    /// <summary>step id -> the set of its transitive dependencies; null on a cycle.</summary>
    static Dictionary<string, HashSet<string>>? Ancestors(Body b)
    {
        var byId = new Dictionary<string, Step>();
        foreach (var s in b.Steps) byId[s.Id] = s;
        var outp = new Dictionary<string, HashSet<string>>();
        var state = new Dictionary<string, int>();
        bool Visit(string id)
        {
            var st = state.GetValueOrDefault(id);
            if (st == 2) return true;
            if (st == 1) return false;
            state[id] = 1;
            var set = new HashSet<string>();
            foreach (var d in byId[id].Deps)
            {
                if (!Visit(d)) return false;
                set.Add(d);
                foreach (var x in outp[d]) set.Add(x);
            }
            outp[id] = set;
            state[id] = 2;
            return true;
        }
        foreach (var s in b.Steps) if (!Visit(s.Id)) return null;
        return outp;
    }

    // ---- digests -----------------------------------------------------------------------------------------------------------
    /// <summary>The digest of a scalar (string | bool | integer Num) as it appears in step receipts.</summary>
    public static string ValueDigest(object? v) => Pca.HashCanonical(new JD { ["d"] = Val, ["v"] = v });
    public static string WorkflowDigest(JD body) => Pca.HashCanonical(new JD { ["d"] = WfRef, ["w"] = body });
    public static string ReceiptRef(JD receipt) => Pca.HashCanonical(new JD { ["d"] = WrRef, ["r"] = receipt });

    // ---- receipts ----------------------------------------------------------------------------------------------------------
    static Rcpt? ReceiptShape(object? ro)
    {
        if (ro is not JD r || !K5Strict.OnlyKeys(r, ReceiptKeys) || !(K5Strict.TryInt(r["v"], out var v) && v == 1)) return null;
        var prevNull = r["prev"] == null;
        if (!K5Strict.IsB32(r["wf"]) || !K5Strict.Rx(r["step"], K5Strict.IdRe) || !K5Strict.IsUint(r["seq"]) || !K5Strict.NullOr(r["prev"], K5Strict.IsB32) || (K5Strict.U(r["seq"]) == 0) != prevNull) return null;
        if (!(r["outcome"] is "ok" or "failed")) return null;
        if (!K5Strict.IsB32(r["params_digest"]) || !K5Strict.IsUint(r["issued_at"]) || !K5Strict.IsB32(r["signer"]) || r["sig"] is not string) return null;
        if (r["outputs"] is not JD o || o.Count > 32) return null;
        var outputs = new Dictionary<string, Out>();
        foreach (var (k, vo) in o)
        {
            if (!K5Strict.NameRe.IsMatch(k) || vo is not JD ov || !K5Strict.OnlyKeys(ov, "digest", "num", "unit", "labels") || !K5Strict.IsB32(ov["digest"]) ||
                !K5Strict.NullOr(ov["num"], K5Strict.IsUint) || !K5Strict.NullOr(ov["unit"], x => K5Strict.Rx(x, K5Strict.UnitRe)) || !K5Strict.SortedUnique(ov["labels"], K5Strict.LabelRe, 16)) return null;
            outputs[k] = new Out { Digest = (string)ov["digest"]!, Num = ov["num"] == null ? null : K5Strict.U(ov["num"]), Unit = StrOrNull(ov["unit"]), Labels = K5Strict.Strs(ov["labels"]) };
        }
        return new Rcpt
        {
            Raw = r, Wf = (string)r["wf"]!, Step = (string)r["step"]!, Seq = K5Strict.U(r["seq"]), Prev = StrOrNull(r["prev"]), Outcome = (string)r["outcome"]!,
            ParamsDigest = (string)r["params_digest"]!, Outputs = outputs, IssuedAt = K5Strict.U(r["issued_at"]), Signer = (string)r["signer"]!, Sig = r["sig"],
        };
    }

    /// <summary>Check the receipt chain against the workflow. Returns the offending index, or null. Also returns the parsed receipts.</summary>
    static int? ReceiptError(Body w, string rsSigner, List<object?> receipts, long now, List<Rcpt> parsed)
    {
        var wd = WorkflowDigest(w.Raw);
        var byId = new Dictionary<string, Step>();
        foreach (var s in w.Steps) byId[s.Id] = s;
        var index = new Dictionary<string, int>();
        Rcpt? prev = null;
        for (var i = 0; i < receipts.Count; i++)
        {
            var r = ReceiptShape(receipts[i]);
            if (r == null || r.Signer != rsSigner || r.Wf != wd || r.Seq != i || r.IssuedAt > now) return i;
            if (!byId.ContainsKey(r.Step) || index.ContainsKey(r.Step)) return i;
            if ((prev == null ? r.Prev != null : r.Prev != ReceiptRef(prev.Raw)) || !K5Strict.VerifyBody(ReceiptDomain, K5Strict.Pick(r.Raw, ReceiptBodyKeys), rsSigner, r.Sig)) return i;
            // a receipt may precede one of its dependencies' receipts only when every edge from that dependency is a declared promise
            foreach (var d in byId[r.Step].Deps)
            {
                if (index.ContainsKey(d)) continue;
                var es = w.Edges.Where(e => e.FromStep == d && e.ToStep == r.Step).ToList();
                if (es.Count == 0 || es.Any(e => e.Promise == null)) return i;
            }
            index[r.Step] = i;
            parsed.Add(r);
            prev = r;
        }
        return null;
    }

    // ---- admission ---------------------------------------------------------------------------------------------------------
    static WfResult Res(string decision, string? code, string? step, int? at = null, IReadOnlyList<int>? pending = null) => new(decision, code, step, at, pending ?? Array.Empty<int>());
    static WfResult Deny(string code, string? step = null, int? at = null) => Res("deny", code, step, at);

    /// <summary>Is <paramref name="root"/> the Merkle plan root this signed, unexpired, pinned-principal workflow authorizes? (<c>plan_root_authorized</c>). Never throws.</summary>
    public static bool PlanRootAuthorized(object? workflow, string? principal, long now, string? root)
    {
        try
        {
            if (workflow is not JD w || !ValidWorkflowBody(w.GetValueOrDefault("body"))) return false;
            var b = ParseBody((JD)w["body"]!);
            return DagError(b) == null && b.Principal == principal && K5Strict.VerifyBody(WorkflowDomain, b.Raw, principal, w.GetValueOrDefault("sig")) && now >= b.IssuedAt && now < b.ExpiresAt && b.PlanRoot == root;
        }
        catch (Exception) { return false; }
    }

    static bool ValidRequest(object? ro) =>
        ro is JD r && K5Strict.OnlyKeys(r, "step", "verb", "resource", "params", "units", "goal_digest", "plan_root") && K5Strict.Rx(r["step"], K5Strict.IdRe) &&
        K5Strict.IsStr(r["verb"], 128) && K5Strict.IsStr(r["resource"], 512) && K5Strict.IsScalarMap(r["params"]) &&
        r["units"] is JD u && u.All(e => K5Strict.NameRe.IsMatch(e.Key) && K5Strict.Rx(e.Value, K5Strict.UnitRe)) &&
        K5Strict.NullOr(r["goal_digest"], K5Strict.IsB32) && K5Strict.NullOr(r["plan_root"], K5Strict.IsB32);

    static WfResult Evaluate(AdmitInput inp, bool bind)
    {
        if (inp.Workflow is not JD sw || !K5Strict.OnlyKeys(sw, "body", "sig") || !ValidWorkflowBody(sw["body"]) || !ValidRequest(inp.Request) || inp.Receipts is not List<object?> receipts ||
            !K5Strict.IsB32(inp.Principal) || !K5Strict.IsB32(inp.RsSigner) || inp.Now < 0) return Deny("bad_workflow");
        var w = ParseBody((JD)sw["body"]!);
        var q = (JD)inp.Request!;
        var qStep = (string)q["step"]!;
        var qParams = (JD)q["params"]!;
        var qUnits = (JD)q["units"]!;
        var now = inp.Now;
        if (DagError(w) != null) return Deny("bad_dag", qStep);
        if (w.Principal != inp.Principal || !K5Strict.VerifyBody(WorkflowDomain, w.Raw, inp.Principal, sw["sig"])) return Deny("bad_signature", qStep);
        if (now < w.IssuedAt) return Deny("not_yet", qStep);
        if (now >= w.ExpiresAt) return Deny("expired", qStep);
        if (StrOrNull(q["goal_digest"]) != w.GoalDigest) return Deny("goal_mismatch", qStep);
        if (StrOrNull(q["plan_root"]) != w.PlanRoot) return Deny("plan_root_mismatch", qStep);
        var done = new List<Rcpt>();
        var bad = ReceiptError(w, inp.RsSigner!, receipts, now, done);
        if (bad != null) return Deny("bad_receipt", qStep, bad);
        var rec = new Dictionary<string, Rcpt>();
        foreach (var r in done) rec[r.Step] = r;
        var step = w.Steps.FirstOrDefault(s => s.Id == qStep);
        if (step == null) return Deny("unplanned_step", qStep);
        if (step.Verb != (string)q["verb"]! || step.Resource != (string)q["resource"]!) return Deny("step_mismatch", qStep);
        var pd = Pca.HashCanonical(qParams);
        if (step.ParamsDigest != null && step.ParamsDigest != pd) return Deny("params_mismatch", qStep);
        rec.TryGetValue(step.Id, out var mine);
        if (bind)
        {
            if (mine == null || mine.ParamsDigest != pd) return Deny("params_mismatch", qStep);
        }
        else
        {
            if (mine != null) return Deny("already_done", qStep);
            if (done.Count + 1 > w.MaxSteps) return Deny("budget_exceeded", qStep);
            foreach (var (name, cap) in w.Caps)
            {
                var spent = done.Sum(r => w.Steps.First(s => s.Id == r.Step).Cost.GetValueOrDefault(name, 0L)) + step.Cost.GetValueOrDefault(name, 0L);
                if (spent > cap) return Deny("budget_exceeded", qStep);
            }
        }
        // dependencies
        var pending = new List<int>();
        var unconstrained = false;
        foreach (var d in step.Deps)
        {
            if (!rec.TryGetValue(d, out var dr))
            {
                var es = w.Edges.Where(e => e.FromStep == d && e.ToStep == step.Id).ToList();
                if (bind || es.Count == 0) return Deny("deps_unmet", qStep);
                if (es.Any(e => e.Promise == null)) unconstrained = true;
                continue;
            }
            if (dr.Outcome != "ok") return Deny("dep_failed", qStep);
            if (step.FreshMs != null && now - dr.IssuedAt > step.FreshMs) return Deny("stale_dep", qStep);
        }
        // edge constraints
        for (var i = 0; i < w.Edges.Count; i++)
        {
            var e = w.Edges[i];
            if (e.ToStep != step.Id) continue;
            if (!rec.TryGetValue(e.FromStep, out var src))
            {
                pending.Add(i);
                continue;
            }
            src.Outputs.TryGetValue(e.FromField, out var o);
            var hasVal = qParams.TryGetValue(e.ToParam, out var val);
            if (o == null || !hasVal) return Deny("edge_missing", qStep, i);
            var unit = qUnits.TryGetValue(e.ToParam, out var uo) ? (string?)uo : null;
            if (o.Unit != unit || o.Unit != e.Unit) return Deny("edge_unit", qStep, i);
            if (e.Op == "eq")
            {
                if (ValueDigest(val) != o.Digest) return Deny("edge_digest", qStep, i);
            }
            else
            {
                if (!K5Strict.TryInt(val, out var n) || o.Num == null) return Deny("edge_value", qStep, i);
                var num = o.Num.Value;
                var ok = e.Op == "le" ? n <= num : e.Op == "ge" ? n >= num : e.Op == "lt" ? n < num : n > num;
                if (!ok) return Deny("edge_relation", qStep, i);
            }
            if (o.Labels.Any(l => e.DenyLabels.Contains(l))) return Deny("taint_flow", qStep, i);
        }
        if (bind && pending.Count > 0) return Deny("deps_unmet", qStep);
        // taint across the DAG: every label any executed ancestor produced
        var anc = Ancestors(w)!;
        var inherited = new HashSet<string>();
        foreach (var a in anc[step.Id])
            if (rec.TryGetValue(a, out var ar)) foreach (var o in ar.Outputs.Values) foreach (var l in o.Labels) inherited.Add(l);
        if (step.DenyLabels.Any(inherited.Contains)) return Deny("taint_flow", qStep);
        if (unconstrained) return Res("escalate", "pipeline_unconstrained", qStep);
        if (step.EscalateLabels.Any(inherited.Contains)) return Res("escalate", "taint_escalate", qStep);
        return Res("allow", null, qStep, null, pending);
    }

    /// <summary>Admit ONE step of the committed workflow, or deny / escalate. Never throws (a failure is deny <c>bad_workflow</c>).</summary>
    public static WfResult AdmitStep(AdmitInput inp)
    {
        try { return Evaluate(inp, false); }
        catch (Exception) { return Deny("bad_workflow"); }
    }

    /// <summary>Promise binding (post hoc): the step already has its receipt; its params are re-checked against every edge now that all of
    /// its dependencies' receipts exist. Never throws.</summary>
    public static WfResult BindPromises(AdmitInput inp)
    {
        try { return Evaluate(inp, true); }
        catch (Exception) { return Deny("bad_workflow"); }
    }
}
