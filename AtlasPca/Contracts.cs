using System.Security.Cryptography;
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The outcome of evaluating a whole contract against one action; mirrors <see cref="ProhibitionResult"/>. <c>Violated</c> holds constitution invariant ids and/or clause ids
/// (<c>&lt;contract&gt;</c>, <c>&lt;action&gt;</c>, <c>&lt;state&gt;</c> for structural failures).</summary>
public sealed record ContractResult(bool Ok, IReadOnlyList<string> Violated, IReadOnlyList<string> Reasons, IReadOnlyList<InvariantEval> Evaluated);

/// <summary><see cref="Contracts.Advance"/>: the verdict plus the next state (the input state unless <c>Ok</c>); <c>DecidedBy</c> is <c>contract</c>, <c>state</c> or <c>none</c>.</summary>
public sealed record AdvanceContractResult(bool Ok, IReadOnlyList<string> Violated, IReadOnlyList<string> Reasons, IReadOnlyList<InvariantEval> Evaluated, JD Next, string DecidedBy);

/// <summary>Behavioral contracts (temporal clauses over the prohibition monitor): an optional embedded constitution (<c>invariants</c>) plus temporal <c>clauses</c> (<c>always</c>, <c>never</c>,
/// <c>precedes</c> / <c>requires_prior</c>, <c>responds_within</c> bounded liveness, <c>and</c>) run against ONE shared, hash-chained monitor state. Pure data and total functions;
/// everything malformed, unknown or unresolvable fails closed exactly as the prohibition monitor does.</summary>
public static class Contracts
{
    public const long Version = 1;
    public const string SigDomain = "atlas-pca/contract/v1\0";
    public const int MaxClauses = 256;
    public const int MaxClauseDepth = 16;
    const int MaxIdLen = 128;

    static string[] ForbiddenIds => new[] { "__proto__", "constructor", "prototype" };
    static string JsStr(object? x) => x switch { null => "null", string s => s, bool b => b ? "true" : "false", JD => "[object Object]", JL l => string.Join(",", l.Select(e => e == null ? "" : JsStr(e))), _ => IntentJs.NumOf(x) is double d ? JsCanon.NumberString(d) : x.ToString() ?? "" };
    // String(m[k]) of the reference: a member that is absent prints "undefined" (an explicit null prints "null").
    static string JsStrAt(JD m, string k) => m.TryGetValue(k, out var v) ? JsStr(v) : "undefined";
    static double D(object? x) => IntentJs.NumOf(x)!.Value;
    static object Num(double d) => d == Math.Floor(d) && Math.Abs(d) < 9e15 ? (object)(long)d : d;

    public static List<string> ValidateClause(object? cl, HashSet<string> seen, int depth)
    {
        if (depth > MaxClauseDepth) return new() { "clause nesting too deep" };
        if (cl is not JD m) return new() { "clause not an object" };
        if (m.GetValueOrDefault("id") is not string { Length: > 0 } id) return new() { "<no id>: missing clause id" };
        List<string> Err(string e) => new() { $"{id}: {e}" };
        if (id.Length > MaxIdLen) return Err("id too long");
        if (ForbiddenIds.Contains(id)) return Err("forbidden id");
        if (!seen.Add(id)) return Err("duplicate id");
        string? e;
        switch (m.GetValueOrDefault("kind") as string)
        {
            case "always":
            case "never":
                e = Prohibitions.ValidateWhen(m.GetValueOrDefault("p"), "p");
                return e != null ? Err(e) : new();
            case "precedes":
            case "requires_prior":
                if ((e = Prohibitions.ValidateWhen(m.GetValueOrDefault("p"), "p")) != null) return Err(e);
                return (e = Prohibitions.ValidateWhen(m.GetValueOrDefault("q"), "q")) != null ? Err(e) : new();
            case "responds_within":
                {
                    if ((e = Prohibitions.ValidateWhen(m.GetValueOrDefault("p"), "p")) != null) return Err(e);
                    if ((e = Prohibitions.ValidateWhen(m.GetValueOrDefault("q"), "q")) != null) return Err(e);
                    var w = m.GetValueOrDefault("within");
                    if (IntentJs.NumOf(w) is not double wd || !double.IsFinite(wd) || Math.Floor(wd) != wd || IntentJs.IsNegZero(wd) || wd < 1 || wd > Prohibitions.MaxDeadline) return Err("within must be an integer in [1, MAX_DEADLINE]");
                    return new();
                }
            case "and":
                {
                    if (m.GetValueOrDefault("clauses") is not JL subs || subs.Count == 0) return Err("and.clauses must be a non-empty array");
                    var o = new List<string>();
                    foreach (var s in subs) o.AddRange(ValidateClause(s, seen, depth + 1));
                    return o;
                }
            default:
                return Err($"unknown clause kind {JsStrAt(m, "kind")}");
        }
    }

    static int Count(JL cls, int depth = 1)
    {
        if (depth > MaxClauseDepth + 1) return MaxClauses + 1;
        int n = 0;
        foreach (var cl in cls)
        {
            n++;
            if (cl is JD d && d.GetValueOrDefault("kind") as string == "and" && d.GetValueOrDefault("clauses") is JL sub) n += Count(sub, depth + 1);
        }
        return n;
    }

    /// <summary>Structural problems with a contract (empty = well formed). Total.</summary>
    public static List<string> Validate(object? c)
    {
        if (c is not JD m) return new() { "contract not an object" };
        var o = new List<string>();
        if (!(IntentJs.NumOf(m.GetValueOrDefault("version")) == Version)) o.Add($"unsupported version {JsStrAt(m, "version")}");
        if (m.GetValueOrDefault("principal") is not string { Length: > 0 }) o.Add("principal missing");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        if (m.ContainsKey("invariants"))
        {
            if (m["invariants"] is not JL invs) { o.Add("invariants not an array"); return o; }
            if (invs.Count > Prohibitions.MaxInvariants) o.Add("too many invariants");
            foreach (var inv in invs)
            {
                o.AddRange(Prohibitions.ValidateInvariant(inv));
                if (inv is JD im && im.GetValueOrDefault("id") is string id && !ids.Add(id)) o.Add($"{id}: duplicate id");
            }
        }
        if (m.ContainsKey("clauses"))
        {
            if (m["clauses"] is not JL cls) { o.Add("clauses not an array"); return o; }
            if (Count(cls) > MaxClauses) o.Add("too many clauses");
            foreach (var cl in cls) o.AddRange(ValidateClause(cl, ids, 1));
        }
        return o;
    }

    static JD Body(JD c) { var b = new JD(c); b.Remove("id"); b.Remove("sig"); return b; }
    static byte[] SigMessage(string id) => Encoding.UTF8.GetBytes(SigDomain).Concat(SHA256.HashData(Encoding.UTF8.GetBytes(id))).ToArray();

    /// <summary>The content address of a contract body (without <c>id</c> and <c>sig</c>).</summary>
    public static string ContractId(JD c) => Pca.HashCanonical(Body(c));

    /// <summary>The principal signs the contract; a malformed one is refused (authoring-time guard).</summary>
    public static JD Sign(JD c, EdKey principal)
    {
        var problems = Validate(c);
        if (problems.Count > 0) throw new ArgumentException("signContract: " + string.Join("; ", problems));
        var id = ContractId(c);
        var o = Body(c);
        o["id"] = id;
        o["sig"] = Pca.B64u(principal.Sign(SigMessage(id)));
        return o;
    }

    /// <summary>Well formed, the id matches the content, signed by <paramref name="expectedPrincipal"/> (or the embedded principal). Never throws.</summary>
    public static (bool Ok, string? Reason) Verify(object? sc, string? expectedPrincipal = null)
    {
        try
        {
            var problems = Validate(sc);
            if (problems.Count > 0) return (false, problems[0]);
            var m = (JD)sc!;
            if (expectedPrincipal != null && !Equals(m["principal"], expectedPrincipal)) return (false, "principal mismatch");
            if (m.GetValueOrDefault("id") is not string id || id != ContractId(m)) return (false, "id does not match content");
            if (m.GetValueOrDefault("sig") is not string sig || !Pca.VerifyEdInternal((string)m["principal"]!, SigMessage(id), sig)) return (false, "bad signature");
            return (true, null);
        }
        catch (Exception) { return (false, "verification error (fail closed)"); }
    }

    /// <summary>The embedded prohibition constitution of a contract (empty when <c>invariants</c> is omitted).</summary>
    public static JD EmbeddedConstitution(JD c) => new() { ["version"] = 1L, ["principal"] = c.GetValueOrDefault("principal"), ["invariants"] = c.GetValueOrDefault("invariants") is JL l ? l : new JL() };

    /// <summary>Lifts a plain constitution into the degenerate contract (no temporal clauses).</summary>
    public static JD FromConstitution(JD c) => new() { ["version"] = Version, ["principal"] = c.GetValueOrDefault("principal"), ["invariants"] = c.GetValueOrDefault("invariants"), ["clauses"] = new JL() };

    sealed record Transition(bool Ok, string? Reason, List<InvariantEval> Rows, Dictionary<string, double> LatchSet, Dictionary<string, double?> DeadlineSet);

    static Transition Base(JD cl, bool ok, string? reason = null) =>
        new(ok, reason, new() { new InvariantEval((string)cl["id"]!, (string)cl["kind"]!, ok ? "pass" : "violated", reason) }, new(), new());

    static Transition EvalClause(JD cl, Dictionary<string, object?> ctx, JD state, double now)
    {
        var latched = (JD)state["latched"]!;
        var deadlines = state.GetValueOrDefault("deadlines") as JD ?? new JD();
        var id = (string)cl["id"]!;
        var desc = cl.GetValueOrDefault("description") as string;
        try
        {
            switch ((string)cl["kind"]!)
            {
                case "always":
                    return Prohibitions.WhenAffirmative(cl["p"], ctx) ? Base(cl, true) : Base(cl, false, desc ?? "always-invariant violated (action does not satisfy p)");
                case "never":
                    return Prohibitions.WhenMatches(cl["p"], ctx) ? Base(cl, false, desc ?? "never-invariant violated (forbidden action)") : Base(cl, true);
                case "precedes":
                case "requires_prior":
                    {
                        var isQ = Prohibitions.WhenMatches(cl["q"], ctx); // the guarded action, conservative
                        var ok = !isQ || latched.ContainsKey(id);
                        var t = Base(cl, ok, ok ? null : desc ?? "precedence violated (prerequisite p not yet admitted before q)");
                        if (!latched.ContainsKey(id) && Prohibitions.WhenAffirmative(cl["p"], ctx)) t.LatchSet[id] = now; // an ambiguous prerequisite must not count
                        return t;
                    }
                case "responds_within":
                    {
                        var within = D(cl["within"]);
                        bool violated = false;
                        double? carried = null;
                        if (deadlines.ContainsKey(id))
                        {
                            var cur = D(deadlines[id]);
                            if (Prohibitions.WhenAffirmative(cl["q"], ctx)) carried = null; // any response discharges all open obligations
                            else
                            {
                                var r = cur - 1;
                                if (r <= 0) violated = true; else carried = r;
                            }
                        }
                        var reason = violated ? desc ?? $"bounded-liveness deadline missed (no q within {JsCanon.NumberString(within)} actions of p)" : null;
                        var rows = new List<InvariantEval> { new(id, "responds_within", violated ? "violated" : "pass", reason) };
                        if (violated) return new(false, reason, rows, new(), new());
                        double? next = carried;
                        if (Prohibitions.WhenMatches(cl["p"], ctx)) next = next == null ? within : Math.Min(next.Value, within);
                        return new(true, null, rows, new(), new() { [id] = next });
                    }
                case "and":
                    {
                        var rows = new List<InvariantEval>(); var ls = new Dictionary<string, double>(); var ds = new Dictionary<string, double?>();
                        bool ok = true; string? reason = null;
                        foreach (var sub in (JL)cl["clauses"]!)
                        {
                            var r = EvalClause((JD)sub!, ctx, state, now);
                            rows.AddRange(r.Rows);
                            foreach (var kv in r.LatchSet) ls[kv.Key] = kv.Value;
                            foreach (var kv in r.DeadlineSet) ds[kv.Key] = kv.Value;
                            if (!r.Ok && ok) { ok = false; reason = r.Reason; }
                        }
                        return new(ok, reason, rows, ls, ds);
                    }
                default:
                    return Base(cl, false, "unknown clause kind (fail closed)");
            }
        }
        catch (Exception) { return Base(cl, false, "clause evaluation error (fail closed)"); }
    }

    static ContractResult Fail(string id, string reason) => new(false, new[] { id }, new[] { $"{id}: {reason}" }, new[] { new InvariantEval(id, "structural", "violated", reason) });

    /// <summary>Evaluates a whole contract (embedded constitution plus temporal clauses) against one action and the running state WITHOUT advancing. Every invariant and clause is evaluated;
    /// the whole contract is one document for the regex budget.</summary>
    public static ContractResult Check(Dictionary<string, object?>? action, object? contract, object? state) => SafeRegex.WithBudget(() => CheckInner(action, contract, state));

    static ContractResult CheckInner(Dictionary<string, object?>? action, object? contract, object? state)
    {
        try
        {
            var cp = Validate(contract);
            if (cp.Count > 0) return Fail("<contract>", cp[0]);
            if (action == null || !action.TryGetValue("action", out var av) || av is not JD ad || ad.GetValueOrDefault("verb") is not string || ad.GetValueOrDefault("resource") is not string) return Fail("<action>", "malformed action");
            var sp = Prohibitions.StateProblem(state);
            if (sp != null) return Fail("<state>", sp);
            var c = (JD)contract!; var st = (JD)state!;
            var ev = new List<InvariantEval>();
            var constitution = EmbeddedConstitution(c);
            if (((JL)constitution["invariants"]!).Count > 0) ev.AddRange(Prohibitions.Check(action, constitution, st).Evaluated);
            var now = D(st["now"]);
            if (c.GetValueOrDefault("clauses") is JL cls)
                foreach (var cl in cls)
                {
                    Transition t;
                    try { t = EvalClause((JD)cl!, action, st, now); }
                    catch (Exception) { t = new(false, "clause evaluation error (fail closed)", new() { new InvariantEval((string)((JD)cl!)["id"]!, "clause", "violated", "clause evaluation error (fail closed)") }, new(), new()); }
                    ev.AddRange(t.Rows);
                }
            var bad = ev.Where(e => e.Result == "violated").ToList();
            return new(bad.Count == 0, bad.Select(e => e.Id).ToList(), bad.Select(e => $"{e.Id}: {e.Reason ?? "violated"}").ToList(), ev);
        }
        catch (Exception) { return Fail("<monitor>", "monitor error (fail closed)"); }
    }

    /// <summary>The deterministic, total verifier: checks the whole contract against one action and, iff it holds, advances the hash-chained state exactly like the prohibition monitor and
    /// overlays the clauses' precedence latches and bounded-liveness deadline counters. Fail closed on anything unresolvable or on a stale chain head; <c>Next</c> is then the input state.</summary>
    public static AdvanceContractResult Advance(JD state, Dictionary<string, object?>? action, object? contract, long? expectedSeq = null, string? expectedStateDigest = null, double? nowArg = null)
    {
        AdvanceContractResult Refuse(string by, ContractResult? r = null, string? reason = null)
        {
            var b = r ?? Check(action, contract, state);
            return new(false, reason != null ? b.Violated.Where(v => v != "<state>").Append("<state>").ToList() : b.Violated, reason != null ? b.Reasons.Append($"<state>: {reason}").ToList() : b.Reasons, b.Evaluated, state, by);
        }
        try
        {
            var now = nowArg ?? D(state["now"]);
            if (expectedSeq != null && (state == null || IntentJs.NumOf(state.GetValueOrDefault("seq")) != expectedSeq)) return Refuse("state", null, "stale state head (seq)");
            if (expectedStateDigest != null)
            {
                string dg; try { dg = Prohibitions.StateDigest(state); } catch (Exception) { dg = "<unhashable>"; }
                if (dg != expectedStateDigest) return Refuse("state", null, "stale state head (digest)");
            }
            var verdict = Check(action, contract, state);
            if (!verdict.Ok)
            {
                var structural = verdict.Violated.Any(v => v.StartsWith('<') && v.EndsWith('>'));
                return new(false, verdict.Violated, verdict.Reasons, verdict.Evaluated, state, structural ? "state" : "contract");
            }
            var c = (JD)contract!;
            var adv = Prohibitions.AdvanceStrict(action, EmbeddedConstitution(c), state, now);
            if (!adv.Ok) return Refuse("state", verdict, "advance failed: " + adv.Reason);
            var latched = new JD((JD)adv.State!["latched"]!);
            var deadlines = state.GetValueOrDefault("deadlines") is JD dl ? new JD(dl) : new JD();
            SafeRegex.WithBudget(() =>
            {
                if (c.GetValueOrDefault("clauses") is JL cls)
                    foreach (var cl in cls)
                    {
                        var t = EvalClause((JD)cl!, action!, state, now);
                        foreach (var (k, v) in t.LatchSet) if (!latched.ContainsKey(k)) latched[k] = Num(v);
                        foreach (var (k, v) in t.DeadlineSet) { if (v == null) deadlines.Remove(k); else deadlines[k] = Num(v.Value); }
                    }
                return 0;
            });
            var next = new JD(adv.State!) { ["latched"] = latched };
            if (deadlines.Count > 0) next["deadlines"] = deadlines;
            var sp = Prohibitions.StateProblem(next);
            if (sp != null) return Refuse("state", verdict, "resulting state invalid: " + sp);
            return new(true, verdict.Violated, verdict.Reasons, verdict.Evaluated, next, "none");
        }
        catch (Exception) { return Refuse("state", null, "advance error (fail closed)"); }
    }

    /// <summary>allow = permitted AND the contract holds; on allow the state advances. The permission verdict is an input that can only be ANDed; the monitor runs regardless.</summary>
    public static (AdvanceContractResult Result, bool Allow) CheckAndAdvance(bool permitted, JD state, Dictionary<string, object?>? action, object? contract, long? expectedSeq = null, string? expectedStateDigest = null, double? now = null)
    {
        var adv = Advance(state, action, contract, expectedSeq, expectedStateDigest, now);
        if (!adv.Ok) return (adv, false);
        if (!permitted) return (new(false, adv.Violated, adv.Reasons.Append("<permission>: not permitted").ToList(), adv.Evaluated, state, "contract"), false);
        return (adv, true);
    }
}
