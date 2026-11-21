using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>One invariant considered by <see cref="Prohibitions.Check"/>: <c>Result</c> is <c>pass</c> or <c>violated</c>. <c>Reason</c> is the text; <c>ReasonValue</c> holds the raw JSON of a non-string (truthy) description, which the reference carries as given.</summary>
public sealed record InvariantEval(string Id, string Kind, string Result, string? Reason, object? ReasonValue = null);

/// <summary>The outcome of evaluating a whole constitution against one action: <c>Violated</c> holds the violated invariant ids (or <c>&lt;constitution&gt;</c>, <c>&lt;action&gt;</c>,
/// <c>&lt;state&gt;</c> for structural failures); every invariant is evaluated (no short circuit).</summary>
public sealed record ProhibitionResult(bool Ok, IReadOnlyList<string> Violated, IReadOnlyList<string> Reasons, IReadOnlyList<InvariantEval> Evaluated);

/// <summary>The outcome of <see cref="Prohibitions.CheckAndAdvance"/>: <c>Next</c> equals the input state unless <c>Allow</c>; <c>DecidedBy</c> is <c>prohibition</c>, <c>permission</c>, <c>state</c> or <c>none</c>.</summary>
public sealed record CheckAndAdvanceResult(bool Allow, string DecidedBy, ProhibitionResult Prohibition, JD? Next, string? Reason);

/// <summary>The prohibition plane: a principal's constitution of invariants (never, never_unless, cap, rate, never_after, require_prior, require_approval_over) evaluated in veto polarity
/// against an action and a running monitor state <c>{now, seq, parent, ledger, latched, deadlines?}</c> that advances through a hash chain. Pure, total and fail closed: a malformed
/// constitution, action or state is a violation, and a transition that cannot record an action faithfully is refused (a dropped contribution would under-count a cap).</summary>
public static partial class Prohibitions
{
    public const long ConstitutionVersion = 1;
    public const string StateDigestDomain = "atlas-pca/monitor-state/v1";
    public const string StateChainDomain = "atlas-pca/monitor-state-link/v1";
    public const int MaxLedger = 10_000;
    public const int MaxInvariants = 256;
    public const long MaxDeadline = 1_000_000;
    const int MaxStateEntries = 100_000, MaxStateKeys = 1024, MaxIdLen = 128;

    static string[] ForbiddenIds => new[] { "__proto__", "constructor", "prototype" };

    static bool Fin(object? x) => IntentJs.NumOf(x) is double d && double.IsFinite(d);
    static double D(object? x) => IntentJs.NumOf(x)!.Value;
    static bool IsInt(object? x) => IntentJs.NumOf(x) is double d && double.IsFinite(d) && Math.Floor(d) == d && !IntentJs.IsNegZero(d);
    static string Js(double d) => JsCanon.NumberString(d);

    /// <summary>The genesis monitor state at <paramref name="now"/>: empty ledger, no latches, seq 0, no parent.</summary>
    public static JD EmptyState(long now) => new() { ["now"] = now, ["seq"] = 0L, ["parent"] = null, ["ledger"] = new JD(), ["latched"] = new JD() };

    static string? ValidateConditions(object? cs, string label)
    {
        if (cs is not JL l || l.Count == 0) return $"{label} must be a non-empty array";
        foreach (var c in l) { var e = ValidateCondition(c); if (e != null) return e; }
        return null;
    }

    /// <summary>Structural problems with an invariant (empty = well formed).</summary>
    public static List<string> ValidateInvariant(object? inv)
    {
        if (inv is not JD m) return new() { "invariant not an object" };
        if (m.GetValueOrDefault("id") is not string { Length: > 0 } id) return new() { "<no id>: missing id" };
        List<string> Err(string e) => new() { $"{id}: {e}" };
        if (id.Length > MaxIdLen) return Err("id too long");
        if (ForbiddenIds.Contains(id)) return Err("forbidden id");
        string? e;
        switch (m.GetValueOrDefault("kind") as string)
        {
            case "never":
                e = ValidateWhen(m.GetValueOrDefault("when"), "when");
                return e != null ? Err(e) : new();
            case "never_unless":
                if ((e = ValidateWhen(m.GetValueOrDefault("when"), "when")) != null) return Err(e);
                return (e = ValidateConditions(m.GetValueOrDefault("unless"), "unless")) != null ? Err(e) : new();
            case "cap":
                if ((e = ValidateWhen(m.GetValueOrDefault("when"), "when")) != null) return Err(e);
                if (m.GetValueOrDefault("amount") is not string am || !am.StartsWith("action.", StringComparison.Ordinal)) return Err("amount must be an action.* path");
                if (!Fin(m.GetValueOrDefault("max")) || D(m["max"]) < 0) return Err("max must be a finite number >= 0");
                if (m.ContainsKey("window_secs") && (!Fin(m["window_secs"]) || D(m["window_secs"]) <= 0)) return Err("bad window_secs");
                return new();
            case "rate":
                if ((e = ValidateWhen(m.GetValueOrDefault("when"), "when")) != null) return Err(e);
                if (!IsInt(m.GetValueOrDefault("max")) || D(m["max"]) < 0 || D(m["max"]) > MaxLedger) return Err("max must be an integer in [0,10000]");
                if (!Fin(m.GetValueOrDefault("window_secs")) || D(m["window_secs"]) <= 0) return Err("window_secs must be > 0");
                return new();
            case "never_after":
                if ((e = ValidateWhen(m.GetValueOrDefault("after"), "after")) != null || (e = ValidateWhen(m.GetValueOrDefault("forbid"), "forbid")) != null) return Err(e);
                return new();
            case "require_prior":
                if ((e = ValidateWhen(m.GetValueOrDefault("when"), "when")) != null || (e = ValidateWhen(m.GetValueOrDefault("prior"), "prior")) != null) return Err(e);
                return new();
            case "require_approval_over":
                if ((e = ValidateWhen(m.GetValueOrDefault("when"), "when")) != null) return Err(e);
                if (m.GetValueOrDefault("amount") is not string am2 || !am2.StartsWith("action.", StringComparison.Ordinal)) return Err("amount must be an action.* path");
                if (!Fin(m.GetValueOrDefault("threshold")) || D(m["threshold"]) < 0) return Err("threshold must be a finite number >= 0");
                return (e = ValidateConditions(m.GetValueOrDefault("approved"), "approved")) != null ? Err(e) : new();
            default:
                return Err($"unknown invariant kind {JsMember(m, "kind")}");
        }
    }

    /// <summary>Structural problems with a constitution (empty = well formed).</summary>
    public static List<string> ValidateConstitution(object? c)
    {
        if (c is not JD m) return new() { "constitution not an object" };
        var o = new List<string>();
        if (!(IntentJs.NumOf(m.GetValueOrDefault("version")) == ConstitutionVersion)) o.Add($"unsupported version {JsMember(m, "version")}");
        if (m.GetValueOrDefault("principal") is not string { Length: > 0 }) o.Add("principal missing");
        if (m.GetValueOrDefault("invariants") is not JL invs) { o.Add("invariants not an array"); return o; }
        if (invs.Count > MaxInvariants) o.Add("too many invariants");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var inv in invs)
        {
            o.AddRange(ValidateInvariant(inv));
            if (inv is JD im && im.GetValueOrDefault("id") is string id && !seen.Add(id)) o.Add($"{id}: duplicate id");
        }
        return o;
    }

    /// <summary>Structural problem with a monitor state (null = well formed). Total.</summary>
    public static string? StateProblem(object? state)
    {
        try
        {
            if (state is not JD s || !Fin(s.GetValueOrDefault("now")) || s.GetValueOrDefault("ledger") is not JD ledger || s.GetValueOrDefault("latched") is not JD latched) return "malformed monitor state";
            if (!IsInt(s.GetValueOrDefault("seq")) || D(s["seq"]) < 0) return "malformed monitor state: seq";
            if (!s.TryGetValue("parent", out var parent) || (parent != null && parent is not string)) return "malformed monitor state: parent"; // a missing member is undefined, not null
            if (D(s["seq"]) == 0 && parent != null) return "malformed monitor state: genesis has a parent";
            if (D(s["seq"]) > 0 && parent == null) return "malformed monitor state: missing chain link";
            double now = D(s["now"]);
            if (ledger.Count > MaxStateKeys || latched.Count > MaxStateKeys) return "malformed monitor state: too many keys";
            long total = 0;
            foreach (var (k, lv) in ledger)
            {
                if (ForbiddenIds.Contains(k) || k.Length > MaxIdLen) return "malformed monitor state: bad ledger key";
                if (lv is not JL l || l.Count > MaxLedger) return "malformed monitor state: bad ledger";
                total += l.Count;
                foreach (var e in l)
                {
                    if (e is not JD ed || !Fin(ed.GetValueOrDefault("t")) || !Fin(ed.GetValueOrDefault("amount")) || D(ed["amount"]) < 0) return "malformed monitor state: bad ledger entry";
                    if (D(ed["t"]) > now) return "malformed monitor state: ledger entry after now (clock regression)";
                }
            }
            if (total > MaxStateEntries) return "malformed monitor state: too many entries";
            foreach (var (k, t) in latched)
            {
                if (ForbiddenIds.Contains(k) || k.Length > MaxIdLen) return "malformed monitor state: bad latch key";
                if (!Fin(t) || D(t) > now) return "malformed monitor state: bad latch";
            }
            if (s.ContainsKey("deadlines"))
            {
                if (s["deadlines"] is not JD dl) return "malformed monitor state: deadlines";
                if (dl.Count > MaxStateKeys) return "malformed monitor state: too many deadline keys";
                foreach (var (k, d) in dl)
                {
                    if (ForbiddenIds.Contains(k) || k.Length > MaxIdLen) return "malformed monitor state: bad deadline key";
                    if (!IsInt(d) || D(d) < 1 || D(d) > MaxDeadline) return "malformed monitor state: bad deadline";
                }
            }
            return null;
        }
        catch (Exception) { return "malformed monitor state"; }
    }

    static int CmpEntry(JD a, JD b)
    {
        var c = D(a["t"]).CompareTo(D(b["t"]));
        return c != 0 ? c : D(a["amount"]).CompareTo(D(b["amount"]));
    }

    /// <summary>The canonical, digest-committed projection of a state: unknown fields dropped, ledger entries reduced to {t, amount} and sorted, empty ledgers and empty deadlines omitted.</summary>
    public static JD CanonicalState(JD state)
    {
        var p = StateProblem(state);
        if (p != null) throw new ArgumentException(p);
        var ledger = new JD();
        foreach (var (k, lv) in (JD)state["ledger"]!)
        {
            var l = ((JL)lv!).Cast<JD>().Select(e => new JD { ["t"] = e["t"], ["amount"] = e["amount"] }).ToList();
            l.Sort(CmpEntry);
            if (l.Count > 0) ledger[k] = l.Cast<object?>().ToList();
        }
        var latched = new JD(); foreach (var (k, v) in (JD)state["latched"]!) latched[k] = v;
        var o = new JD { ["d"] = StateDigestDomain, ["now"] = state["now"], ["seq"] = state["seq"], ["parent"] = state["parent"], ["ledger"] = ledger, ["latched"] = latched };
        if (state.GetValueOrDefault("deadlines") is JD dl && dl.Count > 0) { var d2 = new JD(); foreach (var (k, v) in dl) d2[k] = v; o["deadlines"] = d2; }
        return o;
    }

    public static string StateDigest(JD state) => Pca.HashCanonical(CanonicalState(state));

    /// <summary>The same state at a later <paramref name="now"/>; refuses a regression. Never throws.</summary>
    public static (bool Ok, JD? State, string? Reason) Tick(JD state, double now)
    {
        if (StateProblem(state) != null) return (false, null, "malformed monitor state");
        if (!double.IsFinite(now) || now < D(state["now"])) return (false, null, "clock regression");
        return (true, new JD(state) { ["now"] = now == Math.Floor(now) && Math.Abs(now) < 9e15 ? (object)(long)now : IntentJs.Normalize(now)! }, null);
    }

    static List<JD> WindowEntries(JD state, string id, double? windowSecs)
    {
        if (((JD)state["ledger"]!).GetValueOrDefault(id) is not JL l) return new();
        var now = D(state["now"]);
        var lo = windowSecs is double w ? now - w * 1000 : double.NegativeInfinity;
        var r = l.Cast<JD>().Where(e => D(e["t"]) > lo && D(e["t"]) <= now).ToList();
        r.Sort(CmpEntry);
        return r;
    }

    static bool AllHold(object? cs, Dictionary<string, object?> ctx) => cs is JL l && l.All(c => Predicates.EvaluateCondition(c, ctx));

    static (bool Ok, object? Reason) EvalOne(JD inv, Dictionary<string, object?> ctx, JD state)
    {
        var id = (string)inv["id"]!;
        var desc = inv.GetValueOrDefault("description"); // any JSON type: the reference carries it as given
        var latched = (JD)state["latched"]!;
        switch ((string)inv["kind"]!)
        {
            case "never":
                return WhenMatches(inv["when"], ctx) ? (false, desc ?? "forbidden action") : (true, null);
            case "never_unless":
                if (!WhenMatches(inv["when"], ctx)) return (true, null);
                return AllHold(inv["unless"], ctx) ? (true, null) : (false, desc ?? "forbidden without required condition");
            case "cap":
                {
                    if (!WhenMatches(inv["when"], ctx)) return (true, null);
                    var a = Predicates.ResolvePath(ctx, inv["amount"]);
                    if (!a.Found || !Fin(a.Value) || D(a.Value) < 0) return (false, "amount unresolvable (fail closed)");
                    double spent = WindowEntries(state, id, inv.ContainsKey("window_secs") ? D(inv["window_secs"]) : null).Sum(e => D(e["amount"]));
                    return spent + D(a.Value) <= D(inv["max"]) ? (true, null) : (false, $"cap exceeded: {Js(spent)} + {Js(D(a.Value))} > {Js(D(inv["max"]))}");
                }
            case "rate":
                {
                    if (!WhenMatches(inv["when"], ctx)) return (true, null);
                    int n = WindowEntries(state, id, D(inv["window_secs"])).Count;
                    return n + 1 <= D(inv["max"]) ? (true, null) : (false, $"rate exceeded: {n + 1} > {Js(D(inv["max"]))} per {Js(D(inv["window_secs"]))}s");
                }
            case "never_after":
                if (!latched.ContainsKey(id) || !WhenMatches(inv["forbid"], ctx)) return (true, null);
                return (false, desc ?? "forbidden after trigger");
            case "require_prior":
                if (!WhenMatches(inv["when"], ctx)) return (true, null);
                return latched.ContainsKey(id) ? (true, null) : (false, desc ?? "required prior action not admitted");
            default: // require_approval_over
                {
                    if (!WhenMatches(inv["when"], ctx)) return (true, null);
                    var a = Predicates.ResolvePath(ctx, inv["amount"]);
                    var over = !a.Found || !Fin(a.Value) || D(a.Value) < 0 || D(a.Value) > D(inv["threshold"]);
                    if (!over) return (true, null);
                    return AllHold(inv["approved"], ctx) ? (true, null) : (false, desc ?? $"approval required over {Js(D(inv["threshold"]))}");
                }
        }
    }

    static ProhibitionResult Structural(string id, string reason) => new(false, new[] { id }, new[] { reason }, new[] { new InvariantEval(id, "structural", "violated", reason) });

    static bool WellFormedAction(Dictionary<string, object?>? action) =>
        action != null && action.TryGetValue("action", out var a) && a is JD ad && ad.GetValueOrDefault("verb") is string && ad.GetValueOrDefault("resource") is string;

    /// <summary>Evaluates EVERY invariant (no short circuit) against the action and the running state. The whole constitution is one document: every invariant and condition shares one regex budget.</summary>
    public static ProhibitionResult Check(Dictionary<string, object?>? action, object? constitution, object? state) => SafeRegex.WithBudget(() => CheckInner(action, constitution, state));

    static ProhibitionResult CheckInner(Dictionary<string, object?>? action, object? constitution, object? state)
    {
        try
        {
            var cp = ValidateConstitution(constitution);
            if (cp.Count > 0) return Structural("<constitution>", cp[0]);
            if (!WellFormedAction(action)) return Structural("<action>", "malformed action");
            var sp = StateProblem(state);
            if (sp != null) return Structural("<state>", sp);
            var ev = new List<InvariantEval>();
            foreach (var invo in (JL)((JD)constitution!)["invariants"]!)
            {
                var inv = (JD)invo!;
                (bool Ok, object? Reason) r;
                try { r = EvalOne(inv, action!, (JD)state!); }
                catch (Exception) { r = (false, "evaluation error (fail closed)"); }
                // JavaScript truthiness: a falsy reason (an empty string, 0, false) leaves the row without one; a non-string one is carried as given
                var truthy = r.Reason switch { null => false, string t => t.Length > 0, bool b => b, JD or JL => true, _ => IntentJs.NumOf(r.Reason) is double d && d != 0 && !double.IsNaN(d) };
                ev.Add(new InvariantEval((string)inv["id"]!, (string)inv["kind"]!, r.Ok ? "pass" : "violated", truthy ? JsString(r.Reason) : null, truthy && r.Reason is not string ? r.Reason : null));
            }
            var bad = ev.Where(x => x.Result == "violated").ToList();
            return new(bad.Count == 0, bad.Select(x => x.Id).ToList(), bad.Select(x => $"{x.Id}: {x.Reason ?? "violated"}").ToList(), ev);
        }
        catch (Exception) { return Structural("<monitor>", "monitor error (fail closed)"); }
    }

    /// <summary>The pure, deterministic transition for an ADMITTED action: records cap and rate contributions, latches never_after / require_prior triggers, prunes expired window entries,
    /// bounds the ledger and extends the hash chain. <c>Ok</c> false (never a silently unchanged state) on anything it cannot record faithfully.</summary>
    public static (bool Ok, JD? State, string? Reason) AdvanceStrict(Dictionary<string, object?>? action, object? constitution, JD state, double? now = null) =>
        SafeRegex.WithBudget(() => AdvanceInner(action, constitution, state, now));

    static (bool Ok, JD? State, string? Reason) AdvanceInner(Dictionary<string, object?>? action, object? constitution, JD state, double? nowArg)
    {
        try
        {
            var cp = ValidateConstitution(constitution);
            if (cp.Count > 0) return (false, null, cp[0]);
            var sp = StateProblem(state);
            if (sp != null) return (false, null, sp);
            var now = nowArg ?? D(state["now"]);
            if (!double.IsFinite(now) || now < D(state["now"])) return (false, null, "clock regression");
            if (!WellFormedAction(action)) return (false, null, "malformed action");
            var canon = CanonicalState(state);
            var prevDigest = Pca.HashCanonical(canon);
            var actionDigest = Pca.HashCanonical(action);
            var ledger = new JD();
            foreach (var (k, v) in (JD)canon["ledger"]!) ledger[k] = ((JL)v!).ToList();
            var latched = new JD(); foreach (var (k, v) in (JD)canon["latched"]!) latched[k] = v;
            object NowN() => now == Math.Floor(now) && Math.Abs(now) < 9e15 ? (object)(long)now : IntentJs.Normalize(now)!; // a Num: a bare double has no canonical form
            foreach (var invo in (JL)((JD)constitution!)["invariants"]!)
            {
                var inv = (JD)invo!;
                var id = (string)inv["id"]!; var kind = (string)inv["kind"]!;
                if (kind is "cap" or "rate")
                {
                    var prev = ledger.GetValueOrDefault(id) is JL pl ? pl.Cast<JD>().ToList() : new List<JD>();
                    var lo = inv.ContainsKey("window_secs") ? now - D(inv["window_secs"]) * 1000 : double.NegativeInfinity;
                    var kept = prev.Where(e => D(e["t"]) > lo).ToList();
                    if (WhenMatches(inv["when"], action))
                    {
                        object amount = 1L;
                        if (kind == "cap")
                        {
                            var r = Predicates.ResolvePath(action, inv["amount"]);
                            if (!r.Found || !Fin(r.Value) || D(r.Value) < 0) return (false, null, $"{id}: amount unresolvable");
                            amount = r.Value!;
                        }
                        kept.Add(new JD { ["t"] = NowN(), ["amount"] = amount });
                    }
                    kept.Sort(CmpEntry);
                    if (kept.Count > MaxLedger)
                    {
                        if (kind == "rate") return (false, null, $"{id}: rate ledger overflow");
                        while (kept.Count > MaxLedger)
                        {
                            var x = kept[0]; var y = kept[1];
                            kept.RemoveRange(0, 2);
                            kept.Insert(0, new JD { ["t"] = y["t"], ["amount"] = IntentJs.Normalize(D(x["amount"]) + D(y["amount"]))! }); // keeps the LATER time: never under-counts a cap
                        }
                    }
                    if (kept.Count > 0) ledger[id] = kept.Cast<object?>().ToList(); else ledger.Remove(id);
                }
                else if (kind == "never_after")
                {
                    if (!latched.ContainsKey(id) && WhenMatches(inv["after"], action)) latched[id] = NowN(); // an ambiguous trigger latches (stricter)
                }
                else if (kind == "require_prior")
                {
                    if (!latched.ContainsKey(id) && WhenAffirmative(inv["prior"], action)) latched[id] = NowN(); // an ambiguous prerequisite must NOT count as satisfied
                }
            }
            var next = new JD
            {
                ["now"] = NowN(), ["seq"] = (long)D(state["seq"]) + 1,
                ["parent"] = Pca.HashCanonical(new JD { ["d"] = StateChainDomain, ["state"] = prevDigest, ["action"] = actionDigest }), ["ledger"] = ledger, ["latched"] = latched,
            };
            if (StateProblem(next) != null) return (false, null, "resulting state invalid");
            return (true, next, null);
        }
        catch (Exception) { return (false, null, "advance error (fail closed)"); }
    }

    /// <summary>The pure kernel of the server's critical section: guard the head (compare-and-swap on <paramref name="expectedSeq"/> / <paramref name="expectedStateDigest"/>), compose
    /// authority (allow = permitted AND no prohibition violated; the monitor runs even when not permitted), and on allow compute the next state. Persisting <c>Next</c> iff <c>Allow</c> MUST
    /// happen in the same atomic step that read the state. Never throws.</summary>
    public static CheckAndAdvanceResult CheckAndAdvance(bool permitted, Dictionary<string, object?>? action, object? constitution, JD state, long? expectedSeq = null, string? expectedStateDigest = null)
    {
        var monitored = Check(action, constitution, state);
        CheckAndAdvanceResult Refuse(string by, string? reason = null) => new(false, by, monitored, state, reason);
        try
        {
            if (expectedSeq != null && (state == null || !IsInt(state.GetValueOrDefault("seq")) || (long)D(state["seq"]) != expectedSeq)) return Refuse("state", "stale state head (seq)");
            if (expectedStateDigest != null)
            {
                string? dg; try { dg = StateDigest(state); } catch (Exception) { dg = null; }
                if (dg != expectedStateDigest) return Refuse("state", "stale state head (digest)");
            }
            if (!monitored.Ok) return Refuse("prohibition");
            if (!permitted) return Refuse("permission");
            if (!SafetyEvidence.Attestable(action, constitution, state)) return Refuse("prohibition", "evidence not attestable");
            var adv = AdvanceStrict(action, constitution, state);
            if (!adv.Ok) return Refuse("state", "advance failed: " + adv.Reason);
            return new(true, "none", monitored, adv.State, null);
        }
        catch (Exception) { return Refuse("state", "check-and-advance error (fail closed)"); }
    }
}
