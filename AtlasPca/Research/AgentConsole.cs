// The principal's live agent console (data layer) and the multi-agent session.
//
// The console projects a stream of activity events into a per-agent view with a threat read (the immune read side, see Immune) and models the kill switch as a
// local set a client or gateway consults before dispatching; authoritative revocation is the transparency ledger's revocation epoch. A session groups a root agent and
// the sub-agents it delegates to under ONE signed goal. Both are pure and offline.
//
// An event is {at, agent, verb, resource, outcome: auto|step_up|deny|executed, r?, taint?, digest?, goalCommit?}. JSON values are the core's: Dictionary<string, object?>,
// List<object?>, string, bool, Num.
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Research;

public static class AgentConsole
{
    static Num N(double d) => new(JsX.JsNumString(d));
    static Num N(long l) => IntentJs.OfLong(l);
    static double Dv(object? x) => IntentJs.NumOf(x)!.Value;
    static int Cmp(double x) => x < 0 ? -1 : x > 0 ? 1 : 0;
    static object? Opt(D m, string k) => m.TryGetValue(k, out var v) ? v : null;

    /// <summary>An activity event from a proof-carrying action and the verifier's outcome; <paramref name="at"/> null means the action's own <c>iat</c>. Throws when
    /// <c>cap_chain</c> or <c>action</c> is missing, or the action cannot be put in canonical form.</summary>
    public static D EventFromPCActn(object? pIn, object? outcome, double? at = null)
    {
        if (pIn is not D p) throw new ArgumentException("eventFromPCActn: the action must be an object");
        if (!p.TryGetValue("cap_chain", out var cc) || cc is not L chain) throw new ArgumentException("eventFromPCActn: cap_chain must be a list");
        var leaf = chain.Count == 0 ? null : chain[^1] as D;
        if (!p.TryGetValue("action", out var ao) || ao is not D action) throw new ArgumentException("eventFromPCActn: action must be an object");
        var e = new D();
        if (at != null) e["at"] = N(at.Value);
        else if (p.TryGetValue("iat", out var iat)) e["at"] = iat;
        e["agent"] = leaf != null && leaf.TryGetValue("holder", out var h) && h != null ? h : "unknown";
        if (action.TryGetValue("verb", out var verb)) e["verb"] = verb;
        if (action.TryGetValue("resource", out var res)) e["resource"] = res;
        e["outcome"] = outcome;
        if (p.TryGetValue("risk_claim", out var rc) && rc is D rcm && rcm.TryGetValue("r", out var r)) e["r"] = r;
        if (p.TryGetValue("provenance", out var pv) && pv is D pvm && pvm.TryGetValue("taint_level", out var tl)) e["taint"] = tl;
        e["digest"] = Pca.HashCanonical(p);
        return e;
    }

    static bool Usable(object? o) => o is D e && IntentJs.IsFinite(Opt(e, "at")) && Opt(e, "agent") is string { Length: > 0 };

    // JavaScript `acc += r`: a string (or an object / array, which prints as one) turns the sum into text, anything else adds as a number
    static object JsAdd(object acc, object? r)
    {
        if (acc is string || r is string || r is D || r is L) return JsX.Str(acc) + JsX.Str(r);
        var a = acc is double d ? d : Dv(acc);
        return a + (r is bool b ? (b ? 1.0 : 0.0) : IntentJs.NumOf(r) ?? double.NaN);
    }

    /// <summary>Project events into the console view <c>{agents, totals, window: {from, to}, dropped}</c>, the most threatened agent first (then the most recently seen).
    /// An event with no finite time or no agent id cannot be placed in a timeline or attributed: it is counted in <c>dropped</c>, not guessed.</summary>
    public static D BuildConsole(object? eventsIn)
    {
        if (eventsIn is not L all) throw new ArgumentException("buildConsole: events must be a list");
        var events = all.Where(Usable).Select(e => (D)e!).ToList();
        var dropped = all.Count - events.Count;
        var order = new List<string>();
        var byAgent = new Dictionary<string, List<D>>();
        foreach (var e in events)
        {
            var id = (string)e["agent"]!;
            if (!byAgent.TryGetValue(id, out var list)) { byAgent[id] = list = new(); order.Add(id); }
            list.Add(e);
        }

        var agents = new List<D>();
        foreach (var id in order)
        {
            var sorted = byAgent[id].OrderBy(e => e, Comparer<D>.Create((a, b) => Cmp(Dv(a["at"]) - Dv(b["at"])))).ToList();
            var immune = Immune.InitialState();
            long autos = 0, stepUps = 0, denies = 0, executed = 0;
            object totalRisk = 0.0;
            foreach (var e in sorted)
            {
                var ro = Opt(e, "r");
                object r = ro ?? N(0L);
                totalRisk = JsAdd(totalRisk, r);
                switch (Opt(e, "outcome") as string)
                {
                    case "auto": autos++; break;
                    case "step_up": stepUps++; break;
                    case "deny": denies++; break;
                    case "executed": executed++; break;
                }
                immune = Immune.Observe(immune, new D { ["r"] = r, ["at"] = e["at"], ["stepUp"] = Opt(e, "outcome") as string == "step_up", ["denied"] = Opt(e, "outcome") as string == "deny" });
            }
            agents.Add(new D
            {
                ["agent"] = id, ["actions"] = N((long)sorted.Count), ["autos"] = N(autos), ["stepUps"] = N(stepUps), ["denies"] = N(denies), ["executed"] = N(executed),
                ["totalRisk"] = totalRisk is double t ? N(t) : totalRisk, ["firstSeen"] = sorted[0]["at"], ["lastSeen"] = sorted[^1]["at"], ["threat"] = Immune.Assess(immune),
            });
        }
        // a stable order: the highest threat score first, then the latest sighting
        var ordered = agents.OrderBy(a => a, Comparer<D>.Create((x, y) =>
        {
            var ds = Cmp(Dv(((D)y["threat"]!)["score"]) - Dv(((D)x["threat"]!)["score"]));
            return ds != 0 ? ds : Cmp(Dv(y["lastSeen"]) - Dv(x["lastSeen"]));
        })).ToList();

        long ta = 0, tau = 0, ts = 0, td = 0, te = 0;
        foreach (var a in ordered)
        {
            ta += (long)Dv(a["actions"]); tau += (long)Dv(a["autos"]); ts += (long)Dv(a["stepUps"]); td += (long)Dv(a["denies"]); te += (long)Dv(a["executed"]);
        }
        double from = 0, to = 0;
        if (events.Count > 0)
        {
            from = double.PositiveInfinity; to = double.NegativeInfinity;
            foreach (var e in events) { from = Math.Min(from, Dv(e["at"])); to = Math.Max(to, Dv(e["at"])); }
        }
        return new D
        {
            ["agents"] = new L(ordered), ["totals"] = new D { ["actions"] = N(ta), ["autos"] = N(tau), ["stepUps"] = N(ts), ["denies"] = N(td), ["executed"] = N(te) },
            ["window"] = new D { ["from"] = N(from), ["to"] = N(to) }, ["dropped"] = N((long)dropped),
        };
    }

    /// <summary>The agents whose current threat read is not calm (the console's anomalies panel).</summary>
    public static L Anomalies(D view) =>
        new(((L)view["agents"]!).Where(a => ((D)((D)a!)["threat"]!)["level"] is not "calm"));

    // ---- freeze (the kill switch) ----

    /// <summary>The empty freeze set <c>{frozen: []}</c>.</summary>
    public static D EmptyFreeze() => new() { ["frozen"] = new L() };

    // JavaScript Array.prototype.includes / String.prototype.includes of the set's `frozen` member (a string includes by substring)
    static bool Includes(object? set, object? agent)
    {
        if (set is not D m || !m.TryGetValue("frozen", out var f)) throw new InvalidOperationException("TypeError: freeze set has no frozen member");
        return f switch
        {
            L l => l.Any(x => JsX.StrictEq(x, agent)),
            string s => agent is string a && s.Contains(a, StringComparison.Ordinal),
            _ => throw new InvalidOperationException("TypeError: frozen.includes is not a function"),
        };
    }

    /// <summary>Freeze an agent: the set with the id added, sorted as JavaScript's default sort does (by the text of each member, UTF-16 order); the same set when the
    /// agent is already frozen. Throws on an agent that is not a non-empty string and on a malformed set.</summary>
    public static object? FreezeAgent(object? set, object? agent)
    {
        if (agent is not string { Length: > 0 } id) throw new ArgumentException("freezeAgent: agent must be a non-empty string");
        if (Includes(set, id)) return set;
        var f = ((D)set!)["frozen"];
        var members = new L();
        if (f is L l) members.AddRange(l);
        else foreach (var r in ((string)f!).EnumerateRunes()) members.Add(r.ToString()); // [...string] spreads by code point
        members.Add(id);
        return new D { ["frozen"] = new L(members.OrderBy(x => JsX.Str(x), StringComparer.Ordinal)) };
    }

    /// <summary>The set without the agent. Throws on a malformed set.</summary>
    public static D UnfreezeAgent(object? set, object? agent)
    {
        if (set is not D m || !m.TryGetValue("frozen", out var f) || f is not L l) throw new InvalidOperationException("TypeError: set.frozen.filter is not a function");
        return new D { ["frozen"] = new L(l.Where(x => !JsX.StrictEq(x, agent))) };
    }

    /// <summary>Whether an agent is frozen. Fails closed: an agent with no usable id, or a malformed set, counts as frozen.</summary>
    public static bool IsFrozen(object? set, object? agent)
    {
        if (agent is not string { Length: > 0 } id || set is not D m || !m.TryGetValue("frozen", out var f) || f is not L l) return true;
        return l.Any(x => JsX.StrictEq(x, id));
    }
}

/// <summary>A multi-agent session: <c>Members</c> is the root first, then each added sub-agent in delegation order; <c>GoalCommit</c> the shared signed goal commitment
/// (from the root grant), "" when the grant carries none.</summary>
public sealed class AgentSession
{
    /// <summary>Deepest delegation chain a session accepts.</summary>
    public const int MaxDepth = 32;

    public AgentHandle? Root { get; }
    public IReadOnlyList<AgentHandle> Members { get; }
    public string GoalCommit { get; }

    public AgentSession(AgentHandle? root, IEnumerable<AgentHandle> members, string goalCommit)
    {
        Root = root; Members = members.ToList(); GoalCommit = goalCommit;
    }

    static string GoalOf(AgentHandle h) => Pca.ReadEnvelope(h.Grant) is { } env && env.GetValueOrDefault("goal_commit") is string s ? s : "";

    /// <summary>Start a session from a root agent.</summary>
    public static AgentSession Start(AgentHandle root) => new(root, new[] { root }, GoalOf(root));

    /// <summary>Add a sub-agent: one attenuated delegation hop under the session's current leaf. Throws past <see cref="MaxDepth"/> hops.</summary>
    public static (AgentSession Session, AgentHandle Member) AddMember(AgentSession session, SuiteKey? holder = null, L? addedCaveats = null)
    {
        if (session.Members.Count > MaxDepth) throw new ArgumentOutOfRangeException(nameof(session), $"addMember: a session is limited to {MaxDepth} delegation hops");
        var member = session.Members[^1].SubAgent(holder, addedCaveats);
        return (new AgentSession(session.Root, session.Members.Append(member), session.GoalCommit), member);
    }

    /// <summary>The holder ids (base64url public keys) of every agent in the session.</summary>
    public static L Agents(AgentSession session) => new(session.Members.Select(m => (object?)m.Holder.Ed!.Id));

    /// <summary>A console view scoped to just this session's agents. Throws on a null event or a list that is not one.</summary>
    public static D ConsoleOf(AgentSession session, object? events)
    {
        if (events is not L list) throw new InvalidOperationException("TypeError: events.filter is not a function");
        var ids = Agents(session).Cast<string>().ToHashSet(StringComparer.Ordinal);
        var mine = new L();
        foreach (var e in list)
        {
            if (e == null) throw new InvalidOperationException("TypeError: cannot read properties of null (reading 'agent')");
            if (e is D m && m.GetValueOrDefault("agent") is string a && ids.Contains(a)) mine.Add(e);
        }
        return AgentConsole.BuildConsole(mine);
    }

    /// <summary>True iff every member shares the root's goal commitment (a well-formed team). A root without a readable envelope has no goal commitment (""), and
    /// members that all lack one do not share a goal: false.</summary>
    public static bool SharesGoal(AgentSession session) => session.GoalCommit != "" && session.Members.All(m => GoalOf(m) == session.GoalCommit);

    /// <summary>Depth of the delegation tree (0 = root only).</summary>
    public static int Depth(AgentSession session) => session.Members.Count - 1;
}
