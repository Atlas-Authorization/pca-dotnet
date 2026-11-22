// Proof of progress toward a committed intent. Authority = faithful pursuit of a committed intent: at grant time the goal (objective, potential id, embedder id, metric, epsilon, exploration
// budget) is hashed into a commitment, and each action then carries a step proof that either makes PROGRESS (potential(after) <= potential(before) - epsilon) or is EXPLORATION (it does not,
// and the shortfall is charged to a bounded exploration budget). A verifier recomputes the potential from the committed id and the carried states; nothing the prover says about potentials is
// trusted. Strict invariant: the sum of exploration charges is at most the budget.
//
// Every step commits, inside one hash-chained body, to the goal commitment, the action digest, a before-STATE digest and an after-STATE digest, the sequence number and the previous step; a step
// can be Ed25519-signed (domain-separated) by the acting holder. The descent proof is only as honest as the states it is computed over: a StateSource observes the real post-action state, and an
// AttestedStateSource signs that observation. All quantities are safe integers so recomputation is bit-exact across implementations. Negative authority composes through the step guard: descent can
// never buy an action a guard forbids, and exploration is capped by the budget.
//
// Goals, states, steps and signed steps are JSON trees (Dictionary<string, object?>, List<object?>, string, bool, Num). The digests here are the STRICT canonical hash (the wire form): a state with a
// non-integer of more than 15 significant digits, a negative zero or a lone surrogate has no digest. Never ported: the reference's legacy option that accepts a PQ state attestation without a pinned key.
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>A step proof the verifier refuses, with the denial it maps to.</summary>
public sealed class ProgressError : Exception
{
    public string Code { get; }
    public ProgressError(string code, string message) : base(message) { Code = code; }
}

/// <summary>A registered potential: the function (objective, state to a non-negative safe integer; it may return anything and throw, the caller checks) and the embedder id it is bound to ('' = none).</summary>
public sealed record PotentialSpec(Func<object?, object?, object?> Fn, string Embedder);

/// <summary>Verifier-held registry of version-pinned potentials. Ids are immutable once registered, an id that is not registered fails closed, and the registry can be frozen.</summary>
public sealed class PotentialRegistry
{
    readonly Dictionary<string, PotentialSpec> _m = new(StringComparer.Ordinal);
    bool _frozen;

    /// <summary>Registers <paramref name="fn"/> under <paramref name="id"/> (1..128 UTF-16 units); a registered id cannot be registered again.</summary>
    public PotentialRegistry Register(string id, Func<object?, object?, object?> fn, string embedder = "")
    {
        if (_frozen) throw new InvalidOperationException("registry is frozen");
        if (id == null || id.Length == 0 || id.Length > 128) throw new ArgumentException("potential id: 1..128 chars");
        if (fn == null) throw new ArgumentException("potential must be a function");
        if (embedder == null) throw new ArgumentException("embedder must be a string");
        if (_m.ContainsKey(id)) throw new InvalidOperationException($"potential {id} already registered");
        _m[id] = new PotentialSpec(fn, embedder);
        return this;
    }

    public PotentialSpec? Get(string id) => _m.GetValueOrDefault(id);
    public bool Has(string id) => _m.ContainsKey(id);

    /// <summary>The registered ids, sorted by UTF-16 code units.</summary>
    public List<string> Ids() { var l = _m.Keys.ToList(); l.Sort(StringComparer.Ordinal); return l; }

    public PotentialRegistry Freeze() { _frozen = true; return this; }

    /// <summary>A registry built from a record of potentials (registered in the order given).</summary>
    public static PotentialRegistry From(IEnumerable<KeyValuePair<string, PotentialSpec>> rec)
    {
        var r = new PotentialRegistry();
        foreach (var (k, v) in rec) r.Register(k, v.Fn, v.Embedder);
        return r;
    }

    /// <summary>A fresh, mutable registry holding the three built-in potentials.</summary>
    public static PotentialRegistry Defaults() => new PotentialRegistry()
        .Register("l1-feature-v1", Progress.L1FeaturePotential).Register("dag-remaining-v1", Progress.DagRemainingPotential).Register("dag-weighted-v1", Progress.DagWeightedPotential);
}

/// <summary>The trust boundary. A production source observes the REAL effect of an action and attests to it (a resource-server receipt, an attested executor, a TEE quote, a zk proof). The progress module commits
/// to what the source returns; it cannot establish the source's honesty.</summary>
public interface IStateSource
{
    string Id { get; }

    /// <summary>Observes the world after the action: <c>{state, state_digest, source, evidence?}</c> for the request <c>{action_digest, goal_commitment, prior_digest}</c>. May throw.</summary>
    D? Observe(D request);
}

/// <summary>An in-memory source for tests and demos: the world is a value the caller changes with <see cref="Apply"/>.</summary>
public sealed class InMemoryStateSource : IStateSource
{
    object? _cur;
    int _n;
    public string Id { get; }
    public List<D> Requests { get; } = new();

    public InMemoryStateSource(object? initial, string id = "in-memory") { _cur = Progress.Snapshot(initial); Id = id; }

    public void Apply(object? next) => _cur = Progress.Snapshot(next);

    public D? Observe(D request)
    {
        Requests.Add(request);
        var state = Progress.Snapshot(_cur);
        return new D
        {
            ["state"] = state, ["state_digest"] = Progress.StateDigest(state), ["source"] = Id,
            ["evidence"] = new D { ["kind"] = "in-memory", ["n"] = IntentJs.OfLong(_n++), ["prior"] = request.GetValueOrDefault("prior_digest"), ["action"] = request.GetValueOrDefault("action_digest") },
        };
    }
}

/// <summary>A source whose observations carry a VERIFIABLE SIGNED attestation: for each observation it signs "<c>state_digest</c> is the state after <c>action_digest</c> applied to <c>prior_digest</c>, for this goal,
/// observed by me" with the suite signing machinery. Pair it with <see cref="Progress.AttestedStateVerifier"/> and <c>trustedStateSources</c> to enforce that every step's post-state was attested by a trusted source.</summary>
public sealed class AttestedStateSource : IStateSource
{
    readonly byte[] _secret;
    readonly Func<D, object?> _observe;
    readonly object? _alg;
    readonly SuiteSecretKeys? _suite;
    readonly string? _pqPk;
    readonly List<D> _attestations = new();

    public string Id { get; }
    /// <summary>The source's base64url Ed25519 public key: register it in the verifier's trusted-key map.</summary>
    public string PublicKey { get; }

    /// <param name="signerSecret">The source's Ed25519 seed (signs each attestation).</param>
    /// <param name="observeState">Observes the REAL post-action state for a request.</param>
    /// <param name="alg">The signature suite (default ed25519); for a PQ or hybrid suite pass the source's PQ keys in <paramref name="suite"/>.</param>
    public AttestedStateSource(string id, byte[] signerSecret, Func<D, object?> observeState, string? alg = null, SuiteSecretKeys? suite = null)
    {
        if (string.IsNullOrEmpty(id)) throw new ArgumentException("AttestedStateSource: id is required");
        if (signerSecret == null) throw new ArgumentException("AttestedStateSource: signerSecret must be a Uint8Array");
        if (observeState == null) throw new ArgumentException("AttestedStateSource: observeState must be a function");
        if (alg != null && IntentJs.SuiteOf(alg, true) == null) throw new ArgumentException($"AttestedStateSource: unknown signature alg '{alg}'");
        Id = id; _secret = signerSecret; _observe = observeState; _alg = alg; _suite = suite;
        using (var k = EdKey.FromSeed(signerSecret)) PublicKey = k.Id;
        _pqPk = PqSuites.SuitePqPublicKey(alg, PqSuites.SuiteKeysOf(signerSecret, suite));
    }

    /// <summary>The signed attestations emitted so far (hand these to the verifier).</summary>
    public List<D> Attestations => _attestations.ToList();

    public D? Observe(D request)
    {
        var state = Progress.Snapshot(_observe(request));
        var digest = Progress.StateDigest(state);
        var stmt = new D
        {
            ["source"] = Id, ["goal_commitment"] = request.GetValueOrDefault("goal_commitment"), ["action_digest"] = request.GetValueOrDefault("action_digest"),
            ["prior_digest"] = request.GetValueOrDefault("prior_digest"), ["state_digest"] = digest,
        };
        var fields = PqSuites.SignSuiteArtifact(_alg, PqSuites.SuiteKeysOf(_secret, _suite), Progress.StateAttestationMessage(stmt, _alg, _pqPk));
        var attestation = new D(stmt) { ["sig"] = fields.Sig };
        if (fields.Alg != null) attestation["alg"] = fields.Alg;
        if (fields.PqPk != null) attestation["pq_pk"] = fields.PqPk;
        if (fields.PqSig != null) attestation["pq_sig"] = fields.PqSig;
        _attestations.Add(attestation);
        return new D { ["state"] = state, ["state_digest"] = digest, ["source"] = Id, ["evidence"] = attestation };
    }
}

/// <summary>A stateful tracker of one trajectory: it holds the last state, the chain head and the exploration spent. A step that would push the spent total over the budget is REFUSED (no proof is produced, the
/// state does not advance), which is the "forces step-up / denial" mechanism. In-process: concurrent agents sharing a goal need atomic escrow.</summary>
public sealed class ProgressTracker
{
    int _seq;
    string _head = Progress.Genesis;
    double _spent;
    object? _cur;
    string _curDigest;
    readonly List<D> _log = new();
    readonly PotentialRegistry _reg;
    readonly Func<D, object?>? _guard;

    /// <summary>A detached snapshot of the committed goal.</summary>
    public D Goal { get; }
    public string Commitment { get; }

    /// <summary>Throws when the goal does not hash to <paramref name="commitment"/>, or the registry cannot resolve the potential, or the potential rejects the initial state.</summary>
    /// <param name="guard">The negative-authority check applied to every transition: it returns true to ALLOW; throwing or anything but true denies.</param>
    public ProgressTracker(object? goal, string commitment, object? initial, PotentialRegistry? registry = null, Func<D, object?>? guard = null)
    {
        if (!Progress.VerifyGoalCommitment(goal, commitment)) throw new InvalidOperationException("goal does not match commitment");
        Goal = (D)Progress.Snapshot(goal)!;
        Commitment = commitment;
        _reg = registry ?? Progress.DefaultPotentials;
        _cur = Progress.Snapshot(initial);
        _curDigest = Progress.StateDigest(_cur);
        _guard = guard;
        Progress.PotentialOf(Goal, _reg, _cur); // fail fast: unknown id / embedder / bad initial state
    }

    /// <summary>The total exploration charged so far (always at most the budget).</summary>
    public double Spent => _spent;
    public double Remaining => Dv(Goal["explorationBudget"]) - _spent;
    public object? State => _cur;
    public string CurrentStateDigest => _curDigest;
    /// <summary>Whether the potential of the current state is 0. Throws when the potential cannot be computed.</summary>
    public bool Reached => Progress.PotentialOf(Goal, _reg, _cur) == 0;
    /// <summary>The proofs issued so far (a copy).</summary>
    public List<D> Steps => _log.ToList();

    static double Dv(object? x) => IntentJs.NumOf(x)!.Value;

    /// <summary>Attempts a step to a self-reported <paramref name="after"/>; the state does not advance on denial. <c>{ok: true, step, spent, remaining}</c> or <c>{ok: false, reason, stepUp}</c>.</summary>
    public D Step(object? after, object? actionDigest) => Advance(after, actionDigest, "", "");

    /// <summary>Observes the post-action state from a trusted source and steps to it: the observation's digest and source id are checked, and the source id and evidence digest are committed into the step.
    /// Does not advance on any denial; any fault of the source is <c>state-source-mismatch</c>.</summary>
    public D StepObserved(IStateSource source, object? actionDigest)
    {
        try
        {
            var obs = source.Observe(new D { ["action_digest"] = actionDigest, ["goal_commitment"] = Commitment, ["prior_digest"] = _curDigest });
            if (obs == null || !(obs.GetValueOrDefault("source") is string s && s == source.Id) || !(obs.GetValueOrDefault("state_digest") is string d && d == Progress.StateDigest(obs.GetValueOrDefault("state"))))
                return Denied("state-source-mismatch", false);
            return Advance(obs.GetValueOrDefault("state"), actionDigest, source.Id, Progress.EvidenceDigest(obs.GetValueOrDefault("evidence")));
        }
        catch (Exception) { return Denied("state-source-mismatch", false); }
    }

    static D Denied(string reason, bool stepUp) => new() { ["ok"] = false, ["reason"] = reason, ["stepUp"] = stepUp };

    D Advance(object? afterIn, object? actionDigest, string stateSource, string evidenceDigest)
    {
        if (actionDigest is not string { Length: > 0 }) return Denied("malformed", false);
        object? after; string afterDigest; double pb, pa; (string Mode, double Charge) cls;
        try
        {
            after = Progress.Snapshot(afterIn);
            afterDigest = Progress.StateDigest(after);
            pb = Progress.PotentialOf(Goal, _reg, _cur);
            pa = Progress.PotentialOf(Goal, _reg, after);
            cls = Progress.Classify(pb, pa, Dv(Goal["epsilon"]));
        }
        catch (Exception e) { return Denied(Progress.DenialOf(e), false); }
        if (_guard != null && !Progress.RunGuard(_guard, new D { ["seq"] = IntentJs.OfLong(_seq), ["before"] = _cur, ["after"] = after, ["action_digest"] = actionDigest })) return Denied("prohibited", false);
        var nextSpent = _spent + cls.Charge;
        if (!IntentJs.IsSafeInteger(Jx.NumOut(nextSpent)) || nextSpent > Dv(Goal["explorationBudget"])) return Denied("exploration-exhausted", true);
        var body = new D
        {
            ["goal_commitment"] = Commitment, ["seq"] = IntentJs.OfLong(_seq), ["before"] = _cur, ["after"] = after, ["before_digest"] = _curDigest, ["after_digest"] = afterDigest,
            ["action_digest"] = actionDigest, ["mode"] = cls.Mode, ["potential_before"] = Progress.Int(pb), ["potential_after"] = Progress.Int(pa), ["charge"] = Progress.Int(cls.Charge),
            ["state_source"] = stateSource, ["evidence_digest"] = evidenceDigest, ["prev"] = _head,
        };
        var step = new D(body) { ["digest"] = Progress.StepBodyDigest(body) };
        _log.Add(step);
        _seq++;
        _head = (string)step["digest"]!;
        _spent = nextSpent;
        _cur = after;
        _curDigest = afterDigest;
        return new D { ["ok"] = true, ["step"] = step, ["spent"] = Progress.Int(_spent), ["remaining"] = Progress.Int(Remaining) };
    }
}

public static class Progress
{
    /// <summary>The wire / commitment format version of goals, steps and signed proofs.</summary>
    public const int Version = 2;
    /// <summary>The domain separator of the Ed25519 signature over a progress step.</summary>
    public const string SigDomain = "atlas-pca/progress-step/v2";
    /// <summary>The domain-separated tag of a trajectory-head anchor leaf.</summary>
    public const string AnchorDomain = "atlas-pca/trajectory-anchor/v1";
    /// <summary>The domain-separated tag of a signed state attestation (it ends in one NUL byte).</summary>
    public const string StateAttestationDomain = "atlas-pca/progress-state-attestation/v1\0";
    public const string Genesis = "genesis";

    /// <summary>The frozen registry of the built-in potentials, used when none is supplied.</summary>
    public static PotentialRegistry DefaultPotentials { get; } = PotentialRegistry.Defaults().Freeze();

    // ---- JavaScript value rules ----

    static object? Member(object? o, string k) => ObjectiveRisk.Member(o, k);
    static bool IsObj(object? x) => x is D;
    static bool IsStr(object? x) => x is string;
    static object? Opt(object? o, string k) => Jx.Opt(o, k);

    internal static object Int(double d) => IntentJs.OfLong((long)d);

    static void AssertInt(object? n, string what)
    {
        if (!(Jx.IsNum(n) && IntentJs.IsSafeInteger(n))) throw new InvalidOperationException($"{what}: safe integer required");
    }

    // a JavaScript Set: SameValueZero identity (a string and a number with the same text are different; objects are by reference)
    sealed class SameValueZero : IEqualityComparer<object?>
    {
        public new bool Equals(object? a, object? b)
        {
            if (ReferenceEquals(a, b)) return true;
            if (Jx.IsNum(a) && Jx.IsNum(b)) { var x = IntentJs.NumOf(a)!.Value; var y = IntentJs.NumOf(b)!.Value; return x == y || (double.IsNaN(x) && double.IsNaN(y)); }
            return !(a is D || a is L) && JsX.StrictEq(a, b);
        }
        public int GetHashCode(object? o)
        {
            if (o == null) return 0;
            if (o is string s) return s.GetHashCode();
            if (o is bool b) return b ? 1 : 2;
            if (o is D || o is L) return RuntimeHelpers.GetHashCode(o);
            if (Jx.IsNum(o))
            {
                var x = IntentJs.NumOf(o)!.Value;
                return double.IsNaN(x) ? 7 : (x == 0 ? 0.0 : x).GetHashCode();
            }
            return 3;
        }
    }

    static HashSet<object?> NewSet() => new(new SameValueZero());

    /// <summary>A deep, canonical, detached copy of a value, so a later change by the caller cannot desynchronize a proof (the lenient canonical form, parsed again).</summary>
    internal static object? Snapshot(object? v) => Pca.ParseJson(ObjectiveRisk.Canon(v));

    // ---- potentials ----

    /// <summary>L1 distance in a committed feature space: objective <c>{target: int[]}</c>, state <c>{x: int[]}</c>; equal lengths, safe integers, the running sum checked for overflow. Throws on anything else.</summary>
    public static object? L1FeaturePotential(object? objective, object? state)
    {
        var t = Opt(objective, "target");
        var x = Opt(state, "x");
        if (t is not L tl || x is not L xl || tl.Count != xl.Count) throw new InvalidOperationException("l1-feature-v1: bad shape");
        double d = 0;
        for (int i = 0; i < tl.Count; i++)
        {
            AssertInt(tl[i], "target");
            AssertInt(xl[i], "x");
            d += Math.Abs(IntentJs.NumOf(tl[i])!.Value - IntentJs.NumOf(xl[i])!.Value);
            AssertInt(Jx.NumOut(d), "distance");
        }
        return d;
    }

    /// <summary>Task-set remaining work: objective <c>{tasks: [{id, cost}]}</c> (unique ids, costs non-negative safe integers), state <c>{done: [id]}</c> (known ids); the sum of the costs not done.</summary>
    public static object? DagRemainingPotential(object? objective, object? state)
    {
        var tasks = Opt(objective, "tasks");
        var done = Opt(state, "done");
        if (tasks is not L tl || done is not L dl) throw new InvalidOperationException("dag-remaining-v1: bad shape");
        var ids = NewSet();
        foreach (var t in tl) ids.Add(Jx.Prop(t, "id"));
        if (ids.Count != tl.Count) throw new InvalidOperationException("dag-remaining-v1: duplicate task id");
        var doneSet = NewSet();
        foreach (var d in dl) doneSet.Add(d);
        foreach (var d in doneSet) if (!ids.Contains(d)) throw new InvalidOperationException($"dag-remaining-v1: unknown task {JsX.Str(d)}");
        double rem = 0;
        foreach (var t in tl)
        {
            var cost = Opt(t, "cost");
            AssertInt(cost, "cost");
            if (IntentJs.NumOf(cost)! < 0) throw new InvalidOperationException("negative cost");
            if (!doneSet.Contains(Jx.Prop(t, "id"))) rem += IntentJs.NumOf(cost)!.Value;
            AssertInt(Jx.NumOut(rem), "remaining");
        }
        return rem;
    }

    /// <summary>Weighted-DAG remaining cost with dependency integrity: objective <c>{tasks: [{id, cost >= 0, deps?: [id]}]}</c> (ids unique and non-empty, dependencies known, the graph acyclic), state <c>{done: [id]}</c>
    /// (unique, and DEPENDENCY-CLOSED: a task may be done only if all its dependencies are, so the remaining cost cannot be cheaply gamed by out-of-order claims). The sum of the costs not done.</summary>
    public static object? DagWeightedPotential(object? objective, object? state)
    {
        var tasks = Opt(objective, "tasks");
        var done = Opt(state, "done");
        if (tasks is not L tl || done is not L dl) throw new InvalidOperationException("dag-weighted-v1: bad shape");
        var order = new List<string>();
        var cost = new Dictionary<string, double>(StringComparer.Ordinal);
        var deps = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var t in tl)
        {
            if (!IsObj(t) || Member(t, "id") is not string { Length: > 0 } id) throw new InvalidOperationException("dag-weighted-v1: bad task");
            if (cost.ContainsKey(id)) throw new InvalidOperationException("dag-weighted-v1: duplicate task id");
            var c = Member(t, "cost");
            AssertInt(c, "cost");
            if (IntentJs.NumOf(c)! < 0) throw new InvalidOperationException("negative cost");
            var dv = Member(t, "deps");
            if (dv == null || Jx.IsUndef(dv)) dv = new L();
            if (dv is not L dlist || !dlist.All(IsStr)) throw new InvalidOperationException("dag-weighted-v1: bad deps");
            order.Add(id);
            cost[id] = IntentJs.NumOf(c)!.Value;
            deps[id] = dlist.Cast<string>().ToList();
        }
        // dependencies must exist, and the graph must be acyclic (Kahn)
        var indeg = new Dictionary<string, int>(StringComparer.Ordinal);
        var rev = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var id in order)
        {
            var set = deps[id].Distinct(StringComparer.Ordinal).ToList();
            indeg[id] = set.Count;
            foreach (var d in set)
            {
                if (d == id || !cost.ContainsKey(d)) throw new InvalidOperationException($"dag-weighted-v1: bad dependency {d}");
                if (!rev.TryGetValue(d, out var r)) rev[d] = r = new List<string>();
                r.Add(id);
            }
        }
        var q = order.Where(id => indeg[id] == 0).ToList();
        int seen = 0;
        while (q.Count > 0)
        {
            var id = q[^1];
            q.RemoveAt(q.Count - 1);
            seen++;
            if (rev.TryGetValue(id, out var next))
                foreach (var n in next)
                {
                    var k = indeg[n] - 1;
                    indeg[n] = k;
                    if (k == 0) q.Add(n);
                }
        }
        if (seen != order.Count) throw new InvalidOperationException("dag-weighted-v1: cycle");
        var doneSet = new HashSet<string>(StringComparer.Ordinal);
        foreach (var d in dl)
        {
            if (d is not string ds || !cost.ContainsKey(ds)) throw new InvalidOperationException($"dag-weighted-v1: unknown task {JsX.Str(d)}");
            if (!doneSet.Add(ds)) throw new InvalidOperationException("dag-weighted-v1: duplicate done");
        }
        foreach (var d in doneSet)
            foreach (var dep in deps[d])
                if (!doneSet.Contains(dep)) throw new InvalidOperationException($"dag-weighted-v1: {d} done before dependency {dep}");
        double rem = 0;
        foreach (var id in order)
        {
            if (!doneSet.Contains(id)) rem += cost[id];
            AssertInt(Jx.NumOut(rem), "remaining");
        }
        return rem;
    }

    // ---- goal commitment ----

    static void ValidateGoal(object? goal)
    {
        if (!IsObj(goal)) throw new InvalidOperationException("goal must be an object");
        var eps = Member(goal, "epsilon");
        var budget = Member(goal, "explorationBudget");
        AssertInt(eps, "epsilon");
        AssertInt(budget, "explorationBudget");
        if (IntentJs.NumOf(eps)! < 1) throw new InvalidOperationException("epsilon must be >= 1");
        if (IntentJs.NumOf(budget)! < 0) throw new InvalidOperationException("explorationBudget must be >= 0");
        if (Member(goal, "potential") is not string { Length: > 0 }) throw new InvalidOperationException("potential id required");
        if (!IsStr(Member(goal, "metric"))) throw new InvalidOperationException("metric must be a string");
        var emb = Member(goal, "embedder");
        if (!Jx.IsUndef(emb) && !IsStr(emb)) throw new InvalidOperationException("embedder must be a string");
    }

    /// <summary>The commitment hash of a goal <c>{objective, potential, embedder?, metric, epsilon >= 1, explorationBudget >= 0}</c>: it binds the objective, the potential id, the embedder (absent and "" are the same),
    /// the metric, epsilon and the budget. Throws on an invalid goal.</summary>
    public static string GoalDigest(object? goal)
    {
        ValidateGoal(goal);
        var emb = Member(goal, "embedder");
        return Pca.HashCanonical(new D
        {
            ["t"] = "pca-goal", ["v"] = IntentJs.OfLong(Version), ["objective"] = Member(goal, "objective"), ["potential"] = Member(goal, "potential"),
            ["embedder"] = emb == null || Jx.IsUndef(emb) ? "" : emb, ["metric"] = Member(goal, "metric"), ["epsilon"] = Member(goal, "epsilon"), ["explorationBudget"] = Member(goal, "explorationBudget"),
        });
    }

    /// <summary>Commits a goal: <c>{goal (a detached canonical snapshot), commitment}</c>.</summary>
    public static D CommitGoal(object? goal)
    {
        var c = GoalDigest(goal);
        return new D { ["goal"] = Snapshot(goal), ["commitment"] = c };
    }

    /// <summary>A goal is bound iff it hashes to the commitment the grant carries. Never throws.</summary>
    public static bool VerifyGoalCommitment(object? goal, object? commitment)
    {
        try { return commitment is string c && GoalDigest(goal) == c; }
        catch (Exception) { return false; }
    }

    // ---- steps ----

    /// <summary>The digest of a step body (a step without its <c>digest</c>): the strict hash of <c>{t: "pca-progress-step", v: 2, ...body}</c>.</summary>
    internal static string StepBodyDigest(D body)
    {
        var o = new D { ["t"] = "pca-progress-step", ["v"] = IntentJs.OfLong(Version) };
        foreach (var (k, v) in body) o[k] = v;
        return Pca.HashCanonical(o);
    }

    /// <summary>The digest committing to a state (the state must be canonicalizable JSON in the strict profile).</summary>
    public static string StateDigest(object? state) => Pca.HashCanonical(new D { ["t"] = "pca-state", ["state"] = state });

    /// <summary>The digest of a step's evidence as the step commits to it: the strict hash of <c>{t: "pca-evidence", e: evidence ?? null}</c>.</summary>
    internal static string EvidenceDigest(object? evidence) => Pca.HashCanonical(new D { ["t"] = "pca-evidence", ["e"] = evidence == null || Jx.IsUndef(evidence) ? null : evidence });

    /// <summary>The trajectory head to publish or anchor: the digest of the last step, <c>genesis</c> when there are none.</summary>
    public static object? TrajectoryHead(L steps) => steps.Count > 0 ? Jx.Prop(steps[^1], "digest") : Genesis;

    /// <summary>The digest to place in a PCActn binding the proof to the action: the step's own digest.</summary>
    public static object? ProgressStepDigest(object? step) => Jx.Prop(step, "digest");

    // ---- anchoring the trajectory head into the transparency ledger ----

    /// <summary>The salted commitment of a trajectory head: the opaque leaf appended to the transparency ledger. Throws unless both are non-empty strings.</summary>
    public static string TrajectoryAnchorCommit(object? salt, object? head)
    {
        if (salt is not string { Length: > 0 } || head is not string { Length: > 0 }) throw new ArgumentException("trajectoryAnchorCommit: salt and head must be non-empty strings");
        return Pca.HashCanonical(new D { ["t"] = AnchorDomain, ["salt"] = salt, ["head"] = head });
    }

    /// <summary>True iff <paramref name="salt"/> and <paramref name="head"/> reproduce the anchored commitment. Never throws.</summary>
    public static bool VerifyTrajectoryAnchor(object? commit, object? salt, object? head)
    {
        try { return commit is string c && TrajectoryAnchorCommit(salt, head) == c; }
        catch (Exception) { return false; }
    }

    /// <summary>Anchors the current trajectory head into <paramref name="ledger"/> as a salted commitment, which makes a later rollback of the trajectory externally detectable: <c>{head, salt, commit, index,
    /// ledgerHead: {size, root}}</c>. The salt (default: 16 random bytes) must be retained to open the anchor later.</summary>
    public static D AnchorTrajectoryHead(TransparencyLedger ledger, L steps, string? salt = null)
    {
        var head = TrajectoryHead(steps);
        var s = salt ?? Pca.B64u(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
        var commit = TrajectoryAnchorCommit(s, head);
        var (index, _) = ledger.AppendCommitment(commit);
        return new D { ["head"] = head, ["salt"] = s, ["commit"] = commit, ["index"] = IntentJs.OfLong(index), ["ledgerHead"] = ledger.Head() };
    }

    // ---- potentials of a goal, mode and charge ----

    static PotentialSpec Resolve(D goal, PotentialRegistry reg)
    {
        var spec = reg.Get((string)goal["potential"]!) ?? throw new ProgressError("unknown-potential", $"unknown potential {goal["potential"]}");
        var ge = goal.TryGetValue("embedder", out var e) && e != null ? (string)e : "";
        if (spec.Embedder != ge) throw new ProgressError("embedder-mismatch", "embedder mismatch");
        return spec;
    }

    /// <summary>The potential of a state under the goal: resolved from the registry (an unknown id, or an embedder that is not the goal's, is refused) and checked to be a non-negative safe integer.</summary>
    internal static double PotentialOf(D goal, PotentialRegistry reg, object? state)
    {
        var spec = Resolve(goal, reg);
        double p;
        try
        {
            var raw = spec.Fn(goal["objective"], state);
            AssertInt(raw, "potential");
            p = IntentJs.NumOf(raw)!.Value;
        }
        catch (Exception e) { throw new ProgressError("bad-potential", e.Message); }
        if (p < 0) throw new ProgressError("bad-potential", "potential must be >= 0");
        return p;
    }

    internal static string DenialOf(Exception e) => e is ProgressError pe ? pe.Code : "bad-potential";

    /// <summary>The single source of truth for mode and charge: with required = before - epsilon, a step is PROGRESS when after &lt;= required, or when it reaches 0 from a positive potential; anything else is
    /// exploration, charged the integer shortfall after - required (at least 1).</summary>
    internal static (string Mode, double Charge) Classify(double pb, double pa, double epsilon)
    {
        var required = pb - epsilon;
        if (pa <= required || (pa == 0 && pb > 0)) return ("progress", 0);
        var charge = pa - required;
        try { AssertInt(Jx.NumOut(charge), "charge"); }
        catch (Exception e) { throw new ProgressError("bad-potential", e.Message); }
        return ("exploration", charge);
    }

    internal static bool RunGuard(Func<D, object?> g, D t)
    {
        try { return g(t) is true; }
        catch (Exception) { return false; }
    }

    // ---- state attestations ----

    internal static byte[] StateAttestationMessage(D a, object? alg, string? pqPk)
    {
        var body = IntentJs.BindSuiteFields(new D
        {
            ["source"] = a.GetValueOrDefault("source"), ["goal_commitment"] = a.GetValueOrDefault("goal_commitment"), ["action_digest"] = a.GetValueOrDefault("action_digest"),
            ["prior_digest"] = a.GetValueOrDefault("prior_digest"), ["state_digest"] = a.GetValueOrDefault("state_digest"),
        }, alg, alg != null, pqPk, pqPk != null);
        return Encoding.UTF8.GetBytes(StateAttestationDomain).Concat(IntentJs.CanonBytes(body)).ToArray();
    }

    /// <summary>Verifies a state attestation's signature under a TRUSTED source public key, bound to its exact statement: a PQ or hybrid attestation only under the PQ key the verifier pins
    /// (<paramref name="pqPins"/>: trusted key to PQ key). An unknown suite, a non-string signature or source and an empty trusted key are false. Never throws.</summary>
    public static bool VerifyStateAttestation(object? att, object? trustedPublicKey, IReadOnlyDictionary<string, string>? pqPins = null)
    {
        try
        {
            if (att is not D a || a.GetValueOrDefault("sig") is not string || a.GetValueOrDefault("source") is not string) return false;
            if (trustedPublicKey is not string { Length: > 0 } key) return false;
            var alg = a.GetValueOrDefault("alg");
            var algPresent = a.ContainsKey("alg");
            if (IntentJs.SuiteOf(alg, algPresent) == null) return false;
            var pqPk = a.GetValueOrDefault("pq_pk");
            var msg = StateAttestationMessage(a, algPresent ? alg : null, a.ContainsKey("pq_pk") ? pqPk as string : null);
            return IntentJs.VerifyPinnedSuite(alg, algPresent, key, pqPk, msg, a["sig"], a.GetValueOrDefault("pq_sig"), pqPins);
        }
        catch (Exception) { return false; }
    }

    static string AttestationKey(object? action, object? prior, object? state) => $"{JsX.Str(action)}\0{JsX.Str(prior)}\0{JsX.Str(state)}";

    /// <summary>Builds the evidence check for a step from <c>{trustedKeys: {source id: trusted Ed25519 key}, pqPins?, attestations: [...]}</c>. For each step it looks up the trusted key of <c>state_source</c> (an
    /// untrusted source fails), finds the attestation of the step's action and before / after digests (none fails), requires the step's <c>evidence_digest</c> to reproduce that very attestation (any
    /// tamper fails), then verifies the attestation's signature under the trusted key. Combine with <c>trustedStateSources</c> so a self-reported or unknown source is refused before this runs.</summary>
    public static Func<D, object?> AttestedStateVerifier(D opts)
    {
        var byKey = new Dictionary<string, D>(StringComparer.Ordinal);
        if (opts.GetValueOrDefault("attestations") is L atts)
            foreach (var ao in atts)
                if (ao is D att && att.GetValueOrDefault("action_digest") is string ad && att.GetValueOrDefault("prior_digest") is string pd && att.GetValueOrDefault("state_digest") is string sd)
                    byKey[AttestationKey(ad, pd, sd)] = att;
        var pins = (opts.GetValueOrDefault("pqPins") as D)?.Where(e => e.Value is string).ToDictionary(e => e.Key, e => (string)e.Value!);
        return step =>
        {
            try
            {
                var source = Member(step, "state_source");
                var keys = opts.GetValueOrDefault("trustedKeys") as D;
                if (keys == null || !keys.TryGetValue(JsX.Str(source), out var pub) || pub is not string { Length: > 0 } pk) return false; // source not trusted
                if (!byKey.TryGetValue(AttestationKey(Member(step, "action_digest"), Member(step, "before_digest"), Member(step, "after_digest")), out var att)) return false;
                if (!JsX.StrictEq(att.GetValueOrDefault("source"), source)) return false; // no attestation for this transition
                // the step must commit to exactly this attestation (the same canonical form the tracker hashed)
                if (!JsX.StrictEq(EvidenceDigestOf(att), Member(step, "evidence_digest"))) return false;
                return VerifyStateAttestation(att, pk, pins);
            }
            catch (Exception) { return false; }
        };
    }

    static string EvidenceDigestOf(D att) => Pca.HashCanonical(new D { ["t"] = "pca-evidence", ["e"] = att });

    // ---- verifier side ----

    static D Fail(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    static bool IsStep(object? s)
    {
        if (s is not D m) return false;
        bool Int_(string k) => m.TryGetValue(k, out var v) && IntentJs.IsSafeInteger(v);
        return m.GetValueOrDefault("goal_commitment") is string && Int_("seq") && IntentJs.NumOf(m["seq"])! >= 0 && m.GetValueOrDefault("before_digest") is string && m.GetValueOrDefault("after_digest") is string
            && m.GetValueOrDefault("action_digest") is string && m.GetValueOrDefault("mode") is "progress" or "exploration" && Int_("potential_before") && Int_("potential_after") && Int_("charge")
            && m.GetValueOrDefault("state_source") is string && m.GetValueOrDefault("evidence_digest") is string && m.GetValueOrDefault("prev") is string && m.GetValueOrDefault("digest") is string
            && m.ContainsKey("before") && m.ContainsKey("after");
    }

    static PotentialRegistry RegistryOf(object? opts) => Member(opts, "registry") is PotentialRegistry r ? r : DefaultPotentials;

    static bool Given(object? v) => !Jx.IsUndef(v);

    /// <summary>The stateless re-check of one step against the committed goal: <c>{ok: true, charge}</c> or <c>{ok: false, reason}</c>. Pure and deterministic, never throws. Nothing the step claims is trusted: the
    /// state digests, both potentials, the mode and the charge are recomputed. The first failure wins, in this order: goal commitment, shape, step goal, expected seq / prev / action / before / after digests, body digest,
    /// state digests, potentials, claimed potentials, mode, charge, trusted state sources, attested state required (the default: a self-reported state is refused unless <c>requireAttestedState</c> is false), the guard, the
    /// attestation hook. <paramref name="opts"/> members: <c>expectedSeq, expectedPrev, expectedActionDigest, expectedBeforeDigest, expectedAfterDigest</c>, <c>registry</c> (a <see cref="PotentialRegistry"/>), <c>guard</c>
    /// (<c>Func&lt;D, object?&gt;</c>, true allows), <c>trustedStateSources</c> (a list), <c>requireAttestedState</c>, <c>attestation</c> (<c>Func&lt;D, object?&gt;</c>, true accepts).</summary>
    public static D VerifyProgressStep(object? goal, object? commitment, object? step, D? opts = null)
    {
        try
        {
            if (!VerifyGoalCommitment(goal, commitment)) return Fail("goal-mismatch");
            if (!IsStep(step)) return Fail("malformed");
            var s = (D)step!;
            if (!JsX.StrictEq(s["goal_commitment"], commitment)) return Fail("goal-mismatch");
            var eSeq = Member(opts, "expectedSeq");
            if (Given(eSeq) && !JsX.StrictEq(s["seq"], eSeq)) return Fail("seq-mismatch");
            var ePrev = Member(opts, "expectedPrev");
            if (Given(ePrev) && !JsX.StrictEq(s["prev"], ePrev)) return Fail("chain-break");
            var eAction = Member(opts, "expectedActionDigest");
            if (Given(eAction) && !JsX.StrictEq(s["action_digest"], eAction)) return Fail("action-mismatch");
            var eBefore = Member(opts, "expectedBeforeDigest");
            if (Given(eBefore) && !JsX.StrictEq(s["before_digest"], eBefore)) return Fail("state-mismatch");
            var eAfter = Member(opts, "expectedAfterDigest");
            if (Given(eAfter) && !JsX.StrictEq(s["after_digest"], eAfter)) return Fail("state-mismatch");
            var body = new D(s);
            body.Remove("digest");
            if (StepBodyDigest(body) != (string)s["digest"]!) return Fail("digest-mismatch");
            if (StateDigest(s["before"]) != (string)s["before_digest"]! || StateDigest(s["after"]) != (string)s["after_digest"]!) return Fail("state-digest-mismatch");
            var reg = RegistryOf(opts);
            var g = (D)goal!;
            double pb, pa; (string Mode, double Charge) cls;
            try
            {
                pb = PotentialOf(g, reg, s["before"]);
                pa = PotentialOf(g, reg, s["after"]);
                cls = Classify(pb, pa, IntentJs.NumOf(g["epsilon"])!.Value);
            }
            catch (Exception e) { return Fail(DenialOf(e)); }
            if (pb != IntentJs.NumOf(s["potential_before"])!.Value || pa != IntentJs.NumOf(s["potential_after"])!.Value) return Fail("potential-mismatch");
            if ((string)s["mode"]! != cls.Mode) return Fail("mode-mismatch");
            if (IntentJs.NumOf(s["charge"])!.Value != cls.Charge) return Fail("charge-mismatch");
            var trusted = Member(opts, "trustedStateSources");
            if (Jx.Truthy(trusted) && !(trusted is L tl && tl.Any(x => x is string xs && xs == (string)s["state_source"]!))) return Fail("untrusted-state-source");
            if (!(Member(opts, "requireAttestedState") is false) && (string)s["state_source"]! == "") return Fail("untrusted-state-source");
            if (Member(opts, "guard") is Func<D, object?> guard && !RunGuard(guard, new D { ["seq"] = s["seq"], ["before"] = s["before"], ["after"] = s["after"], ["action_digest"] = s["action_digest"] })) return Fail("prohibited");
            if (Member(opts, "attestation") is Func<D, object?> att)
            {
                var ok = false;
                try { ok = att(s) is true; }
                catch (Exception) { ok = false; }
                if (!ok) return Fail("attestation-failed");
            }
            return new D { ["ok"] = true, ["charge"] = Int(cls.Charge) };
        }
        catch (Exception) { return Fail("malformed"); }
    }

    static D TrajFail(string reason, int at) => new() { ["ok"] = false, ["reason"] = reason, ["at"] = IntentJs.OfLong(at) };

    /// <summary>Verifies a whole trajectory: the goal binding, every step re-checked (see <see cref="VerifyProgressStep"/>), the hash chain, the states contiguous (each step starts where the last ended), the start from
    /// <c>initial</c> / <c>initialDigest</c> when given, the per-step action binding of <c>expectedActionDigests</c> (the same length), and the strict global invariant sum(charge) &lt;= explorationBudget. It recomputes the
    /// charges itself and never trusts a claimed total. <c>{ok: true, spent, remaining, reached, finalPotential (-1 with no steps and no initial), steps, head}</c> or <c>{ok: false, reason, at}</c>.</summary>
    public static D VerifyTrajectory(object? goal, object? commitment, object? stepsIn, D? opts = null)
    {
        if (!VerifyGoalCommitment(goal, commitment)) return TrajFail("goal-mismatch", -1);
        if (stepsIn is not L steps) return TrajFail("malformed", -1);
        var eActions = Member(opts, "expectedActionDigests");
        if (Jx.Truthy(eActions) && eActions is L ea && ea.Count != steps.Count) return TrajFail("action-mismatch", Math.Min(ea.Count, steps.Count));
        object? anchor;
        try
        {
            var initialDigest = Member(opts, "initialDigest");
            var initial = Member(opts, "initial");
            anchor = initialDigest != null && Given(initialDigest) ? initialDigest : !Given(initial) ? Jx.Undef : StateDigest(initial);
        }
        catch (Exception) { return TrajFail("malformed", -1); }
        var g = (D)goal!;
        object prev = Genesis;
        double spent = 0, finalPotential = -1;
        if (steps.Count == 0 && Given(Member(opts, "initial")))
        {
            try { finalPotential = PotentialOf(g, RegistryOf(opts), Member(opts, "initial")); }
            catch (Exception e) { return TrajFail(DenialOf(e), -1); }
        }
        var budget = IntentJs.NumOf(g["explorationBudget"])!.Value;
        for (int i = 0; i < steps.Count; i++)
        {
            var s = steps[i];
            var o = opts == null ? new D() : new D(opts);
            o["expectedSeq"] = IntentJs.OfLong(i);
            o["expectedPrev"] = prev;
            if (eActions is L el) o["expectedActionDigest"] = i < el.Count ? el[i] : Jx.Undef; else o["expectedActionDigest"] = Jx.Undef;
            var r = VerifyProgressStep(goal, commitment, s, o);
            if (r["ok"] is not true) return TrajFail((string)r["reason"]!, i);
            var sd = (D)s!;
            if (!Jx.IsUndef(anchor) && !JsX.StrictEq(sd["before_digest"], anchor)) return TrajFail("discontinuous-state", i);
            spent += IntentJs.NumOf(r["charge"])!.Value;
            if (!IntentJs.IsSafeInteger(Jx.NumOut(spent)) || spent > budget) return TrajFail("budget-exceeded", i);
            anchor = sd["after_digest"];
            prev = (string)sd["digest"]!;
            finalPotential = IntentJs.NumOf(sd["potential_after"])!.Value;
        }
        return new D
        {
            ["ok"] = true, ["spent"] = Int(spent), ["remaining"] = Int(budget - spent), ["reached"] = finalPotential == 0, ["finalPotential"] = Int(finalPotential),
            ["steps"] = IntentJs.OfLong(steps.Count), ["head"] = prev,
        };
    }

    // ---- signed proofs ----

    static byte[] SigMessage(D step, string holder) => Pca.Canon(new D
    {
        ["d"] = SigDomain,
        ["b"] = new D
        {
            ["holder"] = holder, ["goal_commitment"] = Member(step, "goal_commitment"), ["action_digest"] = Member(step, "action_digest"), ["before_digest"] = Member(step, "before_digest"),
            ["after_digest"] = Member(step, "after_digest"), ["seq"] = Member(step, "seq"), ["prev"] = Member(step, "prev"), ["step_digest"] = Member(step, "digest"),
        },
    });

    /// <summary>Signs a step: <c>{step, holder, sig}</c> with an Ed25519 signature (deterministic) over the domain-separated binding of the holder, goal, action, state transition, sequence, chain link and step digest.
    /// <paramref name="holderPublicKey"/> is committed in the message; it is not checked against the key.</summary>
    public static D SignProgressStep(object? step, byte[] secretKey, string holderPublicKey)
    {
        using var key = EdKey.FromSeed(secretKey);
        return new D { ["step"] = step, ["holder"] = holderPublicKey, ["sig"] = Pca.B64u(key.Sign(SigMessage((D)step!, holderPublicKey))) };
    }

    static bool SignedShape(object? sp) => sp is D m && m.GetValueOrDefault("holder") is string && m.GetValueOrDefault("sig") is string && IsStep(m.GetValueOrDefault("step"));

    static bool SigOk(D signed) => Pca.VerifyEdInternal((string)signed["holder"]!, SigMessage((D)signed["step"]!, (string)signed["holder"]!), signed["sig"]);

    /// <summary>Verifies a signed step offline: the shape, the expected holder (<c>holder-mismatch</c>), the expected action (<c>action-mismatch</c>), the goal, the signature by the holder over the binding fields
    /// (<c>bad-signature</c>), THEN the full deterministic step re-check (<see cref="VerifyProgressStep"/>, with the same <paramref name="opts"/>). <c>expectedActionDigest</c> and <c>expectedHolder</c> are
    /// REQUIRED members of <paramref name="opts"/>: a proof cannot be lifted onto another action, goal, state or key.</summary>
    public static D VerifySignedProgressStep(object? goal, object? commitment, object? signed, D opts)
    {
        try
        {
            if (!SignedShape(signed)) return Fail("malformed");
            var sp = (D)signed!;
            var step = (D)sp["step"]!;
            if (!JsX.StrictEq(sp["holder"], Member(opts, "expectedHolder"))) return Fail("holder-mismatch");
            if (!JsX.StrictEq(step["action_digest"], Member(opts, "expectedActionDigest"))) return Fail("action-mismatch");
            if (!JsX.StrictEq(step["goal_commitment"], commitment)) return Fail("goal-mismatch");
            if (!SigOk(sp)) return Fail("bad-signature");
            return VerifyProgressStep(goal, commitment, step, opts);
        }
        catch (Exception) { return Fail("malformed"); }
    }

    /// <summary>Verifies the signature on every step (as <see cref="VerifySignedProgressStep"/>: <c>expectedHolder</c> and <c>expectedActionDigests</c> are REQUIRED) and then the whole trajectory.</summary>
    public static D VerifySignedTrajectory(object? goal, object? commitment, object? signedIn, D opts)
    {
        if (signedIn is not L signed) return TrajFail("malformed", -1);
        var eActions = (L)Member(opts, "expectedActionDigests")!;
        if (eActions.Count != signed.Count) return TrajFail("action-mismatch", Math.Min(eActions.Count, signed.Count));
        for (int i = 0; i < signed.Count; i++)
        {
            try
            {
                if (!SignedShape(signed[i])) return TrajFail("malformed", i);
                var sp = (D)signed[i]!;
                var step = (D)sp["step"]!;
                if (!JsX.StrictEq(sp["holder"], Member(opts, "expectedHolder"))) return TrajFail("holder-mismatch", i);
                if (!JsX.StrictEq(step["action_digest"], eActions[i])) return TrajFail("action-mismatch", i);
                if (!SigOk(sp)) return TrajFail("bad-signature", i);
            }
            catch (Exception) { return TrajFail("malformed", i); }
        }
        var rest = new D(opts);
        rest.Remove("expectedHolder");
        return VerifyTrajectory(goal, commitment, new L(signed.Select(s => ((D)s!)["step"])), rest);
    }

    /// <summary>The constants of the module.</summary>
    public static D Constants() => new()
    {
        ["PROGRESS_VERSION"] = IntentJs.OfLong(Version), ["PROGRESS_SIG_DOMAIN"] = SigDomain, ["TRAJECTORY_ANCHOR_DOMAIN"] = AnchorDomain, ["STATE_ATTESTATION_DOMAIN"] = StateAttestationDomain,
    };
}
