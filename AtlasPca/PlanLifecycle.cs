// Plan lifecycle (T10): explicit states around the plan commitment (the Merkle root an agent signs into every PCActn) and the principal's
// plan authorization.
//
//   draft --Validate--> validated --Commit--> committed --Authorize--> authorized
//     \_____________________\__________________\___________Revoke_______/--> revoked
//
//   - draft: the nodes are recorded; the root is computed from them (never taken from the caller).
//   - validated: the nodes are well-formed (unique ids, verb and resource, a known reversibility class) and passed the server's own
//     validator (for example every node inside the grant's predicates).
//   - committed: the root is fixed. A committed plan is NOT executable: it still needs the principal.
//   - authorized: the principal approved this root for this grant, optionally until ExpiresAt.
//   - revoked: terminal; every later action against the root is denied.
//
// "Executable" is not stored: it is evaluated at the moment of use. A plan is executable when it is authorized, the approval has not
// expired, and its stored nodes still hash to the root. Check adds the per-action staleness rules a server applies immediately before
// execution: the node exists and the operation's verb, resource and params still match what the principal approved. The registry only
// feeds the plan into Authorize (AuthorizeInput.Plans) and names the state on a denial; the wire formats are unchanged. Mirrors the
// reference plan registry; plan-vectors.json pins it.
using System.Globalization;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>A plan's lifecycle state.</summary>
public static class PlanStates
{
    public const string Draft = "draft";
    public const string Validated = "validated";
    public const string Committed = "committed";
    public const string Authorized = "authorized";
    public const string Revoked = "revoked";
    /// <summary>The state reported for a root this grant does not have.</summary>
    public const string Unknown = "unknown";
}

/// <summary>The principal's approval of a plan. <see cref="ExpiresAt"/> (epoch ms) must be a finite time; null: until revoked.</summary>
public sealed record PlanApproval(string By, double? ExpiresAt = null)
{
    internal D ToJson()
    {
        var o = new D { ["by"] = By };
        if (ExpiresAt is double e && double.IsFinite(e)) o["expiresAt"] = new Num(JsCanon.NumberString(e));
        return o;
    }
}

/// <summary>The stored plan. <see cref="Nodes"/> are the plan nodes (<c>{id, verb, resource, params_digest?, reversibility_class?, pre?, post?}</c>); <see cref="Root"/> is their Merkle root, computed by the registry.</summary>
public sealed record PlanRecord(string GrantRef, string Root, IReadOnlyList<Dictionary<string, object?>> Nodes, string State, long CreatedAt)
{
    public long? ValidatedAt { get; init; }
    public long? CommittedAt { get; init; }
    public long? AuthorizedAt { get; init; }
    public PlanApproval? Approval { get; init; }
    public long? RevokedAt { get; init; }
    public string? RevokedReason { get; init; }

    /// <summary>The reference's JSON shape of the record.</summary>
    public Dictionary<string, object?> ToJson()
    {
        var o = new D
        {
            ["grantRef"] = GrantRef, ["root"] = Root, ["nodes"] = Nodes.Select(n => (object?)n).ToList(), ["state"] = State, ["createdAt"] = IntentJs.OfLong(CreatedAt),
        };
        if (ValidatedAt is long v) o["validatedAt"] = IntentJs.OfLong(v);
        if (CommittedAt is long c) o["committedAt"] = IntentJs.OfLong(c);
        if (AuthorizedAt is long a) o["authorizedAt"] = IntentJs.OfLong(a);
        if (Approval != null) o["approval"] = Approval.ToJson();
        if (RevokedAt is long r) o["revokedAt"] = IntentJs.OfLong(r);
        if (RevokedReason != null) o["revokedReason"] = RevokedReason;
        return o;
    }

    internal static PlanRecord? FromJson(object? v)
    {
        if (v is not D m || m.GetValueOrDefault("root") is not string root || m.GetValueOrDefault("nodes") is not L nodes
            || m.GetValueOrDefault("state") is not string state || m.GetValueOrDefault("grantRef") is not string grant) return null;
        if (nodes.Any(n => n is not D)) return null;
        static long? Ms(D obj, string k) => obj.TryGetValue(k, out var x) && IntentJs.NumOf(x) is double d && double.IsFinite(d) ? (long)d : null;
        PlanApproval? ap = null;
        if (m.GetValueOrDefault("approval") is D am)
            ap = new PlanApproval(am.GetValueOrDefault("by") as string ?? "", am.TryGetValue("expiresAt", out var ex) ? IntentJs.NumOf(ex) ?? double.NaN : null);
        return new PlanRecord(grant, root, nodes.Cast<D>().ToList(), state, Ms(m, "createdAt") ?? 0)
        {
            ValidatedAt = Ms(m, "validatedAt"), CommittedAt = Ms(m, "committedAt"), AuthorizedAt = Ms(m, "authorizedAt"), Approval = ap,
            RevokedAt = Ms(m, "revokedAt"), RevokedReason = m.GetValueOrDefault("revokedReason") as string,
        };
    }
}

/// <summary>The result of a lifecycle transition: Ok with the new <see cref="Record"/>, or the <see cref="State"/> the plan is in and the <see cref="Reason"/> it refused.</summary>
public sealed record PlanTransition(bool Ok, PlanRecord? Record, string State, string? Reason)
{
    internal static PlanTransition Success(PlanRecord r) => new(true, r, r.State, null);
    internal static PlanTransition Refused(string state, string reason) => new(false, null, state, reason);

    public Dictionary<string, object?> ToJson() =>
        Ok ? new D { ["ok"] = true, ["record"] = Record!.ToJson() } : new D { ["ok"] = false, ["state"] = State, ["reason"] = Reason };
}

/// <summary>A plan's state at the moment of use. <see cref="Reason"/> says why it is not executable.</summary>
public sealed record PlanStatus(string State, bool Executable, string? Reason = null, PlanRecord? Record = null)
{
    public Dictionary<string, object?> ToJson()
    {
        var o = new D { ["state"] = State, ["executable"] = Executable };
        if (Reason != null) o["reason"] = Reason;
        if (Record != null) o["record"] = Record.ToJson();
        return o;
    }
}

/// <summary>A validator's answer.</summary>
public sealed record PlanValidation(bool Ok, string? Reason = null);

/// <summary>The verifier context for an action against a root: the stored plan and whether it is executable now.</summary>
public sealed record PlanContext(List<object?> Plan, bool PlanAuthorized, PlanStatus Status)
{
    public Dictionary<string, object?> ToJson() => new() { ["plan"] = Plan, ["planAuthorized"] = PlanAuthorized, ["status"] = Status.ToJson() };
}

/// <summary>Options of <see cref="PlanRegistry.Check"/>.</summary>
public sealed class PlanCheckOptions
{
    /// <summary>The plan node the action executes (the PCActn's <c>plan.node_id</c>); null = not named.</summary>
    public string? NodeId { get; set; }
    /// <summary>The operation about to execute: it must match the node (verb, resource, params digest).</summary>
    public Operation? Operation { get; set; }
    /// <summary>The time of the check in epoch ms (null: the registry clock).</summary>
    public long? Now { get; set; }
}

/// <summary>Options of <see cref="PlanRegistry"/>.</summary>
public sealed class PlanRegistryOptions
{
    /// <summary>Where the records live (null: in memory, one process). Use <see cref="SqlAtomicKv"/> for a database.</summary>
    public IAtomicKv? Kv { get; set; }
    /// <summary>The key prefix in <see cref="Kv"/> (default <c>pca-plan:</c>).</summary>
    public string? Prefix { get; set; }
    /// <summary>The clock in epoch ms (null: the wall clock).</summary>
    public Func<long>? Now { get; set; }
    /// <summary>The server's validation, run by <see cref="PlanRegistry.Validate"/> after the structural checks (for example each node is within the grant's predicates). A throw refuses.</summary>
    public Func<PlanRecord, PlanValidation>? Validator { get; set; }
}

/// <summary>The plan lifecycle store. Safe for concurrent use when the <see cref="IAtomicKv"/> is: every transition is one atomic update, so of N concurrent claims of one transition exactly one succeeds.</summary>
public sealed class PlanRegistry
{
    readonly IAtomicKv _kv;
    readonly string _prefix;
    readonly Func<long> _now;
    readonly Func<PlanRecord, PlanValidation>? _validator;

    public PlanRegistry(PlanRegistryOptions? options = null)
    {
        _kv = options?.Kv ?? new MemoryAtomicKv();
        _prefix = string.IsNullOrEmpty(options?.Prefix) ? "pca-plan:" : options!.Prefix!;
        _now = options?.Now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        _validator = options?.Validator;
    }

    string Key(string grantRef, string root) => _prefix + Uri.EscapeDataString(grantRef) + ":" + root;

    static PlanRecord? Decode(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        try { return PlanRecord.FromJson(Pca.ParseJson(text)); }
        catch (Exception) { return null; }
    }

    static PlanTransition Unknown(string root) => PlanTransition.Refused(PlanStates.Unknown, $"plan {root} is unknown for this grant");
    static PlanTransition StoreRefusal(Exception e) => PlanTransition.Refused(PlanStates.Unknown, "the plan store failed (fail closed): " + e.Message);

    /// <summary>The stored plan (null: none for this grant).</summary>
    public PlanRecord? Get(string grantRef, string root) => Decode(_kv.Get(Key(grantRef, root)));

    /// <summary>The Merkle root of the plan-node leaves; throws when a node cannot be hashed.</summary>
    internal static string RootOf(IEnumerable<Dictionary<string, object?>> nodes)
    {
        var list = nodes.ToList();
        if (list.Count == 0) throw new InvalidOperationException("merkleRoot: empty leaf set");
        return Pca.MerkleRoot(list.Select(n => (object?)Pca.NodeLeaf(n)).ToList());
    }

    static List<Dictionary<string, object?>> CloneNodes(IEnumerable<Dictionary<string, object?>> nodes) =>
        ((L)Pca.ParseJson(Pca.Canonicalize(nodes.Select(n => (object?)n).ToList()))!).Cast<D>().ToList();

    /// <summary>The reason a plan's nodes are not well-formed, or null when valid.</summary>
    static string? StructuralProblem(IReadOnlyList<D> nodes)
    {
        if (nodes.Count == 0) return "a plan needs at least one node";
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var n in nodes)
        {
            if (n is null || n.GetValueOrDefault("id") is not string id || id.Length == 0) return "every node needs an id";
            if (!ids.Add(id)) return $"duplicate node id '{id}'";
            if (n.GetValueOrDefault("verb") is not string v || v.Length == 0 || n.GetValueOrDefault("resource") is not string r || r.Length == 0)
                return $"node '{id}' needs a verb and a resource";
            if (n.TryGetValue("reversibility_class", out var rc) && !(rc is string rs && rs is "reversible" or "rate_limited" or "costly" or "irreversible"))
                return $"node '{id}' has an unknown reversibility class '{IntentRevocation.JsText(rc, true)}'";
        }
        return null;
    }

    /// <summary>Atomically moves a plan from one of <paramref name="from"/> to the state <paramref name="to"/> (<paramref name="next"/> computes the new record from the current one).</summary>
    PlanTransition Move(string grantRef, string root, string[] from, string to, Func<PlanRecord, PlanRecord> next)
    {
        var outcome = Unknown(root);
        try
        {
            _kv.Update(Key(grantRef, root), prev =>
            {
                var cur = Decode(prev);
                if (cur == null) { outcome = Unknown(root); return null; }
                if (!from.Contains(cur.State)) { outcome = PlanTransition.Refused(cur.State, $"plan {root} is {cur.State}: cannot {to}"); return null; }
                var rec = next(cur);
                var enc = Pca.Canonicalize(rec.ToJson());
                outcome = PlanTransition.Success(rec);
                return enc;
            });
        }
        catch (Exception e) { return StoreRefusal(e); }
        return outcome;
    }

    /// <summary>Records a draft plan for a grant. The root is computed from <paramref name="nodes"/>. Re-drafting an existing root is refused.</summary>
    public PlanTransition Draft(string grantRef, IEnumerable<Dictionary<string, object?>> nodes)
    {
        if (string.IsNullOrEmpty(grantRef)) return PlanTransition.Refused(PlanStates.Unknown, "a plan needs a grant");
        // structural problems are reported by Validate (a draft can be inspected first); an unhashable plan has no root
        string root;
        List<Dictionary<string, object?>> copy;
        try
        {
            var src = nodes?.ToList() ?? new List<D>();
            root = RootOf(src);
            copy = CloneNodes(src);
        }
        catch (Exception e) { return PlanTransition.Refused(PlanStates.Unknown, "the plan cannot be committed: " + e.Message); }
        var rec = new PlanRecord(grantRef, root, copy, PlanStates.Draft, _now());
        var outcome = PlanTransition.Success(rec);
        try
        {
            var enc = Pca.Canonicalize(rec.ToJson());
            _kv.Update(Key(grantRef, root), prev =>
            {
                var cur = Decode(prev);
                if (cur != null) { outcome = PlanTransition.Refused(cur.State, $"plan {root} already exists ({cur.State})"); return null; }
                outcome = PlanTransition.Success(rec);
                return enc;
            });
        }
        catch (Exception e) { return StoreRefusal(e); }
        return outcome;
    }

    /// <summary>draft to validated (structural checks, then the server's validator).</summary>
    public PlanTransition Validate(string grantRef, string root)
    {
        PlanRecord? cur;
        try { cur = Get(grantRef, root); }
        catch (Exception e) { return StoreRefusal(e); }
        if (cur == null) return Unknown(root);
        if (cur.State != PlanStates.Draft) return PlanTransition.Refused(cur.State, $"plan {root} is {cur.State}: cannot validate");
        var problem = StructuralProblem(cur.Nodes.ToList());
        if (problem == null)
        {
            string? got = null;
            try { got = RootOf(cur.Nodes); } catch (Exception) { /* unhashable: no root */ }
            if (got != root) problem = "the stored nodes no longer hash to the root";
        }
        if (problem != null) return PlanTransition.Refused(cur.State, $"plan {root} is invalid: {problem}");
        if (_validator != null)
        {
            PlanValidation v;
            try { v = _validator(cur with { Nodes = CloneNodes(cur.Nodes) }); }
            catch (Exception e) { v = new PlanValidation(false, "validator error (fail closed): " + e.Message); }
            if (v is not { Ok: true })
                return PlanTransition.Refused(cur.State, $"plan {root} is invalid: {(string.IsNullOrEmpty(v?.Reason) ? "refused by the validator" : v!.Reason)}");
        }
        return Move(grantRef, root, new[] { PlanStates.Draft }, "validate", p => p with { State = PlanStates.Validated, ValidatedAt = _now() });
    }

    /// <summary>validated to committed: the root is fixed; it still needs the principal's authorization to execute.</summary>
    public PlanTransition Commit(string grantRef, string root) =>
        Move(grantRef, root, new[] { PlanStates.Validated }, "commit", p => p with { State = PlanStates.Committed, CommittedAt = _now() });

    /// <summary>committed to authorized with the principal's approval (call it only after verifying the principal's consent). A null approval, an empty <c>By</c> or a non-finite <c>ExpiresAt</c> is refused.</summary>
    public PlanTransition Authorize(string grantRef, string root, PlanApproval? approval)
    {
        string StateOf()
        {
            try { return Get(grantRef, root)?.State ?? PlanStates.Unknown; }
            catch (Exception) { return PlanStates.Unknown; }
        }
        if (approval == null || string.IsNullOrEmpty(approval.By)) return PlanTransition.Refused(StateOf(), "an approval names who approved (`by`)");
        if (approval.ExpiresAt is double e && !double.IsFinite(e)) return PlanTransition.Refused(StateOf(), "approval.expiresAt must be a time (epoch ms)");
        return Move(grantRef, root, new[] { PlanStates.Committed }, "authorize", p => p with { State = PlanStates.Authorized, AuthorizedAt = _now(), Approval = approval });
    }

    /// <summary>Any state except revoked to revoked (terminal).</summary>
    public PlanTransition Revoke(string grantRef, string root, string reason) =>
        Move(grantRef, root, new[] { PlanStates.Draft, PlanStates.Validated, PlanStates.Committed, PlanStates.Authorized }, "revoke",
            p => p with { State = PlanStates.Revoked, RevokedAt = _now(), RevokedReason = reason ?? "" });

    /// <summary>The state now and whether the plan is executable (authorized, approval unexpired, nodes still hash to the root). A store error is reported as not executable.</summary>
    public PlanStatus Status(string grantRef, string root, long? now = null)
    {
        long at = now ?? _now();
        PlanRecord? rec;
        try { rec = Get(grantRef, root); }
        catch (Exception e) { return new PlanStatus(PlanStates.Unknown, false, "the plan store failed (fail closed): " + e.Message); }
        if (rec == null) return new PlanStatus(PlanStates.Unknown, false, $"plan {root} is unknown for this grant");
        if (rec.State != PlanStates.Authorized)
        {
            var why = rec.State switch
            {
                PlanStates.Committed => "committed but not authorized by the principal",
                PlanStates.Revoked => $"revoked ({(string.IsNullOrEmpty(rec.RevokedReason) ? "no reason given" : rec.RevokedReason)})",
                _ => $"{rec.State}, not authorized",
            };
            return new PlanStatus(rec.State, false, $"plan {root} is {why}", rec);
        }
        if (rec.Approval?.ExpiresAt is double exp && !(at < exp))
            return new PlanStatus(rec.State, false, $"plan {root}: the principal's approval expired at {JsCanon.NumberString(exp)}", rec);
        string? got = null;
        try { got = RootOf(rec.Nodes); } catch (Exception) { /* unhashable: no root */ }
        if (got != root) return new PlanStatus(rec.State, false, $"plan {root}: the stored nodes no longer hash to the root", rec);
        return new PlanStatus(rec.State, true, null, rec);
    }

    /// <summary><see cref="Status"/> plus the per-action staleness rules (the node exists, the operation matches it). Run it immediately before execution.</summary>
    public PlanStatus Check(string grantRef, string root, PlanCheckOptions? options = null)
    {
        var o = options ?? new PlanCheckOptions();
        var s = Status(grantRef, root, o.Now);
        if (!s.Executable || s.Record == null || (o.NodeId == null && o.Operation == null)) return s;
        D? node = null;
        if (o.NodeId != null)
        {
            node = s.Record.Nodes.FirstOrDefault(n => n.GetValueOrDefault("id") is string id && id == o.NodeId);
            if (node == null) return s with { Executable = false, Reason = $"plan {root} has no node '{o.NodeId}'" };
        }
        if (o.Operation is { } op)
        {
            var candidates = node != null ? new List<D> { node } : s.Record.Nodes.ToList();
            string digest;
            try { digest = Pca.ParamsDigest(op.Params); }
            catch (Exception) { return s with { Executable = false, Reason = $"plan {root}: the operation's params cannot be hashed" }; }
            var empty = Pca.ParamsDigest(null);
            bool same = candidates.Any(n => n.GetValueOrDefault("verb") is string v && v == op.Verb && n.GetValueOrDefault("resource") is string r && r == op.Resource
                && (n.GetValueOrDefault("params_digest") ?? empty) is string nd && nd == digest);
            if (!same) return s with { Executable = false, Reason = $"plan {root}: the operation ({op.Verb} on {op.Resource} with these params) is not what the principal approved" };
        }
        return s;
    }

    /// <summary>True only when the plan is executable now (fail closed on any error).</summary>
    public bool IsPlanAuthorized(string grantRef, string planRoot)
    {
        try { return Status(grantRef, planRoot).Executable; }
        catch (Exception) { return false; }
    }

    /// <summary>The verifier context for an action against <paramref name="root"/>: the stored plan, and <c>PlanAuthorized</c> = executable. Null: the root is unknown for this grant.</summary>
    public PlanContext? Context(string grantRef, string root, long? now = null)
    {
        var s = Status(grantRef, root, now);
        if (s.Record == null) return null;
        return new PlanContext(CloneNodes(s.Record.Nodes).Select(n => (object?)n).ToList(), s.Executable, s);
    }
}
