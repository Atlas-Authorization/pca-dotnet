// PCA 0.5 `Authorize`: the full authorization pipeline for a resource server or tool guard (additive, opt-in). A mechanical
// port of the Python reference (atlas_pca/authorize.py), itself mirroring the TypeScript `authorize()` / `verifyPCActn`
// (packages/pca/src/server/authorize.ts, agent-native.ts, envelope.ts): same check names, same reason strings, same order,
// same fail-closed behaviour. Never throws: an internal error is a denial.
using System.Data.Common;
using System.Globalization;
using System.Text;
using System.Text.Json;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The operation the handler / tool WILL execute, taken from the server's own routing and parsed input, never from
/// the PCActn. <see cref="Params"/> must be a JSON object: a <see cref="Dictionary{TKey,TValue}"/> of string to JSON values
/// (as produced by <see cref="Pca.ParseJson"/>; plain CLR numbers, strings, booleans, lists and nested dictionaries are
/// accepted and read with JSON number semantics), or a <see cref="JsonElement"/> object.</summary>
public sealed record Operation(string Verb, string Resource, object? Params);

/// <summary>The operation an allowing decision is bound to. <see cref="Id"/> is the digest of the presented PCActn.</summary>
public sealed record AuthorizedOperation(string Verb, string Resource, string ParamsDigest, string Id);

/// <summary>What <see cref="IStateStore.Claim"/> returns. <see cref="Ok"/> is true only when THIS call consumed the counter;
/// on a refusal <see cref="LastCounter"/> is the stored counter when the store knows it.</summary>
public sealed record ClaimResult(bool Ok, long? LastCounter = null);

/// <summary>The replay store: ONE atomic operation of your backend. If a counter is stored for <c>key</c> and <c>counter</c>
/// is not strictly greater, return <c>ClaimResult(false, stored)</c>; otherwise store <c>counter</c> and return
/// <c>ClaimResult(true)</c>. A claim that cannot decide must return <c>ok = false</c>, null, or throw
/// (<see cref="Pca.Authorize"/> then denies).</summary>
public interface IStateStore
{
    ClaimResult? Claim(string key, long counter);

    /// <summary>Where the store lives: <see cref="StoreScope.Shared"/> (every instance of the service sees the same replay state) or
    /// <see cref="StoreScope.Process"/> (one process only; a PCActn would replay once per instance). The default is <c>Process</c>: a
    /// store must DECLARE itself shared, so <see cref="AuthorizeInput.MultiInstance"/> never trusts an undeclared one.</summary>
    StoreScope Scope => StoreScope.Process;

    /// <summary>TTL'd consume-once (max_uses use slots), ONE atomic operation: true iff <paramref name="key"/> has no live record
    /// (a live record has <c>retainUntilMs &gt;= nowMs</c>), in which case it records the key until <paramref name="retainUntilMs"/>;
    /// a live record is never shortened (the later horizon wins). Throws <see cref="ArgumentException"/>, never returns true,
    /// when the key is empty or <paramref name="retainUntilMs"/> &lt; <paramref name="nowMs"/>; a refused call leaves nothing behind.
    /// The store may forget a key once its horizon has passed. The default falls back to <c>Claim(key, 1)</c>, which never expires.</summary>
    bool ConsumeOnce(string key, long retainUntilMs, long nowMs)
    {
        if (string.IsNullOrEmpty(key) || retainUntilMs < nowMs) throw new ArgumentException("ConsumeOnce needs a non-empty key and retainUntilMs >= nowMs");
        return Claim(key, 1)?.Ok == true;
    }
}

/// <summary>See <see cref="IStateStore.Scope"/>.</summary>
public enum StoreScope { Process, Shared }

/// <summary>The optional monotone-pin side of an <see cref="IStateStore"/>: a named non-negative integer that only ever rises (the revocation-epoch
/// rollback pin, key <c>&lt;grant id&gt;:epoch</c>). <see cref="RaisePin"/> is ONE atomic operation (concurrent raises of 6 and 7 leave 7) and
/// returns the pin after the call; <see cref="Pin"/> is null when never raised. Revocation staleness (<see cref="AuthorizeInput.RevocationStaleness"/>)
/// needs a store that implements it.</summary>
public interface IPinStore
{
    long? Pin(string key);
    long RaisePin(string key, long value);
}

/// <summary>The optional trust-budget side of an <see cref="IStateStore"/>: the budget of a grant (key <c>&lt;grant id&gt;:budget</c>) with ONE atomic
/// compare-and-set. <see cref="BudgetCas"/> stores <c>new</c> only while the stored value still equals <c>old</c> (null: none stored) and
/// says whether it did. Without it a call has no budget (B = 0, deny-metered) unless the request context supplies one.</summary>
public interface IBudgetStore
{
    TrustBudget? Budget(string key);
    bool BudgetCas(string key, TrustBudget? old, TrustBudget @new);
}

/// <summary>The optional read side of an <see cref="IStateStore"/>: the last admitted counter of a stream (null: none). It
/// binds an escalation answer to the holder's history; a store without it cannot admit an answered escalation.</summary>
public interface ILastStore
{
    long? Last(string key);
}

/// <summary>In-process reference store (one lock). Correct for ONE process only; use <see cref="SqlStateStore"/> or your
/// database for several instances.</summary>
public sealed class MemoryStateStore : IStateStore, ILastStore, IPinStore, IBudgetStore
{
    readonly Dictionary<string, TrustBudget> _budgets = new(StringComparer.Ordinal);

    public TrustBudget? Budget(string key)
    {
        lock (_lock) return _budgets.TryGetValue(key, out var b) ? b : null;
    }

    public bool BudgetCas(string key, TrustBudget? old, TrustBudget @new)
    {
        lock (_lock)
        {
            _budgets.TryGetValue(key, out var cur);
            if (cur != old) return false;
            _budgets[key] = @new;
            return true;
        }
    }

    readonly Dictionary<string, long> _pins = new(StringComparer.Ordinal);
    public StoreScope Scope => StoreScope.Process;

    public long? Pin(string key)
    {
        lock (_lock) return _pins.TryGetValue(key, out var v) ? v : null;
    }

    public long RaisePin(string key, long value)
    {
        if (string.IsNullOrEmpty(key) || value < 0) throw new ArgumentException("RaisePin needs a non-empty key and a non-negative value");
        lock (_lock)
        {
            if (!_pins.TryGetValue(key, out var v) || value > v) _pins[key] = v = value;
            return v;
        }
    }

    readonly Dictionary<string, long> _last = new(StringComparer.Ordinal);
    readonly Dictionary<string, long> _once = new(StringComparer.Ordinal); // ConsumeOnce: key -> retain_until
    readonly object _lock = new();

    public bool ConsumeOnce(string key, long retainUntilMs, long nowMs)
    {
        if (string.IsNullOrEmpty(key) || retainUntilMs < nowMs) throw new ArgumentException("ConsumeOnce needs a non-empty key and retainUntilMs >= nowMs");
        lock (_lock)
        {
            if (_once.Count >= 1024) // prune expired records once the map is sizeable
                foreach (var k in _once.Where(kv => kv.Value < nowMs).Select(kv => kv.Key).ToList()) _once.Remove(k);
            if (_once.TryGetValue(key, out var r) && r >= nowMs)
            {
                if (retainUntilMs > r) _once[key] = retainUntilMs;
                return false;
            }
            _once[key] = retainUntilMs;
            return true;
        }
    }

    public long? Last(string key)
    {
        lock (_lock) return _last.TryGetValue(key, out var last) ? last : null;
    }

    public ClaimResult? Claim(string key, long counter)
    {
        if (key is null) return new ClaimResult(false);
        lock (_lock)
        {
            if (_last.TryGetValue(key, out var last) && !(counter > last)) return new ClaimResult(false, last);
            _last[key] = counter;
            return new ClaimResult(true);
        }
    }
}

/// <summary>Durable reference store over ADO.NET: one row per counter stream, <c>key</c> is the PRIMARY KEY.
/// The claim is ONE statement, <c>INSERT ... ON CONFLICT(key) DO UPDATE SET last_counter = excluded.last_counter WHERE
/// excluded.last_counter &gt; table.last_counter</c>, which the database runs atomically under the key's unique constraint,
/// so concurrent connections, threads and processes can never both consume the same counter. The SQL works on SQLite
/// (3.24+) and PostgreSQL (9.5+). <paramref name="connectionFactory"/> must return a NEW connection per call (pooled by your
/// provider); the store opens and disposes it.</summary>
public sealed class SqlStateStore : IStateStore, ILastStore, IPinStore, IBudgetStore
{
    public StoreScope Scope => StoreScope.Shared;
    public const string DefaultTable = "pca_replay";
    readonly Func<DbConnection> _connect;
    readonly string _table;

    public SqlStateStore(Func<DbConnection> connectionFactory, string table = DefaultTable)
    {
        _connect = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
        if (string.IsNullOrEmpty(table) || table.Length > 63 || !(char.IsAsciiLetter(table[0]) || table[0] == '_')
            || !table.All(c => char.IsAsciiLetterOrDigit(c) || c == '_'))
            throw new ArgumentException("table must be a plain SQL identifier ([A-Za-z_][A-Za-z0-9_]*)", nameof(table));
        _table = table;
    }

    /// <summary>Create the table when it does not exist.</summary>
    public void EnsureSchema()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = $"CREATE TABLE IF NOT EXISTS {_table} (key TEXT NOT NULL PRIMARY KEY, last_counter BIGINT NOT NULL)";
        cmd.ExecuteNonQuery();
        cmd.CommandText = $"CREATE TABLE IF NOT EXISTS {OnceTable} (key TEXT NOT NULL PRIMARY KEY, retain_until BIGINT NOT NULL)";
        cmd.ExecuteNonQuery();
        cmd.CommandText = $"CREATE INDEX IF NOT EXISTS {OnceTable}_retain ON {OnceTable} (retain_until)";
        cmd.ExecuteNonQuery();
        cmd.CommandText = $"CREATE TABLE IF NOT EXISTS {PinTable} (key TEXT NOT NULL PRIMARY KEY, pin BIGINT NOT NULL)";
        cmd.ExecuteNonQuery();
        cmd.CommandText = $"CREATE TABLE IF NOT EXISTS {BudgetTable} (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)";
        cmd.ExecuteNonQuery();
    }

    string BudgetTable => _table + "_budget";

    static string BudgetText(TrustBudget b) => string.Join("|", new[] { b.B, b.Tau, b.AsOf ?? double.NaN }.Select(x => x.ToString("R", CultureInfo.InvariantCulture)));

    static TrustBudget? ParseBudget(object? v)
    {
        if (v is null or DBNull) return null;
        var f = Convert.ToString(v, CultureInfo.InvariantCulture)!.Split('|');
        if (f.Length != 3) return null;
        var n = f.Select(x => double.Parse(x, CultureInfo.InvariantCulture)).ToArray();
        return new TrustBudget(n[0], n[1], double.IsNaN(n[2]) ? null : n[2]);
    }

    public TrustBudget? Budget(string key)
    {
        using var c = Open();
        using var sel = c.CreateCommand();
        sel.CommandText = $"SELECT value FROM {BudgetTable} WHERE key = @key";
        Param(sel, "@key", key);
        return ParseBudget(sel.ExecuteScalar());
    }

    /// <summary>ONE statement: a missing row is inserted (<c>old</c> null), an existing one is replaced only while its text still equals <c>old</c>.</summary>
    public bool BudgetCas(string key, TrustBudget? old, TrustBudget @new)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        if (old == null)
        {
            cmd.CommandText = $"INSERT INTO {BudgetTable} (key, value) VALUES (@key, @v) ON CONFLICT(key) DO NOTHING";
            Param(cmd, "@key", key);
            Param(cmd, "@v", BudgetText(@new));
        }
        else
        {
            cmd.CommandText = $"UPDATE {BudgetTable} SET value = @v WHERE key = @key AND value = @old";
            Param(cmd, "@v", BudgetText(@new));
            Param(cmd, "@key", key);
            Param(cmd, "@old", BudgetText(old));
        }
        return cmd.ExecuteNonQuery() == 1;
    }

    string PinTable => _table + "_pin";

    public long? Pin(string key)
    {
        using var c = Open();
        using var sel = c.CreateCommand();
        sel.CommandText = $"SELECT pin FROM {PinTable} WHERE key = @key";
        Param(sel, "@key", key);
        var v = sel.ExecuteScalar();
        return v is null or DBNull ? null : Convert.ToInt64(v, CultureInfo.InvariantCulture);
    }

    /// <summary>ONE upsert that only ever raises (<c>WHERE excluded.pin &gt; table.pin</c>), then a read of the stored value.</summary>
    public long RaisePin(string key, long value)
    {
        if (string.IsNullOrEmpty(key) || value < 0 || value > Pca.MaxSafeInt) throw new ArgumentException("RaisePin needs a non-empty key and 0 <= value <= 2^53-1");
        using var c = Open();
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = $"INSERT INTO {PinTable} (key, pin) VALUES (@key, @pin) ON CONFLICT(key) DO UPDATE SET pin = excluded.pin WHERE excluded.pin > {PinTable}.pin";
            Param(cmd, "@key", key);
            Param(cmd, "@pin", value);
            cmd.ExecuteNonQuery();
        }
        return Pin(key) ?? value;
    }

    string OnceTable => _table + "_once";

    /// <summary>TTL'd consume-once over the <c>&lt;table&gt;_once</c> table (created by <see cref="EnsureSchema"/>): expired rows are
    /// pruned, then ONE upsert inserts the key or revives an EXPIRED row (<c>WHERE retain_until &lt; now</c>); one affected row means
    /// this call consumed it. A live row is only ever extended (<c>retain_until</c> never shortens).</summary>
    public bool ConsumeOnce(string key, long retainUntilMs, long nowMs)
    {
        if (string.IsNullOrEmpty(key) || retainUntilMs < nowMs || retainUntilMs > Pca.MaxSafeInt || nowMs < 0)
            throw new ArgumentException("ConsumeOnce needs a non-empty key and 0 <= nowMs <= retainUntilMs <= 2^53-1");
        using var c = Open();
        using (var del = c.CreateCommand())
        {
            del.CommandText = $"DELETE FROM {OnceTable} WHERE retain_until < @now";
            Param(del, "@now", nowMs);
            del.ExecuteNonQuery();
        }
        using (var ins = c.CreateCommand())
        {
            ins.CommandText = $"INSERT INTO {OnceTable} (key, retain_until) VALUES (@key, @r) ON CONFLICT(key) DO UPDATE SET "
                + $"retain_until = excluded.retain_until WHERE {OnceTable}.retain_until < @now";
            Param(ins, "@key", key);
            Param(ins, "@r", retainUntilMs);
            Param(ins, "@now", nowMs);
            if (ins.ExecuteNonQuery() == 1) return true;
        }
        using var ext = c.CreateCommand();
        ext.CommandText = $"UPDATE {OnceTable} SET retain_until = @r WHERE key = @key AND retain_until < @r";
        Param(ext, "@key", key);
        Param(ext, "@r", retainUntilMs);
        ext.ExecuteNonQuery();
        return false;
    }

    public ClaimResult? Claim(string key, long counter)
    {
        if (key is null || counter < 0 || counter > Pca.MaxSafeInt) return new ClaimResult(false);
        using var c = Open();
        using (var cmd = c.CreateCommand())
        {
            cmd.CommandText = $"INSERT INTO {_table} (key, last_counter) VALUES (@key, @counter) ON CONFLICT(key) DO UPDATE SET "
                + $"last_counter = excluded.last_counter WHERE excluded.last_counter > {_table}.last_counter";
            Param(cmd, "@key", key);
            Param(cmd, "@counter", counter);
            if (cmd.ExecuteNonQuery() == 1) return new ClaimResult(true);
        }
        using (var sel = c.CreateCommand())
        {
            sel.CommandText = $"SELECT last_counter FROM {_table} WHERE key = @key";
            Param(sel, "@key", key);
            var v = sel.ExecuteScalar();
            return new ClaimResult(false, v is null or DBNull ? null : Convert.ToInt64(v, CultureInfo.InvariantCulture));
        }
    }

    public long? Last(string key)
    {
        using var c = Open();
        using var sel = c.CreateCommand();
        sel.CommandText = $"SELECT last_counter FROM {_table} WHERE key = @key";
        Param(sel, "@key", key);
        var v = sel.ExecuteScalar();
        return v is null or DBNull ? null : Convert.ToInt64(v, CultureInfo.InvariantCulture);
    }

    DbConnection Open()
    {
        var c = _connect() ?? throw new InvalidOperationException("the connection factory returned null");
        if (c.State != System.Data.ConnectionState.Open) c.Open();
        return c;
    }

    static void Param(DbCommand cmd, string name, object value)
    {
        var p = cmd.CreateParameter();
        p.ParameterName = name;
        p.Value = value;
        cmd.Parameters.Add(p);
    }
}

/// <summary>Outcome of <see cref="Pca.Authorize"/>. <see cref="Allow"/> is the one thing a caller must branch on.
/// <see cref="Status"/> is 200, 401 (no / undecodable / unauthenticated proof) or 403. <see cref="Checks"/> maps each check
/// to <c>pass</c>, <c>fail</c> or <c>not-enforced</c>; <see cref="Reason"/> is the decisive one (an <c>operation</c>
/// failure first). <see cref="Missing"/> names configuration components that were absent (the call was refused before
/// any verification).</summary>
public sealed class AuthorizeResult
{
    public bool Allow { get; init; }
    public int Status { get; init; }
    public IReadOnlyDictionary<string, string> Checks { get; init; } = new Dictionary<string, string>();
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    public string? Reason { get; init; }
    public AuthorizedOperation? Operation { get; init; }
    public Dictionary<string, object?>? Pcactn { get; init; }
    public Verdict? Verdict { get; init; }
    /// <summary>The risk score <c>r</c> the decision priced (null when the grant carries no readable envelope).</summary>
    public double? RiskScore { get; init; }
    /// <summary>The threshold the action needs, derived from the server-held risk and the trust budget.</summary>
    public RequiredThreshold? RequiredThreshold { get; init; }
    /// <summary>The trust budget after the decision (leaked to now, debited when the action ran without a human).</summary>
    public TrustBudget? Budget { get; init; }
    /// <summary>With <see cref="AuthorizeInput.Forbid"/>: the certificate of the forbid-wins decision that allowed the call.</summary>
    public Dictionary<string, object?>? ForbidCertificate { get; init; }
    public IReadOnlyList<string>? Missing { get; init; }
    /// <summary><c>allow</c> (and <see cref="Allow"/> is true), <c>escalate</c> (refused: <see cref="Escalation"/> is the request to
    /// put to the principal) or <c>deny</c>. <see cref="Allow"/> is exactly <c>Decision == "allow"</c>: an escalate is never an allow.</summary>
    public string Decision { get; init; } = "deny";
    /// <summary>The escalation request of an <c>escalate</c>; <c>{answered_by}</c> on an allow admitted by an answer.</summary>
    public Dictionary<string, object?>? Escalation { get; init; }
    /// <summary>The passing checks that rest on a compatibility mode (check name -&gt; why): <c>tighten</c> under rule 21's
    /// <c>model_polarity</c> "legacy". A caller with a high-assurance policy must not accept a degraded pass.</summary>
    public IReadOnlyDictionary<string, string>? Degraded { get; init; }
    /// <summary>The per-check assurance report (T8): what each passing check rests on. The capability chain check is reported as <c>cap_chain</c>.</summary>
    public AssuranceReport Assurance { get; init; } = new();
    /// <summary>Set when the allow replaced an escalation with a veto window (<see cref="AuthorizeInput.Undo"/>): the admission the undo
    /// coordinator returned. The action runs now; the principal can undo it until <see cref="UndoAdmission.WindowEnd"/>.</summary>
    public UndoAdmission? Undo { get; init; }
    /// <summary>The obligations the enforcement point accepts with this allow: <c>{kind: "undo_window", params: {id, window_end}, due: window_end}</c>
    /// under a veto window (report the effect, let the window run); null when none. A PEP that does not run undo windows must refuse it
    /// (<see cref="AtlasPca.Obligations.PepObligationGate"/>).</summary>
    public IReadOnlyList<object?>? Obligations { get; init; }
}

/// <summary>What a <see cref="AuthorizeInput.ThresholdHook"/> reports: whether it enforced a threshold (<see cref="Enforced"/>), whether the proof verified
/// (<see cref="Ok"/>) and the t it enforced (<see cref="T"/>; null: unreported).</summary>
public sealed record ThresholdHookResult(bool Enforced, bool Ok, double? T = null, string? Reason = null);

/// <summary>The freshness gate (<see cref="AuthorizeInput.EnforceFreshness"/>): the signed <c>freshness</c> anchor must name a beacon and a positive epoch, must not lie in the
/// future (beyond <see cref="ClockSkewMs"/>) and must be at most <see cref="MaxAgeMs"/> old. The anchor time is <c>epoch * EpochMs</c>.</summary>
public sealed record FreshnessGate(double MaxAgeMs, double EpochMs = 60_000, double? Now = null, double? ClockSkewMs = null);

/// <summary>The information-flow taint gate (<see cref="AuthorizeInput.EnforceTaint"/>): the registry and resource graph the server classifies the declared lineage with, and the
/// highest taint (0, 0.25, 0.5, 0.75 or 1) the policy accepts.</summary>
public sealed record TaintGate(TaintContext Context, double MaxTaint);

/// <summary>The forbid-wins policy of <see cref="AuthorizeInput.Forbid"/> (see <see cref="Forbid"/>): <see cref="Clauses"/> yields the clause list for the operation (and the resolved grant),
/// <see cref="Clause"/> the cross-signer options, <see cref="Context"/> the <c>subject</c> / <c>env</c> the clause predicates read (the operation supplies the action; a member returned here
/// replaces the same member), and <see cref="RequireCertificate"/> makes the call present a <see cref="AuthorizeInput.ForbidCertificate"/> that is RECOMPUTED, never trusted.</summary>
public sealed record ForbidOptions(Func<Operation, Dictionary<string, object?>?, object?> Clauses, ClauseOptions? Clause = null, Func<AuthorizeInput, Dictionary<string, object?>?>? Context = null, bool RequireCertificate = false);

/// <summary>What a principal resolver answers for a grant issuer.</summary>
public sealed record PrincipalInfo(bool Verified, string? SubjectType = null, string? SubjectId = null);

/// <summary>The passport requirement (<see cref="AuthorizeInput.RequirePassport"/>): the passport options (trusted issuers, skew, evidence age, revocation, pins, hardware verifier; the clock and
/// the subject are set per call: the leaf the PCActn names) and whether the passport must be hardware rooted.</summary>
public sealed record PassportRequirement(PassportOptions Options, bool Hardware = false);

/// <summary>K5 workflow admission option (C-308). <see cref="Principal"/> and <see cref="RsSigner"/> are the keys THIS server pinned (the
/// commitment's and the step receipts'); a key named inside either is never trusted.</summary>
public sealed record WorkflowGate(string Principal, string RsSigner, bool Required = false);

/// <summary>The workflow step ONE call claims to be: the signed commitment, the receipts so far (decoded JSON), the step id, the units
/// (null = {}) and the goal digest (null = none).</summary>
public sealed record WorkflowCall(object? Commitment, object? Receipts, string? Step, object? Units = null, string? GoalDigest = null);

/// <summary>The inputs of <see cref="Pca.Authorize"/>. <see cref="Audience"/>, <see cref="ResolveGrant"/>,
/// <see cref="StateStore"/>, <see cref="IsRevoked"/> and <see cref="Operation"/> are REQUIRED; a missing one denies.</summary>
public sealed class AuthorizeInput
{
    /// <summary>What the handler / tool will execute (from the server, never from the PCActn).</summary>
    public Operation? Operation { get; set; }
    /// <summary>This resource server's id (the PCActn's signed <c>aud</c> must equal it).</summary>
    public string? Audience { get; set; }
    /// <summary><c>grant_ref -&gt; grant</c> from your own store (null = unknown grant).</summary>
    public Func<string, Dictionary<string, object?>?>? ResolveGrant { get; set; }
    /// <summary>Asynchronous resolver, used by <see cref="Pca.AuthorizeAsync"/> instead of <see cref="ResolveGrant"/> when set
    /// (ignored by the synchronous <see cref="Pca.Authorize"/>).</summary>
    public Func<string, Task<Dictionary<string, object?>?>>? ResolveGrantAsync { get; set; }
    /// <summary>Replay store with an atomic claim (<see cref="MemoryStateStore"/>, <see cref="SqlStateStore"/>, or yours).</summary>
    public IStateStore? StateStore { get; set; }
    /// <summary><c>(pcactn, grant) -&gt; revoked?</c>; only <c>false</c> passes (true, null, or an exception denies).</summary>
    public Func<Dictionary<string, object?>, Dictionary<string, object?>, bool?>? IsRevoked { get; set; }
    /// <summary>A high-assurance policy (T8): when the evidence behind the passing checks is weaker, missing, unlabelled, awaiting-audit, degraded or
    /// unsupported, the <c>assurance</c> check fails and the request is denied before any replay state is written. <see cref="AssuranceHooks"/>
    /// carries the labels of the verifier's hooks (the report never trusts presented evidence). Every result carries the
    /// <see cref="AuthorizeResult.Assurance"/> report whether or not a requirement is set.</summary>
    public AssuranceRequirement? RequireAssurance { get; set; }
    /// <summary>The verifier's hooks whose assurance labels the report reads.</summary>
    public AssuranceHooks? AssuranceHooks { get; set; }
    /// <summary>The plan registry (T10). When the context names no plan, the plan the PCActn commits to (<c>plan.root</c>) is looked up for
    /// this grant: its nodes and whether it is executable now feed <c>plan_root_authorized</c>, and a plan that is not executable
    /// (unknown, not yet authorized, expired, revoked) also fails <c>plan_state</c> with the registry's reason.</summary>
    public PlanRegistry? Plans { get; set; }
    /// <summary>Revocation staleness (T9; off when null or empty): caps how old the revocation state may be, by the action's effective
    /// reversibility class (the stricter of the context's <c>reversibility_class</c> and the signed one; missing or unknown counts as
    /// irreversible). It needs <see cref="RevocationState"/> (the state source) and, for a signed epoch, <see cref="GuardianPublic"/>
    /// (plus <see cref="GuardianPins"/> for a post-quantum guardian). The result is the required <c>freshness</c> check;
    /// <see cref="IsRevoked"/> stays the revocation answer and works unchanged.</summary>
    public RevocationStalenessPolicy? RevocationStaleness { get; set; }
    /// <summary><c>(pcactn, grant) -&gt; state</c>: the guardian-signed epoch or bare root (with its issue time) the revocation answer rests on. An exception denies.</summary>
    public Func<Dictionary<string, object?>, Dictionary<string, object?>, RevocationState?>? RevocationState { get; set; }
    /// <summary>The pinned Ed25519 identity (base64url) of the epoch guardian.</summary>
    public string? GuardianPublic { get; set; }
    /// <summary>Which capability ids need a non-membership proof when <see cref="RevocationStaleness"/> is on. Default: every <c>id</c> in the PCActn's <c>cap_chain</c>; return an empty list for a freshness-only gate.</summary>
    public Func<Dictionary<string, object?>, IReadOnlyList<string>>? RevocationIds { get; set; }
    /// <summary><c>(pcactn, id) -&gt; proof</c>: the non-membership proof {size, lo?, hi?} for a capability id. Without it, or when it returns null, the request is denied (fail closed).</summary>
    public Func<Dictionary<string, object?>, string, Dictionary<string, object?>?>? RevocationProofFor { get; set; }
    /// <summary>PQ key pins of a post-quantum guardian ({Ed25519 identity: ML-DSA public key}).</summary>
    public IReadOnlyDictionary<string, string>? GuardianPins { get; set; }
    /// <summary>Epoch milliseconds (default: the wall clock).</summary>
    public long? Now { get; set; }
    /// <summary><c>"single-step"</c>: accept a one-node plan whose node is exactly this operation. Otherwise
    /// <see cref="Context"/> must return the principal-authorized <c>plan</c> with <c>plan_authorized: true</c>.</summary>
    public string? Plan { get; set; }
    /// <summary><c>pcactn -&gt; context</c> with optional <c>plan</c>, <c>plan_authorized</c>, <c>subject</c>, <c>env</c>,
    /// <c>blast_radius</c>, <c>recent_action_times</c>, <c>reversibility_class</c> (the server's authoritative class; the
    /// agent may only declare a stricter one). Null result = empty context; an exception denies.</summary>
    public Func<Dictionary<string, object?>, Dictionary<string, object?>?>? Context { get; set; }
    /// <summary>Forwarded to the core verifier.</summary>
    public IntentPolicy? IntentPolicy { get; set; }
    /// <summary>Intent Layer v2 verifier state (its <c>params</c> default to the operation's).</summary>
    public IntentV2Context? IntentV2 { get; set; }
    /// <summary>Per-proof Intent Layer v2 state (wins over <see cref="IntentV2"/>); an exception denies.</summary>
    public Func<Dictionary<string, object?>, IntentV2Context?>? IntentV2Provider { get; set; }
    /// <summary>Asynchronous <see cref="IntentV2Provider"/>, used by <see cref="Pca.AuthorizeAsync"/> only.</summary>
    public Func<Dictionary<string, object?>, Task<IntentV2Context?>>? IntentV2ProviderAsync { get; set; }
    /// <summary>Consistency-token (<c>fresh_at</c>) policy, forwarded to the core verifier. Null (the default): a PCActn carrying the
    /// member is refused (fail closed), one without is unaffected.</summary>
    public FreshAtPolicy? FreshAt { get; set; }
    /// <summary>Forwarded to the core verifier.</summary>
    public IReadOnlyCollection<string>? AllowedSuites { get; set; }
    /// <summary>Declares that several instances serve this resource. True with a process-scoped <see cref="StateStore"/> (<see cref="IStateStore.Scope"/>) is a
    /// configuration error (a process-scoped store lets one PCActn replay once per instance); false or null does not weaken anything the store
    /// declares. Null: on exactly when the store is shared.</summary>
    public bool? MultiInstance { get; set; }
    /// <summary>The risk inputs the SERVER derives for this operation (each in [0,1]: <c>semanticDistance</c>, <c>reversibility</c>, <c>blastRadius</c>, <c>taint</c>,
    /// <c>confidence</c>, <c>age</c>); merged over <c>Context["risk"]</c>. A missing or non-finite input is its WORST case (age comes from the trust
    /// budget, the semantic distance from the plan), so a deployment that supplies none step-ups every action to t=3.</summary>
    public IReadOnlyDictionary<string, double>? ServerRisk { get; set; }
    /// <summary>Like <see cref="ServerRisk"/>, computed per call from the operation, the grant and the PCActn; its members win.</summary>
    public Func<Operation, Dictionary<string, object?>, Dictionary<string, object?>, IReadOnlyDictionary<string, double>?>? ServerRiskFor { get; set; }
    /// <summary>The threshold co-signature hook: reports whether it ENFORCED a threshold on this PCActn and the t it enforced. An action whose server-derived
    /// threshold is above 1 is refused (check <c>threshold</c>) unless the hook enforced at least that t. Null or an unenforcing hook: <c>not-enforced</c>; a throw fails the check.</summary>
    public Func<Dictionary<string, object?>, Dictionary<string, object?>, ThresholdHookResult?>? ThresholdHook { get; set; }
    /// <summary>Risk input names the server MUST have supplied (check <c>risk_inputs</c>); a missing one fails. Null: not checked.</summary>
    public IReadOnlyList<string>? RequireRiskInputs { get; set; }
    /// <summary>A tightened risk policy (check <c>adaptive</c>): it may only NARROW the grant's own policy, so an action it would put at a HIGHER threshold than the grant's own policy does is refused.</summary>
    public RiskPolicy? Adaptive { get; set; }
    /// <summary>The time-based form of <see cref="Adaptive"/>: called with the decision time (epoch ms), it returns the tightened policy (a <see cref="RiskPolicy"/> or a <c>risk_policy</c> JSON object) or null
    /// for none. An invalid policy refuses the call (<c>adaptive: invalid policy (&lt;why&gt;)</c>); a throwing delegate refuses too. It wins over the fixed <see cref="Adaptive"/>.</summary>
    public Func<long, object?>? AdaptivePolicy { get; set; }
    /// <summary>A durable contract enforcer (check <c>contract</c>): the action is first PEEKED against the stored contract state (a violation or a latch refuses the call before its replay counter is
    /// spent), and the state advances (committing a latch on a violation) only once the action is admitted. Null: off.</summary>
    public ContractEnforcer? Contracts { get; set; }
    /// <summary>The forbid-wins policy (check <c>forbid</c>; see <see cref="ForbidOptions"/>): a forbid beats every permit; a decision other than allow refuses the call before its replay counter is spent. Null: off.</summary>
    public ForbidOptions? Forbid { get; set; }
    /// <summary>The certificate the call presents (see <see cref="ForbidOptions.RequireCertificate"/>).</summary>
    public object? ForbidCertificate { get; set; }
    /// <summary>Require the grant to be a linked template instantiation (check <c>template</c>): it must carry a <c>template_ref</c> that resolves in the registry this returns
    /// (<c>{templates, overlays?, trusted, params?}</c>, signed by a trusted organisation key, with any verified tighten overlay) and the grant's policy must equal the instantiation.</summary>
    public Func<object?>? RequireLinkedTemplate { get; set; }
    /// <summary>The dead-man liveness beacon of this grant (check <c>beacon</c>; see <see cref="Beacons"/>): <c>(grant_ref, pcactn) -&gt; beacon</c>. When it presents one it must verify under
    /// the pinned issuers, must not be older than the highest sequence already accepted (the host's value and the <c>&lt;grant id&gt;:beacon</c> pin of the state store, which a beacon
    /// replay protection REQUIRES to implement <see cref="IPinStore"/>), and must be the one the PCActn's signed <c>freshness.beacon_ref</c> commits. No beacon: <c>not-enforced</c>.</summary>
    public Func<string, Dictionary<string, object?>, BeaconPresented?>? Beacon { get; set; }
    /// <summary>The information-flow taint gate (check <c>taint_gate</c>; see <see cref="TaintGate"/>). Null: <c>not-enforced</c>.</summary>
    public TaintGate? EnforceTaint { get; set; }
    /// <summary>The freshness gate (check <c>freshness</c>; see <see cref="FreshnessGate"/>). Null: off.</summary>
    public FreshnessGate? EnforceFreshness { get; set; }
    /// <summary>Resolves the grant issuer to an enrolled principal (check <c>principal</c>: pass when verified, else not-enforced; a throw is unverified).</summary>
    public Func<string, Dictionary<string, object?>, PrincipalInfo?>? ResolvePrincipal { get; set; }
    /// <summary>Deny unless <see cref="ResolvePrincipal"/> yields a verified principal.</summary>
    public bool RequireVerifiedPrincipal { get; set; }
    /// <summary>Require a verified agent passport (check <c>passport</c>), decided BEFORE the replay counter is spent; the passport's subject must be the leaf the PCActn names.</summary>
    public PassportRequirement? RequirePassport { get; set; }
    /// <summary>The signed passport presented with the call (see <see cref="RequirePassport"/>).</summary>
    public object? Passport { get; set; }
    /// <summary>Server-side post-quantum pins <c>grant issuer -&gt; PQ public key</c> (check <c>pq_pin</c>, an authentication failure when it fails). An Ed25519
    /// grant has no PQ key to pin and passes whatever the pins are; a pure-PQ or hybrid grant passes only when the pins hold an own entry for its issuer that is
    /// byte-equal to the grant's <c>pq_pk</c> (a missing pin is <c>no server-side PQ pin for the grant issuer (suite &lt;alg&gt;)</c>, a different one
    /// <c>the grant pq_pk does not match the server-side pin</c>). Null (the default): the check is not reported and the stored grant alone roots the key.</summary>
    public IReadOnlyDictionary<string, string>? PqPins { get; set; }
    /// <summary>Checks whose status may be <c>unsupported</c> without denying. A PCActn carrying a feature this verifier does not implement
    /// (today <c>bond_ref</c>, check <c>bond</c>) reports it as <c>unsupported</c>, never a pass, and is denied unless the check is listed here.</summary>
    public IReadOnlyCollection<string>? AllowUnsupported { get; set; }
    /// <summary>Extra check names that must pass (the defaults always apply).</summary>
    public IEnumerable<string>? Require { get; set; }
    /// <summary>The pinned principal keys whose <see cref="AtlasPca.Escalation"/> answers count (empty: every escalate is refused).</summary>
    public IReadOnlyList<PinnedSigner>? EscalationPrincipals { get; set; }
    /// <summary>The principal's signed answer for THIS action (parsed JSON). A verdict whose every failing check is escalate-class is
    /// decision <c>escalate</c>; it is admitted only by a valid answer bound to this grant, this PCActn and the holder's history head
    /// (the <see cref="StateStore"/> must also implement <see cref="ILastStore"/>); the replay claim spends it; an answer never
    /// upgrades a deny.</summary>
    public object? EscalationAnswer { get; set; }
    /// <summary>How long an issued escalation request is valid, ms (null: one hour; 0 expires it at once).</summary>
    public long? EscalationRequestTtlMs { get; set; }
    /// <summary>K7: recompute H(R), the canonical approval render digest, from the executed params and the verifier's own definition
    /// (<see cref="Approval.Render"/> + <see cref="Approval.RenderDigest"/>); null means none could be derived. By default an answer is
    /// admitted only over a recomputed render and must be signed over exactly it.</summary>
    public Func<Dictionary<string, object?>, string?>? EscalationRender { get; set; }
    /// <summary>The documented INSECURE opt-out of that default: accept escalation answers with no recomputed render (an answer that
    /// carries a render is still refused when none was recomputed).</summary>
    public bool InsecureUnboundApproval { get; set; }

    /// <summary>K5 (C-308; null = off): the workflow admission gate. With a <see cref="WorkflowCall"/> the step is decided by
    /// <see cref="Workflow.AdmitStep"/> BEFORE the replay stage (a refusal never spends the PCActn's counter); without one the call is refused
    /// when <see cref="WorkflowGate.Required"/>. A non-allow is a 403 with the single failing check <c>workflow</c> (decision <c>escalate</c> for an escalate).</summary>
    public WorkflowGate? Workflow { get; set; }
    /// <summary>The workflow step THIS call is (read only when <see cref="Workflow"/> is set).</summary>
    public WorkflowCall? WorkflowCall { get; set; }

    /// <summary>Provenance by default (check <c>provenance_flow</c>; <see cref="ArgProvenance"/>). ALWAYS ON: an operation of a sensitive action
    /// (anything the <see cref="ArgProvenanceOptions.Actions"/> facts do not define as read-only, and every unknown action) is <c>escalate</c>
    /// unless its choice and every sink argument derive from the principal: a verified mediator chain whose context was the principal's own
    /// message, a value the principal typed verbatim, an executable principal-authorized plan from <see cref="Plans"/>, or an admitted
    /// <see cref="Workflow"/> step (the choice only). A principal-signed escalation answer admits the escalated call; a forged or malformed
    /// bundle is <c>deny</c>. This only configures the gate (pins, action facts, observations); null = no pins, unknown actions, no
    /// observations. The ONLY opt-out is the grant's signed envelope member <c>provenance: {mode: "insecure_off"}</c> (dangerous: injected
    /// content can then steer the grant's sensitive actions); the envelope may also name the principal's own mediator pins.</summary>
    public ArgProvenanceOptions? ProvenanceFlow { get; set; }
    /// <summary>The provenance bundle presented with THIS call (parsed JSON, <see cref="ProvenanceRecorder.ForAction"/>); null = none (unlabelled).
    /// A request reader fills it from the <c>PCA-Provenance</c> header or the <c>pca_provenance</c> body member (<see cref="ArgProvenance.ReadBundle"/>).</summary>
    public object? Provenance { get; set; }
    /// <summary>Set by a request reader when the request presented a bundle that does not decode (<see cref="ArgProvenance.ReadBundle"/>):
    /// <c>provenance_flow</c> fails closed (deny).</summary>
    public bool ProvenanceUnreadable { get; set; }
    /// <summary>Optional undo windows: <c>(pcactn, grant, operation) -&gt; admission</c>. Called ONLY when the decision is <c>escalate</c>, no
    /// escalation answer was presented, and the escalation is not a provenance one (<c>provenance_flow</c> or Intent Layer v2 <c>provenance</c>
    /// failing: reversibility does not make an action injected content chose safe to run). CONTRACT: return an admission only after your undo
    /// coordinator (the TypeScript coordinator or the hosted ledger) has DURABLY opened the window's record for this action and confirmed the
    /// action reversible with a compensation the grant authorizes; return null otherwise. A null, an exception or an admission whose obligation
    /// is malformed is no admission (the escalation stands). On admission every failing (escalate-class) check passes, <c>undo_window</c>
    /// passes, the decision is allow and the result carries <see cref="AuthorizeResult.Undo"/> and the <c>undo_window</c> obligation.</summary>
    public Func<Dictionary<string, object?>, Dictionary<string, object?>, Operation, UndoAdmission?>? Undo { get; set; }

    /// <summary>A shallow copy (the executor sets the operation per call on a copy of its configuration).</summary>
    internal AuthorizeInput CloneForCall() => (AuthorizeInput)MemberwiseClone();
    /// <summary>Caveat language v2 input per request (<see cref="K1Input"/>: the verifier's discharge pins, the discharges and narrow block
    /// the request carries, revoked discharges, the verified SPIFFE ID, the holder's history). The callback receives the PCActn and
    /// returns null for "none". Null (the default) changes nothing except that a K1 caveat type (<c>needs_discharge</c>, <c>sealed</c>,
    /// <c>max_uses</c>, <c>derive</c>, <c>spiffe_bound</c>) is refused (the caveat language is not configured). When set, K1 caveats of the leaf hop and a verified narrow
    /// block are evaluated by <see cref="CaveatLang.EvaluateK1"/> (the verifier computes the action digest itself), a narrow block's plain
    /// caveats join the delegated list, and <c>max_uses</c> is spent in the replay store only after the counter claim succeeded.</summary>
    public Func<Dictionary<string, object?>, K1Input?>? K1 { get; set; }
}

public static partial class Pca
{
    public const string EnvelopeCaveat = "envelope";

    /// <summary>The checks that must be <c>pass</c> (not merely "not failed"): the TypeScript <c>DEFAULT_REQUIRED_CHECKS</c>
    /// plus the operation binding and the policy. <see cref="AuthorizeInput.Require"/> can add names, never remove these.</summary>
    public static IReadOnlyList<string> DefaultRequiredChecks => new[]
        { "counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound", "operation", "params_digest", "policy" };

    // A failing one of these is an authentication failure (401), everything else is insufficient authority (403).
    public static IReadOnlyList<string> AuthnChecks => new string[] { "wire", "version", "audience", "validity", "chain", "grant_ref_bound", "leaf_signature", "malformed", "grant_ref", "pq_pin" };

    /// <summary>The store key of a holder's counter stream (the TypeScript <c>pcaStateKey</c> default scope).</summary>
    public static string StateKey(string grantId, string leafHolder) => grantId + ":" + leafHolder;

    // ---- the envelope (TypeScript envelope.ts readEnvelope / risk.ts validateRiskPolicy) ----

    internal static string? ValidateRiskPolicy(object? p)
    {
        // a JSON array is an object there, with no members
        if (p is not JD && p is not JL) return "risk_policy must be an object";
        var m = p as JD ?? new JD();
        var wo = IntentJs.Get(m, "weights");
        if (wo is not JD && wo is not JL) return "risk_policy.weights missing";
        var w = wo as JD ?? new JD();
        foreach (var k in new[] { "alpha", "beta", "gamma", "delta", "epsilon", "zeta" })
        {
            var v = Fin(IntentJs.Get(w, k));
            if (v is null || v < 0) return $"risk_policy.weights.{k} must be finite and >= 0";
        }
        var vals = new Dictionary<string, double>();
        foreach (var k in new[] { "theta1", "theta2", "kappa", "lambda", "rho", "bMax" })
        {
            var v = Fin(IntentJs.Get(m, k));
            if (v is null) return $"risk_policy.{k} must be finite";
            vals[k] = v.Value;
        }
        if (vals["theta1"] < 0 || vals["theta2"] < vals["theta1"]) return "risk_policy requires 0 <= theta1 <= theta2";
        if (vals["kappa"] <= 0) return "risk_policy.kappa must be > 0";
        if (vals["lambda"] < 0 || vals["rho"] < 0 || vals["bMax"] < 0) return "risk_policy lambda/rho/bMax must be >= 0";
        return null;
    }

    /// <summary>The grant's policy envelope: its FIRST <c>envelope</c> caveat without <c>type</c>, or null when absent or
    /// malformed (<c>goal_commit</c> a string, <c>predicates</c> and <c>caveats</c> lists, <c>agent_binding</c> an object or
    /// list, a valid <c>risk_policy</c>).</summary>
    public static Dictionary<string, object?>? ReadEnvelope(object? grant)
    {
        try
        {
            if (IntentJs.Get(grant, "caveats") is not JL cs) return null;
            var cv = cs.FirstOrDefault(c => c is JD d && IntentJs.Get(d, "type") is EnvelopeCaveat) as JD;
            if (cv is null) return null;
            var e = cv.Where(kv => kv.Key != "type").ToDictionary(kv => kv.Key, kv => kv.Value);
            if (IntentJs.Get(e, "goal_commit") is not string) return null;
            if (IntentJs.Get(e, "predicates") is not JL || IntentJs.Get(e, "caveats") is not JL) return null;
            if (IntentJs.Get(e, "agent_binding") is not (JD or JL)) return null;
            if (ValidateRiskPolicy(IntentJs.Get(e, "risk_policy")) != null) return null;
            return e;
        }
        catch (Exception) { return null; }
    }

    /// <summary>Every root caveat except the first <c>envelope</c> one (TypeScript <c>rootCaveats</c>); a non-list is
    /// returned as is, a non-object grant yields null.</summary>
    public static object? RootCaveats(object? grant) => Caveats.RootCaveats(grant);

    /// <summary>TypeScript <c>requiresAttestation</c>: any agent pin in <c>agent_binding</c> requires a bound attestation.</summary>
    internal static bool RequiresAttestation(object? binding)
    {
        var b = binding as JD ?? new JD();
        static bool Ne(object? x) => x is JL l && l.Count > 0;
        bool hasMin = b.TryGetValue("min_measurement", out var mm) && !(mm is string s && s.Length == 0);
        return Ne(IntentJs.Get(b, "model_allowlist")) || hasMin || (IntentJs.Get(b, "operator") is string op && op.Length > 0)
            || Ne(IntentJs.Get(b, "weights_allowlist")) || Ne(IntentJs.Get(b, "system_prompt_allowlist"))
            || Ne(IntentJs.Get(b, "tool_manifest_allowlist")) || IntentJs.Get(b, "require_hardware") is true
            || IntentJs.Get(b, "require_measured_weights") is true;
    }

    // ---- the semantic firewall: `tool_schema` caveats (TypeScript agent-native.ts) ----

    public const int MaxSchemaDepth = 8;
    public const int MaxSchemaNodes = 256;
    public const int MaxObjectProps = 64;
    public const int MaxEnumValues = 256;
    public const int DefaultMaxArrayItems = 256;
    public const int AbsoluteMaxArrayItems = 4096;
    public const int DefaultMaxStringLen = 65_536;
    public const int AbsoluteMaxStringLen = 1_048_576;
    public const int MaxValueNodes = 10_000;

    static Dictionary<string, string[]> SpecKeys => new()
    {
        ["string"] = new[] { "type", "enum", "const", "minLength", "maxLength", "prefix" },
        ["number"] = new[] { "type", "enum", "const", "min", "max" },
        ["integer"] = new[] { "type", "enum", "const", "min", "max" },
        ["boolean"] = new[] { "type", "enum", "const" },
        ["object"] = new[] { "type", "props", "required" },
        ["array"] = new[] { "type", "items", "minItems", "maxItems" },
    };

    sealed class Budget { public int N; }

    /// <summary>A finite JSON number as a double (JavaScript semantics), else null. A bool is never a number.</summary>
    static double? Fin(object? o)
    {
        double d;
        switch (o)
        {
            case Num n:
                if (!double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out d)) return null;
                break;
            case double x: d = x; break;
            case float x: d = x; break;
            case int x: d = x; break;
            case long x: d = x; break;
            case decimal x: d = (double)x; break;
            default: return null;
        }
        return double.IsFinite(d) ? d : null;
    }

    static bool IsIntegral(object? x) => Fin(x) is double f && Math.Floor(f) == f && !IntentJs.IsNegZero(f);
    static bool NonNegInt(object? x, int mx) => Fin(x) is double f && Math.Floor(f) == f && !IntentJs.IsNegZero(f) && f >= 0 && f <= mx;
    static bool SafeName(string n) => n.Length is >= 1 and <= 64 && n.All(c => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_');

    /// <summary>JavaScript <c>===</c> on the scalars a schema can hold (numbers compare as doubles; a bool is never a number).</summary>
    static bool JsEq(object? a, object? b)
    {
        var fa = Fin(a); var fb = Fin(b);
        if (fa != null || fb != null) return fa != null && fb != null && fa.Value == fb.Value;
        if (a is bool || b is bool) return a is bool x && b is bool y && x == y;
        if (a is string s && b is string t) return string.Equals(s, t, StringComparison.Ordinal);
        return false;
    }

    /// <summary>Validate a <c>tool_schema</c> argument schema (closed; shape, depth, node count, bounds). Null when valid.</summary>
    public static string? ValidateArgSchema(object? schema)
    {
        if (schema is not JD s) return "schema must be an object";
        if (!OnlyKeys(s, new[] { "props", "required" })) return "unknown schema key";
        return ObjectSchemaError(IntentJs.Get(s, "props"), s.TryGetValue("required", out var r), r, 1, new Budget());
    }

    static string? ObjectSchemaError(object? props, bool hasRequired, object? required, int depth, Budget budget)
    {
        if (depth > MaxSchemaDepth) return "schema too deep";
        if (++budget.N > MaxSchemaNodes) return "schema too large";
        if (props is not JD pm) return "props must be an object";
        if (pm.Count > MaxObjectProps) return "too many props";
        foreach (var (n, spec) in pm)
        {
            if (!SafeName(n)) return $"invalid property name '{(n.Length > 32 ? n[..32] : n)}'";
            var e = SpecError(spec, depth + 1, budget);
            if (e != null) return $"{n}: {e}";
        }
        if (hasRequired)
        {
            if (required is not JL rl || rl.Count > MaxObjectProps) return "required must be a short array";
            foreach (var r in rl) if (r is not string rs || !pm.ContainsKey(rs)) return "required names an undeclared property";
        }
        return null;
    }

    static string? SpecError(object? specObj, int depth, Budget budget)
    {
        if (depth > MaxSchemaDepth) return "schema too deep";
        if (++budget.N > MaxSchemaNodes) return "schema too large";
        if (specObj is not JD spec || IntentJs.Get(spec, "type") is not string t || !SpecKeys.ContainsKey(t)) return "unknown type";
        if (!OnlyKeys(spec, SpecKeys[t])) return "unknown spec key";
        if (t == "object")
        {
            budget.N--; // counted once by ObjectSchemaError
            return ObjectSchemaError(IntentJs.Get(spec, "props"), spec.TryGetValue("required", out var r), r, depth, budget);
        }
        if (t == "array")
        {
            bool hasMin = spec.TryGetValue("minItems", out var mi), hasMax = spec.TryGetValue("maxItems", out var ma);
            if (hasMin && !NonNegInt(mi, AbsoluteMaxArrayItems)) return "bad minItems";
            if (hasMax && !NonNegInt(ma, AbsoluteMaxArrayItems)) return "bad maxItems";
            if (hasMin && hasMax && Fin(mi) > Fin(ma)) return "minItems > maxItems";
            return SpecError(IntentJs.Get(spec, "items"), depth + 1, budget);
        }
        bool Ok(object? v) => t switch
        {
            "string" => v is string s && s.Length <= 1024,
            "boolean" => v is bool,
            _ => Fin(v) != null && (t == "number" || IsIntegral(v)),
        };
        if (spec.TryGetValue("const", out var cst) && !Ok(cst)) return "bad const";
        if (spec.TryGetValue("enum", out var en))
        {
            if (en is not JL el || el.Count == 0 || el.Count > MaxEnumValues || !el.All(Ok)) return "bad enum";
        }
        if (t == "string")
        {
            bool hasMin = spec.TryGetValue("minLength", out var mn), hasMax = spec.TryGetValue("maxLength", out var mx);
            if (hasMin && !NonNegInt(mn, AbsoluteMaxStringLen)) return "bad minLength";
            if (hasMax && !NonNegInt(mx, AbsoluteMaxStringLen)) return "bad maxLength";
            if (hasMin && hasMax && Fin(mn) > Fin(mx)) return "minLength > maxLength";
            if (spec.TryGetValue("prefix", out var pf) && (pf is not string ps || ps.Length > 512)) return "bad prefix";
        }
        else if (t is "number" or "integer")
        {
            bool hasMin = spec.TryGetValue("min", out var mn), hasMax = spec.TryGetValue("max", out var mx);
            if (hasMin && Fin(mn) is null) return "bad min";
            if (hasMax && Fin(mx) is null) return "bad max";
            if (hasMin && hasMax && Fin(mn) > Fin(mx)) return "min > max";
        }
        return null;
    }

    /// <summary>JavaScript <c>JSON.stringify(k.length &gt; 48 ? k.slice(0, 48) + '…' : k)</c>.</summary>
    static string Show(string k) => JsonQuote(k.Length > 48 ? k[..48] + "…" : k);

    static string JsonQuote(string s)
    {
        var sb = new StringBuilder("\"");
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { sb.Append(c).Append(s[i + 1]); i++; }
                    else if (char.IsSurrogate(c)) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }

    static string? CheckValue(JD spec, object? v, string path, int depth, Budget budget)
    {
        if (depth > MaxSchemaDepth + 1) return $"{path}: too deep";
        if (++budget.N > MaxValueNodes) return $"{path}: too many values";
        var t = IntentJs.Get(spec, "type");
        if (t is "object")
        {
            if (v is not JD o) return $"{path}: expected object";
            return CheckObject((JD)spec["props"]!, IntentJs.Get(spec, "required"), o, path, depth, budget);
        }
        if (t is "array")
        {
            if (v is not JL a) return $"{path}: expected array";
            double mx = Math.Min(spec.TryGetValue("maxItems", out var mi) ? Fin(mi)!.Value : DefaultMaxArrayItems, AbsoluteMaxArrayItems);
            if (a.Count > mx) return $"{path}: exceeds maxItems";
            if (spec.TryGetValue("minItems", out var mn) && a.Count < Fin(mn)!.Value) return $"{path}: below minItems";
            for (int i = 0; i < a.Count; i++)
            {
                var e = CheckValue((JD)spec["items"]!, a[i], $"{path}[{i}]", depth + 1, budget);
                if (e != null) return e;
            }
            return null;
        }
        if (t is "string")
        {
            if (v is not string s) return $"{path}: wrong type (expected string)";
            int n = s.Length; // UTF-16 code units, as JavaScript
            double mx = Math.Min(spec.TryGetValue("maxLength", out var ml) ? Fin(ml)!.Value : DefaultMaxStringLen, AbsoluteMaxStringLen);
            if (n > mx) return $"{path}: exceeds maxLength";
            if (spec.TryGetValue("minLength", out var mn) && n < Fin(mn)!.Value) return $"{path}: below minLength";
            if (spec.TryGetValue("prefix", out var pf) && !s.StartsWith((string)pf!, StringComparison.Ordinal)) return $"{path}: violates prefix";
        }
        else if (t is "number" or "integer")
        {
            var f = Fin(v);
            if (f is null || (t is "integer" && (Math.Floor(f.Value) != f.Value || IntentJs.IsNegZero(f.Value)))) return $"{path}: wrong type (expected {t})";
            if (spec.TryGetValue("min", out var mn) && f < Fin(mn)) return $"{path}: below min";
            if (spec.TryGetValue("max", out var mx) && f > Fin(mx)) return $"{path}: above max";
        }
        else if (t is "boolean")
        {
            if (v is not bool) return $"{path}: wrong type (expected boolean)";
        }
        else return $"{path}: unknown type";
        if (spec.TryGetValue("const", out var c) && !JsEq(c, v)) return $"{path}: violates const";
        if (spec.TryGetValue("enum", out var en) && !((JL)en!).Any(e => JsEq(e, v))) return $"{path}: violates enum";
        return null;
    }

    static string? CheckObject(JD props, object? required, JD obj, string path, int depth, Budget budget)
    {
        foreach (var k in obj.Keys) if (!props.ContainsKey(k)) return $"{path}: unexpected argument {Show(k)}";
        if (required is JL rl)
            foreach (var r in rl) if (!obj.ContainsKey((string)r!)) return $"{path}: missing required argument '{r}'";
        foreach (var (k, v) in obj)
        {
            var e = CheckValue((JD)props[k]!, v, $"{path}.{k}", depth + 1, budget);
            if (e != null) return e;
        }
        return null;
    }

    /// <summary>Evaluate a tool call against a <c>tool_schema</c> caveat (same rules and reasons as the TypeScript
    /// <c>evaluateToolSchema</c>). Never throws.</summary>
    public static (bool Ok, string? Reason) EvaluateToolSchema(object? caveat, ToolCall? call)
    {
        try
        {
            if (caveat is not JD cv || IntentJs.Get(cv, "type") is not "tool_schema" || IntentJs.Get(cv, "tool") is not string tool || tool.Length == 0)
                return (false, "malformed tool_schema caveat");
            var verr = ValidateArgSchema(IntentJs.Get(cv, "schema"));
            if (verr != null) return (false, "malformed tool_schema caveat: " + verr);
            var schema = (JD)cv["schema"]!;
            if (!Equals(HashCanonical(schema), IntentJs.Get(cv, "schema_digest"))) return (false, "schema digest mismatch");
            var sig = IntentRevocation.JsText(IntentJs.Get(cv, "signature_digest"), cv.ContainsKey("signature_digest"));
            if (!Equals(HashCanonical(new JD { ["tool"] = tool, ["signature_digest"] = sig, ["schema"] = schema }), IntentJs.Get(cv, "binding_digest")))
                return (false, "binding digest mismatch");
            if (call is null || call.Tool is null || call.Args is not JD args) return (false, "malformed call");
            if (call.Tool != tool) return (false, $"tool {Show(call.Tool)} not authorized");
            // the signature the runtime actually dispatches to: a swapped or shadowed tool changes its digest
            if (call.ToolSignature != null && !Equals(HashCanonical(call.ToolSignature), IntentJs.Get(cv, "signature_digest")))
                return (false, "tool signature differs from the authorized signature");
            if (call.ToolSignatureDigest != null && !Equals(call.ToolSignatureDigest, IntentJs.Get(cv, "signature_digest")))
                return (false, "signed tool_binding differs from the authorized tool signature");
            var e = CheckObject((JD)schema["props"]!, IntentJs.Get(schema, "required"), args, "args", 1, new Budget());
            return e != null ? (false, e) : (true, null);
        }
        catch (Exception) { return (false, "evaluation error (fail closed)"); }
    }

    // ---- the agent-native caveat evaluator (TypeScript evaluateAgentCaveats) ----

    static bool AgentCaveatSatisfied(object? cvObj, JD ctx, JD actionCtx, ToolCall? toolCall)
    {
        try
        {
            if (cvObj is not JD cv) return false;
            var t = IntentJs.Get(cv, "type");
            if (t is "tool_schema") return EvaluateToolSchema(cv, toolCall).Ok;
            if (t is "predicates")
            {
                if (IntentJs.Get(cv, "allow") is not JL allow) return false;
                return allow.Any(p => Predicates.PredicateMatches(p, actionCtx));
            }
            // max_spend and the stock types: the 0.4.1 evaluator (unknown types fail closed there)
            return Caveats.EvaluateCaveats(new JL { cv }, ctx).Ok;
        }
        catch (Exception) { return false; }
    }

    /// <summary>Evaluate caveats with the agent-native evaluator: the stock types of <see cref="Caveats.EvaluateCaveats"/>,
    /// plus <c>predicates</c> (<c>allow</c>: the action must match one predicate; needs <paramref name="actionCtx"/> =
    /// <c>{action: {...}, subject?, env?}</c>) and <c>tool_schema</c> (needs <paramref name="toolCall"/>).
    /// <paramref name="ctx"/> is the stock context (<c>now</c>, <c>action</c>, <c>blast_radius</c>, ...). Unknown types fail
    /// closed. Never throws.</summary>
    public static Caveats.Result EvaluateAgentCaveats(object? caveats, Dictionary<string, object?>? ctx,
        Dictionary<string, object?>? actionCtx = null, ToolCall? toolCall = null)
    {
        try
        {
            return SafeRegex.WithBudget(() =>
            {
                if (caveats is not JL list) return new Caveats.Result(false, new[] { "<malformed caveats>" });
                var failed = new List<string>();
                foreach (var cv in list)
                {
                    if (ctx is null) throw new ArgumentNullException(nameof(ctx)); // explicit: a null context refuses (the catch below), never reads as empty
                    if (!AgentCaveatSatisfied(cv, new JD(ctx), actionCtx ?? new JD(), toolCall))
                        failed.Add(cv is JD d && IntentJs.Get(d, "type") is string ts ? ts : "<malformed>");
                }
                return new Caveats.Result(failed.Count == 0, failed);
            });
        }
        catch (Exception) { return new Caveats.Result(false, new[] { "<evaluation error>" }); }
    }

    // ---- authorize ----

    internal static int ClassRank(object? c) => c switch
    {
        "reversible" => 0,
        "rate_limited" or "costly" => 1,
        _ => 2,
    };

    static AuthorizeResult Refuse(int status, string check, string reason, IReadOnlyList<string>? missing = null, JD? pcactn = null) =>
        new() { Allow = false, Status = status, Checks = new Dictionary<string, string> { [check] = "fail" }, Reasons = new[] { reason }, Reason = reason, Missing = missing, Pcactn = pcactn };

    /// <summary>Names of the required components that are absent (empty = complete): <c>Audience</c>, <c>ResolveGrant</c>,
    /// <c>StateStore</c>, <c>IsRevoked</c>, in that order.</summary>
    public const string MultiInstanceNeedsShared = "multiInstance requires a shared state store (a process-scoped store lets one PCActn replay once per instance)";
    public const string BeaconNeedsPins = "beacon replay protection needs a state store that implements pins";
    public const string StalenessNeedsPins = "revocation staleness needs a state store that implements pins (rollback protection)";
    /// <summary>The trust budget of one stream: per audience, grant and leaf holder (as the reference's replay state row).</summary>
    static string BudgetKeyOf(string? aud, JD grant, string grantRef, JD p)
    {
        var holder = IntentJs.Get(p, "cap_chain") is JL c && c.Count > 0 ? IntentJs.Get(c[^1], "holder") as string : null;
        return $"aud:{Uri.EscapeDataString(aud ?? "")}:{IntentJs.Get(grant, "id") as string ?? grantRef}:{holder}:budget";
    }

    static string PinKey(string grantId) => grantId + ":epoch";

    public static List<string> MissingAuthorizeComponents(AuthorizeInput? input) => MissingComponents(input, false);

    static List<string> MissingComponents(AuthorizeInput? input, bool async)
    {
        var missing = new List<string>();
        if (string.IsNullOrEmpty(input?.Audience)) missing.Add("Audience");
        if (input?.ResolveGrant is null && !(async && input?.ResolveGrantAsync is not null)) missing.Add("ResolveGrant");
        if (input?.StateStore is null) missing.Add("StateStore");
        if (input?.IsRevoked is null) missing.Add("IsRevoked");
        if (input?.MultiInstance == true && input.StateStore is { Scope: StoreScope.Process }) missing.Add(MultiInstanceNeedsShared);
        if (input?.Beacon != null && input.StateStore is not null and not IPinStore) missing.Add(BeaconNeedsPins);
        if (input?.RevocationStaleness is { IsOn: true } sp)
        {
            if (input.StateStore is not null and not IPinStore) missing.Add(StalenessNeedsPins);
            if (input.RevocationState is null) missing.Add("RevocationState (required by RevocationStaleness)");
            if (sp.Error() is { } bad) missing.Add("RevocationStaleness (invalid: " + bad + ")");
        }
        // an escalation answer is bound to the holder's history head: a store that cannot read it cannot be used with pinned principals
        if (input?.EscalationPrincipals is { Count: > 0 } && input.StateStore is not null and not ILastStore) missing.Add("StateStore.Last (required by EscalationPrincipals)");
        return missing;
    }

    /// <summary>The operation as a private JSON tree (canonical round trip), or null when it is not a valid operation.</summary>
    static (string Verb, string Resource, JD Params)? CopyOperation(Operation? op)
    {
        if (op is null || string.IsNullOrEmpty(op.Verb) || string.IsNullOrEmpty(op.Resource)) return null;
        var tree = ToJsonTree(op.Params, 0);
        if (tree is not JD) return null;
        return (op.Verb, op.Resource, (JD)ParseStrict(Canonicalize(tree))!);
    }

    /// <summary>Operation params exactly as <see cref="Authorize"/> reads them (a private canonical JSON tree); null when not a JSON object.
    /// Throws on an unsupported value.</summary>
    internal static JD? OperationParamsTree(object? prms) => ToJsonTree(prms, 0) is JD tree ? (JD)ParseStrict(Canonicalize(tree))! : null;

    /// <summary>The canonical JSON text of a host value (JSON.parse number semantics). Throws on an unsupported value.</summary>
    internal static string JsonText(object? v) => Canonicalize(ToJsonTree(v, 0));

    /// <summary>A JSON tree of a host value with JSON.parse number semantics (CLR numbers and <see cref="Num"/> spellings are
    /// read as binary64, as the TypeScript reference reads a parsed body).</summary>
    static object? ToJsonTree(object? v, int depth)
    {
        if (depth > MaxJsonDepth + 1) throw new InvalidOperationException("params nesting too deep");
        switch (v)
        {
            case null: return null;
            case string or bool: return v;
            case Num n: return IntentJs.NormNum(n.Raw);
            case int or long or short or byte or sbyte or ushort or uint:
                return new Num(Convert.ToInt64(v, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture));
            case double or float or decimal or ulong:
                return IntentJs.Normalize(Convert.ToDouble(v, CultureInfo.InvariantCulture));
            case JsonElement je: return FromJsonElement(je, depth);
            case IDictionary<string, object?> m:
                {
                    var o = new JD(StringComparer.Ordinal);
                    foreach (var (k, x) in m) o[k] = ToJsonTree(x, depth + 1);
                    return o;
                }
            case System.Collections.IEnumerable e:
                {
                    var l = new JL();
                    foreach (var x in e) l.Add(ToJsonTree(x, depth + 1));
                    return l;
                }
            default: throw new InvalidOperationException("params: unsupported value type " + v.GetType().Name);
        }
    }

    static object? FromJsonElement(JsonElement e, int depth) => e.ValueKind switch
    {
        JsonValueKind.Null => null,
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Number => IntentJs.NormNum(e.GetRawText()),
        JsonValueKind.Object => e.EnumerateObject().Aggregate(new JD(StringComparer.Ordinal), (o, p) =>
        {
            if (o.ContainsKey(p.Name)) throw new InvalidOperationException("params: duplicate key");
            o[p.Name] = ToJsonTree(p.Value, depth + 1);
            return o;
        }),
        JsonValueKind.Array => e.EnumerateArray().Select(x => ToJsonTree(x, depth + 1)).ToList(),
        _ => throw new InvalidOperationException("params: undefined JSON value"),
    };

    static (JD? P, string? Err) Coerce(object? pcactn)
    {
        switch (pcactn)
        {
            case JD d: return (d, null);
            case string s:
                if (ArtifactTooLarge(s)) return (null, "undecodable");
                return ParseObject(s);
            case byte[] b:
                if (b.Length > MaxArtifactBytes) return (null, "undecodable");
                string text;
                try { text = new UTF8Encoding(false, true).GetString(b); }
                catch (Exception) { return (null, "undecodable"); }
                return ParseObject(text);
            case null: return (null, "absent");
            default: return (null, "undecodable");
        }
    }

    static (JD? P, string? Err) ParseObject(string text)
    {
        try { return ParseStrict(text) is JD o ? (o, null) : (null, "undecodable"); }
        catch (Exception) { return (null, "undecodable"); }
    }

    sealed record Prepared(JD P, string GrantRef, (string Verb, string Resource, JD Params) Op);

    /// <summary>Stage 1 (configuration, operation, decode, grant_ref): a refusal, or the prepared request.</summary>
    static (AuthorizeResult? Refusal, Prepared? Ready) Prepare(object? pcactn, AuthorizeInput? input, bool async)
    {
        var missing = MissingComponents(input, async);
        if (input?.Plan != null && input.Plan != "single-step") missing.Add("Plan (only 'single-step' or null)");
        if (missing.Count > 0)
            return (Refuse(403, "authorize_config", $"authorize_config: missing required component(s): {string.Join(", ", missing)} (fail closed)", missing), null);
        var op = CopyOperation(input!.Operation);
        if (op is null)
            return (Refuse(403, "operation", "operation: authorize needs the operation to execute (verb, resource, params) (fail closed)"), null);
        // K5 (C-308): required-and-absent is decided BEFORE the decode (it needs no PCActn); an unreadable PCActn with a step is the decode's to refuse.
        if (input.Workflow is { Required: true } && input.WorkflowCall == null)
            return (Refuse(403, "workflow", "workflow: this call carries no workflow step (fail closed)"), null);
        var (p, err) = Coerce(pcactn);
        if (p is null) return (err == "absent" ? Refuse(401, "wire", "wire: no PCActn presented") : Refuse(401, "pcactn", "undecodable PCActn: could not be decoded"), null);
        if (IntentJs.Get(p, "grant_ref") is not string grantRef) return (Refuse(401, "malformed", "malformed: grant_ref is not a string", pcactn: p), null);
        return (null, new Prepared(p, grantRef, op.Value));
    }

    /// <summary>Authorize ONE operation: configuration, the core checks, revocation, a carried zk proof (refused), the
    /// operation binding (verb, resource and the signed params digest), grant_ref, params_digest, plan, attestation (refused
    /// when the grant pins the agent), reversibility, the delegated caveats and the policy (envelope predicates, envelope
    /// caveats, root caveats), the required checks, and only then the atomic replay claim. Never throws.</summary>
    public static AuthorizeResult Authorize(object? pcactn, AuthorizeInput input)
    {
        try
        {
            var (refusal, ready) = Prepare(pcactn, input, false);
            if (refusal != null) return refusal;
            JD? grant;
            try { grant = input.ResolveGrant!(ready!.GrantRef); }
            catch (Exception) { return Refuse(403, "resolve_grant", "resolve_grant: grant resolution failed (fail closed)", pcactn: ready!.P); }
            return Continue(ready, grant, input, null);
        }
        catch (Exception e) { return Refuse(403, "authorize", "authorize: error (fail closed): " + e.GetType().Name); }
    }

    /// <summary><see cref="Authorize"/> with an asynchronous grant resolver (<see cref="AuthorizeInput.ResolveGrantAsync"/>)
    /// and Intent Layer v2 provider (<see cref="AuthorizeInput.IntentV2ProviderAsync"/>). Same pipeline, same results.</summary>
    public static async Task<AuthorizeResult> AuthorizeAsync(object? pcactn, AuthorizeInput input)
    {
        try
        {
            var (refusal, ready) = Prepare(pcactn, input, true);
            if (refusal != null) return refusal;
            JD? grant;
            try
            {
                grant = input.ResolveGrantAsync != null ? await input.ResolveGrantAsync(ready!.GrantRef).ConfigureAwait(false)
                    : input.ResolveGrant!(ready!.GrantRef);
            }
            catch (Exception) { return Refuse(403, "resolve_grant", "resolve_grant: grant resolution failed (fail closed)", pcactn: ready!.P); }
            Func<JD, IntentV2Context?>? v2 = null;
            if (grant != null && input.IntentV2ProviderAsync != null)
            {
                // awaited here, surfaced in pipeline order (after the context callback) by Continue
                IntentV2Context? got = null; Exception? failed = null;
                try { got = await input.IntentV2ProviderAsync(ready.P).ConfigureAwait(false); }
                catch (Exception e) { failed = e; }
                v2 = _ => failed != null ? throw failed : got;
            }
            return Continue(ready, grant, input, v2);
        }
        catch (Exception e) { return Refuse(403, "authorize", "authorize: error (fail closed): " + e.GetType().Name); }
    }

    /// <summary>The <see cref="AuthorizeResult.Degraded"/>["tighten"] text of a verdict that passed rule 21 under model_polarity "legacy".</summary>
    public const string LegacyPolarityDegraded = "model_polarity 'legacy': a grant reads a model-derived value in where (rule 21)";

    static readonly AsyncLocal<Action<Verdict>?> CoreHookSlot = new();

    /// <summary>Test seam: may edit the core verdict (e.g. inject an escalate-class failure) before the pipeline reads it. Flows
    /// with the async context, so concurrent tests do not see each other's hook; always null in production.</summary>
    internal static Action<Verdict>? CoreHook { get => CoreHookSlot.Value; set => CoreHookSlot.Value = value; }

    static readonly AsyncLocal<Action?> WorkflowHookSlot = new();

    /// <summary>Test seam: runs inside the workflow-admission try, so its fail-closed catch is tested (nothing in the admission
    /// itself throws today). Flows with the async context; always null in production.</summary>
    internal static Action? WorkflowHook { get => WorkflowHookSlot.Value; set => WorkflowHookSlot.Value = value; }

    static readonly AsyncLocal<Action?> K1CheckHookSlot = new();

    /// <summary>Test seam: runs inside the try of the check for K1 caveats with no K1 option, so its fail-closed catch is tested (EvaluateK1 is
    /// total today). Flows with the async context; always null in production.</summary>
    internal static Action? K1CheckHook { get => K1CheckHookSlot.Value; set => K1CheckHookSlot.Value = value; }

    static AuthorizeResult? WorkflowRefusal(JD p, AuthorizeInput input, (string Verb, string Resource, JD Params) op, long now)
    {
        var w = input.Workflow!;
        var c = input.WorkflowCall;
        if (c == null) return w.Required ? Refuse(403, "workflow", "workflow: this call carries no workflow step (fail closed)", pcactn: p) : null;
        var root = IntentJs.Get(IntentJs.Get(p, "plan"), "root") as string; // null when unreadable: it cannot equal a committed root
        var request = new JD
        {
            ["step"] = c.Step, ["verb"] = op.Verb, ["resource"] = op.Resource, ["params"] = op.Params,
            ["units"] = c.Units ?? new JD(), ["goal_digest"] = c.GoalDigest, ["plan_root"] = root,
        };
        var d = Workflow.AdmitStep(new AdmitInput(c.Commitment, w.Principal, w.RsSigner, c.Receipts, now, request));
        if (d.Decision == "allow") return null;
        var why = $"workflow: {d.Code ?? "refused"}{(d.Step != null ? $" (step {d.Step})" : "")}";
        return new AuthorizeResult
        {
            Allow = false, Status = 403, Checks = new Dictionary<string, string> { ["workflow"] = "fail" }, Reasons = new[] { why }, Reason = why, Pcactn = p,
            Decision = d.Decision == "escalate" ? "escalate" : "deny",
        };
    }

    static AuthorizeResult Continue(Prepared ready, JD? grant, AuthorizeInput input, Func<JD, IntentV2Context?>? v2Override)
    {
        var p = ready.P;
        var op = ready.Op;
        var grantRef = ready.GrantRef;
        if (grant is null) return Refuse(401, "grant_ref", "grant_ref: does not resolve to a known grant", pcactn: p);

        long now = input.Now ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        JD ctx = new();
        if (input.Context != null)
        {
            try { ctx = input.Context(p) ?? new JD(); }
            catch (Exception) { return Refuse(403, "context", "context: the context callback failed (fail closed)", pcactn: p); }
        }

        PlanStatus? planStatus = null;
        // provenance_flow commitments: an executable principal-authorized plan from the registry (never one the request supplies), an admitted workflow step
        bool principalPlan = false, principalControl = false;
        if (input.Plans != null && IntentJs.Get(ctx, "plan") == null)
        {
            var planRoot = IntentJs.Get(IntentJs.Get(p, "plan"), "root") as string ?? "";
            try
            {
                var pc = input.Plans.Context(grantRef, planRoot, now);
                if (pc != null)
                {
                    ctx = new JD(ctx) { ["plan"] = pc.Plan, ["plan_authorized"] = pc.PlanAuthorized };
                    planStatus = pc.Status;
                    principalPlan = pc.PlanAuthorized && pc.Status.Executable;
                }
                else if (input.Plan != "single-step") planStatus = new PlanStatus(PlanStates.Unknown, false, $"plan {planRoot} is unknown to the plan registry");
            }
            catch (Exception) { return Refuse(403, "plan_state", "plan_state: the plan registry failed (fail closed)", pcactn: p); }
        }

        IntentV2Context? v2 = input.IntentV2;
        var provider = v2Override ?? input.IntentV2Provider;
        if (provider != null)
        {
            try { v2 = provider(p); }
            catch (Exception) { return Refuse(403, "intent_v2", "intent_v2: verifier state unavailable (fail closed)", pcactn: p); }
        }
        // Rules 20 / 21 read the signed envelope of the stored grant: when it carries units / tighten / model_polarity or a grant-side where
        // reads a model-derived path, the v2 pipeline needs the plaintext params and the host env even if the host configured no v2 context.
        if (v2 == null && IntentV2.NeedsModelRules(grant)) v2 = IntentV2Context.FromJson(new JD());
        if (v2 != null && v2.WellFormed) v2 = v2.WithDefaults(op.Params, IntentJs.Get(ctx, "env"));

        // ---- K5 workflow admission (C-308): decided before the guard and the replay claim, so a refusal never spends the counter
        if (input.Workflow != null)
        {
            try
            {
                WorkflowHook?.Invoke();
                var wr = WorkflowRefusal(p, input, op, now);
                if (wr != null) return wr;
                // an admitted step of the principal's signed workflow: the CHOICE of this action is the principal's (the values are not)
                principalControl = input.WorkflowCall != null;
            }
            catch (Exception) { return Refuse(403, "workflow", "workflow: error (fail closed)", pcactn: p); }
        }

        // ---- 1. the core checks
        var core = VerifyPcactnCore(p, grant, now, input.Audience!, input.AllowedSuites, input.IntentPolicy, v2, input.FreshAt, PlanRootPolicy.Skip); // Authorize decides plan_root_authorized itself
        CoreHook?.Invoke(core);
        if (core.Checks.TryGetValue("wire", out var wireOk) && !wireOk)
        {
            var r = core.Reason.Length > 0 ? core.Reason : "wire: malformed PCActn";
            return new AuthorizeResult
            {
                Allow = false, Status = 401, Checks = new Dictionary<string, string> { ["wire"] = "fail", ["malformed"] = "fail" },
                Reasons = new[] { r }, Reason = r, Pcactn = p, Verdict = core,
            };
        }
        var checks = new Dictionary<string, string>();
        var order = new List<string>();
        void Mark(string name, string status) { if (!checks.ContainsKey(name)) order.Add(name); checks[name] = status; }
        foreach (var (k, ok) in core.Checks) Mark(k, ok ? "pass" : "fail");
        var reasons = new List<string>();
        if (!core.Allow)
        {
            // the first failure, then every further failing v2 check (the whole set decides escalate vs deny)
            if (core.Reasons.Count > 0) reasons.AddRange(core.Reasons);
            else if (core.Reason.Length > 0) reasons.Add(core.Reason);
        }
        void Fail(string name, string why) { Mark(name, "fail"); reasons.Add(name + ": " + why); }

        // ---- 2. revocation (required) and a carried zk proof (no verifier here: fail closed)
        bool? revoked;
        try { revoked = input.IsRevoked!(p, grant); }
        catch (Exception) { revoked = null; }
        if (revoked == false) Mark("revocation", "pass");
        else Fail("revocation", revoked == true ? "the grant is revoked" : "the revocation check failed (fail closed)");
        bool freshnessOn = input.RevocationStaleness is { IsOn: true };
        double? freshEpoch = null; // the signed epoch of an admitted freshness pass: raises the rollback pin once the action is allowed
        if (freshnessOn)
        {
            RevocationState? st = null; bool failedSource = false;
            try
            {
                st = input.RevocationState!(p, grant);
                // the stored pin is the floor under whatever last-accepted epoch the host supplied (rollback protection)
                if (IntentJs.Get(grant, "id") is string pgid && input.StateStore is IPinStore pins && pins.Pin(PinKey(pgid)) is long pin && st != null)
                    st = st with { LastAcceptedEpoch = Math.Max(st.LastAcceptedEpoch ?? pin, pin) };
            }
            catch (Exception) { failedSource = true; }
            string? why = failedSource ? "the revocation state source failed (fail closed)" : RevocationFreshness.ForAuthorize(input, ctx, p, st, now);
            if (why == null)
            {
                Mark("freshness", "pass");
                if (st?.Epoch != null && IntentJs.NumOf(IntentJs.Get(st.Epoch, "epoch")) is double fe) freshEpoch = fe;
            }
            else Fail("freshness", why);
        }
        // the core refuses a carried proof too; it keeps only its first failure, so name this one when an earlier check took that slot
        if (p.ContainsKey("zk_compliance") && !reasons.Contains("zk_compliance: " + ZkUnenforced)) Fail("zk_compliance", ZkUnenforced);

        var action = IntentJs.Get(p, "action") as JD ?? new JD();
        var signedDigest = IntentJs.Get(action, "params_digest");
        var opDigest = ParamsDigest(op.Params);
        string Js(object? x) => IntentRevocation.JsText(x, true);

        // ---- 3. the operation binding
        if (!Equals(IntentJs.Get(action, "verb"), op.Verb) || !Equals(IntentJs.Get(action, "resource"), op.Resource))
            Fail("operation", $"the proof is for {Js(IntentJs.Get(action, "verb"))} on {Js(IntentJs.Get(action, "resource"))}, but this operation is {op.Verb} on {op.Resource}");
        else if (!Equals(opDigest, signedDigest))
            Fail("operation", $"the proof's params_digest does not match the params of this {op.Verb} operation");
        else Mark("operation", "pass");

        // ---- 4. server-side PQ pin (a non-Ed25519 grant needs a matching pin), grant_ref, params, plan, attestation, reversibility
        if (input.PqPins is { } pqPins)
        {
            var galg = IntentJs.Get(grant, "alg") as string ?? "ed25519";
            var pin = IntentJs.Get(grant, "issuer") is string gi && pqPins.TryGetValue(gi, out var pv) ? pv : null;
            // a pin exists so that a quantum attacker who recovers an issuer's classical key cannot mint grants: a classical grant from a PINNED issuer is refused
            if (galg == "ed25519" && IntentJs.Get(grant, "issuer") is string gi0 && pqPins.ContainsKey(gi0))
                Fail("pq_pin", "the grant issuer is pinned to a post-quantum key; a classical grant is refused");
            else if (galg == "ed25519") Mark("pq_pin", "pass");
            else if (pin != null && IntentJs.Get(grant, "pq_pk") is string gpk && pin == gpk) Mark("pq_pin", "pass");
            else Fail("pq_pin", pin == null ? $"no server-side PQ pin for the grant issuer (suite {galg})" : "the grant pq_pk does not match the server-side pin");
        }
        // the reference's M1 taint gate: lineage the server cannot verify, or above the policy maximum, fails closed
        if (input.EnforceTaint is { } tg)
        {
            var (tok, twhy) = Taint.Gate(IntentJs.Get(p, "provenance"), tg.Context, tg.MaxTaint);
            if (tok) Mark("taint_gate", "pass"); else Fail("taint_gate", twhy!);
        }
        else Mark("taint_gate", "not-enforced");
        // the dead-man liveness beacon: genuine, not replayed, and the one the PCActn's signed freshness.beacon_ref commits
        long? beaconSeq = null;
        {
            BeaconPresented? bc = null;
            try { if (input.Beacon != null && IntentJs.Get(grant, "id") is string bgid) bc = input.Beacon(grantRef, p); }
            catch (Exception) { bc = null; }
            if (bc == null) Mark("beacon", "not-enforced");
            else
            {
                var gid = IntentJs.Get(grant, "id") as string ?? "";
                long? last = bc.LastAcceptedSeq;
                try { if (input.StateStore is IPinStore bpins && bpins.Pin(gid + ":beacon") is long bp) last = last is long hl ? Math.Max(hl, bp) : bp; }
                catch (Exception) { last = long.MaxValue; } // a pin store that cannot answer accepts no beacon
                var bv = Beacons.Verify(bc.Beacon, new BeaconCheck { Issuers = bc.Issuers, Now = now, Instance = bc.Instance, Scope = gid, PqPins = bc.PqPins });
                var seqObj = (bc.Beacon as JD)?.GetValueOrDefault("seq");
                var seq = IntentJs.NumOf(seqObj);
                var replayed = bv.Ok && last is long lv && seq is double sv && sv < lv;
                var refBinds = bv.Ok && !replayed && Equals(IntentJs.Get(IntentJs.Get(p, "freshness"), "beacon_ref"), Beacons.Ref(bc.Beacon));
                if (!bv.Ok) Fail("beacon", bv.Reason ?? "beacon rejected");
                else if (replayed) Fail("beacon", $"beacon seq {JsCanon.NumberString(seq!.Value)} is older than the last accepted {last} (replay)");
                else if (!refBinds) Fail("beacon", "PCActn freshness.beacon_ref does not bind the presented beacon");
                else { Mark("beacon", "pass"); beaconSeq = (long)seq!.Value; }
            }
        }
        // the forbid-wins policy: decided before the replay counter is spent; a certificate the call presents is recomputed, never trusted
        JD? forbidCert = null;
        if (input.Forbid is { } fo)
        {
            try
            {
                var fop = new Operation(op.Verb, op.Resource, op.Params);
                var fctx = new JD { ["action"] = new JD { ["verb"] = op.Verb, ["resource"] = op.Resource, ["params"] = op.Params } };
                if (fo.Context?.Invoke(input) is { } fextra) foreach (var kv in fextra) fctx[kv.Key] = kv.Value;
                var fclauses = fo.Clauses(fop, grant);
                var fd = Forbid.Decide(fclauses, fctx, fo.Clause);
                if (fd.Decision != "allow") Fail("forbid", $"{fd.Decision} by {fd.WinnerKind}{(fd.WinnerId != null ? " " + fd.WinnerId : "")}");
                else
                {
                    forbidCert = Forbid.Certify(fclauses, fctx, fo.Clause);
                    if (fo.RequireCertificate && input.ForbidCertificate == null) Fail("forbid", "the call carries no certificate (fail closed)");
                    else if (fo.RequireCertificate && Forbid.Check(input.ForbidCertificate, fclauses, fctx, fo.Clause) is { Ok: false } fc) Fail("forbid", $"certificate refused ({fc.Reason ?? "mismatch"})");
                    else Mark("forbid", "pass");
                }
            }
            catch (Exception) { Fail("forbid", "the clause policy could not be evaluated (fail closed)"); }
        }
        // contracts: peeked now (read only), committed once the action is admitted
        if (input.Contracts is { } cenf)
        {
            var cpeek = cenf.Peek(new JD { ["action"] = new JD { ["verb"] = op.Verb, ["resource"] = op.Resource, ["params"] = op.Params } });
            if (!cpeek.Allow) Fail("contract", $"{cpeek.Reason}{(cpeek.Violated.Count > 0 ? $" ({string.Join(",", cpeek.Violated)})" : "")}");
            else Mark("contract", "pass");
        }
        // requireLinkedTemplate: the grant must be the instantiation of a linked, trusted template
        if (input.RequireLinkedTemplate is { } linkRegistry)
        {
            try
            {
                var lenv = ReadEnvelope(grant);
                if (lenv == null) Fail("template", "the grant has no readable envelope");
                else if (!lenv.ContainsKey("template_ref")) Fail("template", "the grant carries no template_ref");
                else
                {
                    var lv = PolicyAuthoring.VerifyLinkedPolicy(lenv, linkRegistry());
                    if (lv.Ok) Mark("template", "pass"); else Fail("template", lv.Reason ?? "refused");
                }
            }
            catch (Exception) { Fail("template", "the template registry could not be read (fail closed)"); }
        }
        // enforce.freshness (the reference's M3 gate): a missing, stub or stale signed freshness anchor is refused
        if (input.EnforceFreshness is { } fg)
        {
            var fnow = fg.Now ?? now;
            var skew = fg.ClockSkewMs is double sk && double.IsFinite(sk) ? Math.Max(0, sk) : 0;
            var fr = IntentJs.Get(p, "freshness");
            if (!(fg.EpochMs > 0) || !double.IsFinite(fg.MaxAgeMs) || fg.MaxAgeMs < 0)
                Fail("freshness", "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)");
            else if (IntentJs.Get(fr, "beacon_ref") is not string { Length: > 0 } || !IntentJs.IsSafeInteger(IntentJs.Get(fr, "epoch")) || !(IntentJs.NumOf(IntentJs.Get(fr, "epoch")) > 0))
                Fail("freshness", "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)");
            else
            {
                var anchor = IntentJs.NumOf(IntentJs.Get(fr, "epoch"))!.Value * fg.EpochMs;
                if (anchor > fnow + skew) Fail("freshness", "freshness anchor is in the future");
                else if (fnow - anchor > fg.MaxAgeMs) Fail("freshness", $"freshness anchor is stale (older than {JsCanon.NumberString(fg.MaxAgeMs)} ms)");
                else if (checks.GetValueOrDefault("freshness") != "fail") Mark("freshness", "pass"); // a failed revocation-staleness check stands
            }
        }
        // requireVerifiedPrincipal + resolvePrincipal: identity enforcement at the resource server
        if (input.ResolvePrincipal is { } resolvePrincipal)
        {
            PrincipalInfo? info;
            try { info = IntentJs.Get(grant, "issuer") is string iss0 ? resolvePrincipal(iss0, grant) : null; }
            catch (Exception) { info = null; }
            var verified = info?.Verified == true;
            if (input.RequireVerifiedPrincipal && !verified) Fail("principal", "the grant issuer is not an enrolled, verified principal");
            else Mark("principal", verified ? "pass" : "not-enforced");
        }
        else if (input.RequireVerifiedPrincipal) Fail("principal", "requireVerifiedPrincipal needs a resolvePrincipal resolver");
        // requirePassport: decided before the replay counter is spent; the passport's subject must be the leaf the PCActn names
        if (input.RequirePassport is { } rpass)
        {
            var leafHolder = IntentJs.Get(p, "cap_chain") is JL cl && cl.Count > 0 ? IntentJs.Get(cl[^1], "holder") as string : null;
            if (leafHolder == null) Fail("passport", "subject_mismatch");
            else
            {
                var po = rpass.Options;
                var pv = Passports.Verify(input.Passport, new PassportOptions
                {
                    TrustedIssuers = po.TrustedIssuers, NowMs = (long)now, ClockSkewMs = po.ClockSkewMs, MaxEvidenceAgeMs = po.MaxEvidenceAgeMs, Subject = leafHolder,
                    PqPins = po.PqPins, Attest = po.Attest, DefaultHardware = po.DefaultHardware, Revoked = po.Revoked,
                });
                if (!pv.Ok) Fail("passport", pv.Reason!);
                else if (rpass.Hardware && !pv.HardwareVerified) Fail("passport", "hardware_evidence_missing");
                else Mark("passport", "pass");
            }
        }
        if (Equals(grantRef, IntentJs.Get(grant, "id"))) Mark("grant_ref", "pass");
        else Fail("grant_ref", "does not reference the supplied grant");
        if (Equals(opDigest, signedDigest)) Mark("params_digest", "pass");
        else Fail("params_digest", "supplied params do not hash to action.params_digest");

        var pl = IntentJs.Get(p, "plan") as JD ?? new JD();
        var nodeId = IntentJs.Get(pl, "node_id");
        var planNodes = IntentJs.Get(ctx, "plan");
        var planAuthorized = IntentJs.Get(ctx, "plan_authorized");
        if (input.Plan == "single-step" && planNodes == null)
        {
            planNodes = new JL
            {
                new JD
                {
                    ["id"] = Js(nodeId), ["verb"] = op.Verb, ["resource"] = op.Resource, ["params_digest"] = opDigest,
                    ["reversibility_class"] = IntentJs.Get(action, "reversibility_class"),
                },
            };
            planAuthorized = true;
        }
        if (planNodes != null)
        {
            string? known;
            try { known = MerkleRoot(((JL)planNodes).Select(n => (object?)NodeLeaf(n)).ToList()); }
            catch (Exception) { known = null; }
            if (known == null || !Equals(known, IntentJs.Get(pl, "root"))) Fail("plan_root_authorized", "known plan does not match plan.root");
            else if (planAuthorized is not true) Fail("plan_root_authorized", "the plan root has not been authorized by the principal");
            else Mark("plan_root_authorized", "pass");
        }
        // K5: default-deny. There is no opt-out in this pipeline (a lower-level core verifier has no plan_root_authorized check here).
        else Fail("plan_root_authorized", "default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set InsecureSkipPlanRootCheck)");
        if (planStatus != null)
        {
            if (planStatus.Executable) Mark("plan_state", "pass");
            else Fail("plan_state", planStatus.Reason!); // every non-executable status here names its reason (PlanRegistry.Status, or the unknown-plan one above)
        }

        var env = ReadEnvelope(grant);
        if (RequiresAttestation(env != null ? IntentJs.Get(env, "agent_binding") : null))
            Fail("attestation", "the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED (no attestation verifier in this SDK: fail closed)");

        var declared = IntentJs.Get(action, "reversibility_class");
        var effective = declared;
        var serverClass = IntentJs.Get(ctx, "reversibility_class");
        if (serverClass != null)
        {
            int dr = ClassRank(declared), sr = ClassRank(serverClass);
            if (dr < sr) Fail("reversibility", $"declared class '{Js(declared)}' is less restrictive than the authoritative '{Js(serverClass)}'");
            else Mark("reversibility", "pass");
            effective = dr > sr ? declared : serverClass;
        }

        // ---- 5. policy: envelope predicates + envelope caveats + root caveats; then the delegated caveats
        var chain = IntentJs.Get(p, "cap_chain") as JL ?? new JL();
        int depth = Math.Max(0, chain.Count - 1);
        var inner = new JD { ["verb"] = IntentJs.Get(action, "verb"), ["resource"] = IntentJs.Get(action, "resource"), ["params"] = op.Params };
        if (effective != null) inner["reversibility_class"] = effective;
        var actionCtx = new JD { ["action"] = inner };
        if (IntentJs.Get(ctx, "subject") is { } subject) actionCtx["subject"] = subject;
        var predEnv = V2Env(p, grant, v2, now, IntentJs.Get(ctx, "env"));
        if (predEnv != null) actionCtx["env"] = predEnv;
        var toolCall = new ToolCall(inner["verb"] as string, op.Params, IntentJs.Get(p, "tool_binding") as string);
        var revClass = effective;
        if (revClass == null && nodeId is string nid && planNodes is JL pnl)
            revClass = pnl.OfType<JD>().Where(n => Equals(IntentJs.Get(n, "id"), nid)).Select(n => IntentJs.Get(n, "reversibility_class")).FirstOrDefault();
        var cctx = new JD { ["now"] = now, ["action"] = inner, ["delegation_depth"] = (long)depth };
        if (IntentJs.Get(ctx, "blast_radius") is { } br) cctx["blast_radius"] = br;
        if (revClass != null) cctx["reversibility_class"] = revClass;
        if (IntentJs.Get(ctx, "recent_action_times") is { } rat) cctx["recent_action_times"] = rat;

        // ---- caveat language v2 (opt-in): K1 caveat types are taken out of the stock lists and evaluated by CaveatLang
        K1Result? k1res = null;
        string? k1Error = null;
        if (input.K1 != null)
        {
            try
            {
                var k1in = input.K1(p) ?? new K1Input();
                k1res = CaveatLang.EvaluateK1(grant, chain.Count > 0 ? chain : null, k1in.WithActionDigest(CaveatLang.DischargeActionDigest(p)), new K1Context(now, inner));
            }
            catch (Exception) { k1Error = "the K1 input callback failed (fail closed)"; }
        }
        else
        {
            // no K1 option: a K1 caveat anywhere in the chain (root or delegated) is refused, never left to a stock evaluator
            try
            {
                K1CheckHook?.Invoke();
                var unconfigured = CaveatLang.EvaluateK1(grant, chain.Count > 0 ? chain : null, null, new K1Context(now, inner));
                if (unconfigured.Bound.Count > 0) k1res = unconfigured;
            }
            catch (Exception) { k1Error = "the K1 caveats could not be checked (fail closed)"; }
        }
        var k1CaveatTypes = CaveatLang.K1CaveatTypes;
        object? NoK1(object? cs) => k1res != null && cs is JL l ? l.Where(x => !CaveatLang.IsK1Caveat(x, k1CaveatTypes)).ToList() : cs;

        List<string> PolicyStep()
        {
            var why = new List<string>();
            if (env == null) return new List<string> { "grant carries no valid envelope" };
            var pr = EnvelopePredicates(IntentJs.Get(env, "predicates"), actionCtx);
            if (pr != null) why.Add(pr);
            var r1 = EvaluateAgentCaveats(IntentJs.Get(env, "caveats"), cctx, actionCtx, toolCall);
            if (!r1.Ok) why.Add("caveat(s) not satisfied: " + string.Join(", ", r1.Failed));
            var r2 = EvaluateAgentCaveats(NoK1(RootCaveats(grant)), cctx, actionCtx, toolCall);
            if (!r2.Ok) why.Add("root caveat(s) not satisfied: " + string.Join(", ", r2.Failed));
            return why;
        }

        var narrowPlain = k1res?.Plain ?? new List<object?>();
        if (chain.Count > 0 || narrowPlain.Count > 0)
        {
            object? extra = null;
            if (chain.Count > 0)
            {
                var leaf = chain[^1] as JD ?? new JD();
                var gcs = IntentJs.Get(grant, "caveats") as JL ?? new JL();
                extra = IntentJs.Get(leaf, "caveats") is JL lcs ? lcs.Skip(gcs.Count).ToList() : null;
            }
            else extra = new List<object?>();
            // a verified narrow block's plain caveats join the delegated list
            if (extra is List<object?> el && narrowPlain.Count > 0) extra = el.Concat(narrowPlain).ToList();
            var dr = EvaluateAgentCaveats(NoK1(extra), cctx, actionCtx, toolCall);
            if (dr.Ok) Mark("delegated_caveats", "pass");
            else Fail("delegated_caveats", "delegation caveat(s) not satisfied: " + string.Join(", ", dr.Failed));
        }
        if (k1Error != null) Fail("k1_caveats", k1Error);
        else if (k1res != null)
        {
            if (k1res.Ok) Mark("k1_caveats", "pass");
            else Fail("k1_caveats", "caveat(s) not satisfied: " + string.Join("; ", k1res.Failed.Select((f, i) => $"{f} ({k1res.Reasons[i]})")));
        }

        List<string> policyWhy;
        try { policyWhy = SafeRegex.WithBudget(PolicyStep); }
        catch (Exception) { policyWhy = new List<string> { "policy evaluation error (fail closed)" }; }
        if (policyWhy.Count > 0)
        {
            Mark("policy", "fail");
            reasons.AddRange(policyWhy.Select(w => "policy: " + w));
        }
        else Mark("policy", "pass");

        // ---- 5b. risk, trust budget and threshold step-up (the reference's decide() steps 3-5 and the threshold rule): the server prices the action
        // from the inputs IT supplies; a missing one is its worst case. t > 1 needs a threshold hook that enforced at least that t.
        RiskStep? riskState = null;
        var release = checks.GetValueOrDefault("policy") == "pass" && checks.GetValueOrDefault("delegated_caveats") != "fail" && checks.GetValueOrDefault("k1_caveats") != "fail";
        if (env != null && Risk.PolicyOf(IntentJs.Get(env, "risk_policy")) is { } riskPolicy)
        {
            riskState = PolicyRiskStep(riskPolicy, p, grant, ctx, planNodes, nodeId, revClass, now, input, op, BudgetKeyOf(input.Audience, grant, grantRef, p), release);
            if (riskState.BudgetPresent) Mark("budget", "pass"); else Mark("budget", "not-enforced");
            foreach (var w in riskState.Reasons) reasons.Add(w.StartsWith("budget:", StringComparison.Ordinal) ? w : "policy: " + w);
            var (thStatus, hookT) = ThresholdHookStatus(input.ThresholdHook, p, grant, checks, reasons, Mark);
            var tReq = riskState.Threshold.T;
            if (tReq > 1 && release)
            {
                // the reference compares the floored value (NaN is unreported, +/-Infinity clamp) and prints the value the hook reported, unfloored
                if (thStatus == "pass" && !(hookT is double ht && !double.IsNaN(ht) && Math.Floor(ht) >= tReq))
                    Fail("threshold", $"threshold hook enforced t={(hookT is double hv ? (double.IsNaN(hv) ? "NaN" : double.IsPositiveInfinity(hv) ? "Infinity" : double.IsNegativeInfinity(hv) ? "-Infinity" : JsCanon.NumberString(hv)) : "unreported")} but the server requires t={tReq} (below the server-derived threshold; derive t from server-held data)");
                else if (thStatus == "fail") Fail("threshold", $"t={tReq} required and the threshold proof was rejected");
                else if (thStatus != "pass") Fail("threshold", $"t={tReq} ({riskState.Threshold.Proof}) required but no threshold verifier is enforced");
            }
            if (input.RequireRiskInputs is { } req)
            {
                var sup = RiskSupplied(ctx, input, op, grant, p);
                var lacking = req.Where(k => !(Fin(sup.GetValueOrDefault(k)) != null || (k == "semanticDistance" && planNodes is JL))).ToList();
                if (lacking.Count == 0) Mark("risk_inputs", "pass");
                else Fail("risk_inputs", "required risk input(s) not supplied by the server: " + string.Join(", ", lacking));
            }
            RiskPolicy? adaptive = input.Adaptive;
            if (input.AdaptivePolicy != null)
            {
                try
                {
                    var got = input.AdaptivePolicy(now);
                    if (got is RiskPolicy rp) adaptive = rp;
                    else if (got == null) adaptive = null;
                    else if (ValidateRiskPolicy(got) is { } badPolicy) { Fail("adaptive", $"invalid policy ({badPolicy})"); adaptive = null; }
                    else adaptive = Risk.PolicyOf(got);
                }
                catch (Exception ex) { Fail("authorize", $"error (fail closed): {ex.Message}"); adaptive = null; } // the reference lets it reach authorize()'s catch-all
            }
            if (adaptive is { } ad)
            {
                // a tightened risk policy can only NARROW: it may not require a LOWER threshold than the grant's own policy
                var adT = Risk.Required(riskState.R, ad.Theta1, ad.Theta2).T;
                if (adT > riskState.Threshold.T) Fail("adaptive", $"tightened policy requires threshold t={adT} (grant policy: t={riskState.Threshold.T})");
            }
        }
        else if (input.RequireRiskInputs != null || input.Adaptive != null || input.AdaptivePolicy != null) Fail("risk_inputs", "the grant carries no readable risk policy (fail closed)");

        // ---- required checks (default-deny), then the replay counter
        // `replay` is decided by the claim below: tentatively pass (as the TypeScript guard does), flipped to fail on a refusal.
        // the replay check is the READ of the stream's last counter, as the reference does it (the claim itself happens only once everything else passed): a refused step still names a replayed counter
        var replayRefused = false;
        try
        {
            if (input.StateStore is ILastStore lastStore && chain.Count > 0 && IntentJs.Get(chain[^1], "holder") is string rh && IntentJs.Get(grant, "id") is string rg
                && IntentJs.IsNonNeg(IntentJs.Get(p, "counter")) && lastStore.Last(StateKey(rg, rh)) is long rlast && !(IntentJs.Lng(IntentJs.Get(p, "counter")) > rlast))
            {
                Fail("replay", $"{IntentJs.Lng(IntentJs.Get(p, "counter")).ToString(CultureInfo.InvariantCulture)} is not greater than last seen {rlast.ToString(CultureInfo.InvariantCulture)} (replay)");
                replayRefused = true;
            }
        }
        catch (Exception) { /* the claim below decides */ }
        if (!replayRefused) Mark("replay", "pass");
        AssuranceReport Report()
        {
            var src = new AssuranceSources
            {
                Pcactn = p, Hooks = input.AssuranceHooks ?? new AssuranceHooks(),
                Checks = order.Select(n => new KeyValuePair<string, string>(n == "chain" ? "cap_chain" : n, checks[n])).ToList(), // the reference's name for the capability chain check
            };
            if (core.LegacyModelPolarity && checks.GetValueOrDefault("tighten") == "pass") src.Degraded = new Dictionary<string, string> { ["tighten"] = LegacyPolarityDegraded };
            return Assurance.BuildReport(src);
        }
        if (input.RequireAssurance != null && Assurance.Unmet(Report(), input.RequireAssurance) is { } unmet)
        {
            Mark("assurance", "fail");
            reasons.Add(unmet);
        }
        // reported before the required checks, so a required bond is refused as unsupported (server/verify.ts:221), whatever AllowUnsupported says
        if (p.ContainsKey("bond_ref")) Mark("bond", "unsupported");
        // `counter` in a require list is the documented alias of `replay` (it always meant the stateful check here).
        foreach (var name in DefaultRequiredChecks.Concat(freshnessOn ? new[] { "freshness" } : Array.Empty<string>()).Concat(input.Beacon != null ? new[] { "beacon" } : Array.Empty<string>()).Concat((input.Require?.Where(n => n != null) ?? Enumerable.Empty<string>()).Select(n => n == "counter" ? "replay" : n)))
        {
            var st = checks.GetValueOrDefault(name);
            if (st != "pass" && st != "fail")
            {
                Mark(name, "fail");
                reasons.Add($"{name}: required check is {st ?? "absent"} (default-deny: not enforced by this resource server)");
            }
        }

        // ---- provenance by default: its own check name (`provenance` is the Intent Layer v2 rule 17 check, never overwritten)
        try
        {
            var (pvStatus, pvWhy) = ProvenanceFlowCheck(input, p, grant, op, principalPlan, principalControl);
            if (pvStatus == "fail") Fail("provenance_flow", pvWhy!);
            // a required provenance_flow was refused above, before this gate ran (server/require-pca.ts:853-868): its outcome never lifts that
            else if (checks.GetValueOrDefault("provenance_flow") != "fail") Mark("provenance_flow", pvStatus);
        }
        catch (Exception) { Fail("provenance_flow", "evaluation error (fail closed)"); }

        JD? escalation = null;
        string? answeredBy = null;
        UndoAdmission? undo = null;
        JD? undoObligation = null;
        AuthorizeResult Deny()
        {
            int status = AuthnChecks.Any(c => checks.GetValueOrDefault(c) == "fail") ? 401 : 403;
            return new AuthorizeResult
            {
                Allow = false, Status = status, Checks = Ordered(checks, order), Reasons = reasons,
                Reason = Decisive(checks, order, reasons), Pcactn = p, Verdict = core,
                Decision = escalation != null ? "escalate" : "deny", Escalation = escalation, Assurance = Report(),
                RiskScore = riskState?.R, RequiredThreshold = riskState?.Threshold, Budget = riskState?.After,
            };
        }

        var holder = chain.Count > 0 ? IntentJs.Get(chain[^1], "holder") as string : null;
        var counterObj = IntentJs.Get(p, "counter");
        if (p.ContainsKey("bond_ref") && input.AllowUnsupported?.Contains("bond") != true)
        {
            reasons.Add("bond: unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)");
            return Deny();
        }
        if (checks.Values.Any(s => s == "fail"))
        {
            if (holder == null || IntentJs.Get(grant, "id") is not string gid || !AllEscalateClass(checks, reasons)) return Deny();
            // Ternary decision: every failing check is escalate-class. Never admitted by itself.
            long? last = null;
            bool headKnown = false;
            if (input.StateStore is ILastStore ls)
            {
                try { last = ls.Last(StateKey(gid, holder)); headKnown = true; }
                catch (Exception) { /* head unknown: no answer can be bound */ }
            }
            // a counter the stream already passed is a replay (deny), never an escalation: no request, no answer, no undo window
            if (headKnown && last is long seen && IntentJs.NumOf(counterObj) is double cn && cn <= seen)
            {
                Fail("replay", $"{IntentRevocation.JsText(counterObj, true)} is not greater than last seen {seen} (replay)");
                return Deny();
            }
            string? renderDigest = null;
            try { renderDigest = input.EscalationRender?.Invoke(p); } catch (Exception) { renderDigest = null; }
            try { escalation = Escalation.BuildRequest(input.Audience, grant, p, last, reasons, now, input.EscalationRequestTtlMs, renderDigest); }
            catch (Exception) { return Deny(); }
            // an answer with no pinned principal is judged too (and refused with that reason), never silently ignored
            if (input.EscalationAnswer != null && !input.InsecureUnboundApproval && renderDigest == null)
            {
                // K7 default: an answer is admitted only over a render the verifier recomputed
                reasons.Add("escalation: an approval render is required and none could be recomputed (set EscalationRender, or InsecureUnboundApproval)");
            }
            else if (input.EscalationAnswer != null && headKnown)
            {
                EscalationVerdict v;
                try { v = Escalation.Verify(input.EscalationAnswer, input.EscalationPrincipals, new EscalationBinding(Escalation.PolicyDigest(grant), Escalation.ActionDigest(p), Escalation.HistoryHead(last), renderDigest), now); }
                catch (Exception) { v = new EscalationVerdict(false, Reason: "escalation answer error (fail closed)"); }
                if (v.Ok && v.Decision == "allow")
                {
                    foreach (var n in order.ToList()) if (checks[n] == "fail") checks[n] = "pass";
                    Mark("escalation", "pass");
                    reasons.Add("escalation: answered allow by principal " + v.Principal![..Math.Min(8, v.Principal.Length)]);
                    answeredBy = v.Principal;
                    escalation = null;
                }
                else if (v.Ok) reasons.Add("escalation: the principal answered deny");
                else reasons.Add("escalation: " + v.Reason);
            }
            // Undo window: an unanswered escalation runs now under a veto window the coordinator durably opened. Only escalate-class failures
            // are lifted (exactly what an answer would lift). Never for a provenance escalation.
            bool provenanceEscalated = checks.GetValueOrDefault("provenance_flow") == "fail" || checks.GetValueOrDefault("provenance") == "fail";
            if (escalation != null && input.Undo != null && input.EscalationAnswer == null && !provenanceEscalated)
            {
                UndoAdmission? adm;
                try { adm = input.Undo(p, grant, new Operation(op.Verb, op.Resource, op.Params)); }
                catch (Exception) { adm = null; } // an admission that cannot be decided is no admission: the escalation stands
                var obligation = adm is { Compensation: not null } ? UndoWindows.Obligation(adm) : null;
                if (adm != null && obligation != null && !string.IsNullOrEmpty(adm.Compensation.Verb) && AtlasPca.Obligations.ObligationError(obligation) == null)
                {
                    foreach (var n in order.ToList()) if (checks[n] == "fail") checks[n] = "pass";
                    Mark("undo_window", "pass");
                    reasons.Add($"undo_window: runs now under a veto window until {adm.WindowEnd.ToString(CultureInfo.InvariantCulture)} (compensation {adm.Compensation.Verb})");
                    undo = adm;
                    undoObligation = obligation;
                    escalation = null;
                }
            }
            if (escalation != null) return Deny();
        }

        if (holder == null || IntentJs.Get(grant, "id") is not string grantId || !IntentJs.IsNonNeg(counterObj))
        {
            Fail("replay", "no counter stream for this proof (fail closed)");
            return Deny();
        }
        long counter = IntentJs.Lng(counterObj);
        ClaimResult? claimed;
        try { claimed = input.StateStore!.Claim(StateKey(grantId, holder), counter); }
        catch (Exception) { claimed = null; }
        if (claimed is not { Ok: true })
        {
            if (claimed == null) Fail("replay", "the replay store failed (fail closed)");
            else if (claimed.LastCounter is long last) Fail("replay", $"{counter} is not greater than last seen {last} (replay)");
            else Fail("replay", $"{counter} was already claimed (replay)");
            return Deny();
        }
        if (input.Contracts is { } cenf2)
        {
            var cc = cenf2.Check(new JD { ["action"] = new JD { ["verb"] = op.Verb, ["resource"] = op.Resource, ["params"] = op.Params } }, true);
            if (!cc.Allow)
            {
                Fail("contract", $"{cc.Reason}{(cc.Violated.Count > 0 ? $" ({string.Join(",", cc.Violated)})" : "")}");
                return Deny();
            }
        }
        // the trust budget is persisted only now: the counter claim succeeded and every check passed
        if (riskState is { Persist: true } && input.StateStore is IBudgetStore budgetStore)
        {
            bool saved;
            try { saved = budgetStore.BudgetCas(riskState.BudgetKey, riskState.Stored, riskState.After); }
            catch (Exception) { saved = false; }
            if (!saved)
            {
                Fail("budget", "the budget store refused the update (changed concurrently or failed): fail closed");
                return Deny();
            }
        }
        // the beacon sequence pin rises only on an allow too (a replayed older beacon can then never resurrect a halted grant)
        if (beaconSeq is long bseq && input.StateStore is IPinStore beaconPins)
        {
            try { beaconPins.RaisePin(grantId + ":beacon", bseq); }
            catch (Exception)
            {
                Fail("beacon", "the beacon pin could not be raised (fail closed)");
                return Deny();
            }
        }
        // the rollback pin rises only on an allow (a denied action never raises it); a store that fails here denies (fail closed)
        if (freshEpoch is double raise && input.StateStore is IPinStore pinStore)
        {
            try { pinStore.RaisePin(PinKey(grantId), (long)raise); }
            catch (Exception)
            {
                Fail("freshness", "the revocation epoch pin could not be raised (fail closed)");
                return Deny();
            }
        }
        // max_uses is spent only now that everything else allowed and the counter claim succeeded; a refusal here cannot give the counter back
        if (k1res != null)
        {
            var uses = CaveatLang.ReserveMaxUses(input.StateStore!, k1res.Bound, now);
            if (!uses.Ok)
            {
                Fail("k1_caveats", uses.Reason!);
                return Deny();
            }
        }
        return new AuthorizeResult
        {
            Allow = true, Status = 200, Checks = Ordered(checks, order), Reasons = reasons, Pcactn = p, Verdict = core, Decision = "allow", Assurance = Report(),
            Escalation = answeredBy != null ? new JD { ["answered_by"] = answeredBy } : null,
            Undo = undo, Obligations = undoObligation != null ? new List<object?> { undoObligation } : null,
            Degraded = core.LegacyModelPolarity && checks.GetValueOrDefault("tighten") == "pass" ? new Dictionary<string, string> { ["tighten"] = LegacyPolarityDegraded } : null,
            Operation = new AuthorizedOperation(op.Verb, op.Resource, (string)signedDigest!, HashCanonical(p)),
            RiskScore = riskState?.R, RequiredThreshold = riskState?.Threshold, Budget = riskState?.After, ForbidCertificate = forbidCert,
        };
    }

    sealed record RiskStep(double R, RequiredThreshold Threshold, Admission Adm, TrustBudget? Stored, bool Persist, TrustBudget After, bool BudgetPresent, List<string> Reasons, string BudgetKey = "");

    /// <summary>The reversibility classes an optimistic fast path may rely on; any other (or an unknown) class counts as irreversible.</summary>
    static string[] FastPathClasses => new[] { "reversible", "rate_limited", "costly" };

    /// <summary>The risk inputs the SERVER supplied (request context, then <see cref="AuthorizeInput.ServerRisk"/>, then <see cref="AuthorizeInput.ServerRiskFor"/>; later wins).</summary>
    static Dictionary<string, object?> RiskSupplied(JD ctx, AuthorizeInput input, (string Verb, string Resource, JD Params) op, JD grant, JD p)
    {
        var sup = new Dictionary<string, object?>();
        // every source speaks: per input the RISKIER value stands (higher, but lower for reversibility and confidence); a non-finite value is the worst case
        void Merge(string k, object? v)
        {
            if (!sup.TryGetValue(k, out var old)) { sup[k] = v; return; }
            if (Fin(old) is not double a || Fin(v) is not double b) { sup[k] = double.NaN; return; }
            sup[k] = k is "reversibility" or "confidence" ? Math.Min(a, b) : Math.Max(a, b);
        }
        if (IntentJs.Get(ctx, "risk") is JD cr) foreach (var kv in cr) Merge(kv.Key, kv.Value);
        if (input.ServerRisk != null) foreach (var kv in input.ServerRisk) Merge(kv.Key, kv.Value);
        if (input.ServerRiskFor?.Invoke(new Operation(op.Verb, op.Resource, op.Params), grant, p) is { } more) foreach (var kv in more) Merge(kv.Key, kv.Value);
        return sup;
    }

    /// <summary>The policy VM's numeric decision (the reference's decide() steps 3-5): the risk r from the server-supplied inputs (a missing or non-finite input is its
    /// worst case), the trust budget leaked up to <paramref name="now"/>, the required threshold and the budget admission. An ABSENT budget is a DENY-METERED budget
    /// (B = 0): any machine-only (t &lt; 3) action with a cost above zero must step up. A malformed budget or input is the worst case; nothing here throws on it.</summary>
    static RiskStep PolicyRiskStep(RiskPolicy pol, JD p, JD grant, JD ctx, object? planNodes, object? nodeId, object? revClass, long now, AuthorizeInput input,
        (string Verb, string Resource, JD Params) op, string budgetKey, bool release)
    {
        var reasons = new List<string>();
        var bIn = IntentJs.Get(ctx, "budget");
        TrustBudget? budget = null, stored = null;
        bool persist = false;
        if (bIn == null && input.StateStore is IBudgetStore bs)
        {
            stored = bs.Budget(budgetKey);
            budget = stored ?? new TrustBudget(pol.BMax, now, now);
            persist = true;
        }
        else if (bIn is JD bd && Fin(bd.GetValueOrDefault("B")) is double bb && Fin(bd.GetValueOrDefault("tau")) is double tau)
            budget = new TrustBudget(bb, tau, Fin(bd.GetValueOrDefault("asOf")));
        var present = budget != null;
        if (budget == null)
        {
            budget = new TrustBudget(0, now, now);
            persist = false;
            reasons.Add("budget: no budget supplied \u2014 fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge");
        }
        var leaked = Risk.Leak(budget, now, pol.Lambda);
        var supplied = RiskSupplied(ctx, input, op, grant, p);
        double In(string k, double worst) => Fin(supplied.GetValueOrDefault(k)) is double v ? v : worst;
        var worstIn = Risk.Worst;
        var missing = Risk.InputKeys.Where(k => k != "age" && Fin(supplied.GetValueOrDefault(k)) == null).ToList();
        var sd = In("semanticDistance", worstIn.SemanticDistance);
        if (planNodes is JL pn && Fin(supplied.GetValueOrDefault("semanticDistance")) == null)
        {
            var goal = IntentJs.Get(ctx, "goal_node_id") as string ?? (pn.Count > 0 ? IntentJs.Get(pn[^1], "id") as string : null);
            sd = nodeId is string nid0 && goal != null ? Risk.PlanGeodesic(pn, nid0, goal) : 1;
            missing.Remove("semanticDistance");
        }
        var age = Fin(supplied.GetValueOrDefault("age")) is double av ? av : Risk.AgeSinceTouch(leaked, now, Fin(IntentJs.Get(ctx, "age_horizon_ms")) ?? 3_600_000);
        var inputs = new RiskInputs(sd, In("reversibility", worstIn.Reversibility), In("blastRadius", worstIn.BlastRadius), In("taint", worstIn.Taint), In("confidence", worstIn.Confidence), age);
        if (missing.Count > 0) reasons.Add("risk input(s) missing, assumed worst case: " + string.Join(", ", missing));
        // the signed caution can only RAISE the risk, never lower it
        var rFloor = Fin(IntentJs.Get(p, "caution")) is double cau ? Math.Min(1, Math.Max(0, cau)) : 0;
        var r = Math.Max(Risk.Score(inputs, pol), rFloor);
        var irreversible = !(revClass is string rc && FastPathClasses.Contains(rc));
        var rt = Risk.Required(r, pol.Theta1, pol.Theta2, irreversible);
        var adm = Risk.AdmitOf(Risk.Required(r, pol.Theta1, pol.Theta2).T, leaked.B >= Risk.Cost(r, pol.Kappa));
        if (adm.NeedStepUp)
            reasons.Add(rt.T < 3 && adm.T == 3 ? "trust budget depleted: human recharge required" : $"risk {Risk.ToFixed3(r)} exceeds auto threshold: step-up to t={adm.T}");
        return new RiskStep(r, Risk.Escalate(rt, adm.T), adm, stored, persist, release && adm.Metered ? Risk.Debit(leaked, Risk.Cost(r, pol.Kappa)) : leaked, present, reasons, budgetKey);
    }

    /// <summary>The threshold hook: its status (<c>pass</c>, <c>fail</c> or <c>not-enforced</c>, also recorded as the <c>threshold</c> check) and the t it enforced. No hook or a hook
    /// that did not enforce is <c>not-enforced</c>; a rejecting or throwing hook fails (fail closed).</summary>
    static (string Status, double? T) ThresholdHookStatus(Func<JD, JD, ThresholdHookResult?>? hook, JD p, JD grant, Dictionary<string, string> checks, List<string> reasons, Action<string, string> mark)
    {
        var status = "not-enforced";
        double? hookT = null;
        if (hook != null)
        {
            try
            {
                var res = hook(p, grant);
                if (res is { Enforced: true })
                {
                    if (res.Ok) { status = "pass"; hookT = res.T; }
                    else { status = "fail"; reasons.Add("threshold: " + (res.Reason ?? "rejected")); }
                }
            }
            catch (Exception)
            {
                status = "fail";
                reasons.Add("threshold: threshold hook error (fail closed)");
            }
        }
        mark("threshold", status);
        return (status, hookT);
    }

    /// <summary>The provenance_flow gate (TypeScript <c>provenanceCheck</c>): the grant envelope's signed <c>provenance</c> member (malformed
    /// fails; <c>insecure_off</c> is not-enforced), an unreadable bundle fails, then <see cref="ArgProvenance.Decide"/> under the configured pins
    /// plus the envelope's. pass; escalate -&gt; fail <c>escalate: &lt;reason&gt;</c> (escalate-class); deny -&gt; fail <c>&lt;code&gt;: &lt;reason&gt;</c>.
    /// The operation is always bound here (a call without one was refused before the decode).</summary>
    static (string Status, string? Reason) ProvenanceFlowCheck(AuthorizeInput input, JD p, JD grant, (string Verb, string Resource, JD Params) op, bool principalPlan, bool principalControl)
    {
        var env = ReadEnvelope(grant);
        object? penv = null;
        if (env != null && env.ContainsKey("provenance"))
        {
            penv = env["provenance"];
            var e = ArgProvenance.EnvelopeError(penv);
            if (e != null) return ("fail", $"the grant's provenance member is malformed: {e}");
        }
        // the principal's signed, documented-dangerous opt-out
        if (IntentJs.Get(penv, "mode") is "insecure_off") return ("not-enforced", null);
        if (input.ProvenanceUnreadable) return ("fail", "the provenance bundle is unreadable (fail closed)");
        var o = input.ProvenanceFlow;
        var operation = new Operation(op.Verb, op.Resource, op.Params);
        object? action = null;
        if (o?.Actions != null)
        {
            try { action = o.Actions(operation); }
            catch (Exception) { return ("fail", "the action facts resolver failed (fail closed)"); }
        }
        var observed = new JL();
        if (o?.Observed != null)
        {
            try { foreach (var x in o.Observed(p, operation, ArgProvenance.BundleSession(input.Provenance)) ?? Array.Empty<ProvObservation>()) observed.Add(x?.ToJson()); }
            catch (Exception) { return ("fail", "the observation source failed (fail closed)"); }
        }
        var pins = new JL();
        foreach (var pin in o?.Mediators ?? Array.Empty<ProvMediatorPin>()) pins.Add(pin?.ToJson());
        if (IntentJs.Get(penv, "mediators") is JL envPins) pins.AddRange(envPins);
        var d = ArgProvenance.Decide(new ArgProvenanceInput
        {
            Bundle = input.Provenance, Operation = new JD { ["verb"] = op.Verb, ["resource"] = op.Resource, ["params"] = op.Params },
            Mediators = pins, Action = action, PrincipalPlan = principalPlan, PrincipalControl = principalControl, Observed = observed,
        });
        if (d.Outcome == "pass") return ("pass", null);
        return ("fail", d.Outcome == "escalate" ? "escalate: " + d.Reason : $"{d.Code}: {d.Reason}");
    }

    /// <summary>At least one check failed and every failing check has reasons that all start with an escalate prefix.</summary>
    static bool AllEscalateClass(Dictionary<string, string> checks, List<string> reasons) =>
        PcaDecision.Of(checks.Where(kv => kv.Value == "fail").Select(kv => kv.Key), reasons) == PcaDecision.Escalate;

    static Dictionary<string, string> Ordered(Dictionary<string, string> checks, List<string> order)
    {
        var o = new Dictionary<string, string>();
        foreach (var n in order) o[n] = checks[n];
        return o;
    }

    static string Decisive(Dictionary<string, string> checks, List<string> order, List<string> reasons)
    {
        foreach (var n in order.Where(n => n == "operation").Concat(order.Where(n => n == "plan_state")).Concat(order.Where(n => n != "operation" && n != "plan_state")))
        {
            if (checks[n] != "fail") continue;
            var hit = reasons.FirstOrDefault(r => r.StartsWith(n + ":", StringComparison.Ordinal));
            if (hit != null) return hit;
        }
        return reasons.Count > 0 ? reasons[0] : "denied";
    }

    /// <summary>The plan leaf of a known plan node (Python <c>_plan_leaf(n["id"], n, conditions_digest(n.pre, n.post))</c>):
    /// throws for a node without an id, verb or resource.</summary>
    internal static JD NodeLeaf(object? n)
    {
        var node = (JD)n!;
        var id = IntentJs.Get(node, "id") ?? throw new InvalidOperationException("missing node id");
        if (!node.ContainsKey("verb") || !node.ContainsKey("resource")) throw new InvalidOperationException("missing verb / resource");
        var pd = IntentJs.Get(node, "params_digest");
        var rc = IntentJs.Get(node, "reversibility_class");
        return new JD
        {
            ["node_id"] = id, ["verb"] = node["verb"], ["resource"] = node["resource"],
            ["params_digest"] = pd ?? ParamsDigest(null), ["reversibility_class"] = rc ?? DefaultRev,
            ["conditions"] = ConditionsDigest(IntentJs.Get(node, "pre"), IntentJs.Get(node, "post")),
        };
    }

    /// <summary>Envelope predicates (default deny): null when one predicate permits the action, else the reason.</summary>
    internal static string? EnvelopePredicates(object? predicates, JD actionCtx)
    {
        try
        {
            if (predicates is not JL l || l.Count == 0) return "envelope grants no predicates";
            if (l.Any(p => Predicates.PredicateMatches(p, actionCtx))) return null;
            var a = IntentJs.Get(actionCtx, "action");
            var limit = Predicates.FirstUnmetLimit(predicates, actionCtx);
            if (limit != null) return $"{limit} not satisfied for {IntentRevocation.JsText(IntentJs.Get(a, "verb"), IntentJs.Own(a, "verb"))} on {IntentRevocation.JsText(IntentJs.Get(a, "resource"), IntentJs.Own(a, "resource"))}";
            return $"no predicate permits {IntentRevocation.JsText(IntentJs.Get(a, "verb"), IntentJs.Own(a, "verb"))} on {IntentRevocation.JsText(IntentJs.Get(a, "resource"), IntentJs.Own(a, "resource"))}";
        }
        catch (Exception) { return "predicate evaluation error (fail closed)"; }
    }

    /// <summary>The predicate <c>env</c>: the host's, with the verifier-computed Intent Layer v2 members (TypeScript <c>v2Env</c>).</summary>
    static object? V2Env(JD p, JD grant, IntentV2Context? v2, long now, object? env)
    {
        if (!p.ContainsKey("intent_session")) return env;
        var rest = env is JD e ? new JD(e) : new JD();
        foreach (var k in new[] { "acc", "mon", "canon", "world", "prov", "class" }) rest.Remove(k);
        foreach (var (k, v) in IntentV2.Decide(p, grant, v2, now).Env) if (v != null) rest[k] = v;
        return rest;
    }

    /// <summary>True only if <paramref name="result"/> allowed exactly this operation (verb, resource, params digest). Call it
    /// where the side effect runs, with the values it is about to use. Never throws.</summary>
    public static bool IsAuthorizedFor(AuthorizeResult? result, Operation? operation)
    {
        try
        {
            var b = result is { Allow: true } ? result.Operation : null;
            var op = CopyOperation(operation);
            if (b is null || op is null) return false;
            return b.Verb == op.Value.Verb && b.Resource == op.Value.Resource && b.ParamsDigest == ParamsDigest(op.Value.Params);
        }
        catch (Exception) { return false; }
    }
}

/// <summary>A tool call for <see cref="Pca.EvaluateToolSchema"/>: the tool name, its arguments (a JSON object) and,
/// optionally, the PCActn's signed <c>tool_binding</c> digest and the tool signature the runtime actually dispatches to (a JSON value
/// whose canonical digest must equal the caveat's <c>signature_digest</c>); null = absent.</summary>
public sealed record ToolCall(string? Tool, object? Args, string? ToolSignatureDigest = null, object? ToolSignature = null);
