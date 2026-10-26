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
}

/// <summary>In-process reference store (one lock). Correct for ONE process only; use <see cref="SqlStateStore"/> or your
/// database for several instances.</summary>
public sealed class MemoryStateStore : IStateStore
{
    readonly Dictionary<string, long> _last = new(StringComparer.Ordinal);
    readonly object _lock = new();

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
public sealed class SqlStateStore : IStateStore
{
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
    public IReadOnlyList<string>? Missing { get; init; }
}

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
    /// <summary>Forwarded to the core verifier.</summary>
    public IReadOnlyCollection<string>? AllowedSuites { get; set; }
    /// <summary>Extra check names that must pass (the defaults always apply).</summary>
    public IEnumerable<string>? Require { get; set; }
}

public static partial class Pca
{
    public const string EnvelopeCaveat = "envelope";

    /// <summary>The checks that must be <c>pass</c> (not merely "not failed"): the TypeScript <c>DEFAULT_REQUIRED_CHECKS</c>
    /// plus the operation binding and the policy. <see cref="AuthorizeInput.Require"/> can add names, never remove these.</summary>
    public static readonly IReadOnlyList<string> DefaultRequiredChecks = new[]
        { "counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound", "operation", "params_digest", "policy" };

    // A failing one of these is an authentication failure (401), everything else is insufficient authority (403).
    static readonly string[] AuthnChecks = { "wire", "version", "audience", "validity", "chain", "grant_ref_bound", "leaf_signature", "malformed", "grant_ref" };

    /// <summary>The store key of a holder's counter stream (the TypeScript <c>pcaStateKey</c> default scope).</summary>
    public static string StateKey(string grantId, string leafHolder) => grantId + ":" + leafHolder;

    // ---- the envelope (TypeScript envelope.ts readEnvelope / risk.ts validateRiskPolicy) ----

    static string? ValidateRiskPolicy(object? p)
    {
        if (p is not JD m) return "risk_policy must be an object";
        if (IntentJs.Get(m, "weights") is not JD w) return "risk_policy.weights missing";
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
    static bool RequiresAttestation(object? binding)
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

    static readonly Dictionary<string, string[]> SpecKeys = new()
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

    static bool IsIntegral(object? x) => Fin(x) is double f && Math.Floor(f) == f;
    static bool NonNegInt(object? x, int mx) => Fin(x) is double f && Math.Floor(f) == f && f >= 0 && f <= mx;
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
            if (f is null || (t is "integer" && Math.Floor(f.Value) != f.Value)) return $"{path}: wrong type (expected {t})";
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
                    if (ctx is null) throw new ArgumentNullException(nameof(ctx));
                    if (!AgentCaveatSatisfied(cv, new JD(ctx), actionCtx ?? new JD(), toolCall))
                        failed.Add(cv is JD d && IntentJs.Get(d, "type") is string ts ? ts : "<malformed>");
                }
                return new Caveats.Result(failed.Count == 0, failed);
            });
        }
        catch (Exception) { return new Caveats.Result(false, new[] { "<evaluation error>" }); }
    }

    // ---- authorize ----

    static int ClassRank(object? c) => c switch
    {
        "reversible" => 0,
        "rate_limited" or "costly" => 1,
        _ => 2,
    };

    static AuthorizeResult Refuse(int status, string check, string reason, IReadOnlyList<string>? missing = null, JD? pcactn = null) =>
        new() { Allow = false, Status = status, Checks = new Dictionary<string, string> { [check] = "fail" }, Reasons = new[] { reason }, Reason = reason, Missing = missing, Pcactn = pcactn };

    /// <summary>Names of the required components that are absent (empty = complete): <c>Audience</c>, <c>ResolveGrant</c>,
    /// <c>StateStore</c>, <c>IsRevoked</c>, in that order.</summary>
    public static List<string> MissingAuthorizeComponents(AuthorizeInput? input) => MissingComponents(input, false);

    static List<string> MissingComponents(AuthorizeInput? input, bool async)
    {
        var missing = new List<string>();
        if (string.IsNullOrEmpty(input?.Audience)) missing.Add("Audience");
        if (input?.ResolveGrant is null && !(async && input?.ResolveGrantAsync is not null)) missing.Add("ResolveGrant");
        if (input?.StateStore is null) missing.Add("StateStore");
        if (input?.IsRevoked is null) missing.Add("IsRevoked");
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
        var (p, err) = Coerce(pcactn);
        if (p is null) return (Refuse(401, "wire", err == "absent" ? "wire: no PCActn presented" : "wire: PCActn could not be decoded"), null);
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

        IntentV2Context? v2 = input.IntentV2;
        var provider = v2Override ?? input.IntentV2Provider;
        if (provider != null)
        {
            try { v2 = provider(p); }
            catch (Exception) { return Refuse(403, "intent_v2", "intent_v2: verifier state unavailable (fail closed)", pcactn: p); }
        }
        if (v2 != null && v2.WellFormed && v2.Get("params") == null) v2 = v2.WithParams(op.Params);

        // ---- 1. the core checks
        var core = VerifyPcactnCore(p, grant, now, input.Audience!, input.AllowedSuites, input.IntentPolicy, v2);
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
        if (!core.Allow && core.Reason.Length > 0) reasons.Add(core.Reason);
        void Fail(string name, string why) { Mark(name, "fail"); reasons.Add(name + ": " + why); }

        // ---- 2. revocation (required) and a carried zk proof (no verifier here: fail closed)
        bool? revoked;
        try { revoked = input.IsRevoked!(p, grant); }
        catch (Exception) { revoked = null; }
        if (revoked == false) Mark("revocation", "pass");
        else Fail("revocation", revoked == true ? "the grant is revoked" : "the revocation check failed (fail closed)");
        if (p.ContainsKey("zk_compliance"))
            Fail("zk_compliance", "PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed)");

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

        // ---- 4. grant_ref, params, plan, attestation, reversibility
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
        else Mark("plan_root_authorized", "not-enforced");

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
        var toolCall = new ToolCall(inner["verb"] as string ?? "", op.Params, IntentJs.Get(p, "tool_binding") as string);
        var revClass = effective;
        if (revClass == null && nodeId is string nid && planNodes is JL pnl)
            revClass = pnl.OfType<JD>().Where(n => Equals(IntentJs.Get(n, "id"), nid)).Select(n => IntentJs.Get(n, "reversibility_class")).FirstOrDefault();
        var cctx = new JD { ["now"] = now, ["action"] = inner, ["delegation_depth"] = (long)depth };
        if (IntentJs.Get(ctx, "blast_radius") is { } br) cctx["blast_radius"] = br;
        if (revClass != null) cctx["reversibility_class"] = revClass;
        if (IntentJs.Get(ctx, "recent_action_times") is { } rat) cctx["recent_action_times"] = rat;

        List<string> PolicyStep()
        {
            var why = new List<string>();
            if (env == null) return new List<string> { "grant carries no valid envelope" };
            var pr = EnvelopePredicates(IntentJs.Get(env, "predicates"), actionCtx);
            if (pr != null) why.Add(pr);
            var r1 = EvaluateAgentCaveats(IntentJs.Get(env, "caveats"), cctx, actionCtx, toolCall);
            if (!r1.Ok) why.Add("caveat(s) not satisfied: " + string.Join(", ", r1.Failed));
            var r2 = EvaluateAgentCaveats(RootCaveats(grant), cctx, actionCtx, toolCall);
            if (!r2.Ok) why.Add("root caveat(s) not satisfied: " + string.Join(", ", r2.Failed));
            return why;
        }

        if (chain.Count > 0)
        {
            var leaf = chain[^1] as JD ?? new JD();
            var gcs = IntentJs.Get(grant, "caveats") as JL ?? new JL();
            object? extra = IntentJs.Get(leaf, "caveats") is JL lcs ? lcs.Skip(gcs.Count).ToList() : null;
            var dr = EvaluateAgentCaveats(extra, cctx, actionCtx, toolCall);
            if (dr.Ok) Mark("delegated_caveats", "pass");
            else Fail("delegated_caveats", "delegation caveat(s) not satisfied: " + string.Join(", ", dr.Failed));
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

        // ---- required checks (default-deny), then the replay counter
        // `replay` is decided by the claim below: tentatively pass (as the TypeScript guard does), flipped to fail on a refusal.
        Mark("replay", "pass");
        // `counter` in a require list is the documented alias of `replay` (it always meant the stateful check here).
        foreach (var name in DefaultRequiredChecks.Concat((input.Require?.Where(n => n != null) ?? Enumerable.Empty<string>()).Select(n => n == "counter" ? "replay" : n)))
        {
            var st = checks.GetValueOrDefault(name);
            if (st != "pass" && st != "fail")
            {
                Mark(name, "fail");
                reasons.Add($"{name}: required check is {st ?? "absent"} (default-deny: not enforced by this resource server)");
            }
        }

        AuthorizeResult Deny()
        {
            int status = AuthnChecks.Any(c => checks.GetValueOrDefault(c) == "fail") ? 401 : 403;
            return new AuthorizeResult
            {
                Allow = false, Status = status, Checks = Ordered(checks, order), Reasons = reasons,
                Reason = Decisive(checks, order, reasons), Pcactn = p, Verdict = core,
            };
        }

        if (checks.Values.Any(s => s == "fail")) return Deny();

        var holder = chain.Count > 0 ? IntentJs.Get(chain[^1], "holder") as string : null;
        var counterObj = IntentJs.Get(p, "counter");
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
        return new AuthorizeResult
        {
            Allow = true, Status = 200, Checks = Ordered(checks, order), Reasons = reasons, Pcactn = p, Verdict = core,
            Operation = new AuthorizedOperation(op.Verb, op.Resource, (string)signedDigest!, HashCanonical(p)),
        };
    }

    static Dictionary<string, string> Ordered(Dictionary<string, string> checks, List<string> order)
    {
        var o = new Dictionary<string, string>();
        foreach (var n in order) o[n] = checks[n];
        return o;
    }

    static string Decisive(Dictionary<string, string> checks, List<string> order, List<string> reasons)
    {
        foreach (var n in order.Where(n => n == "operation").Concat(order.Where(n => n != "operation")))
        {
            if (checks[n] != "fail") continue;
            var hit = reasons.FirstOrDefault(r => r.StartsWith(n + ":", StringComparison.Ordinal));
            if (hit != null) return hit;
        }
        return reasons.Count > 0 ? reasons[0] : "denied";
    }

    /// <summary>The plan leaf of a known plan node (Python <c>_plan_leaf(n["id"], n, conditions_digest(n.pre, n.post))</c>):
    /// throws for a node without an id, verb or resource.</summary>
    static JD NodeLeaf(object? n)
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
/// optionally, the PCActn's signed <c>tool_binding</c> digest (null = absent).</summary>
public sealed record ToolCall(string? Tool, object? Args, string? ToolSignatureDigest = null);
