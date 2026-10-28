// K5 tokenisation vault and aggregate read limits (C-315..C-319). Companion of ReadSide. Port of packages/pca/src/read-vault.ts; replays
// packages/pca/conformance/vault-aggregate-vectors.json. Total (never throws: a failure is deny bad_request), integers only, signed-grant
// VERIFICATION only (this SDK does not sign). Inputs are parsed JSON values (Pca.ParseJson).
//
// VAULT: RedactReadWithVault runs RedactRead and records every minted token; Detokenize returns the value only for the same signed,
// unexpired, pinned-principal grant, a sink it lists and a class it allows (an escalate class asks).
// AGGREGATES: AggregateRead is a pure step over an explicit state: query cap, epsilon budget, group size k, per-value clamp, the SAME
// answer for a repeated query without a new charge, and (dp) discrete Laplace noise from an INTEGER-EXACT sampler (Canonne-Kamath-Steinke)
// over a stream of SHA-256 blocks. 'seeded' noise is deterministic (the shared vectors pin it); 'secure' noise is keyed by the OS CSPRNG.
using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using S = AtlasPca.K5Strict;

namespace AtlasPca;

/// <param name="Cls">the data class of the tokenised field</param>
/// <param name="Value">the original scalar (string, bool or a parsed integer Num)</param>
/// <param name="Grant">the digest of the read grant the token was minted under</param>
/// <param name="Exp">the grant's expires_at</param>
public sealed record VaultEntry(string Cls, object? Value, string Grant, long Exp);

public interface IVaultStore
{
    void Put(string token, VaultEntry entry);
    VaultEntry? Get(string token);
}

/// <summary>In-memory vault (thread safe). A production vault belongs in your own durable store behind <see cref="IVaultStore"/>.</summary>
public sealed class MemoryVault : IVaultStore
{
    readonly ConcurrentDictionary<string, VaultEntry> _m = new(StringComparer.Ordinal);
    public void Put(string token, VaultEntry entry) => _m[token] = entry;
    public VaultEntry? Get(string token) => _m.TryGetValue(token, out var e) ? e : null;
}

public sealed record DetokenizeInput(object? Grant, object? Principal, object? Now, object? Sink, object? Token, IVaultStore Store);

public sealed record DetokenizeResult(string Decision, string? Code, object? Value)
{
    public JD ToJson() => new() { ["decision"] = Decision, ["code"] = Code, ["value"] = Value };
}

/// <param name="Values">one integer per row (a parsed JSON array; for count only the number of rows matters)</param>
/// <param name="Salt">a string of at least 16 characters; with noise 'seeded' it (and the query digest) seeds the noise</param>
/// <param name="Noise">'seeded' (deterministic: vectors, tests, reproducible audits) or 'secure' (the PRODUCTION setting: OS CSPRNG, not reproducible)</param>
/// <param name="State">{spent_micro, queries, answered} (parsed JSON; the result's State has the same shape)</param>
public sealed record AggregateInput(object? Grant, object? Principal, object? Now, object? Verb, object? Resource, object? Purpose, object? Fn, object? Values, object? Salt, object? Noise, object? State);

/// <summary>State is a JSON tree {spent_micro, queries, answered} of integer <see cref="Num"/>s, so it can be fed straight into the next call.</summary>
public sealed record AggregateResult(string Decision, string? Code, long? Value, JD State, long ChargedMicro)
{
    public JD ToJson() => new()
    {
        ["decision"] = Decision,
        ["code"] = Code,
        ["value"] = Value,
        ["state"] = State,
        ["charged_micro"] = ChargedMicro,
    };
}

/// <summary>A source of uniform integers.</summary>
public interface IDraws { long Uniform(long n); }

public static class ReadVault
{
    public const string AggregateDomain = "atlas-pca/aggregate-grant/v1\0";
    const string AgRef = "atlas-pca/aggregate-grant-ref/v1";
    const string AgQ = "atlas-pca/aggregate-query/v1";
    const string AgN = "atlas-pca/aggregate-noise/v1";
    const string DpStream = "atlas-pca/dp-stream/v1";
    const long Two48 = 1L << 48;
    const int MaxSteps = 100_000;

    static readonly Regex FnRe = new(@"\A(count|sum)\z", RegexOptions.None);
    static readonly string[] RuleKeys = { "verb", "resource_prefix", "purposes", "fns", "min_group", "clamp", "epsilon_micro", "dp" };
    static readonly string[] BodyKeys = { "v", "id", "principal", "issued_at", "expires_at", "rules", "epsilon_budget_micro", "max_queries" };

    static Num N(long v) => new(v.ToString(CultureInfo.InvariantCulture));

    // ---- vault ---------------------------------------------------------------------------------------------------------------

    /// <summary><see cref="ReadSide.RedactRead"/> that also records every token it minted in <paramref name="store"/>.</summary>
    public static ReadResult RedactReadWithVault(ReadInput inp, IVaultStore store)
    {
        var r = ReadSide.RedactRead(inp);
        if (r.Decision != "allow") return r;
        try
        {
            var body = (JD)((JD)inp.Grant!)["body"]!; // RedactRead allowed it, so the grant is valid
            var digest = ReadSide.ReadGrantDigest(body);
            var exp = S.U(body["expires_at"]);
            var record = (JD)inp.Record!;
            foreach (var (path, fo) in r.Fields)
            {
                var f = (JD)fo!;
                if ((string)f["action"]! == "masked" && f["kind"] is "token")
                    store.Put((string)r.View[path]!, new VaultEntry((string)f["class"]!, record[path], digest, exp));
            }
            return r;
        }
        catch (Exception) { return new ReadResult("deny", "bad_request", new JD(), new JD(), new List<string>(), new Dictionary<string, long>()); }
    }

    static DetokenizeResult No(string code) => new("deny", code, null);

    /// <summary>Turn a token back into its value, only for a sink the grant allows that token's class to reach.</summary>
    public static DetokenizeResult Detokenize(DetokenizeInput inp)
    {
        try
        {
            if (!S.IsB32(inp.Principal) || !S.IsUint(inp.Now) || inp.Token is not string token || inp.Sink is not string sink || inp.Store == null) return No("bad_request");
            var now = S.U(inp.Now);
            if (inp.Grant is not JD sg || !S.OnlyKeys(sg, "body", "sig") || !ReadSide.ValidReadGrantBody(sg["body"])) return No("bad_grant");
            var body = (JD)sg["body"]!;
            if ((string)body["principal"]! != (string)inp.Principal! || !S.VerifyBody(ReadSide.GrantDomain, body, inp.Principal, sg["sig"])) return No("bad_signature");
            if (now < S.U(body["issued_at"])) return No("not_yet");
            if (now >= S.U(body["expires_at"])) return No("expired");
            var e = inp.Store.Get(token);
            if (e == null || e.Grant != ReadSide.ReadGrantDigest(body)) return No("unknown_token");
            if (now >= e.Exp) return No("expired");
            if (!((JD)body["sinks"]!).TryGetValue(sink, out var ro)) return No("unknown_sink");
            var rule = (JD)ro!;
            if (S.Strs(rule["allow"]).Contains(e.Cls)) return new("allow", null, e.Value);
            if (S.Strs(rule["escalate"]).Contains(e.Cls)) return new("escalate", "label_escalate", null);
            return No("label_flow");
        }
        catch (Exception) { return No("bad_request"); }
    }

    // ---- aggregates ----------------------------------------------------------------------------------------------------------

    public static JD EmptyAggregateState() => new() { ["spent_micro"] = N(0), ["queries"] = N(0), ["answered"] = new JD() };

    static bool ValidRule(object? ro) =>
        ro is JD r && S.OnlyKeys(r, RuleKeys) && S.IsStr(r["verb"], 128) && S.IsStr(r["resource_prefix"], 512) && S.SortedUnique(r["purposes"], S.IdRe, 16) && ((List<object?>)r["purposes"]!).Count > 0 &&
        S.SortedUnique(r["fns"], FnRe, 2) && ((List<object?>)r["fns"]!).Count > 0 && S.IsUint(r["min_group"]) && S.U(r["min_group"]) >= 1 && S.IsUint(r["clamp"]) && S.U(r["clamp"]) <= 1_000_000 &&
        S.IsUint(r["epsilon_micro"]) && S.U(r["epsilon_micro"]) <= 1_073_741_824 && r["dp"] is bool dp && (!dp || S.U(r["epsilon_micro"]) >= 1);

    /// <summary>Shape of an aggregate grant body (no signature).</summary>
    public static bool ValidAggregateGrantBody(object? bo) =>
        bo is JD b && S.OnlyKeys(b, BodyKeys) && S.TryInt(b["v"], out var v) && v == 1 && S.Rx(b["id"], S.IdRe) && S.IsB32(b["principal"]) && S.IsUint(b["issued_at"]) && S.IsUint(b["expires_at"]) &&
        b["rules"] is List<object?> rules && rules.Count >= 1 && rules.Count <= 16 && rules.All(ValidRule) && S.IsUint(b["epsilon_budget_micro"]) && S.IsUint(b["max_queries"]);

    public static string AggregateGrantDigest(JD body) => Pca.HashCanonical(new JD { ["d"] = AgRef, ["g"] = body });

    static AggregateResult Fail(string code, JD? state = null) => new("deny", code, null, state ?? EmptyAggregateState(), 0);

    /// <summary>Answer one aggregate under the grant, or refuse. The input state is never mutated. Never throws.</summary>
    public static AggregateResult AggregateRead(AggregateInput inp)
    {
        try
        {
            // a malformed state is the one refusal that returns the EMPTY state
            if (inp.State is not JD st || !S.IsUint(st.GetValueOrDefault("spent_micro")) || !S.IsUint(st.GetValueOrDefault("queries")) || st.GetValueOrDefault("answered") is not JD answered ||
                !answered.Values.All(v => S.TryInt(v, out _))) return Fail("bad_request");
            AggregateResult Keep(string code) => Fail(code, st);
            var spent = S.U(st["spent_micro"]);
            var queries = S.U(st["queries"]);
            if (!S.IsB32(inp.Principal) || !S.IsUint(inp.Now)) return Keep("bad_request");
            var now = S.U(inp.Now);
            if (inp.Grant is not JD sg || !S.OnlyKeys(sg, "body", "sig") || !ValidAggregateGrantBody(sg["body"])) return Keep("bad_grant");
            var g = (JD)sg["body"]!;
            if ((string)g["principal"]! != (string)inp.Principal! || !S.VerifyBody(AggregateDomain, g, inp.Principal, sg["sig"])) return Keep("bad_signature");
            if (now < S.U(g["issued_at"])) return Keep("not_yet");
            if (now >= S.U(g["expires_at"])) return Keep("expired");
            if (!S.IsStr(inp.Verb, 128) || !S.IsStr(inp.Resource, 512) || !S.Rx(inp.Purpose, S.IdRe) || !(inp.Fn is "count" or "sum") || !(inp.Noise is "seeded" or "secure") ||
                inp.Salt is not string salt || salt.Length < 16 || inp.Values is not List<object?> values || values.Count > 1_000_000 || !values.All(v => S.TryInt(v, out _))) return Keep("bad_request");
            var verb = (string)inp.Verb!;
            var resource = (string)inp.Resource!;
            var purpose = (string)inp.Purpose!;
            var fn = (string)inp.Fn!;
            var rule = ((List<object?>)g["rules"]!).Cast<JD>().FirstOrDefault(r => (string)r["verb"]! == verb && resource.StartsWith((string)r["resource_prefix"]!, StringComparison.Ordinal) && S.Strs(r["purposes"]).Contains(purpose));
            if (rule == null || !S.Strs(rule["fns"]).Contains(fn)) return Keep("no_read_scope");
            var clamp = S.U(rule["clamp"]);
            if (values.Count < S.U(rule["min_group"])) return Keep("group_too_small");
            var clampedSum = values.Sum(v => Math.Clamp(S.U(v), -clamp, clamp));
            var qd = Pca.HashCanonical(new JD { ["d"] = AgQ, ["g"] = AggregateGrantDigest(g), ["verb"] = verb, ["resource"] = resource, ["purpose"] = purpose, ["fn"] = fn, ["n"] = (long)values.Count, ["s"] = clampedSum });
            if (answered.TryGetValue(qd, out var prior)) return new("allow", null, S.U(prior), st, 0);
            if (queries + 1 > S.U(g["max_queries"])) return Keep("query_cap");
            var dp = (bool)rule["dp"]!;
            var eps = S.U(rule["epsilon_micro"]);
            var cost = dp ? eps : 0;
            if (spent + cost > S.U(g["epsilon_budget_micro"])) return Keep("epsilon_exhausted");
            var exact = fn == "count" ? values.Count : clampedSum;
            if (dp)
            {
                var sens = fn == "count" ? 1 : clamp;
                var draws = (string)inp.Noise! == "secure" ? SecureDraws() : SeededDraws(Pca.HashCanonical(new JD { ["d"] = AgN, ["salt"] = salt, ["q"] = qd }));
                exact += DiscreteLaplace(draws, eps, sens * 1_000_000);
            }
            var nextAnswered = new JD(answered) { [qd] = N(exact) };
            var next = new JD { ["spent_micro"] = N(spent + cost), ["queries"] = N(queries + 1), ["answered"] = nextAnswered };
            return new("allow", null, exact, next, cost);
        }
        catch (Exception) { return Fail("bad_request"); } // includes a sampler bad bound / no termination
    }

    // ---- integer-exact discrete Laplace sampler (Canonne, Kamath, Steinke 2020, Alg. 1-2) --------------------------------------
    // Integer arithmetic over a stream of 48-bit draws from SHA-256 blocks, so every language agrees byte for byte. P[x] ~ exp(-|x| s / t).

    sealed class SeededStream : IDraws
    {
        readonly string _seed;
        long _block;
        readonly long[] _buf = new long[5];
        int _pos = 5;
        public SeededStream(string seed) { _seed = seed; }

        long Next48()
        {
            if (_pos == 5)
            {
                var bytes = Pca.B64uDecode(Pca.HashCanonical(new JD { ["d"] = DpStream, ["seed"] = _seed, ["i"] = _block++ }), 32) ?? throw new InvalidOperationException("dp stream: bad block");
                for (var k = 0; k < 5; k++)
                {
                    long v = 0;
                    for (var j = 0; j < 6; j++) v = v * 256 + bytes[k * 6 + j];
                    _buf[k] = v;
                }
                _pos = 0;
            }
            return _buf[_pos++];
        }

        public long Uniform(long n)
        {
            if (n < 1 || n > (1L << 47)) throw new ArgumentOutOfRangeException(nameof(n), "uniform: bad bound");
            var limit = Two48 - (Two48 % n);
            for (var i = 0; i < MaxSteps; i++)
            {
                var r = Next48();
                if (r < limit) return r % n;
            }
            throw new InvalidOperationException("uniform: no draw");
        }
    }

    /// <summary>A draw source: block i is SHA-256 of the canonical {d, seed, i}; each block yields five 48-bit values.</summary>
    public static IDraws SeededDraws(string seed) => new SeededStream(seed);

    /// <summary>The PRODUCTION mode: a fresh 32-byte seed from the operating system's CSPRNG. Answers differ per call; a repeated query is still answered from the state.</summary>
    public static IDraws SecureDraws() => new SeededStream(Pca.B64u(RandomNumberGenerator.GetBytes(32)));

    static bool Bern(IDraws d, long num, long den) => d.Uniform(den) < num; // Bernoulli(num/den)

    /// <summary>Bernoulli(exp(-num/den)) for 0 &lt;= num/den &lt;= 1.</summary>
    static bool BernExpSmall(IDraws d, long num, long den)
    {
        for (long k = 1; k <= MaxSteps; k++)
            if (!Bern(d, num, den * k)) return k % 2 == 1;
        throw new InvalidOperationException("bernoulli: no termination");
    }

    /// <summary>Discrete Laplace with P[x] proportional to exp(-|x| s / t) (CKS Alg. 2: s the rate numerator, t the scale denominator).</summary>
    public static long DiscreteLaplace(IDraws d, long s, long t)
    {
        for (var outer = 0; outer < MaxSteps; outer++)
        {
            var u = d.Uniform(t);
            if (!BernExpSmall(d, u, t)) continue;
            long v = 0;
            while (BernExpSmall(d, 1, 1)) if (++v > MaxSteps) throw new InvalidOperationException("laplace: no termination");
            var y = (u + t * v) / s;
            var negative = d.Uniform(2) == 1;
            if (negative && y == 0) continue;
            return negative ? -y : y;
        }
        throw new InvalidOperationException("laplace: no sample");
    }
}
