// The software attestation layer of the reference (attestation.ts): the binding hash, the dev attestor and its documents, the document registry, the bounded
// nonce store and the nonce entropy gate, the agent-binding match, VerifyAttestation and its hook, the multi-root (threshold over independent roots) verifier
// and evidence anchoring. The decisions are the reference's (stage order, first failure wins, the single-use nonce rule, the N-of-M reconciliation): the same
// facts give the same verdict and the same reason text. Documents, bindings, contexts and claims are the JSON tree (Dictionary / List / Num / string / bool /
// null) in the reference's member names. A hardware verifier is any IHardwareAttestation; a nonce store is any IAttestationNonceStore. Everything is synchronous.
// The legacy unbound-PQ opt-out is not offered: a post-quantum or hybrid attestation verifies only under a pinned key.
using System.Globalization;
using System.Numerics;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>A hardware attestation verifier: <c>Verify({document, ctx, nowMs, expected})</c> answers <c>{ok, reason?, measured?, bound?, hostAsserted?}</c> (a JSON object).</summary>
public interface IHardwareAttestation
{
    object? Verify(D input);
}

/// <summary>An <see cref="IHardwareAttestation"/> over a function.</summary>
public sealed class HardwareAttestationFn(Func<D, object?> fn) : IHardwareAttestation
{
    public object? Verify(D input) => fn(input);
}

/// <summary>A single-use store of server-issued attestation nonces. <c>Consume</c> must be atomic: true for the first call with a nonce, false for every later one.</summary>
public interface IAttestationNonceStore
{
    bool Consume(object? nonce);
}

/// <summary>The in-memory single-process nonce store: a consumed nonce is refused for the retention window; a store full of retained nonces refuses new ones (it never evicts
/// a live one); only aged-out entries are dropped. A clock reading that is not a safe integer refuses the nonce (fail closed).</summary>
public sealed class MemoryNonceStore : IAttestationNonceStore
{
    readonly double _max, _retention;
    readonly Func<object?> _clock;
    readonly Dictionary<string, double> _seen = new(StringComparer.Ordinal);
    readonly List<string> _order = new(); // insertion order == time order
    readonly object _gate = new();

    /// <param name="max">null: 100000; else a positive safe integer.</param>
    /// <param name="retentionMs">null: one hour; else a positive safe integer (ms).</param>
    /// <param name="now">null: the wall clock.</param>
    public MemoryNonceStore(object? max = null, object? retentionMs = null, Func<object?>? now = null)
    {
        max ??= IntentJs.OfLong(100_000);
        if (!IntentJs.IsSafeInteger(max) || IntentJs.NumOf(max)!.Value < 1)
            throw new ArgumentException("memoryNonceStore: max must be a positive integer (a store that retains nothing gives no replay protection)");
        retentionMs ??= IntentJs.OfLong(AttestationSoft.DefaultNonceRetentionMs);
        if (!IntentJs.IsSafeInteger(retentionMs) || IntentJs.NumOf(retentionMs)!.Value <= 0)
            throw new ArgumentException("memoryNonceStore: retentionMs must be a positive integer (ms)");
        _max = IntentJs.NumOf(max)!.Value;
        _retention = IntentJs.NumOf(retentionMs)!.Value;
        _clock = now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }

    public bool Consume(object? nonce)
    {
        if (nonce is not string n) return false;
        lock (_gate)
        {
            var tv = _clock();
            if (!IntentJs.IsSafeInteger(tv)) return false; // integer epoch ms only; anything else fails closed
            double t = IntentJs.NumOf(tv)!.Value;
            if (_seen.TryGetValue(n, out var at))
            {
                if (t - at < _retention) return false; // retained: a replay
                _seen.Remove(n); // aged out of retention: treated as new
                _order.Remove(n);
            }
            if (_seen.Count >= _max)
            {
                // make room ONLY from entries that aged out of retention; never evict a live one
                foreach (var k in _order.ToList())
                {
                    if (t - _seen[k] < _retention) break;
                    _seen.Remove(k);
                    _order.Remove(k);
                }
                if (_seen.Count >= _max) return false; // full of live nonces: fail closed
            }
            _seen[n] = t;
            _order.Add(n);
            return true;
        }
    }
}

/// <summary>A software-mode attestor for development and CI: signs attestation documents with <c>secret</c>. A self-asserted identity, not a hardware root.</summary>
public sealed class DevAttestor
{
    /// <summary>The b64u key a verifier lists in <c>trustedAttestorKeys</c>.</summary>
    public string PublicKey { get; }
    readonly byte[] _secret;
    readonly string? _alg;
    readonly SuiteSecretKeys? _suite;
    readonly string? _pqPk;

    internal DevAttestor(byte[] secret, string? alg, SuiteSecretKeys? suite)
    {
        _secret = secret;
        _alg = alg;
        _suite = suite;
        using var k = EdKey.FromSeed(secret);
        PublicKey = k.Id;
        _pqPk = PqSuites.SuitePqPublicKey(alg, suite);
    }

    static object Need(D claims, string k) => claims.TryGetValue(k, out var v) ? v! : throw new InvalidOperationException("canonicalize: undefined member " + k);

    /// <summary>Sign a software-mode document over the claims (model_id, weights_digest, runtime_measurement, operator, nonce, issued_at, expires_at; optional
    /// system_prompt_digest, tool_manifest_digest; holder_pub + grant_ref + epoch bind it). The suite and the attestor's PQ key are signed into the body.</summary>
    public D Attest(D claims)
    {
        var body = new D
        {
            ["model_id"] = claims.GetValueOrDefault("model_id"), ["weights_digest"] = claims.GetValueOrDefault("weights_digest"),
            ["runtime_measurement"] = claims.GetValueOrDefault("runtime_measurement"), ["operator"] = claims.GetValueOrDefault("operator"),
            ["nonce"] = claims.GetValueOrDefault("nonce"), ["issued_at"] = claims.GetValueOrDefault("issued_at"), ["expires_at"] = claims.GetValueOrDefault("expires_at"),
            ["attestor"] = PublicKey, ["mode"] = "software",
        };
        foreach (var k in new[] { "model_id", "weights_digest", "runtime_measurement", "operator", "nonce", "issued_at", "expires_at" }) _ = Need(claims, k); // an absent claim has no canonical form
        foreach (var k in new[] { "system_prompt_digest", "tool_manifest_digest" })
            if (claims.TryGetValue(k, out var v)) body[k] = v;
        if (claims.ContainsKey("holder_pub") && claims.ContainsKey("grant_ref") && claims.ContainsKey("epoch"))
            body["binding"] = AttestationSoft.AttestationBindingB64u(new D
            {
                ["holderPub"] = claims["holder_pub"], ["grantRef"] = claims["grant_ref"], ["epoch"] = claims["epoch"], ["nonce"] = claims.GetValueOrDefault("nonce"),
            });
        var signed = IntentJs.BindSuiteFields(body, _alg, _alg != null, _pqPk, _pqPk != null);
        var fields = PqSuites.SignSuiteArtifact(_alg, PqSuites.SuiteKeysOf(_secret, _suite), AttestationSoft.Message(signed));
        var doc = new D(signed) { ["sig"] = fields.Sig };
        if (fields.PqSig != null) doc["pq_sig"] = fields.PqSig;
        return doc;
    }
}

public static class AttestationSoft
{
    public const string BindDomain = "atlas-pca/attest-bind/v1\0";
    public const string AnchorDomain = "atlas-pca/attest-anchor/v1\0";
    public const string DocDomain = "atlas-pca/attest/v1\0";
    public const double MaxAttestationAgeMs = 5 * 60_000;
    public const long DefaultNonceRetentionMs = 60 * 60 * 1000;
    public const int MinAttestationNonceBytes = 16;

    /// <summary>JavaScript <c>undefined</c> (a member that is absent), distinct from JSON null.</summary>
    internal static readonly object Undef = new();

    /// <summary>The published constants of the module.</summary>
    public static D Constants() => new()
    {
        ["ATTEST_BIND_DOMAIN"] = BindDomain, ["MAX_ATTESTATION_AGE_MS"] = Facade.JsNumber(MaxAttestationAgeMs), ["DEFAULT_NONCE_RETENTION_MS"] = IntentJs.OfLong(DefaultNonceRetentionMs),
        ["MIN_ATTESTATION_NONCE_BYTES"] = IntentJs.OfLong(MinAttestationNonceBytes), ["ATTEST_ANCHOR_DOMAIN"] = AnchorDomain,
    };

    // ---- JavaScript value helpers ----

    static object? G(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : Undef;

    static object? Path(object? o, params string[] keys)
    {
        foreach (var k in keys)
        {
            o = G(o, k);
            if (ReferenceEquals(o, Undef)) return Undef;
        }
        return o;
    }

    internal static string Js(object? x) => IntentRevocation.JsText(ReferenceEquals(x, Undef) ? null : x, !ReferenceEquals(x, Undef));

    static double? Fin(object? x) => IntentJs.NumOf(x) is double d && double.IsFinite(d) ? d : null;

    /// <summary>JavaScript strict equality of two JSON values (a number never equals a boolean or a string; objects by reference).</summary>
    internal static bool Seq(object? a, object? b)
    {
        if (ReferenceEquals(a, Undef) || ReferenceEquals(b, Undef)) return ReferenceEquals(a, b);
        if (a is null || b is null) return a is null && b is null;
        var na = IntentJs.NumOf(a);
        var nb = IntentJs.NumOf(b);
        if (na != null || nb != null) return na is double x && nb is double y && x == y;
        if (a is string s && b is string t) return string.Equals(s, t, StringComparison.Ordinal);
        if (a is bool p && b is bool q) return p == q;
        return ReferenceEquals(a, b);
    }

    /// <summary>JavaScript truthiness (an empty object or array is truthy).</summary>
    internal static bool Truthy(object? x) => x switch
    {
        _ when ReferenceEquals(x, Undef) => false,
        null => false,
        bool b => b,
        string s => s.Length > 0,
        _ when IntentJs.NumOf(x) is double d => d != 0 && !double.IsNaN(d),
        _ => true,
    };

    static string Msg(Exception e) => string.IsNullOrEmpty(e.Message) ? "unknown" : e.Message;

    internal static byte[] Message(object? body) => IntentJs.Message(DocDomain, body);

    // ---- the binding ----

    static string Lp(object? v) => (string)v!;

    /// <summary>The 64-byte report_data value SHA-512(domain || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce)). Throws on a missing field or an epoch that is not a non-negative safe integer.</summary>
    public static byte[] AttestationBinding(object? exp)
    {
        var holder = G(exp, "holderPub"); var grant = G(exp, "grantRef"); var nonce = G(exp, "nonce"); var epoch = G(exp, "epoch");
        if (exp is not D || holder is not string { Length: > 0 }) throw new ArgumentException("binding: holderPub required");
        if (grant is not string { Length: > 0 }) throw new ArgumentException("binding: grantRef required");
        if (nonce is not string { Length: > 0 }) throw new ArgumentException("binding: nonce required");
        if (!IntentJs.IsSafeInteger(epoch) || IntentJs.NumOf(epoch)!.Value < 0) throw new ArgumentException("binding: epoch must be a non-negative safe integer");
        return AttestUtil.BindingBytes(new AtlasPca.AttestationBinding(Lp(holder), Lp(grant), IntentJs.NumOf(epoch)!.Value, Lp(nonce)));
    }

    /// <summary>The base64url form of <see cref="AttestationBinding"/> (what a software document carries in <c>binding</c>).</summary>
    public static string AttestationBindingB64u(object? exp) => Pca.B64u(AttestationBinding(exp));

    /// <summary>base64url(sha256(canonical(document))): a content address of a signed quote (strict canonical form).</summary>
    public static string AttestationDigest(object? doc) => Pca.HashCanonical(doc);

    /// <summary>A dev attestor over a 32-byte Ed25519 secret. <paramref name="alg"/> null is ed25519; another suite needs its PQ key material in <paramref name="suite"/>. Throws on an unknown alg.</summary>
    public static DevAttestor CreateDevAttestor(byte[] secret, string? alg = null, SuiteSecretKeys? suite = null)
    {
        if (IntentJs.SuiteError(alg, alg != null) != null) throw new ArgumentException($"createDevAttestor: unknown signature alg '{alg}'");
        return new DevAttestor(secret, alg, suite);
    }

    /// <summary>A resolver over a document list keyed by the document's NONCE (the last document of a nonce wins): the document whose nonce is the PCActn's
    /// <c>attestation.quote_digest</c>, or null.</summary>
    public static Func<object?, D?> AttestationRegistry(object? docs)
    {
        var byNonce = new Dictionary<string, D>(StringComparer.Ordinal);
        if (docs is L l)
            foreach (var d in l)
                if (d is D dd && dd.GetValueOrDefault("nonce") is string n) byNonce[n] = dd;
        return ctx => Path(ctx, "pcactn", "attestation", "quote_digest") is string key && byNonce.TryGetValue(key, out var doc) ? doc : null;
    }

    // ---- the nonce entropy gate ----

    static bool HexChar(char c) => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
    static bool B64Char(char c) => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-';

    /// <summary>Whether the nonce plausibly carries at least <paramref name="minBytes"/> (never below 16) bytes of entropy: hex or base64url of that length with at least 8 distinct
    /// characters. A syntactic floor only: the server must still draw nonces from a CSPRNG.</summary>
    public static bool NonceEntropyOk(object? nonce, object? minBytes = null)
    {
        if (nonce is not string s) return false;
        double mb = minBytes == null ? MinAttestationNonceBytes : JsJson.ToJsNumber(minBytes);
        double need = double.IsNaN(mb) ? double.NaN : Math.Max(mb, MinAttestationNonceBytes);
        bool hex = s.Length > 0 && s.All(HexChar), b64 = s.Length > 0 && s.All(B64Char);
        if (!hex && !b64) return false;
        double bytes = hex ? s.Length / 2.0 : Math.Floor(s.Length * 3 / 4.0);
        if (bytes < need) return false;
        return s.Distinct().Count() >= 8;
    }

    // ---- the agent-binding match ----

    static bool IsSvnBound(object? x) => IntentJs.NumOf(x) is double d && IntentJs.IsSafeInteger(x) && d >= 0 && !IntentJs.IsNegZero(d);

    static bool SvnSpec(object? mm) => mm is D d && d.Count == 1 && d.TryGetValue("svn", out var v) && IsSvnBound(v);

    static double? MeasuredSvn(object? runtime)
    {
        if (runtime is not string s || s.Length == 0 || !s.All(c => c is >= '0' and <= '9') || (s.Length > 1 && s[0] == '0')) return null;
        var n = BigInteger.Parse(s, CultureInfo.InvariantCulture);
        return n <= (BigInteger)IntentJs.MaxSafe ? (double)n : null;
    }

    static bool NonEmptyList(object? x) => x is L l && l.Count > 0;

    /// <summary>Whether anything pins the agent's identity (so a missing document is a deny). A malformed <c>min_measurement</c> counts: it fails closed.</summary>
    public static bool RequiresAttestation(object? binding)
    {
        var b = binding as D ?? new D();
        bool hasMin = b.TryGetValue("min_measurement", out var mm) && !(mm is string ms && ms.Length == 0);
        return NonEmptyList(b.GetValueOrDefault("model_allowlist")) || hasMin || (b.GetValueOrDefault("operator") is string op && op.Length > 0)
            || NonEmptyList(b.GetValueOrDefault("weights_allowlist")) || NonEmptyList(b.GetValueOrDefault("system_prompt_allowlist"))
            || NonEmptyList(b.GetValueOrDefault("tool_manifest_allowlist")) || b.GetValueOrDefault("require_hardware") is true || b.GetValueOrDefault("require_measured_weights") is true;
    }

    static bool Member(object? list, object? x) => list is L l && l.Any(e => Seq(e, x));

    /// <summary>The first constraint of <paramref name="binding"/> that the measured identity violates (null when it satisfies every pinned one). A pinned digest the identity does not
    /// carry fails closed; a malformed <c>min_measurement</c> is never satisfied.</summary>
    public static string? MatchAgentBinding(object? ident, object? binding)
    {
        var b = binding as D ?? new D();
        var i = ident;
        bool hasMm = b.TryGetValue("min_measurement", out var mm);
        if (i == null) throw new InvalidOperationException("Cannot read properties of null (reading 'runtime_measurement')");
        var runtime = G(i, "runtime_measurement");
        if (NonEmptyList(b.GetValueOrDefault("model_allowlist")) && !Member(b["model_allowlist"], G(i, "model_id")))
            return $"model_id {Js(G(i, "model_id"))} not in model_allowlist";
        if (hasMm && !(mm is string e0 && e0.Length == 0))
        {
            if (mm is string want)
            {
                if (!Seq(runtime, want)) return "runtime_measurement does not match required min_measurement";
            }
            else if (!SvnSpec(mm))
                return "min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)";
            else
            {
                var bound = IntentJs.NumOf(((D)mm!)["svn"])!.Value;
                var got = MeasuredSvn(runtime);
                if (got == null) return $"runtime_measurement {Js(runtime)} is not an integer SVN (required min svn {JsJson.ToJsString(((D)mm)["svn"])})";
                if (got < bound) return $"runtime_measurement svn {JsJson.NumberToString(got.Value)} is below required min svn {JsJson.ToJsString(((D)mm)["svn"])}";
            }
        }
        if (b.GetValueOrDefault("operator") is string op && op.Length > 0 && !Seq(G(i, "operator"), op)) return $"operator {Js(G(i, "operator"))} is not the bound operator";
        if (b.GetValueOrDefault("require_measured_weights") is true && G(i, "weights_measured") is not true)
            return "weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)";
        if (NonEmptyList(b.GetValueOrDefault("weights_allowlist")) && !Member(b["weights_allowlist"], G(i, "weights_digest")))
            return "weights_digest not in weights_allowlist (model swap / fine-tune?)";
        if (NonEmptyList(b.GetValueOrDefault("system_prompt_allowlist")) && !(G(i, "system_prompt_digest") is string sp && Member(b["system_prompt_allowlist"], sp)))
            return "system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)";
        if (NonEmptyList(b.GetValueOrDefault("tool_manifest_allowlist")) && !(G(i, "tool_manifest_digest") is string tm && Member(b["tool_manifest_allowlist"], tm)))
            return "tool_manifest_digest not in tool_manifest_allowlist (tools changed?)";
        return null;
    }

    /// <summary>Whether the document's nonce is the one the PCActn declares in <c>attestation.quote_digest</c>.</summary>
    public static bool NonceBinds(object? doc, object? ctx) => G(doc, "nonce") is string n && Seq(n, Path(ctx, "pcactn", "attestation", "quote_digest"));

    // ---- VerifyAttestation ----

    static string? NonceAgeReason(object? issued, double now, double skew, double maxAge)
    {
        if (Fin(issued) is not double iss) return "server nonce issue time unknown (cannot establish freshness)";
        if (now + skew < iss) return "nonce issued in the future";
        if (now - iss > maxAge + skew) return "attestation nonce expired (stale quote)";
        return null;
    }

    static string Window(double now, double skew, object? iatO, object? expO)
    {
        if (Fin(iatO) is not double iat || Fin(expO) is not double exp) return "malformed";
        if (exp < iat) return "malformed";
        if (now + skew < iat) return "notyet";
        if (now - skew > exp) return "expired";
        return "valid";
    }

    static string[] Order(bool hasHw)
    {
        string[] head = ["KPresent", "KBindingConstructible", "KGrantRef", "KEpoch", "KQuote", "KDocNonce", "KReqHwVerifier", "KReqHwMode"];
        string[] mid = hasHw
            ? ["KHwNonceAge", "KHwOk", "KHwBound", "KHwMeasured"]
            : ["KSoftMode", "KAttestorTrusted", "KAlgKnown", "KSigOk", "KBindingPresent", "KBindingEq", "KWindowWellFormed", "KNotYetValid", "KExpired", "KSoftNonceAge"];
        return [.. head, .. mid, "KAgentBinding"];
    }

    static D SoftwareIdentity(D d)
    {
        var o = new D();
        foreach (var k in new[] { "model_id", "weights_digest", "runtime_measurement", "operator" })
            if (d.TryGetValue(k, out var v)) o[k] = v;
        foreach (var k in new[] { "system_prompt_digest", "tool_manifest_digest" })
            if (d.GetValueOrDefault(k) is string s) o[k] = s;
        return o;
    }

    static IReadOnlyDictionary<string, string>? Pins(object? v) => v is D d ? d.Where(e => e.Value is string).ToDictionary(e => e.Key, e => (string)e.Value!) : null;

    /// <summary>Verify the document for one action: <c>{ok, present, bound, reason?, identity?}</c>. Input members: <c>document</c>, <c>ctx</c> ({pcactn, grant}), <c>expected</c> (the
    /// server-issued binding), <c>nowMs</c>, <c>trustedAttestorKeys</c>, <c>pqPins</c>?, <c>hardwareVerifier</c> (an <see cref="IHardwareAttestation"/>)?, <c>maxNonceAgeMs</c>?, <c>clockSkewMs</c>?.
    /// The stages run in a fixed order and the first failure wins; the hardware route needs the verifier to report ok, bound and a measured identity, the software route a trusted attestor,
    /// a known alg, a verifying signature (post-quantum only under a pin), a binding equal to the expected one and a live validity window; the agent_binding match always runs last.</summary>
    public static D VerifyAttestation(D inp)
    {
        var doc = inp.GetValueOrDefault("document");
        bool present = doc is D or L;
        D Fail(string reason) => new() { ["ok"] = false, ["present"] = present, ["bound"] = false, ["reason"] = reason };
        try
        {
            var ctx = inp.GetValueOrDefault("ctx");
            var expected = inp.GetValueOrDefault("expected");
            if (Fin(inp.GetValueOrDefault("nowMs")) is not double now) return Fail("verifier clock is not a finite time (fail closed)");
            var trusted = new HashSet<string>(StringComparer.Ordinal);
            if (inp.GetValueOrDefault("trustedAttestorKeys") is L tk) foreach (var k in tk) if (k is string ks) trusted.Add(ks);
            double skew = Fin(inp.GetValueOrDefault("clockSkewMs")) is double cs ? Math.Max(0, cs) : 0;
            var ma = Fin(inp.GetValueOrDefault("maxNonceAgeMs"));
            double maxAge = Math.Min(ma is double m && m > 0 ? m : MaxAttestationAgeMs, MaxAttestationAgeMs);
            var hwVerifier = inp.GetValueOrDefault("hardwareVerifier") as IHardwareAttestation;
            bool hasHw = hwVerifier != null;
            var d = doc as D ?? new D();
            object? envMemo = null;
            bool envDone = false;
            D? Env()
            {
                if (!envDone)
                {
                    if (ctx == null) throw new InvalidOperationException("Cannot read properties of null (reading 'grant')");
                    envMemo = Pca.ReadEnvelope(G(ctx, "grant") is var g && !ReferenceEquals(g, Undef) ? g : null);
                    envDone = true;
                }
                return (D?)envMemo;
            }
            bool RequireHw() => Env() is { } e && Path(e, "agent_binding", "require_hardware") is true;
            string? win = null;
            string Win() => win ??= Window(now, skew, d.GetValueOrDefault("issued_at"), d.GetValueOrDefault("expires_at"));
            string binding = "";
            object? identity = null;

            (bool, string) Stage(string k)
            {
                switch (k)
                {
                    case "KPresent": return (present, "no attestation document for this action");
                    case "KBindingConstructible":
                        try { binding = AttestationBindingB64u(expected); return (true, ""); }
                        catch (Exception e) { return (false, "attestation binding not constructible: " + (string.IsNullOrEmpty(e.Message) ? "invalid" : e.Message)); }
                    case "KGrantRef": return (Seq(Path(ctx, "pcactn", "grant_ref"), G(expected, "grantRef")), "attestation binding: PCActn grant_ref differs from expected grant");
                    case "KEpoch": return (Seq(Path(ctx, "pcactn", "attestation", "epoch"), G(expected, "epoch")), "attestation binding: PCActn attestation epoch differs from expected epoch");
                    case "KQuote": return (Seq(Path(ctx, "pcactn", "attestation", "quote_digest"), G(expected, "nonce")), "attestation nonce does not bind to this PCActn");
                    case "KDocNonce": return (Seq(G(d, "nonce"), G(expected, "nonce")), "attestation nonce does not match the server-issued nonce");
                    case "KReqHwVerifier": return (!RequireHw() || hasHw, "agent_binding.require_hardware: no hardware verifier is configured (fail closed)");
                    case "KReqHwMode": return (!RequireHw() || d.GetValueOrDefault("mode") is "hardware", "agent_binding.require_hardware: attestation document is not hardware-rooted (software mode)");
                    case "KHwNonceAge": { var r = NonceAgeReason(G(expected, "nonceIssuedAt"), now, skew, maxAge); return (r == null, r ?? ""); }
                    case "KSoftMode": return (d.GetValueOrDefault("mode") is "software", $"document mode {Js(G(d, "mode"))} needs a hardwareVerifier");
                    case "KAttestorTrusted": { var at = d.GetValueOrDefault("attestor") as string; return (at != null && trusted.Contains(at), "attestor key is not trusted"); }
                    case "KAlgKnown": return (IntentJs.SuiteError(d.GetValueOrDefault("alg"), d.ContainsKey("alg")) == null, "attestation declares an unknown signature alg");
                    case "KSigOk":
                    {
                        bool ok = false;
                        if (d.GetValueOrDefault("sig") is string sig)
                        {
                            var body = d.Where(e => e.Key is not ("sig" or "pq_sig")).ToDictionary(e => e.Key, e => e.Value);
                            ok = IntentJs.VerifyPinnedSuite(d.GetValueOrDefault("alg"), d.ContainsKey("alg"), d.GetValueOrDefault("attestor") as string ?? "", d.GetValueOrDefault("pq_pk"),
                                Message(body), sig, d.GetValueOrDefault("pq_sig"), Pins(inp.GetValueOrDefault("pqPins")));
                        }
                        return (ok, "attestation signature does not verify");
                    }
                    case "KBindingPresent": return (d.GetValueOrDefault("binding") is string { Length: > 0 }, "attestation is not bound (binding absent)");
                    case "KBindingEq": return (Seq(G(d, "binding"), binding), "attestation binding mismatch (holder/grant/epoch/nonce)");
                    case "KWindowWellFormed": return (Win() != "malformed", "malformed attestation validity window");
                    case "KNotYetValid": return (Win() != "notyet", "attestation not yet valid");
                    case "KExpired": return (Win() != "expired", "attestation expired");
                    case "KSoftNonceAge":
                    {
                        var issued = G(expected, "nonceIssuedAt");
                        if (IntentJs.NumOf(issued) == null) return (true, "");
                        var r = NonceAgeReason(issued, now, skew, maxAge);
                        return (r == null, r ?? "");
                    }
                    case "KAgentBinding":
                    {
                        var env = Env();
                        var ab = env == null ? Undef : Path(env, "agent_binding");
                        var err = MatchAgentBinding(identity, ReferenceEquals(ab, Undef) ? null : ab);
                        return (err == null, err ?? "");
                    }
                    default: throw new InvalidOperationException("unknown stage " + k);
                }
            }

            object? hw = null;
            foreach (var k in Order(hasHw))
            {
                if (k == "KHwOk")
                {
                    hw = hwVerifier!.Verify(new D { ["document"] = doc, ["ctx"] = ctx, ["nowMs"] = inp.GetValueOrDefault("nowMs"), ["expected"] = expected });
                    if (hw == null) throw new InvalidOperationException("Cannot read properties of null (reading 'ok')");
                }
                if (k == "KAgentBinding" && identity == null) identity = hasHw ? G(hw, "measured") : SoftwareIdentity(d);
                bool holds;
                string why;
                if (k == "KHwOk")
                {
                    holds = Truthy(G(hw, "ok"));
                    var rs = G(hw, "reason");
                    why = "hardware attestation rejected: " + (ReferenceEquals(rs, Undef) || rs == null ? "invalid" : Js(rs));
                }
                else if (k == "KHwBound") { holds = G(hw, "bound") is true; why = "hardware verifier did not confirm report_data binding"; }
                else if (k == "KHwMeasured") { holds = Truthy(G(hw, "measured")); why = "hardware verifier returned no measured identity"; }
                else (holds, why) = Stage(k);
                if (!holds) return Fail(why);
            }
            return new D { ["ok"] = true, ["present"] = true, ["bound"] = true, ["identity"] = identity };
        }
        catch (Exception e) { return Fail("attestation verification error (fail closed): " + Msg(e)); }
    }

    // ---- the hook ----

    /// <summary>The attestation hook for the pipeline: <c>hook(ctx)</c> answers <c>{enforced: true, ok, reason?, present, bound}</c>. Options: <c>trustedAttestorKeys</c>, <c>nonceStore</c> (an
    /// <see cref="IAttestationNonceStore"/>), <c>minNonceBytes</c>, <c>hardwareVerifier</c>, <c>resolveDocument</c> (Func&lt;object?, object?&gt;), <c>expectedBinding</c> (Func&lt;object?, object?&gt;),
    /// <c>insecure_selfDeclaredNonce</c>, <c>maxNonceAgeMs</c>, <c>now</c> (Func&lt;object?&gt;, ms), <c>clockSkewMs</c>, <c>pqPins</c>. Without <c>expectedBinding</c> the hook is closed (no server-issued
    /// nonce); an ok and bound verdict also needs the store's single-use answer when a store is configured. The hook carries its assurance label (from the configuration, never the document).</summary>
    public static Func<object?, D> CreateAttestationVerifier(D opts)
    {
        var o = new D(opts);
        var trusted = o.GetValueOrDefault("trustedAttestorKeys") is L tl ? new L(tl) : new L();
        var resolve = o.GetValueOrDefault("resolveDocument") as Func<object?, object?>;
        var clock = o.GetValueOrDefault("now") as Func<object?> ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        var store = o.GetValueOrDefault("nonceStore") as IAttestationNonceStore;
        var expectedBinding = o.GetValueOrDefault("expectedBinding") as Func<object?, object?>;
        bool insecure = o.GetValueOrDefault("insecure_selfDeclaredNonce") is true;
        var hardware = o.GetValueOrDefault("hardwareVerifier") as IHardwareAttestation;

        D Wrap(D v)
        {
            var r = new D { ["enforced"] = true, ["ok"] = v["ok"] };
            if (Truthy(v.GetValueOrDefault("reason"))) r["reason"] = v["reason"];
            r["present"] = v["present"];
            r["bound"] = v["bound"];
            return r;
        }
        D Closed(bool present, string reason) => Wrap(new D { ["ok"] = false, ["present"] = present, ["bound"] = false, ["reason"] = reason });

        D Hook(object? ctx)
        {
            try
            {
                var document = resolve?.Invoke(ctx);
                object? expected = null;
                if (expectedBinding != null) expected = expectedBinding(ctx);
                else if (insecure)
                {
                    var chain = Path(ctx, "pcactn", "cap_chain");
                    var leaf = chain is L cl && cl.Count > 0 ? cl[^1] : G(ctx, "grant");
                    var holder = G(leaf, "holder");
                    var e = new D { ["holderPub"] = holder is string ? holder : "", ["grantRef"] = Path(ctx, "pcactn", "grant_ref"), ["epoch"] = Path(ctx, "pcactn", "attestation", "epoch"), ["nonce"] = Path(ctx, "pcactn", "attestation", "quote_digest") };
                    expected = e.Where(kv => !ReferenceEquals(kv.Value, Undef)).ToDictionary(kv => kv.Key, kv => kv.Value);
                }
                if (!Truthy(expected)) return Closed(Truthy(document), "no server-issued attestation nonce/binding available (fail closed)");
                var nonce = G(expected, "nonce");
                if (!insecure && !NonceEntropyOk(ReferenceEquals(nonce, Undef) ? null : nonce, o.GetValueOrDefault("minNonceBytes")))
                    return Closed(Truthy(document), "attestation nonce has less than 128 bits of entropy (F-5; use a CSPRNG nonce of >= 16 bytes)");
                var verdict = VerifyAttestation(new D
                {
                    ["document"] = document, ["ctx"] = ctx, ["expected"] = expected, ["nowMs"] = clock(), ["trustedAttestorKeys"] = trusted, ["pqPins"] = o.GetValueOrDefault("pqPins"),
                    ["hardwareVerifier"] = hardware, ["maxNonceAgeMs"] = o.GetValueOrDefault("maxNonceAgeMs"), ["clockSkewMs"] = o.GetValueOrDefault("clockSkewMs"),
                });
                if (verdict["ok"] is true && verdict["bound"] is true && store != null && !store.Consume(ReferenceEquals(nonce, Undef) ? null : nonce))
                    return Closed((bool)verdict["present"]!, "attestation nonce already consumed (replay)");
                return Wrap(verdict);
            }
            catch (Exception e) { return Closed(false, "attestation verification error (fail closed): " + Msg(e)); }
        }

        Func<object?, D> hook = Hook;
        var label = insecure ? new AssuranceLabel("unknown", "insecure-self-declared-nonce")
            : hardware != null ? AssuranceLabels.Of(hardware) ?? new AssuranceLabel("unknown")
            : new AssuranceLabel("software");
        return AssuranceLabels.Set(hook, label);
    }

    // ---- the multi-root verifier ----

    static readonly string[] IdentFields = ["model_id", "weights_digest", "runtime_measurement", "operator", "system_prompt_digest", "tool_manifest_digest"];

    static string? Sid(object? v) => v is string { Length: > 0 } s ? s : null;

    sealed class MultiRoot(IReadOnlyList<D> roots, double threshold) : IHardwareAttestation
    {
        public object? Verify(D inp)
        {
            try
            {
                var passed = new List<(int Idx, object? M)>();
                var host = new D();
                for (int i = 0; i < roots.Count; i++)
                {
                    var root = roots[i];
                    object? res;
                    try { res = ((IHardwareAttestation)root["verifier"]!).Verify(inp); }
                    catch (Exception e) { res = new D { ["ok"] = false, ["reason"] = $"root '{root["id"]}' threw (fail closed): {Msg(e)}" }; }
                    bool ok = res is D rd && rd.GetValueOrDefault("ok") is true && rd.GetValueOrDefault("bound") is true && Truthy(rd.GetValueOrDefault("measured"));
                    if (ok)
                    {
                        var rd2 = (D)res!;
                        passed.Add((i, rd2["measured"]));
                        if (Truthy(rd2.GetValueOrDefault("hostAsserted")) && rd2["hostAsserted"] is D ha) foreach (var (k, v) in ha) host[$"{root["id"]}.{k}"] = v;
                    }
                    else if (root.GetValueOrDefault("required") is true)
                    {
                        var why = res is not D rr ? $"root '{root["id"]}' returned a malformed result (fail closed)" : Truthy(rr.GetValueOrDefault("reason")) ? Js(rr["reason"]) : "invalid";
                        return new D { ["ok"] = false, ["reason"] = $"required attestation root '{root["id"]}' failed: {why}" };
                    }
                }
                if (passed.Count < threshold)
                    return new D { ["ok"] = false, ["reason"] = $"multi-root attestation below threshold ({passed.Count}/{JsJson.NumberToString(threshold)} independent roots corroborated)" };
                var merged = new Dictionary<string, string?>();
                foreach (var name in IdentFields)
                {
                    string? chosen = null; int who = -1;
                    foreach (var (idx, m) in passed)
                    {
                        var v = Sid(G(m, name));
                        if (v == null) continue;
                        if (chosen == null) { chosen = v; who = idx; }
                        else if (chosen != v)
                            return new D { ["ok"] = false, ["reason"] = $"multi-root attestation identity conflict: roots '{roots[who]["id"]}' and '{roots[idx]["id"]}' disagree on {name}" };
                    }
                    merged[name] = chosen;
                }
                var w = merged["weights_digest"];
                bool measuredFlag = w != null && passed.Any(p => G(p.M, "weights_measured") is true && Sid(G(p.M, "weights_digest")) == w);
                var measured = new D
                {
                    ["model_id"] = merged["model_id"] ?? "", ["weights_digest"] = merged["weights_digest"] ?? "", ["weights_measured"] = measuredFlag,
                    ["runtime_measurement"] = merged["runtime_measurement"] ?? "", ["operator"] = merged["operator"] ?? "",
                };
                foreach (var k in new[] { "system_prompt_digest", "tool_manifest_digest" })
                    if (!string.IsNullOrEmpty(merged[k])) measured[k] = merged[k];
                var outp = new D { ["ok"] = true, ["bound"] = true, ["measured"] = measured };
                if (host.Count > 0) outp["hostAsserted"] = host;
                return outp;
            }
            catch (Exception e) { return new D { ["ok"] = false, ["reason"] = "multi-root attestation error (fail closed): " + Msg(e) }; }
        }
    }

    /// <summary>A hardware verifier that needs <c>threshold</c> of the independent roots to corroborate (every <c>required</c> root must pass, and the passing roots' identities must not
    /// conflict). Policy: <c>{threshold, roots: [{id, verifier (an IHardwareAttestation), required?, suite?}]}</c>. Throws on no roots, a threshold that is not an integer in [1, roots.length], or an
    /// empty or duplicate id. The verifier carries the assurance label of the fewest hardware roots any accepted quorum can contain.</summary>
    public static IHardwareAttestation CreateMultiRootVerifier(object? policy)
    {
        var roots = G(policy, "roots") is L rl ? rl : null;
        var threshold = G(policy, "threshold");
        if (roots == null || roots.Count == 0) throw new ArgumentException("createMultiRootVerifier: at least one attestation root is required");
        if (Fin(threshold) is not double t || t != Math.Floor(t) || t < 1 || t > roots.Count) throw new ArgumentException("createMultiRootVerifier: threshold must be an integer in [1, roots.length]");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var copy = new List<D>();
        foreach (var r in roots)
        {
            if (r is not D rd || rd.GetValueOrDefault("id") is not string { Length: > 0 } id) throw new ArgumentException("createMultiRootVerifier: each root needs a non-empty id");
            if (!ids.Add(id)) throw new ArgumentException($"createMultiRootVerifier: duplicate root id '{id}'");
            copy.Add(new D(rd));
        }
        var v = new MultiRoot(copy, t);
        var level = AtlasPca.Assurance.MultiRootLevel(copy.Select(r => new AttestationRoot(r.GetValueOrDefault("verifier"), r.GetValueOrDefault("required") is true)).ToList(), (int)t);
        return AssuranceLabels.Set(v, new AssuranceLabel(level, "multi-root:" + string.Join("+", copy.Select(r => (string)r["id"]!))));
    }

    // ---- evidence anchoring ----

    static object? Req(D d, string k) => d.TryGetValue(k, out var v) ? v : throw new InvalidOperationException("canonicalize: undefined member " + k);

    /// <summary>The strict, domain-separated digest of verified attestation evidence <c>{identity, binding, rootIds?, suite?, verifiedAt}</c>: the opaque commitment leaf appended to the
    /// transparency ledger. It binds the measured identity and the holder, grant, epoch and nonce.</summary>
    public static string AttestationEvidenceDigest(object? evidence)
    {
        var ev = (D)evidence!;
        var ident = (D)Req(ev, "identity")!;
        var binding = (D)Req(ev, "binding")!;
        object? Opt(string k) => ident.GetValueOrDefault(k) ?? "";
        var roots = (ev.GetValueOrDefault("rootIds") is L rl ? rl : new L()).Select(r => (string)r!).ToList();
        roots.Sort(StringComparer.Ordinal); // UTF-16 code unit order
        return Pca.HashCanonical(new D
        {
            ["domain"] = AnchorDomain, ["holder"] = Req(binding, "holderPub"), ["grant"] = Req(binding, "grantRef"), ["epoch"] = Req(binding, "epoch"), ["nonce"] = Req(binding, "nonce"),
            ["model_id"] = Req(ident, "model_id"), ["weights_digest"] = Req(ident, "weights_digest"), ["weights_measured"] = ident.GetValueOrDefault("weights_measured") is true,
            ["runtime_measurement"] = Req(ident, "runtime_measurement"), ["operator"] = Req(ident, "operator"),
            ["system_prompt_digest"] = Opt("system_prompt_digest"), ["tool_manifest_digest"] = Opt("tool_manifest_digest"),
            ["roots"] = roots.Cast<object?>().ToList(), ["suite"] = ev.GetValueOrDefault("suite") ?? "", ["verified_at"] = Req(ev, "verifiedAt"),
        });
    }

    /// <summary>Append the evidence digest to the transparency ledger as an opaque commitment and, with a guardian secret, sign the new tree head (a PQ-capable suite makes the record
    /// post-quantum accountable). Returns <c>{index, commit, sth?}</c>. Fails closed (throws) with no ledger; with <paramref name="required"/> also without a guardian secret or when the head
    /// cannot be signed. After-the-fact accountability, not prevention.</summary>
    public static D AnchorAttestationEvidence(object? evidence, TransparencyLedger? ledger, byte[]? guardianSecret = null, SuiteKey? suite = null, string? instanceId = null, Func<object?>? now = null, bool required = false)
    {
        static D Fail(string msg) => throw new InvalidOperationException("attestation anchoring (fail closed): " + msg);
        if (ledger == null) return Fail("no transparency ledger available");
        if (required && guardianSecret == null) return Fail("required anchoring needs a guardian secret to sign the tree head");
        var commit = AttestationEvidenceDigest(evidence);
        var prevRoot = (string)ledger.Head()["root"]!;
        var index = ledger.AppendCommitment(commit).Index;
        var head = ledger.Head();
        D? sth = null;
        if (guardianSecret != null)
        {
            var ts = (now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()))();
            try
            {
                if (!(IntentJs.NumOf(ts) is double tsv && double.IsFinite(tsv))) throw new InvalidOperationException("tree head timestamp must be a finite number");
                using var key = EdKey.FromSeed(guardianSecret);
                sth = Ledger.SignTreeHead(key, new D
                {
                    ["instance_id"] = instanceId ?? "", ["principal"] = ledger.Principal, ["size"] = head["size"], ["root"] = head["root"], ["prev_root"] = prevRoot, ["timestamp"] = ts,
                }, suite);
            }
            catch (Exception e) when (required) { return Fail("tree-head signing failed: " + Msg(e)); }
            catch (Exception) { sth = null; }
        }
        var outp = new D { ["index"] = index, ["commit"] = commit };
        if (sth != null) outp["sth"] = sth;
        return outp;
    }
}
