// The post-quantum software / HSM attestation root of the reference (attest-pq-software.ts): a statement signed under a post-quantum or hybrid suite (domain "atlas-pca/attest-pq/v1\0") and its verifier
// (trusted PQ keys, optional Ed25519 keys, requirePq / requireHybrid, allowed suites, measurement policy). Honest scope: the measurement is software- or HSM-attested, NOT silicon-measured
// (weights_measured is always false), so the root can satisfy a post-quantum requirement but never require_hardware. The verifier is a hardware verifier usable as a root of the multi-root verifier.
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>An attestor over post-quantum key material (ML-DSA or SLH-DSA, pure or hybrid with an Ed25519 attestor key).</summary>
public sealed class PqSoftwareAttestor
{
    readonly string _alg;
    readonly SuiteSecretKeys _keys;
    readonly string? _edPublic;

    /// <summary>The attestor's post-quantum public key (b64u), bound into every statement.</summary>
    public string PqPublicKey { get; }

    /// <summary>The Ed25519 attestor key (b64u), or null without an Ed25519 secret.</summary>
    public string? Ed25519PublicKey => _edPublic;

    internal PqSoftwareAttestor(string alg, SuiteSecretKeys keys, string pqPublicKey, string? edPublic)
    {
        _alg = alg;
        _keys = keys;
        PqPublicKey = pqPublicKey;
        _edPublic = edPublic;
    }

    /// <summary>A signed statement for <c>{measurement, holder_pub, grant_ref, epoch, nonce, ...}</c> (optional weights_digest, system_prompt_digest, tool_manifest_digest, model_id, operator are carried when given):
    /// <c>{measurement, binding, alg, pq_pk, attestor_ed25519?, ..., sig, pq_sig?}</c>. Throws without a measurement or on a binding that cannot be built.</summary>
    public D Attest(D claims)
    {
        var binding = AttestationSoft.AttestationBindingB64u(new D
        {
            ["holderPub"] = claims.GetValueOrDefault("holder_pub"), ["grantRef"] = claims.GetValueOrDefault("grant_ref"), ["epoch"] = claims.GetValueOrDefault("epoch"), ["nonce"] = claims.GetValueOrDefault("nonce"),
        });
        if (!claims.TryGetValue("measurement", out var measurement)) throw new InvalidOperationException("canonicalize: undefined member measurement");
        var body = new D { ["measurement"] = measurement, ["binding"] = binding, ["alg"] = _alg, ["pq_pk"] = PqPublicKey };
        if (_edPublic != null) body["attestor_ed25519"] = _edPublic;
        foreach (var k in new[] { "weights_digest", "system_prompt_digest", "tool_manifest_digest", "model_id", "operator" })
            if (claims.TryGetValue(k, out var v)) body[k] = v;
        var parts = PqSuites.SignWithSuite(_alg, _keys, AttestPqSoftware.StatementMessage(body));
        var st = new D(body) { ["sig"] = parts.Sig };
        if (parts.PqSig != null) st["pq_sig"] = parts.PqSig;
        return st;
    }
}

public static class AttestPqSoftware
{
    public const string Domain = "atlas-pca/attest-pq/v1\0";

    /// <summary>The published constants of the module.</summary>
    public static D Constants() => new() { ["PQ_ATTEST_DOMAIN"] = Domain };

    internal static byte[] StatementMessage(D body) => IntentJs.Message(Domain, body);

    static bool HasPq(Pq.Prim p) => p is Pq.Prim.MlDsa65 or Pq.Prim.MlDsa87 or Pq.Prim.Slh128f or Pq.Prim.Slh256s; // the FN-DSA and LESS suites are not post-quantum here

    static Pq.Suite? SuiteOf(object? alg) => alg is string s && Pq.Suites.TryGetValue(s, out var suite) ? suite : null;

    static bool HasKey(Pq.Prim p, SuiteSecretKeys k) => p switch
    {
        Pq.Prim.MlDsa65 => k.MlDsa != null, Pq.Prim.MlDsa87 => k.MlDsa87 != null, Pq.Prim.Slh128f => k.SlhDsa != null, Pq.Prim.Slh256s => k.SlhDsa256s != null, _ => false,
    };

    /// <summary>An attestor over PQ key material. <paramref name="alg"/> null is the default suite (refused: classical). Throws for an unknown or classical alg, PQ key material of another family, or a hybrid suite
    /// without <paramref name="edSecret"/>.</summary>
    public static PqSoftwareAttestor CreatePqSoftwareAttestor(string? alg, SuiteSecretKeys keys, byte[]? edSecret = null)
    {
        alg ??= "ed25519";
        if (SuiteOf(alg) is not { } suite) throw new ArgumentException($"createPqSoftwareAttestor: unknown signature alg '{alg}'");
        if (!HasPq(suite.Pq)) throw new ArgumentException($"createPqSoftwareAttestor: '{alg}' is classical; the PQ root requires a post-quantum suite");
        if (!HasKey(suite.Pq, keys)) throw new ArgumentException($"createPqSoftwareAttestor: '{alg}' requires the matching PQ key material");
        if (suite.NeedsPqSig && edSecret == null) throw new ArgumentException($"createPqSoftwareAttestor: hybrid suite '{alg}' requires edSecret");
        string? edPub = null;
        if (edSecret != null) { using var k = EdKey.FromSeed(edSecret); edPub = k.Id; }
        var all = edSecret != null ? PqSuites.SuiteKeysOf(edSecret, keys) : keys;
        return new PqSoftwareAttestor(alg, all, PqSuites.SuitePqPublicKey(alg, all)!, edPub);
    }

    static D DefaultIdentity(D st)
    {
        var o = new D
        {
            ["model_id"] = st.GetValueOrDefault("model_id") is string m ? m : "", ["weights_digest"] = st.GetValueOrDefault("weights_digest") is string w ? w : "", ["weights_measured"] = false,
            ["runtime_measurement"] = st.GetValueOrDefault("measurement"), ["operator"] = st.GetValueOrDefault("operator") is string op ? op : "",
        };
        foreach (var k in new[] { "system_prompt_digest", "tool_manifest_digest" }) if (st.GetValueOrDefault(k) is string s) o[k] = s;
        return o;
    }

    sealed class Verifier(L measurements, L? weights, HashSet<string> trustedPq, HashSet<string> trustedEd, bool requirePq, bool requireHybrid, HashSet<string>? allowed,
        Func<D, D> derive, Func<object?, object?, object?>? resolve) : IHardwareAttestation
    {
        static D Fail(string reason) => new() { ["ok"] = false, ["reason"] = reason };

        public object? Verify(D input)
        {
            try
            {
                if (resolve == null) return Fail("no PQ-software evidence resolver configured (fail closed)");
                if (resolve(input.GetValueOrDefault("document"), input.GetValueOrDefault("ctx")) is not D st || st.GetValueOrDefault("alg") is not string alg) return Fail("no PQ-software attestation statement for this action");
                if (SuiteOf(alg) is not { } suite) return Fail($"PQ statement declares an unknown signature alg '{alg}'");
                if (requirePq && !HasPq(suite.Pq)) return Fail($"PQ required: a classical-only suite '{alg}' is not accepted by the post-quantum root");
                if (requireHybrid && !(suite.NeedsPqSig && HasPq(suite.Pq))) return Fail($"hybrid required: suite '{alg}' is not a classical+PQ hybrid");
                if (allowed != null && !allowed.Contains(alg)) return Fail($"suite '{alg}' is not in the allowed-suites list");
                if (suite.NeedsPqPk && !(st.GetValueOrDefault("pq_pk") is string pk && trustedPq.Contains(pk))) return Fail("PQ attestor key is not trusted");
                if ((suite.NeedsPqSig || !HasPq(suite.Pq)) && !(st.GetValueOrDefault("attestor_ed25519") is string ed && trustedEd.Contains(ed))) return Fail("hybrid Ed25519 attestor key is not trusted");
                var body = st.Where(e => e.Key is not ("sig" or "pq_sig")).ToDictionary(e => e.Key, e => e.Value);
                var message = StatementMessage(body);
                if (!(st.GetValueOrDefault("sig") is string sig && PqSuites.VerifyWithSuite(alg, st.GetValueOrDefault("attestor_ed25519") as string, suite.NeedsPqPk ? st["pq_pk"] as string : null, message, sig, st.GetValueOrDefault("pq_sig"))))
                    return Fail("PQ attestation signature does not verify");
                var expected = input.GetValueOrDefault("expected");
                if (!AttestationSoft.Truthy(expected)) return Fail("no expected attestation binding supplied");
                string expectedB64u;
                try { expectedB64u = Pca.B64u(AttestationSoft.AttestationBinding(expected)); }
                catch (Exception e) { return Fail("binding not constructible: " + (string.IsNullOrEmpty(e.Message) ? "invalid" : e.Message)); }
                if (st.GetValueOrDefault("binding") is not string { Length: > 0 } binding) return Fail("PQ statement is not bound (binding absent)");
                if (binding != expectedB64u) return Fail("PQ statement binding mismatch (holder/grant/epoch/nonce)");
                if (!measurements.Any(m => AttestationSoft.Seq(m, st.TryGetValue("measurement", out var mv) ? mv : AttestationSoft.Undef))) return Fail("measurement not in policy allowlist");
                if (weights is { Count: > 0 } && !(st.GetValueOrDefault("weights_digest") is string wd && weights.Any(w => AttestationSoft.Seq(w, wd)))) return Fail("measured weights digest not in policy allowlist");
                return new D { ["ok"] = true, ["bound"] = true, ["measured"] = derive(st), ["hostAsserted"] = new D { ["suite"] = alg } };
            }
            catch (Exception e) { return Fail("pq-software verification error (fail closed): " + (string.IsNullOrEmpty(e.Message) ? "unknown" : e.Message)); }
        }
    }

    /// <summary>A hardware-verifier root over PQ-signed statements. Options: <c>trustedPqPublicKeys</c> (at least one), <c>trustedEd25519PublicKeys</c>, <c>requirePq</c> (default true), <c>requireHybrid</c>,
    /// <c>allowedSuites</c>, <c>policy</c> {measurements (non-empty), weightsMeasurements?, deriveIdentity? (Func&lt;D, D&gt;)} and <c>resolveEvidence</c> (Func&lt;object?, object?, object?&gt;: document, ctx). Throws on
    /// a construction refusal.</summary>
    public static IHardwareAttestation CreatePqSoftwareVerifier(D opts)
    {
        if (opts.GetValueOrDefault("policy") is not D policy || policy.GetValueOrDefault("measurements") is not L ms || ms.Count == 0)
            throw new ArgumentException("createPqSoftwareVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)");
        var trustedPq = (opts.GetValueOrDefault("trustedPqPublicKeys") as L ?? new L()).OfType<string>().ToHashSet(StringComparer.Ordinal);
        if (trustedPq.Count == 0) throw new ArgumentException("createPqSoftwareVerifier: at least one trusted PQ public key is required (fail closed)");
        var trustedEd = (opts.GetValueOrDefault("trustedEd25519PublicKeys") as L ?? new L()).OfType<string>().ToHashSet(StringComparer.Ordinal);
        HashSet<string>? allowed = !opts.ContainsKey("allowedSuites") ? null : opts["allowedSuites"] is L al ? al.OfType<string>().ToHashSet(StringComparer.Ordinal) : new HashSet<string>();
        var v = new Verifier(new L(ms), policy.GetValueOrDefault("weightsMeasurements") is L wl ? new L(wl) : null, trustedPq, trustedEd, opts.GetValueOrDefault("requirePq") is not false,
            opts.GetValueOrDefault("requireHybrid") is true, allowed, policy.GetValueOrDefault("deriveIdentity") as Func<D, D> ?? DefaultIdentity, opts.GetValueOrDefault("resolveEvidence") as Func<object?, object?, object?>);
        return v;
    }
}
