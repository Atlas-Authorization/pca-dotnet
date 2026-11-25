// The artifact attestation verifier: Sigstore build provenance joined to runtime attestation, issued as a discharge. For one discharge request the verifier checks the bundle against
// the pinned trust roots (offline), applies its own provenance policy and the join (the running digest must be a provenance subject), then signs the discharge the request asks
// for with the gate's claims. Any failure returns no discharge, so the caveat refuses: provenance can only remove authority.
using System.Security.Cryptography;
using AtlasPca.Analyzer;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.AttestEat;

public static class EatProvenance
{
    static object? P(object? o, string k) => Jx.Prop(o, k);

    /// <summary>Issues the discharge. <paramref name="input"/>: <c>bundle</c>, <c>policy</c> (the verifier's provenance policy), <c>runtime?</c> ({alg, digest} from
    /// <see cref="EatToken.RuntimeDigestFromEat"/>; a JSON null is a failed join, absent only when the policy does not require it), <c>request</c> (the discharge request), <c>now</c> (epoch ms),
    /// <c>ttl_ms?</c> (at most the request's; default the request's). <paramref name="roots"/> is the pinned trust roots, <paramref name="issuer"/> the <c>artifact</c>-class key.
    /// <paramref name="nonce"/> yields the 16 discharge nonce bytes (default: random). Result: <c>{ok: true, discharge, facts, level}</c>, or <c>{ok: false, stage: "sigstore", code, detail}</c>
    /// or <c>{ok: false, stage: "gate", code}</c>; a malformed request or an over-long lifetime throws.</summary>
    public static D IssueArtifactDischarge(object? input, SigstorePinnedRoots roots, SuiteKey issuer, Func<byte[]>? nonce = null)
    {
        var v = Sigstore.VerifySigstoreBundle(P(input, "bundle"), roots);
        if (!v.Ok) return new D { ["ok"] = false, ["stage"] = "sigstore", ["code"] = v.Code, ["detail"] = v.Detail };
        var runtime = P(input, "runtime");
        // an EAT that yielded no digest is not "no runtime": it is a failed join
        if (runtime == null) return new D { ["ok"] = false, ["stage"] = "gate", ["code"] = "no_runtime" };

        var nowO = P(input, "now");
        var gateIn = new D { ["facts"] = v.Facts };
        var policy = P(input, "policy");
        if (!Jx.IsUndef(policy)) gateIn["policy"] = policy;
        if (!Jx.IsUndef(runtime)) gateIn["runtime"] = runtime;
        gateIn["now"] = Jx.NumOut(Math.Floor(Jx.ToNumber(nowO) / 1000));
        var gate = ProvenanceGate.Gate(gateIn);
        if (!gate.Ok) return new D { ["ok"] = false, ["stage"] = "gate", ["code"] = gate.Code };

        var request = P(input, "request");
        var ttlO = P(input, "ttl_ms");
        var reqTtl = P(request, "ttl_ms");
        var ttl = ttlO == null || Jx.IsUndef(ttlO) ? reqTtl : ttlO;
        if (Jx.ToNumber(ttl) > Jx.ToNumber(reqTtl)) throw new ArgumentException("provenanceDischargeBody: ttl_ms exceeds what the caveat accepts");
        var body = new D { ["v"] = 1L, ["kind"] = "pca-discharge" };
        foreach (var k in new[] { "caveat_id", "issuer", "cap_hash", "bind", "action_digest" }) { var x = P(request, k); if (!Jx.IsUndef(x)) body[k] = x; }
        body["claims"] = gate.Claims;
        body["iat"] = nowO;
        body["not_after"] = Jx.NumOut(Jx.ToNumber(nowO) + Jx.ToNumber(ttl));
        body["nonce"] = Pca.B64u(nonce?.Invoke() ?? RandomNumberGenerator.GetBytes(16));
        var discharge = Issue.SignDischarge(body, issuer);
        return new D { ["ok"] = true, ["discharge"] = discharge, ["facts"] = v.Facts, ["level"] = Jx.NumOut(gate.Level) };
    }
}
