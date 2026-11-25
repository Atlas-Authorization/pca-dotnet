// The post-quantum co-signature of a verified attestation verdict: once the classical hardware root has been verified, the verdict a deployment records is bound under a
// post-quantum suite (ML-DSA-65 by default), so downstream trust in the record no longer rests on a classical root. The signed bytes are the canonical verdict bytes.
using System.Security.Cryptography;
using System.Text;
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.AttestEat;

public static class EatPqCoSign
{
    static object? P(object? o, string k) => Jx.Prop(o, k);
    static object? Clean(object? x) => Jx.IsUndef(x) ? null : x;

    /// <summary>Co-signs a verdict under a post-quantum suite: <c>{verdict, cosig: {cosignedAt, sig, pq_sig?}, suite, signer_pub: {pq, ed?}}</c>. <paramref name="suite"/> is one of
    /// <see cref="PcaAttestEat.PqCoSignSuites"/> (null: ML-DSA-65); the key material it needs must be given (<paramref name="pq"/> of the suite's primitive; <paramref name="ed"/> for a hybrid)
    /// or the call throws, so a signer never emits a weaker co-signature than it meant to. <paramref name="now"/> (epoch ms) defaults to the clock.</summary>
    public static D CoSignAttestation(object? verdict, EdKey? ed, PqKey? pq, object? suite = null, object? now = null)
    {
        var suiteO = suite == null || Jx.IsUndef(suite) ? PcaAttestEat.DefaultPqCoSignSuite : suite;
        if (!PcaAttestEat.IsPqCoSignSuite(suiteO)) throw new ArgumentException($"coSignAttestation: '{JsX.Str(suiteO)}' is not an accepted post-quantum co-sign suite");
        var name = (string)suiteO;
        if (!Pq.Suites.TryGetValue(name, out var s)) throw new ArgumentException($"coSignAttestation: unknown suite '{name}'");

        object cosignedAt = Jx.Fin(now) != null ? now! : Jx.NumOut(AtlasPca.ReplayClock.NowMs());
        var msg = PcaAttestEat.CanonicalVerdictBytes(verdict, cosignedAt);

        // the public keys come first, so a missing key pair fails closed with a clear message
        if (pq == null || pq.Prim != s.Pq) throw new ArgumentException($"coSignAttestation: suite '{name}' requires {Slot(s.Pq)} key material");
        var signerPub = new D { ["pq"] = pq.PkB64u };
        if (s.NeedsPqSig)
        {
            if (ed == null) throw new ArgumentException($"coSignAttestation: hybrid suite '{name}' requires edSecret");
            signerPub["ed"] = ed.Id;
        }
        var (sig, pqSig) = SuiteKey.Create(name, ed, pq).Sign(msg);
        var cosig = new D { ["cosignedAt"] = cosignedAt, ["sig"] = sig };
        if (pqSig != null) cosig["pq_sig"] = pqSig;
        return new D { ["verdict"] = verdict, ["cosig"] = cosig, ["suite"] = name, ["signer_pub"] = signerPub };
    }

    static string Slot(Pq.Prim p) => p switch { Pq.Prim.MlDsa65 => "mlDsa", Pq.Prim.MlDsa87 => "mlDsa87", Pq.Prim.Slh128f => "slhDsa", _ => "slhDsa256s" };

    static bool CtEq(string a, string b)
    {
        var x = Encoding.UTF8.GetBytes(a); var y = Encoding.UTF8.GetBytes(b);
        return x.Length == y.Length && CryptographicOperations.FixedTimeEquals(x, y);
    }

    /// <summary>The signer public key of a co-signed artifact: a non-empty <c>pq</c> and an optional non-empty <c>ed</c>; null when malformed.</summary>
    static D? ParseSignerPub(object? v)
    {
        if (v is not D || P(v, "pq") is not string pq || pq.Length == 0) return null;
        var o = new D { ["pq"] = pq };
        if (P(v, "ed") is string ed && ed.Length > 0) o["ed"] = ed;
        return o;
    }

    static bool SignerMatches(object? expected, D got)
    {
        if (expected == null) throw new InvalidOperationException("Cannot read properties of null (reading 'pq')");
        var expPq = expected as string ?? P(expected, "pq");
        if (expPq is not string ep || !CtEq(ep, (string)got["pq"]!)) return false;
        if (expected is not string && P(expected, "ed") is string ee)
        {
            if (!got.TryGetValue("ed", out var ge) || ge is not string gs || !CtEq(ee, gs)) return false;
        }
        return true;
    }

    /// <summary>Verifies a co-signed attestation. The signed bytes are recomputed from the artifact's OWN verdict, so a tampered field no longer matches. Options: <c>expectedSigner?</c> (the
    /// <c>pq</c> key as a string, or <c>{pq, ed?}</c>: the co-signer must be that one; checked before anything else), <c>maxAgeMs?</c> (a future or over-age co-signature fails),
    /// <c>now?</c> (epoch ms). Never throws: <c>{ok, reason?, suite?, verdict?, signer_pub?, cosignedAt?, ageMs?}</c>.</summary>
    public static D VerifyCoSignedAttestation(object? cosigned, object? opts = null)
    {
        static D Refuse(string reason) => new() { ["ok"] = false, ["reason"] = reason };
        opts ??= new D(); // no options given
        try
        {
            if (cosigned is not D c) return Refuse("co-signed attestation is not an object");
            var verdict = P(c, "verdict");
            if (verdict is not D || P(verdict, "tier") is not string || P(verdict, "trustworthy") is not bool) return Refuse("verdict is missing or has a non-string tier / non-boolean trustworthy");
            var cosig = P(c, "cosig");
            if (cosig is not D || Jx.Fin(P(cosig, "cosignedAt")) is not double cosignedAt || P(cosig, "sig") is not string sig) return Refuse("cosig is missing or has a non-numeric cosignedAt / non-string sig");
            var suiteO = P(c, "suite");
            if (!PcaAttestEat.IsPqCoSignSuite(suiteO)) return Refuse($"suite '{JsX.Str(suiteO)}' is not an accepted post-quantum co-sign suite");
            var suiteName = (string)suiteO!;
            if (!Pq.Suites.TryGetValue(suiteName, out var suite)) return Refuse($"unknown suite '{suiteName}'");
            var signerPub = ParseSignerPub(P(c, "signer_pub"));
            if (signerPub == null) return Refuse("signer_pub is missing or has no post-quantum public key");

            var now = Jx.Fin(P(opts, "now")) is double nd ? nd : AtlasPca.ReplayClock.NowMs();
            var ageMs = now - cosignedAt;
            D Result(bool ok, string? reason)
            {
                var r = new D { ["ok"] = ok };
                if (reason != null) r["reason"] = reason;
                r["suite"] = suiteName; r["verdict"] = verdict; r["signer_pub"] = signerPub; r["cosignedAt"] = P(cosig, "cosignedAt"); r["ageMs"] = Jx.NumOut(ageMs);
                return r;
            }

            // signer pinning first, before anything else that could leak which gate failed
            var expected = P(opts, "expectedSigner");
            if (!Jx.IsUndef(expected) && !SignerMatches(expected, signerPub)) return Result(false, "co-signer public key does not match the expected signer");

            var maxAgeO = P(opts, "maxAgeMs");
            if (!Jx.IsUndef(maxAgeO))
            {
                if (Jx.Fin(maxAgeO) is not double maxAge || maxAge <= 0) return Result(false, "invalid maxAgeMs");
                if (cosignedAt > now) return Result(false, "co-sign timestamp is in the future");
                if (ageMs > maxAge) return Result(false, "co-signature is stale (older than maxAgeMs)");
            }

            var msg = PcaAttestEat.CanonicalVerdictBytes(verdict, P(cosig, "cosignedAt"));
            var edPk = suite.NeedsPqSig ? signerPub.GetValueOrDefault("ed") : null;
            if (!Pca.VerifySuiteSig(suiteName, edPk, signerPub["pq"], msg, sig, Clean(P(cosig, "pq_sig"))))
                return Result(false, "post-quantum co-signature does not verify (tampered verdict, wrong key, or bad signature)");
            return Result(true, null);
        }
        catch (Exception e) { return Refuse("co-signature verification error (fail closed): " + e.Message); }
    }
}
