using System.Text;
using AtlasPca.Js;
using AtlasPca.Notary;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the notary package (attestation, field disclosure, PCActn binding, the attested_fact caveat and the key ring)
/// against the TypeScript reference. The reference replaced its salt source by a counter hash that restarts at 0 for every notarizeResponse case;
/// the native replays with the same salts.</summary>
public class RefNotaryTests
{
    const string M = "ref-notary";

    // a {"$bytes": b64u} map becomes bytes, at any depth
    static object? FromJ(object? v) => v switch
    {
        D m when Base.IsBytes(m) => Base.Bytes(m),
        D m => m.ToDictionary(e => e.Key, e => FromJ(e.Value)),
        L l => l.Select(FromJ).ToList(),
        _ => v,
    };

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D { ["BODY_COMMIT_ALG"] = PcaNotary.BodyCommitAlg, ["ATTESTED_FACT_CAVEAT"] = PcaNotary.AttestedFactCaveat });

    [Fact] public void NotaryMessage() => Base.Check(M, "notaryMessage", a => PcaNotary.NotaryMessage(a[0]));

    [Fact]
    public void NotarizeResponse() => Base.Check(M, "notarizeResponse", a =>
    {
        var o = (D)FromJ(a[1])!;
        var kp = (D)o["notaryKey"]!;
        int ctr = 0;
        var opts = new NotarizeOptions
        {
            NotaryKey = new NotaryKeyPair(kp["secretKey"] is string sk ? Pca.B64uDecode(sk)! : (byte[])kp["secretKey"]!, (byte[])kp["publicKey"]!),
            ObservedAt = o.GetValueOrDefault("observedAt"),
            TextChunkSize = o.GetValueOrDefault("textChunkSize") is Num n ? JsJson.ToJsNumber(n) : null,
            Salt = () => Pca.B64u(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("notary-oracle-salt/" + ctr++)).AsSpan(0, 16).ToArray()),
        };
        var (att, wit) = PcaNotary.NotarizeResponse(a[0], opts);
        return new D { ["attestation"] = att, ["witness"] = wit };
    });

    [Fact] public void DiscloseField() => Base.Check(M, "discloseField", a => PcaNotary.DiscloseField(a[0], a[1], a[2]));
    [Fact] public void VerifyNotaryAttestation() => Base.Check(M, "verifyNotaryAttestation", a => PcaNotary.VerifyNotaryAttestation(a[0], FromJ(a[1])));
    [Fact] public void VerifyDisclosedField() => Base.Check(M, "verifyDisclosedField", a => PcaNotary.VerifyDisclosedField(a[0], a[1], FromJ(a[2])));
    [Fact] public void FactRef() => Base.Check(M, "factRef", a => PcaNotary.FactRef(a[0]));
    [Fact] public void BindFactToPcActn() => Base.Check(M, "bindFactToPcActn", a => PcaNotary.BindFactToPcActn(a[0], a[1]));
    [Fact] public void FactMatchesPcActn() => Base.Check(M, "factMatchesPcActn", a => PcaNotary.FactMatchesPcActn(a[0], a[1]));
    [Fact] public void RequireAttestedFact() => Base.Check(M, "requireAttestedFact", a => PcaNotary.RequireAttestedFact(FromJ(a[0])));
    [Fact] public void IsAttestedFactCaveat() => Base.Check(M, "isAttestedFactCaveat", a => PcaNotary.IsAttestedFactCaveat(a[0]));
    [Fact] public void NotaryKeyUsable() => Base.Check(M, "notaryKeyUsable", a => PcaNotary.NotaryKeyUsable(a[0], a[1], a[2]));

    [Fact]
    public void EvaluateAttestedFactCaveat() => Base.Check(M, "evaluateAttestedFactCaveat", a =>
        a.Count > 2 ? PcaNotary.EvaluateAttestedFactCaveat(a[0], a[1], a[2]) : PcaNotary.EvaluateAttestedFactCaveat(a[0], a[1]));

    [Fact]
    public void EveryFnHasATest() { Base.Covers(M, new[]
    {
        "constants", "notaryMessage", "notarizeResponse", "discloseField", "verifyNotaryAttestation", "verifyDisclosedField", "factRef", "bindFactToPcActn",
        "factMatchesPcActn", "requireAttestedFact", "isAttestedFactCaveat", "notaryKeyUsable", "evaluateAttestedFactCaveat",
    }); Assert.Equal(1752, Base.Total(M)); }
}
