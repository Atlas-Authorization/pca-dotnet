using System.Text.RegularExpressions;
using Wa = AtlasPca.Webauthn.Webauthn;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the WebAuthn step-up co-sign oracle (test-data/ref-webauthn.json.gz, TS reference @atlasauth/pca-webauthn).</summary>
public class RefWebauthnTests
{
    const string M = "ref-webauthn";

    /// <summary>{"$bytes": b64u} members become byte[] (the oracle carries bytes that way, also nested).</summary>
    static object? Rev(object? v) => v switch
    {
        D m when Base.IsBytes(m) => Base.Bytes(m),
        D m => m.ToDictionary(e => e.Key, e => Rev(e.Value)),
        L l => l.Select(Rev).ToList(),
        _ => v,
    };

    static readonly Dictionary<string, string> CamelNames = new()
    {
        ["authenticator_data"] = "authenticatorData", ["client_data_json"] = "clientDataJSON", ["public_key"] = "publicKey", ["expected_challenge"] = "expectedChallenge",
        ["rp_id"] = "rpId", ["require_uv"] = "requireUV", ["stored_sign_count"] = "storedSignCount", ["require_low_s"] = "requireLowS", ["reject_cross_origin"] = "rejectCrossOrigin",
    };

    static D Camel(D d) => d.ToDictionary(e => CamelNames.GetValueOrDefault(e.Key, e.Key), e => e.Value);

    // the two reasons that carry a JS engine message are compared up to the colon
    static object? Norm(D r) => r.GetValueOrDefault("reason") is string s
        ? new D(r) { ["reason"] = Regex.Replace(s, @"^(public key could not be resolved|verification error \(fail closed\)):.*$", "$1", RegexOptions.Singleline) }
        : r;

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D { ["MAX_AUTHENTICATOR_DATA_BYTES"] = Wa.MaxAuthenticatorDataBytes, ["MAX_CLIENT_DATA_BYTES"] = Wa.MaxClientDataBytes, ["MAX_SIGNATURE_BYTES"] = Wa.MaxSignatureBytes });

    [Fact]
    public void CoseKeyToJwk() => Base.Check(M, "coseKeyToJwk", a => Base.IsBytes(a[0]) ? Wa.CoseKeyToJwk(Base.Bytes(a[0])) : throw new ArgumentException("coseKeyToJwk: expected a Uint8Array"));

    [Fact]
    public void ParseAuthenticatorData() => Base.Check(M, "parseAuthenticatorData", a => Base.IsBytes(a[0]) ? Wa.ParseAuthenticatorData(Base.Bytes(a[0])) : null);

    [Fact]
    public void BuildStepUpChallenge() => Base.Check(M, "buildStepUpChallenge", a => Wa.BuildStepUpChallenge(Rev(a[0])));

    [Fact]
    public void StepUpChallengeB64u() => Base.Check(M, "stepUpChallengeB64u", a => Wa.StepUpChallengeB64u(Rev(a[0])));

    [Fact]
    public void BuildApprovalChallenge() => Base.Check(M, "buildApprovalChallenge", a => Wa.BuildApprovalChallenge(Rev(a[0]), a[1]));

    [Fact]
    public void ApprovalChallengeForActn() => Base.Check(M, "approvalChallengeForActn", a => Wa.ApprovalChallengeForActn(Rev(a[0]), a[1]));

    [Fact]
    public void SpcPaymentError() => Base.Check(M, "spcPaymentError", a => Wa.SpcPaymentError(a[0], a[1], (string)a[2]!));

    [Fact]
    public void VerifyAssertion() => Base.Check(M, "verifyAssertion", a =>
    {
        var assertion = (D)Rev(a[0])!;
        var expect = (D)Rev(a[1])!;
        // the Python lane's corpus spells the members in snake case and names the recorded regression calls "regression"
        bool snake = assertion.ContainsKey("authenticator_data");
        if (snake) { assertion = Camel(assertion); expect = Camel(expect); }
        var calls = new L();
        if (expect.Remove("hook") || snake) expect["onSignCountRegression"] = new Action<D>(i => calls.Add(i));
        var result = Wa.VerifyAssertion(assertion, expect);
        return new D { ["result"] = Norm(result), [snake ? "regression" : "hook"] = calls };
    });

    [Fact]
    public void EveryFnIsCovered() { Base.Covers(M, new[] { "constants", "coseKeyToJwk", "parseAuthenticatorData", "buildStepUpChallenge", "stepUpChallengeB64u", "buildApprovalChallenge", "approvalChallengeForActn", "spcPaymentError", "verifyAssertion" }); Assert.Equal(1362, Base.Total(M)); }
}
