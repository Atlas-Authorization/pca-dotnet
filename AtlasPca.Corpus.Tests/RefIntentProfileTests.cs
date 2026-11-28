using AtlasPca;
using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.IntentPkg.IntentOmega;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of intent profiles (shape, sign, verify, succession, scope, standing rules, veto cells, usability) against the TypeScript
/// reference (test-data/ref-intent-profile.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentProfileTests
{
    const string M = "ref-intent-profile";

    [Fact] public void SignIntentProfileFn() => Base.Check(M, "signIntentProfile", a => IntentProfile.SignIntentProfile((D)a[0]!, Pca.B64uDecode(a[1])!));

    [Fact]
    public void IntentProfileShapeErrorFn() => Base.Check(M, "intentProfileShapeError", a =>
        IntentProfile.IntentProfileShapeError(a[0], a.Count < 2 || a[1] is not D o || o.GetValueOrDefault("signed") is not false));

    [Fact] public void VerifyIntentProfileFn() => Base.Check(M, "verifyIntentProfile", a => IntentProfile.VerifyIntentProfile(a[0]));
    [Fact] public void IntentProfileDigestFn() => Base.Check(M, "intentProfileDigest", a => IntentProfile.IntentProfileDigest(a[0]));
    [Fact] public void VerifyProfileSuccessionFn() => Base.Check(M, "verifyProfileSuccession", a => IntentProfile.VerifyProfileSuccession(a[0], a[1]));
    [Fact] public void ProfileAppliesFn() => Base.Check(M, "profileApplies", a => IntentProfile.ProfileApplies((D)a[0]!, (D)a[1]!));
    [Fact] public void StandingAdmitsFn() => Base.Check(M, "standingAdmits", a => IntentProfile.StandingAdmits((D)a[0]!, (D)a[1]!, (D)a[2]!));
    [Fact] public void StandingPermitsFn() => Base.Check(M, "standingPermits", a => IntentProfile.StandingPermits((D)a[0]!, (D)a[1]!, (D)a[2]!));
    [Fact] public void ProfileVetoCellsFn() => Base.Check(M, "profileVetoCells", a => IntentProfile.ProfileVetoCells((D)a[0]!, OmegaFromJson(a[1])));

    [Fact]
    public void ProfileCeilingFn() => Base.Check(M, "profileCeiling", a => IntentProfile.ProfileCeiling((D)a[0]!, (D)a[1]!)(VerbSpaceFromJson(a[2]), OutcomeFromJson(a[3])));

    [Fact] public void ProfileUsableFn() => Base.Check(M, "profileUsable", a => IntentProfile.ProfileUsable((D)a[0]!, (D)a[1]!));

    [Fact]
    public void AllFnsHandled() { Base.Covers(M, new[]
    {
        "signIntentProfile", "intentProfileShapeError", "verifyIntentProfile", "intentProfileDigest", "verifyProfileSuccession", "profileApplies", "standingAdmits", "standingPermits",
        "profileVetoCells", "profileCeiling", "profileUsable",
    }); Assert.Equal(1996, Base.Total(M)); }
}
