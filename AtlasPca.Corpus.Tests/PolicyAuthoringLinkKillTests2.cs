using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Exact-output kills for <see cref="PolicyAuthoring.VerifyLinkedPolicy"/>, against the resolve rows of policy-link-vectors.json (a fresh parse per test).</summary>
public class PolicyAuthoringLinkKillTests2
{
    static JD Row(int i) => D(L(Load("policy-link-vectors.json")["resolve"])[i]);

    static string Digest(JD row) => (string)D(row["ref"])["version_digest"]!;

    /// <summary>An envelope carrying exactly the policy the row's reference resolves to.</summary>
    static JD Envelope(JD row)
    {
        var policy = D(D(row["expect"])["policy"]);
        return new JD { ["predicates"] = policy["predicates"], ["caveats"] = policy["caveats"], ["template_ref"] = row["ref"] };
    }

    [Fact]
    public void AnEnvelopeWithoutATemplateRefIsFine()
    {
        var row = Row(0);
        var env = Envelope(row);
        env.Remove("template_ref");
        Assert.Equal((true, (string?)null, (string?)null), PolicyAuthoring.VerifyLinkedPolicy(env, row["registry"]));
        Assert.Equal((true, (string?)null, (string?)null), PolicyAuthoring.VerifyLinkedPolicy(new JD(), null));
    }

    [Fact]
    public void AnEnvelopeThatCarriesExactlyTheInstantiationVerifiesAndNamesTheTemplate()
    {
        var row = Row(0);
        Assert.Equal((true, (string?)null, (string?)Digest(row)), PolicyAuthoring.VerifyLinkedPolicy(Envelope(row), row["registry"]));
    }

    [Fact]
    public void AVerifiedOverlayIsPartOfWhatTheEnvelopeMustCarry()
    {
        var row = Row(3);
        Assert.Equal((true, (string?)null, (string?)Digest(row)), PolicyAuthoring.VerifyLinkedPolicy(Envelope(row), row["registry"]));
        // the same envelope without the overlay's additions is not the linked policy
        var plain = Row(0);
        var env = Envelope(plain);
        env["template_ref"] = row["ref"];
        Assert.Equal((false, (string?)"grant policy differs from the linked template instantiation", (string?)null), PolicyAuthoring.VerifyLinkedPolicy(env, row["registry"]));
    }

    [Fact]
    public void ARefusedResolutionIsTheRefusalReason()
    {
        var gone = Row(1);
        Assert.Equal((false, (string?)"template version is not in the registry", (string?)null), PolicyAuthoring.VerifyLinkedPolicy(WithRef(Envelope(Row(0)), gone), gone["registry"]));
        var bad = Row(5);
        Assert.Equal((false, (string?)"bad overlay signature", (string?)null), PolicyAuthoring.VerifyLinkedPolicy(WithRef(Envelope(Row(0)), bad), bad["registry"]));
    }

    static JD WithRef(JD env, JD row)
    {
        return new JD(env) { ["template_ref"] = row["ref"] };
    }

    [Fact]
    public void AnyDifferenceFromTheLinkedPolicyIsRefused()
    {
        var row = Row(0);
        var msg = (false, (string?)"grant policy differs from the linked template instantiation", (string?)null);
        Assert.Equal(msg, PolicyAuthoring.VerifyLinkedPolicy(new JD(Envelope(row)) { ["predicates"] = new JL() }, row["registry"]));
        Assert.Equal(msg, PolicyAuthoring.VerifyLinkedPolicy(new JD(Envelope(row)) { ["caveats"] = new JL() }, row["registry"]));
        var noCaveats = Envelope(row);
        noCaveats.Remove("caveats");
        Assert.Equal(msg, PolicyAuthoring.VerifyLinkedPolicy(noCaveats, row["registry"]));
        var noPredicates = Envelope(row);
        noPredicates.Remove("predicates");
        Assert.Equal(msg, PolicyAuthoring.VerifyLinkedPolicy(noPredicates, row["registry"]));
    }

    [Fact]
    public void AFaultWhileVerifyingIsARefusalNeverAnException()
    {
        var row = Row(0);
        Assert.Equal((false, (string?)"link verification error (fail closed)", (string?)null), PolicyAuthoring.VerifyLinkedPolicy(null!, row["registry"]));
    }
}
