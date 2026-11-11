using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// A hop whose caveats member is not an array (missing, null, {}, "x", 5) is refused by the early shape check, whatever its signature: the allocation rule never sees it.
// (The reference words it "malformed caveats" at the allocation rule; the stricter early refusal is kept.) The roots are genuinely signed, so only the shape rule refuses them.
public class CaveatsNotArrayTests
{
    static EdKey Key => EdKey.FromSeed(Enumerable.Repeat((byte)0x91, 32).ToArray());

    /// <summary>A root hand-signed over the given caveats value (<paramref name="has"/> false: the member is omitted from the capability, so its body carries null).</summary>
    static JD Root(object? caveats, bool has = true)
    {
        var body = new JD { ["issuer"] = Key.Id, ["holder"] = "h", ["caveats"] = caveats, ["parent"] = null };
        var digest = Pca.HashCanonical(body);
        var sig = Pca.B64u(Key.Sign(Pca.Cat(System.Text.Encoding.UTF8.GetBytes(Pca.CapDomain), Pca.B64uDecode(digest, 32)!)));
        var cap = new JD { ["id"] = digest, ["issuer"] = Key.Id, ["holder"] = "h", ["body_digest"] = digest, ["sig"] = sig };
        if (has) cap["caveats"] = caveats;
        return cap;
    }

    static (string Why, bool Ok) Verify(JD cap) => Pca.VerifyChain(new JL { cap }, Key.Id, true);

    [Fact]
    public void AControlWithAnEmptyListVerifies() => Assert.Equal(("", true), Verify(Root(new JL())));

    [Fact]
    public void AHopWhoseCaveatsIsNotAnArrayIsRefusedByTheShapeCheck()
    {
        Assert.Equal(("hop 0: malformed capability", false), Verify(Root(null, has: false)));
        Assert.Equal(("hop 0: malformed capability", false), Verify(Root(null)));
        Assert.Equal(("hop 0: malformed capability", false), Verify(Root(new JD())));
        Assert.Equal(("hop 0: malformed capability", false), Verify(Root("x")));
        Assert.Equal(("hop 0: malformed capability", false), Verify(Root(5L)));
    }
}
