using System.Numerics;
using AtlasPca.Mpc;
using AtlasPca.Mpc.LweOt;
using Xunit;

namespace AtlasPca.MpcLweOt.Tests;

/// <summary>The endemic base OT as the OT-extension's base OT: a channel seeded by it extends correctly. liblweot must load (ATLAS_LWEOT_LIB).</summary>
public class EndemicChannelTests
{
    [Fact]
    public void ExtensionOverEndemicBaseOt()
    {
        Assert.True(Lattice.Available(), "liblweot must load (ATLAS_LWEOT_LIB)");
        var ch = new Ot.OtChannel(Ot.OtRandom(Ot.SplitMix64(new BigInteger(4242))), EndemicOt.WithEndemicBaseOt(), null);
        var choices = new[] { 0, 1, 1, 0, 1, 0, 0, 1, 1, 1 };
        var m0 = Enumerable.Range(0, choices.Length).Select(i => new BigInteger(1000 + i)).ToArray();
        var m1 = Enumerable.Range(0, choices.Length).Select(i => new BigInteger(2000 + i)).ToArray();
        var e = ch.Extend(choices, m0, m1);
        for (int j = 0; j < choices.Length; j++) Assert.Equal(choices[j] == 1 ? m1[j] : m0[j], e.Received[j]);
        Assert.Null(ch.BaseTranscript);
        // a second round reuses the same base OT
        var e2 = ch.Extend(new[] { 1, 0 }, new[] { new BigInteger(7), new BigInteger(8) }, new[] { new BigInteger(9), new BigInteger(10) });
        Assert.Equal(new[] { new BigInteger(9), new BigInteger(8) }, e2.Received);
    }
}
