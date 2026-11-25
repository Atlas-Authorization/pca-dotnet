
using AtlasPca.Ratchet;
using Xunit;

namespace AtlasPca.Corpus.Tests;

// Point validation is fail-closed whatever libsodium build answers its validity query: B + T (T of order 2) is mixed-order and must be refused.
public class MixedOrderPointTests
{
    static byte[] Hex(string s) => Convert.FromHexString(s);

    [Fact]
    public void DecodeSafePointRefusesTorsionAndAcceptsMinusBase()
    {
        var b = Hex("5866666666666666666666666666666666666666666666666666666666666666");
        var t2 = Hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"); // (0, -1), order 2
        var mixed = EdwardsPoint.FromBytes(b).Add(EdwardsPoint.FromBytes(t2)).ToBytes();
        var negB = Hex("58666666666666666666666666666666666666666666666666666666666666e6");
        Assert.Equal(b, Frost.DecodeSafePoint(b).ToBytes());
        Assert.Equal(negB, Frost.DecodeSafePoint(negB).ToBytes());
        foreach (var bad in new[] { mixed, t2, Hex("0100000000000000000000000000000000000000000000000000000000000000"), new byte[32],
                     Hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f") })
            Assert.Throws<ArgumentException>(() => Frost.DecodeSafePoint(bad));
    }

    [Fact]
    public void RistrettoEncodingWithBit255SetIsRefused()
    {
        var g = Hex("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"); // RFC 9496 generator
        Assert.NotNull(RistrettoPoint.TryDecode(g));
        g[31] |= 0x80;
        Assert.Null(RistrettoPoint.TryDecode(g));
    }
}
