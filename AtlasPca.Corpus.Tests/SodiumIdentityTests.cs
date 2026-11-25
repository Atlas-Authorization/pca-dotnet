// libsodium refuses an identity result from its multiplications; these pin how the wrappers map that (the reference returns the identity).
using System.Numerics;
using AtlasPca.Ratchet;
using Xunit;

namespace AtlasPca.Corpus.Tests;

public class SodiumIdentityTests
{
    [Fact]
    public void EdwardsMultiplyByOrderOrZeroIsIdentity()
    {
        Assert.True(EdwardsPoint.Base.Multiply(EdwardsPoint.Order).IsIdentity());
        Assert.True(EdwardsPoint.Base.Multiply(BigInteger.Zero).IsIdentity());
        Assert.True(EdwardsPoint.Zero.Multiply(7).IsIdentity());
        Assert.True(EdwardsPoint.Base.Multiply(EdwardsPoint.Order + 1).SameAs(EdwardsPoint.Base));
        Assert.True(EdwardsPoint.Base.IsTorsionFree());
        Assert.True(EdwardsPoint.Zero.IsTorsionFree());
    }

    [Fact]
    public void EdwardsTorsionPointDecodesButIsSmallOrder()
    {
        var t = EdwardsPoint.FromBytes(Convert.FromHexString("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")); // order 2
        Assert.True(t.IsSmallOrder());
        Assert.False(t.IsTorsionFree());
        Assert.Throws<InvalidOperationException>(() => t.Multiply(3));
        Assert.Throws<ArgumentException>(() => EdwardsPoint.FromBytes(Convert.FromHexString("0100000000000000000000000000000000000000000000000000000000000080"))); // x = 0, sign set
        Assert.Throws<ArgumentException>(() => EdwardsPoint.FromBytes(Convert.FromHexString("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))); // y = p + 1
    }

    [Fact]
    public void RistrettoIdentityMultiplyIsIdentity()
    {
        Assert.True(RistrettoPoint.Zero.Multiply(5).Equals(RistrettoPoint.Zero));
        Assert.True(RistrettoPoint.Base.Multiply(RistrettoPoint.Order - 1).Add(RistrettoPoint.Base).Equals(RistrettoPoint.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => RistrettoPoint.Base.Multiply(RistrettoPoint.Order));
    }

    [Fact]
    public void RistrettoScalarOpsMatchBigInteger()
    {
        var a = BigInteger.Pow(3, 200); var b = BigInteger.Pow(5, 90);
        var l = RistrettoScalar.Order;
        Assert.Equal(a * b % l, RistrettoScalar.Mul(a, b));
        Assert.Equal((a - b) % l + (a < b ? l : 0), RistrettoScalar.Sub(a, b));
        Assert.Equal(-a % l + l, RistrettoScalar.Mod(-a));
    }
}
