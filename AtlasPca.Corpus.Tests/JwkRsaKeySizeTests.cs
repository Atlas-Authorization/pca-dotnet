using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

// The RSA key rule refuses a JWK whose modulus is under 512 bits even when the key is otherwise well formed (odd, two large prime
// factors, odd exponent): the RSA import itself would accept it.
public class JwkRsaKeySizeTests
{
    // a 384-bit product of two 192-bit primes
    const string Modulus384 = "8ba4e263c85c65c3db9a09ffd887d08a875d8ceae5b52adae5903b4d37d890fec26a3a05ae302a5cacbfda14865ff95b";

    [Fact]
    public void A384BitModulusIsUnsupported()
    {
        var n = Pca.B64u(Convert.FromHexString(Modulus384));
        var e = Assert.Throws<AttestError>(() => AttestJws.JwkRsaKey(n, "AQAB"));
        Assert.Equal("error:1E08010C:DECODER routines::unsupported", e.Message);
    }
}
