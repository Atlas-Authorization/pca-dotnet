// Wesolowski verifiable delay function over an RSA group (mirrors @atlasauth/pca-vdf): y = x^(2^T) mod N by T sequential squarings plus a
// proof checked in O(log T) work. Big-integer arithmetic is System.Numerics.BigInteger (the reference is plain BigInt, no vetted VDF library
// exists in the .NET BCL); the Fiat-Shamir challenge prime is byte-identical to the reference (domain, length-prefixed transcript, counter/block
// sha256 expansion, same deterministic Miller-Rabin + strong Lucas test). Verification fails closed and never throws.
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace AtlasPca.Vdf;

/// <summary>A VDF output and its Wesolowski proof.</summary>
public sealed record VdfProof(BigInteger Y, BigInteger Pi);

/// <summary>A verification result; Reason is a machine-readable refusal token.</summary>
public readonly record struct VdfVerdict(bool Ok, string? Reason = null);

/// <summary>An INSECURE development modulus: the caller knows the factors (the trapdoor), so it delays nobody who holds them.</summary>
public sealed record InsecureDevVdfSetup(BigInteger N, BigInteger P, BigInteger Q, int Bits)
{
    public bool InsecureDevOnly => true;
}

public static class Vdf
{
    public const int ChallengePrimeBits = 256;
    public const int InsecureDevSetupDefaultBits = 2048;
    public const int MinProductionModulusBits = 2048;
    const string HashToPrimeDomain = "atlas-pca/vdf/wesolowski/hash-to-prime/v1\0";

    /// <summary>The RSA Factoring Challenge RSA-2048 modulus (unfactored as far as is publicly known).</summary>
    public static readonly BigInteger Rsa2048ChallengeModulus = BigInteger.Parse(
        "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072" +
        "84499268739280728777673597141834727026189637501497182469116507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686" +
        "99875491824224336372590851418654620435767984233871847744479207399342365848238242811981638150106748104516603773060562016196762561338441436038339044149526" +
        "34432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822" +
        "120720357", System.Globalization.CultureInfo.InvariantCulture);
    public static readonly BigInteger DefaultModulus = Rsa2048ChallengeModulus;

    // ---- bigint / byte helpers ----
    /// <summary>Big-endian bytes to a non-negative integer.</summary>
    public static BigInteger BytesToBigInt(byte[] bytes) => new(bytes, isUnsigned: true, isBigEndian: true);

    /// <summary>Non-negative integer to minimal big-endian bytes (0 is a single 0x00).</summary>
    public static byte[] BigIntToBytes(BigInteger value)
    {
        if (value.Sign < 0) throw new ArgumentOutOfRangeException(nameof(value), "bigIntToBytes: negative value");
        return value.IsZero ? new byte[] { 0 } : value.ToByteArray(isUnsigned: true, isBigEndian: true);
    }

    static byte[] U32(uint n) => new[] { (byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n };
    static byte[] U64(ulong n) { var b = new byte[8]; for (int i = 7; i >= 0; i--) { b[i] = (byte)n; n >>= 8; } return b; }
    static byte[] Lp(byte[] b) => Pca.Cat(U32((uint)b.Length), b);

    /// <summary>Number.isSafeInteger(T) and T >= 0.</summary>
    static bool StepsOk(double t) => double.IsFinite(t) && t == Math.Round(t) && Math.Abs(t) <= 9007199254740991.0 && t >= 0;

    static BigInteger NormalizeSteps(double t)
    {
        if (!StepsOk(t)) throw new ArgumentOutOfRangeException(nameof(t), $"VDF: steps T must be a non-negative safe integer, got {t}");
        return new BigInteger(t);
    }

    static BigInteger Mod(BigInteger a, BigInteger n) => ((a % n) + n) % n;

    public static BigInteger Gcd(BigInteger a, BigInteger b) => BigInteger.GreatestCommonDivisor(a, b);

    static bool IsUnit(BigInteger v, BigInteger n) => v.Sign > 0 && v < n && Gcd(v, n).IsOne;

    /// <summary>base^exp mod mod by square-and-multiply. exp >= 0, mod > 0.</summary>
    public static BigInteger Modpow(BigInteger b, BigInteger exp, BigInteger mod)
    {
        if (mod.Sign <= 0) throw new ArgumentOutOfRangeException(nameof(mod), "modpow: modulus must be positive");
        if (mod.IsOne) return BigInteger.Zero;
        if (exp.Sign < 0) throw new ArgumentOutOfRangeException(nameof(exp), "modpow: negative exponent (no inverse in a group of unknown order)");
        return BigInteger.ModPow(Mod(b, mod), exp, mod);
    }

    // ---- primality ----
    static readonly BigInteger[] SmallPrimes = new[] { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97 }.Select(p => new BigInteger(p)).ToArray();

    static int Jacobi(BigInteger a, BigInteger n)
    {
        int r = 1;
        a = Mod(a, n);
        while (!a.IsZero)
        {
            while (a.IsEven)
            {
                a >>= 1;
                var m = (int)(n & 7);
                if (m == 3 || m == 5) r = -r;
            }
            (a, n) = (n, a);
            if ((int)(a & 3) == 3 && (int)(n & 3) == 3) r = -r;
            a %= n;
        }
        return n.IsOne ? r : 0;
    }

    static bool IsPerfectSquare(BigInteger n)
    {
        if (n.Sign < 0) return false;
        if (n < 2) return true;
        var x = BigInteger.One << (int)((n.GetBitLength() + 1) / 2);
        for (;;)
        {
            var y = (x + n / x) >> 1;
            if (y >= x) return x * x == n;
            x = y;
        }
    }

    /// <summary>Strong Lucas probable-prime test, Selfridge method A parameters (Baillie-PSW). Expects odd n > 2; false otherwise or for a perfect square.</summary>
    public static bool IsStrongLucasProbablePrime(BigInteger n)
    {
        if (n < 3 || n.IsEven || IsPerfectSquare(n)) return false;
        BigInteger D = 5;
        for (;;)
        {
            var j = Jacobi(D, n);
            if (j == -1) break;
            if (j == 0 && BigInteger.Abs(D) != n) return false;
            D = D.Sign > 0 ? -(D + 2) : -D + 2;
        }
        var P = BigInteger.One;
        var Q = (BigInteger.One - D) / 4;
        BigInteger Half(BigInteger x) => (x.IsEven ? x : x + n) >> 1;
        var d = n + 1;
        int s = 0;
        while (d.IsEven) { d >>= 1; s++; }
        var U = BigInteger.One;
        var V = P;
        var Qk = Mod(Q, n);
        for (long i = (long)d.GetBitLength() - 2; i >= 0; i--)
        {
            U = Mod(U * V, n);
            V = Mod(V * V - 2 * Qk, n);
            Qk = Mod(Qk * Qk, n);
            if (!(d >> (int)i).IsEven)
            {
                var u1 = Half(Mod(P * U + V, n));
                var v1 = Half(Mod(D * U + P * V, n));
                U = u1;
                V = v1;
                Qk = Mod(Qk * Q, n);
            }
        }
        if (U.IsZero || V.IsZero) return true;
        for (int r = 1; r < s; r++)
        {
            V = Mod(V * V - 2 * Qk, n);
            if (V.IsZero) return true;
            Qk = Mod(Qk * Qk, n);
        }
        return false;
    }

    /// <summary>Strong (Miller-Rabin) probable-prime test of an odd n > 2 against the fixed small-prime bases; refuses even n and n &lt; 3.</summary>
    public static bool IsMillerRabinProbablePrime(BigInteger n)
    {
        if (n < 3 || n.IsEven) return false;
        var d = n - 1;
        int s = 0;
        while (d.IsEven) { d >>= 1; s++; }
        foreach (var a in SmallPrimes)
        {
            var b = a % n;
            if (b.IsZero) continue;
            var x = Modpow(b, d, n);
            if (x.IsOne || x == n - 1) continue;
            bool pass = false;
            for (int i = 1; i < s; i++)
            {
                x = x * x % n;
                if (x == n - 1) { pass = true; break; }
            }
            if (!pass) return false;
        }
        return true;
    }

    /// <summary>Trial division by the small primes, Miller-Rabin, then strong Lucas. Deterministic.</summary>
    public static bool IsProbablePrime(BigInteger n)
    {
        if (n < 2) return false;
        foreach (var p in SmallPrimes)
        {
            if (n == p) return true;
            if ((n % p).IsZero) return false;
        }
        return IsMillerRabinProbablePrime(n) && IsStrongLucasProbablePrime(n);
    }

    // ---- hash-to-prime ----
    /// <summary>The Fiat-Shamir challenge prime l, deterministic in the full transcript (x, y, T, N). bits is a safe integer in [8, 8192].</summary>
    public static BigInteger HashToPrime(BigInteger x, BigInteger y, double T, BigInteger N, double bits = ChallengePrimeBits)
    {
        if (!(double.IsFinite(bits) && bits == Math.Round(bits) && bits >= 8 && bits <= 8192)) throw new ArgumentOutOfRangeException(nameof(bits), "hashToPrime: bits must be an integer in [8, 8192]");
        var nbits = (int)bits;
        var steps = NormalizeSteps(T);
        var xr = Mod(x, N);
        var yr = Mod(y, N);
        var transcript = Pca.Cat(Encoding.UTF8.GetBytes(HashToPrimeDomain), Lp(BigIntToBytes(xr)), Lp(BigIntToBytes(yr)), Lp(BigIntToBytes(steps)), Lp(BigIntToBytes(N)), Lp(U32((uint)nbits)));
        var seed = Pca.Sha(transcript);
        int bytesNeeded = (nbits + 7) / 8;
        var topBit = BigInteger.One << (nbits - 1);
        var mask = (BigInteger.One << nbits) - 1;
        for (ulong counter = 0; ; counter++)
        {
            var chunks = new List<byte>();
            for (uint blockIndex = 0; chunks.Count < bytesNeeded; blockIndex++)
                chunks.AddRange(Pca.Sha(Pca.Cat(seed, U64(counter), U32(blockIndex))));
            var candidate = (BytesToBigInt(chunks.Take(bytesNeeded).ToArray()) & mask) | topBit | BigInteger.One;
            if (IsProbablePrime(candidate)) return candidate;
        }
    }

    // ---- the VDF ----
    /// <summary>y = x^(2^T) mod N by T REAL sequential squarings (the enforced delay).</summary>
    public static BigInteger SequentialSquare(BigInteger x, double T, BigInteger N)
    {
        if (N <= 1) throw new ArgumentOutOfRangeException(nameof(N), "VDF: modulus N must be > 1");
        var steps = NormalizeSteps(T);
        var y = Mod(x, N);
        for (BigInteger i = 0; i < steps; i++) y = y * y % N;
        return y;
    }

    /// <summary>pi = x^floor(2^T / l) mod N by T squarings and a running remainder of 2^i mod l (2^T is never formed).</summary>
    static BigInteger WesolowskiProof(BigInteger x, BigInteger T, BigInteger l, BigInteger N)
    {
        var xr = Mod(x, N);
        var pi = BigInteger.One % N;
        var r = BigInteger.One % l;
        for (BigInteger i = 0; i < T; i++)
        {
            var twoR = r * 2;
            var b = twoR / l;
            r = twoR % l;
            pi = pi * pi % N;
            if (b.IsOne) pi = pi * xr % N;
        }
        return pi;
    }

    static void RequireEvalInput(BigInteger x, BigInteger N)
    {
        if (N <= 3 || N.IsEven) throw new ArgumentOutOfRangeException(nameof(N), "VDF: modulus N must be odd and > 3");
    }

    static BigInteger RequireInput(BigInteger x, BigInteger N)
    {
        var xr = Mod(x, N);
        if (!IsUnit(xr, N) || xr.IsOne || xr == N - 1)
            throw new ArgumentOutOfRangeException(nameof(x), "VDF: input x must be a non-trivial unit mod N (not 0, 1, -1, or sharing a factor with N)");
        return xr;
    }

    /// <summary>Evaluate: y = x^(2^T) mod N and the Wesolowski proof, challenge prime l = HashToPrime(x, y, T, N).</summary>
    public static VdfProof VdfEval(BigInteger x, double T, BigInteger N)
    {
        RequireEvalInput(x, N);
        var steps = NormalizeSteps(T);
        RequireInput(x, N);
        var y = SequentialSquare(x, T, N);
        var l = HashToPrime(x, y, T, N);
        return new VdfProof(y, WesolowskiProof(x, steps, l, N));
    }

    public const string BadModulus = "bad-modulus", BadSteps = "bad-steps", NonCanonicalY = "non-canonical-y", NonCanonicalPi = "non-canonical-pi",
        BadInputX = "bad-input-x", EquationMismatch = "equation-mismatch", MalformedInput = "malformed-input";

    static VdfVerdict No(string reason) => new(false, reason);

    /// <summary>Verify in O(log T): accept iff pi^l * x^r == y (mod N) with l = HashToPrime(x, y, T, N), r = 2^T mod l. Never throws.</summary>
    public static VdfVerdict VdfVerifyDetailed(BigInteger x, BigInteger y, BigInteger pi, double T, BigInteger N)
    {
        try
        {
            if (N <= 3 || N.IsEven) return No(BadModulus);
            if (!StepsOk(T)) return No(BadSteps);
            if (!IsUnit(y, N)) return No(NonCanonicalY);
            if (!IsUnit(pi, N)) return No(NonCanonicalPi);
            var xr = Mod(x, N);
            if (!IsUnit(xr, N) || xr.IsOne || xr == N - 1) return No(BadInputX);
            var l = HashToPrime(x, y, T, N);
            var r = Modpow(2, new BigInteger(T), l);
            var lhs = Modpow(pi, l, N) * Modpow(xr, r, N) % N;
            return lhs == y ? new VdfVerdict(true) : No(EquationMismatch);
        }
        catch { return No(MalformedInput); }
    }

    /// <summary>The smaller of y and N - y (the plain output is only defined up to sign).</summary>
    public static BigInteger CanonicalVdfOutput(BigInteger y, BigInteger N) => y > N - y ? N - y : y;

    /// <summary>Evaluate with a UNIQUE output: y and pi are the canonical (smaller) representatives.</summary>
    public static VdfProof VdfEvalCanonical(BigInteger x, double T, BigInteger N)
    {
        RequireEvalInput(x, N);
        var steps = NormalizeSteps(T);
        RequireInput(x, N);
        var y = CanonicalVdfOutput(SequentialSquare(x, T, N), N);
        var l = HashToPrime(x, y, T, N);
        return new VdfProof(y, CanonicalVdfOutput(WesolowskiProof(x, steps, l, N), N));
    }

    /// <summary>Verify a canonical-output proof: rejects y or pi above N/2; accepts the relation up to sign.</summary>
    public static VdfVerdict VdfVerifyCanonicalDetailed(BigInteger x, BigInteger y, BigInteger pi, double T, BigInteger N)
    {
        try
        {
            if (N <= 3 || N.IsEven) return No(BadModulus);
            if (!StepsOk(T)) return No(BadSteps);
            if (!IsUnit(y, N) || y > N - y) return No(NonCanonicalY);
            if (!IsUnit(pi, N) || pi > N - pi) return No(NonCanonicalPi);
            var xr = Mod(x, N);
            if (!IsUnit(xr, N) || xr.IsOne || xr == N - 1) return No(BadInputX);
            var l = HashToPrime(x, y, T, N);
            var r = Modpow(2, new BigInteger(T), l);
            var lhs = Modpow(pi, l, N) * Modpow(xr, r, N) % N;
            return lhs == y || lhs == N - y ? new VdfVerdict(true) : No(EquationMismatch);
        }
        catch { return No(MalformedInput); }
    }

    public static bool VdfVerifyCanonical(BigInteger x, BigInteger y, BigInteger pi, double T, BigInteger N) => VdfVerifyCanonicalDetailed(x, y, pi, T, N).Ok;
    public static bool VdfVerify(BigInteger x, BigInteger y, BigInteger pi, double T, BigInteger N) => VdfVerifyDetailed(x, y, pi, T, N).Ok;

    // ---- dev-only modulus generation and the production screen ----
    static BigInteger RandomPrime(int bits, Func<int, byte[]> rnd)
    {
        if (bits < 16) throw new ArgumentOutOfRangeException(nameof(bits), "randomPrime: bits too small");
        int bytes = (bits + 7) / 8;
        var topBit = BigInteger.One << (bits - 1);
        var mask = (BigInteger.One << bits) - 1;
        for (int attempt = 0; attempt < 50_000; attempt++)
        {
            var candidate = (BytesToBigInt(rnd(bytes)) & mask) | topBit | BigInteger.One;
            if (IsProbablePrime(candidate)) return candidate;
        }
        throw new InvalidOperationException("insecureDevSetup: randomness source failed to yield a prime (stuck or constant RNG?)");
    }

    static readonly HashSet<BigInteger> InsecureDevModuli = new();
    static readonly HashSet<BigInteger> ProductionScreenPassed = new();
    static readonly object Reg = new();

    /// <summary>Generate an RSA modulus for DEVELOPMENT / TESTS ONLY: this process knows p and q, the trapdoor that skips the whole delay. The timelock layer refuses it unless opted in by name.</summary>
    public static InsecureDevVdfSetup InsecureDevSetup(int bits = InsecureDevSetupDefaultBits, Func<int, byte[]>? randomBytes = null)
    {
        if (bits < 32) throw new ArgumentOutOfRangeException(nameof(bits), "insecureDevSetup: bits must be a safe integer >= 32");
        var rnd = randomBytes ?? (n => RandomNumberGenerator.GetBytes(n));
        int half = bits / 2;
        var p = RandomPrime(half, rnd);
        var q = RandomPrime(bits - half, rnd);
        for (int i = 0; p == q; i++)
        {
            if (i >= 8) throw new InvalidOperationException("insecureDevSetup: randomness source returned the same prime repeatedly (constant RNG?)");
            q = RandomPrime(bits - half, rnd);
        }
        var n2 = p * q;
        lock (Reg) InsecureDevModuli.Add(n2);
        return new InsecureDevVdfSetup(n2, p, q, (int)n2.GetBitLength());
    }

    static readonly BigInteger[] ScreenPrimes = BuildScreenPrimes();
    static BigInteger[] BuildScreenPrimes()
    {
        const int limit = 1 << 16;
        var sieve = new bool[limit];
        var o = new List<BigInteger>();
        for (int i = 2; i < limit; i++)
        {
            if (sieve[i]) continue;
            o.Add(i);
            for (long j = (long)i * i; j < limit; j += i) sieve[j] = true;
        }
        return o.ToArray();
    }

    /// <summary>Screen a modulus for the production path: refuses a dev-setup modulus of this process, under 2048 bits, even, a perfect square, prime, or with a prime factor below 2^16. A screen, not a proof of unknown factorisation.</summary>
    public static (bool Ok, string? Reason) CheckProductionModulus(BigInteger N)
    {
        bool dev, passed;
        lock (Reg) { dev = InsecureDevModuli.Contains(N); passed = ProductionScreenPassed.Contains(N); }
        if (!dev && passed) return (true, null);
        if (dev) return (false, "modulus came from insecureDevSetup(): its factors are known, so it provides no delay");
        if (N <= 3) return (false, "modulus is too small");
        if (N.GetBitLength() < MinProductionModulusBits) return (false, $"modulus is below {MinProductionModulusBits} bits");
        if (N.IsEven) return (false, "modulus is even");
        if (IsPerfectSquare(N)) return (false, "modulus is a perfect square");
        if (IsProbablePrime(N)) return (false, "modulus is prime (group order N-1 is public)");
        foreach (var p in ScreenPrimes)
            if ((N % p).IsZero) return (false, $"modulus has the small prime factor {p}");
        lock (Reg) ProductionScreenPassed.Add(N);
        return (true, null);
    }
}
