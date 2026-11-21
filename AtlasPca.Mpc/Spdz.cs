using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using static AtlasPca.Mpc.Field;

namespace AtlasPca.Mpc;

/// <summary>
/// SPDZ-style authenticated secret sharing over F_p: the malicious-with-abort (dishonest-majority) layer. A global MAC key alpha is additively
/// shared; every authenticated value carries MAC shares summing to alpha*x under MAC_KEYS independent keys; the batched commit-then-open
/// MAC-check aborts on any deviation, so the result is correct or an abort. The authenticated triples come from a trusted dealer (the explicit
/// trust assumption); the online phase is the real thing.
/// </summary>
public static class Spdz
{
    /// <summary>One global MAC key, additively shared. <c>Alpha</c> is for dealer preprocessing and tests only.</summary>
    public sealed record MacKey(BigInteger[] AlphaShares, BigInteger Alpha);

    /// <summary>The global MAC keys: key 0 is AlphaShares/Alpha; ExtraKeys are further independent keys.</summary>
    public sealed record MacContext(int N, BigInteger[] AlphaShares, BigInteger Alpha, List<MacKey> ExtraKeys);

    /// <summary>value shares sum to x, mac shares to alpha*x (key 0), ExtraMac[l-1] to ExtraKeys[l-1].Alpha*x.</summary>
    public sealed record AuthSV(BigInteger[] Value, BigInteger[] Mac, BigInteger[][] ExtraMac);

    public sealed record AuthTriple(AuthSV A, AuthSV B, AuthSV C);

    public const int MAC_KEYS = 2;
    public const int MIN_MAC_SOUNDNESS_BITS = 100;
    public const int SACRIFICE_PARTNERS = 2;

    public static List<MacKey> MacKeysOf(MacContext ctx)
    {
        var o = new List<MacKey> { new(ctx.AlphaShares, ctx.Alpha) };
        o.AddRange(ctx.ExtraKeys);
        return o;
    }

    /// <summary>keys * (log2 p - 1): the soundness in bits of the batched MAC-check.</summary>
    public static double MacSoundnessBits(int keys, BigInteger? p = null)
    {
        double d = ToDouble(p ?? PRIME);
        double l = Math.Log(d) / Math.Log(2);
        double r = Math.Round(l, MidpointRounding.ToEven);
        if (Math.Abs(l - r) < 1e-9 && Math.Pow(2, r) == d) l = r;
        return keys * (l - 1);
    }

    // Java BigInteger.doubleValue: round to nearest, ties to even (the BCL conversion truncates)
    static double ToDouble(BigInteger v)
    {
        if (v.Sign < 0) return -ToDouble(-v);
        long bl = (long)v.GetBitLength();
        if (bl <= 53) return (double)v;
        int shift = (int)(bl - 53);
        var q = v >> shift;
        var rem = v - (q << shift);
        var half = BigInteger.One << (shift - 1);
        if (rem > half || (rem == half && !q.IsEven)) q += 1;
        return (double)q * Math.Pow(2, shift);
    }

    /// <summary>Raised when the MAC-check detects an inconsistent opening/MAC: the protocol ABORTS, no output.</summary>
    public class MacCheckAbort(string message) : Exception(message);

    public static MacContext SetupMac(int n, IFieldSource rng, int keys = MAC_KEYS)
    {
        if (n < 1) throw new ArgumentException("setupMac: n must be a positive integer");
        if (keys < 1 || keys > 16) throw new ArgumentException("setupMac: keys must be an integer in [1, 16]");
        var first = Mk(n, rng);
        var extra = new List<MacKey>();
        for (int i = 0; i < keys - 1; i++) extra.Add(Mk(n, rng));
        return new MacContext(n, first.AlphaShares, first.Alpha, extra);
    }

    static MacKey Mk(int n, IFieldSource rng)
    {
        var alpha = rng.Next();
        return new MacKey(Sharing.Share(alpha, n, rng), alpha);
    }

    public static AuthSV AuthShare(BigInteger secret, MacContext ctx, IFieldSource rng)
    {
        var v = Mod(secret);
        var value = Sharing.Share(v, ctx.N, rng);
        var mac = Sharing.Share(Fmul(ctx.Alpha, v), ctx.N, rng);
        var extra = new BigInteger[ctx.ExtraKeys.Count][];
        for (int l = 0; l < extra.Length; l++) extra[l] = Sharing.Share(Fmul(ctx.ExtraKeys[l].Alpha, v), ctx.N, rng);
        return new AuthSV(value, mac, extra);
    }

    public static AuthSV AuthConstant(BigInteger c, MacContext ctx)
    {
        var v = Mod(c);
        var value = new BigInteger[ctx.N];
        value[0] = v;
        var mac = ScaleAll(ctx.AlphaShares, v);
        var extra = new BigInteger[ctx.ExtraKeys.Count][];
        for (int l = 0; l < extra.Length; l++) extra[l] = ScaleAll(ctx.ExtraKeys[l].AlphaShares, v);
        return new AuthSV(value, mac, extra);
    }

    static BigInteger[] ScaleAll(BigInteger[] xs, BigInteger c)
    {
        var o = new BigInteger[xs.Length];
        for (int i = 0; i < xs.Length; i++) o[i] = Fmul(xs[i], c);
        return o;
    }

    static BigInteger[] Zip(BigInteger[] x, BigInteger[] y, Func<BigInteger, BigInteger, BigInteger> f)
    {
        var o = new BigInteger[x.Length];
        for (int i = 0; i < x.Length; i++) o[i] = f(x[i], y[i]);
        return o;
    }

    static BigInteger[][] ZipMac(BigInteger[][] x, BigInteger[][] y, Func<BigInteger, BigInteger, BigInteger> f)
    {
        var o = new BigInteger[x.Length][];
        for (int l = 0; l < x.Length; l++) o[l] = Zip(x[l], y[l], f);
        return o;
    }

    public static AuthSV AddAuth(AuthSV x, AuthSV y)
    {
        RequireSame(x, y);
        return new AuthSV(Zip(x.Value, y.Value, Fadd), Zip(x.Mac, y.Mac, Fadd), ZipMac(x.ExtraMac, y.ExtraMac, Fadd));
    }

    public static AuthSV SubAuth(AuthSV x, AuthSV y)
    {
        RequireSame(x, y);
        return new AuthSV(Zip(x.Value, y.Value, Fsub), Zip(x.Mac, y.Mac, Fsub), ZipMac(x.ExtraMac, y.ExtraMac, Fsub));
    }

    public static AuthSV NegAuth(AuthSV x)
    {
        var e = new BigInteger[x.ExtraMac.Length][];
        for (int l = 0; l < e.Length; l++) e[l] = NegAll(x.ExtraMac[l]);
        return new AuthSV(NegAll(x.Value), NegAll(x.Mac), e);
    }

    static BigInteger[] NegAll(BigInteger[] xs)
    {
        var o = new BigInteger[xs.Length];
        for (int i = 0; i < xs.Length; i++) o[i] = Fneg(xs[i]);
        return o;
    }

    public static AuthSV ScaleAuth(AuthSV x, BigInteger c)
    {
        var k = Mod(c);
        var e = new BigInteger[x.ExtraMac.Length][];
        for (int l = 0; l < e.Length; l++) e[l] = ScaleAll(x.ExtraMac[l], k);
        return new AuthSV(ScaleAll(x.Value, k), ScaleAll(x.Mac, k), e);
    }

    /// <summary>x + c for a PUBLIC constant c: c to one party's value share, alpha_i*c to every party's MAC share under every key.</summary>
    public static AuthSV AddPublicAuth(AuthSV x, BigInteger c, MacContext ctx)
    {
        int n = ctx.N;
        if (x.Value.Length != n || x.Mac.Length != n || ctx.AlphaShares.Length != n)
            throw new ArgumentException("addPublicAuth: shared value and MAC context disagree on the party count");
        if (x.ExtraMac.Length != ctx.ExtraKeys.Count) throw new ArgumentException("addPublicAuth: shared value and MAC context disagree on the key count");
        var k = Mod(c);
        var value = (BigInteger[])x.Value.Clone();
        value[0] = Fadd(value[0], k);
        var mac = new BigInteger[n];
        for (int i = 0; i < n; i++) mac[i] = Fadd(x.Mac[i], Fmul(ctx.AlphaShares[i], k));
        var extra = new BigInteger[x.ExtraMac.Length][];
        for (int l = 0; l < extra.Length; l++)
        {
            var row = x.ExtraMac[l];
            var key = ctx.ExtraKeys[l];
            if (row.Length != n || key.AlphaShares.Length != n) throw new ArgumentException("addPublicAuth: extra MAC party count mismatch");
            extra[l] = new BigInteger[n];
            for (int i = 0; i < n; i++) extra[l][i] = Fadd(row[i], Fmul(key.AlphaShares[i], k));
        }
        return new AuthSV(value, mac, extra);
    }

    public static AuthSV NotBitAuth(AuthSV b, MacContext ctx) => AddPublicAuth(NegAuth(b), BigInteger.One, ctx);

    public static AuthTriple GenAuthTriple(MacContext ctx, IFieldSource rng)
    {
        var a = rng.Next();
        var b = rng.Next();
        var asv = AuthShare(a, ctx, rng);
        var bsv = AuthShare(b, ctx, rng);
        var csv = AuthShare(Fmul(a, b), ctx, rng);
        return new AuthTriple(asv, bsv, csv);
    }

    /// <summary>A triple to deliver plus its sacrifice partners (every partner shares keep.b).</summary>
    public sealed record TripleWithPartners(AuthTriple Keep, List<AuthTriple> Partners);

    /// <summary>TEST-ONLY lying-dealer fault: the dealer authenticates a wrong product. Null entries mean no delta.</summary>
    public sealed record DealerFault(BigInteger? KeepCDelta, List<BigInteger?>? PartnerCDelta);

    public static TripleWithPartners GenTripleWithPartners(MacContext ctx, IFieldSource rng, int partners = SACRIFICE_PARTNERS, DealerFault? fault = null)
    {
        if (partners < 1 || partners > 8) throw new ArgumentException("genTripleWithPartners: partners must be in [1, 8]");
        var a = rng.Next();
        var b = rng.Next();
        var bSV = AuthShare(b, ctx, rng);
        var kd = fault?.KeepCDelta ?? BigInteger.Zero;
        var keepA = AuthShare(a, ctx, rng);
        var keepC = AuthShare(Fadd(Fmul(a, b), kd), ctx, rng);
        var keep = new AuthTriple(keepA, bSV, keepC);
        var ps = new List<AuthTriple>();
        for (int r = 0; r < partners; r++)
        {
            var ah = rng.Next();
            var pd = fault?.PartnerCDelta != null && r < fault.PartnerCDelta.Count && fault.PartnerCDelta[r] != null ? fault.PartnerCDelta[r]!.Value : BigInteger.Zero;
            var pa = AuthShare(ah, ctx, rng);
            var pc = AuthShare(Fadd(Fmul(ah, b), pd), ctx, rng);
            ps.Add(new AuthTriple(pa, bSV, pc));
        }
        return new TripleWithPartners(keep, ps);
    }

    /// <summary>Sacrifice check: certifies the kept triples or throws <see cref="MacCheckAbort"/>, emitting nothing.</summary>
    public static List<AuthTriple> SacrificeVerify(List<TripleWithPartners> batch, MacContext ctx, IFieldSource rng, List<Deviation>? deviations)
    {
        var engine = new SpdzEngine(ctx, deviations);
        var taus = new List<BigInteger>();
        foreach (var t in batch)
        {
            var keep = t.Keep;
            if (t.Partners.Count < 1) throw new MacCheckAbort("sacrifice: a triple without partners cannot be certified");
            foreach (var sac in t.Partners)
            {
                if (!keep.B.Value.SequenceEqual(sac.B.Value)) throw new MacCheckAbort("sacrifice: partner does not share b with the triple");
                var e = rng.Next();
                if (e.IsZero) e = BigInteger.One;
                var rho = engine.Open(SubAuth(ScaleAuth(keep.A, e), sac.A), "sacrifice:rho");
                var tau = SubAuth(ScaleAuth(keep.C, e), sac.C);
                tau = SubAuth(tau, ScaleAuth(keep.B, rho));
                taus.Add(engine.Open(tau, "sacrifice:tau"));
            }
        }
        engine.MacCheck(rng);
        foreach (var t in taus)
            if (!t.IsZero)
                throw new MacCheckAbort("Beaver-triple sacrifice FAILED: residual tau=" + t + " != 0 - a malformed triple (c != a*b) was delivered; aborting with no triple emitted");
        return batch.Select(t => t.Keep).ToList();
    }

    /// <summary>A party's broadcast deviation in the online phase (models an active cheater). Null ValueDelta / MacDelta mean none; MacKey defaults to 0.</summary>
    public sealed record Deviation(int OpenIndex, int Party, BigInteger? ValueDelta, BigInteger? MacDelta, int? MacKey);

    /// <summary>One partial opening as it reaches the MAC-check: the public value and MacShares[key][party].</summary>
    public sealed record OpenedValue(BigInteger Value, BigInteger[][] MacShares, string Label);

    /// <summary>Arithmetic core of the batched MAC-check over an arbitrary modulus p; returns sigma[key][party].</summary>
    public static BigInteger[][] MacResiduals(BigInteger p, BigInteger[][] alphaShares, List<OpenedValue> opened, BigInteger[][] challenges)
    {
        static BigInteger M(BigInteger x, BigInteger p) { var r = x % p; return r.Sign < 0 ? r + p : r; }
        var o = new BigInteger[alphaShares.Length][];
        for (int l = 0; l < alphaShares.Length; l++)
        {
            var r = challenges[l];
            var a = BigInteger.Zero;
            for (int j = 0; j < opened.Count; j++) a = M(a + r[j] * opened[j].Value, p);
            var alphas = alphaShares[l];
            o[l] = new BigInteger[alphas.Length];
            for (int i = 0; i < alphas.Length; i++)
            {
                var gamma = BigInteger.Zero;
                for (int j = 0; j < opened.Count; j++) gamma = M(gamma + r[j] * opened[j].MacShares[l][i], p);
                o[l][i] = M(gamma - alphas[i] * a, p);
            }
        }
        return o;
    }

    /// <summary>The SPDZ online engine: partial openings and the batched MAC-check.</summary>
    public sealed class SpdzEngine
    {
        readonly MacContext _ctx;
        readonly List<Deviation> _deviations;
        readonly List<OpenedValue> _opened = new();
        int _counter;

        public SpdzEngine(MacContext ctx, List<Deviation>? deviations = null)
        {
            double bits = MacSoundnessBits(1 + ctx.ExtraKeys.Count);
            if (bits < MIN_MAC_SOUNDNESS_BITS)
                throw new ArgumentException("SpdzEngine: MAC context gives only " + (long)Math.Floor(bits + 0.5) + " bits of statistical soundness (< " + MIN_MAC_SOUNDNESS_BITS
                    + "); use setupMac(n, rng) with the default " + MAC_KEYS + " keys");
            _ctx = ctx;
            _deviations = deviations ?? new List<Deviation>();
        }

        public int OpenCount() => _counter;

        public BigInteger Open(AuthSV x, string label = "")
        {
            int idx = _counter++;
            if (x.ExtraMac.Length != _ctx.ExtraKeys.Count) throw new ArgumentException("open: value and MAC context disagree on the key count");
            var valueShares = (BigInteger[])x.Value.Clone();
            var macShares = new BigInteger[1 + x.ExtraMac.Length][];
            macShares[0] = (BigInteger[])x.Mac.Clone();
            for (int l = 0; l < x.ExtraMac.Length; l++) macShares[l + 1] = (BigInteger[])x.ExtraMac[l].Clone();
            foreach (var d in _deviations)
            {
                if (d.OpenIndex != idx) continue;
                if (d.Party < 0 || d.Party >= _ctx.N) throw new ArgumentException("Deviation.party out of range");
                if (d.ValueDelta != null) valueShares[d.Party] = Fadd(valueShares[d.Party], d.ValueDelta.Value);
                if (d.MacDelta != null)
                {
                    int key = d.MacKey ?? 0;
                    if (key < 0 || key >= macShares.Length) throw new ArgumentException("Deviation.macKey out of range");
                    macShares[key][d.Party] = Fadd(macShares[key][d.Party], d.MacDelta.Value);
                }
            }
            var value = BigInteger.Zero;
            foreach (var s in valueShares) value = Fadd(value, s);
            _opened.Add(new OpenedValue(value, macShares, label));
            return value;
        }

        /// <summary>Batched MAC-check over every partial open so far; throws <see cref="MacCheckAbort"/> on any inconsistency.</summary>
        public void MacCheck(IFieldSource rng)
        {
            if (_opened.Count == 0) return;
            var keys = MacKeysOf(_ctx);
            var challenges = new BigInteger[keys.Count][];
            for (int l = 0; l < keys.Count; l++)
            {
                challenges[l] = new BigInteger[_opened.Count];
                for (int j = 0; j < _opened.Count; j++) challenges[l][j] = rng.Next();
            }
            var alphas = new BigInteger[keys.Count][];
            for (int l = 0; l < keys.Count; l++) alphas[l] = keys[l].AlphaShares;
            var sigma = MacResiduals(PRIME, alphas, _opened, challenges);

            for (int l = 0; l < sigma.Length; l++)
            {
                var nonces = new BigInteger[sigma[l].Length];
                for (int i = 0; i < nonces.Length; i++) nonces[i] = rng.Next();
                var commitments = new string[nonces.Length];
                for (int i = 0; i < nonces.Length; i++) commitments[i] = Commit(sigma[l][i], nonces[i]);
                for (int i = 0; i < commitments.Length; i++)
                    if (Commit(sigma[l][i], nonces[i]) != commitments[i])
                        throw new MacCheckAbort("MAC-check: commitment from party " + i + " did not open consistently");
            }
            for (int l = 0; l < sigma.Length; l++)
            {
                var residual = BigInteger.Zero;
                foreach (var s in sigma[l]) residual = Fadd(residual, s);
                if (!residual.IsZero)
                    throw new MacCheckAbort("MAC-check FAILED (key " + l + "): residual " + residual + " != 0 — an actively-malicious party was detected; aborting with no output");
            }
        }
    }

    /// <summary>Authenticated Beaver multiplication consuming <paramref name="triple"/>; the d and e openings are recorded for the MAC-check.</summary>
    public static AuthSV BeaverMulAuth(AuthSV x, AuthSV y, AuthTriple triple, MacContext ctx, SpdzEngine engine, string label)
    {
        RequireSame(x, triple.A);
        RequireSame(x, triple.B);
        RequireSame(x, triple.C);
        RequireSame(x, y);
        var d = engine.Open(SubAuth(x, triple.A), label + ":d");
        var e = engine.Open(SubAuth(y, triple.B), label + ":e");
        var z = AddAuth(triple.C, AddAuth(ScaleAuth(triple.B, d), ScaleAuth(triple.A, e)));
        return AddPublicAuth(z, Fmul(d, e), ctx);
    }

    public static BigInteger AuthValue(AuthSV x)
    {
        var a = BigInteger.Zero;
        foreach (var s in x.Value) a = Fadd(a, s);
        return a;
    }

    /// <summary>SHA-256 binding commitment to a field element under a nonce.</summary>
    internal static string Commit(BigInteger value, BigInteger nonce) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Hex(value) + ":" + Hex(nonce)))).ToLowerInvariant();

    static void RequireSame(AuthSV x, AuthSV y)
    {
        if (x.Value.Length != y.Value.Length || x.Mac.Length != y.Mac.Length)
            throw new ArgumentException("authenticated shared values must have the same party count");
        if (x.ExtraMac.Length != y.ExtraMac.Length) throw new ArgumentException("authenticated shared values must carry the same number of MAC keys");
        for (int l = 0; l < x.ExtraMac.Length; l++)
            if (x.ExtraMac[l].Length != y.ExtraMac[l].Length) throw new ArgumentException("authenticated shared values must have the same party count");
    }
}
