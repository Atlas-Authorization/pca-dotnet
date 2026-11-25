using System.Numerics;

namespace AtlasPca.Mpc;

/// <summary>
/// The malicious-secure (SPDZ) runner: the same composition as <see cref="Runner.ComposeSecure"/>, but every shared value carries a MAC and
/// nothing is accepted as output until the batched MAC-check passes (correct result or <see cref="Spdz.MacCheckAbort"/>). Offline phase: a
/// no-dealer provider (the default, OT-based), or an explicit trusted dealer with sacrifice-certified triples.
/// </summary>
public static class SpdzRunner
{
    /// <summary>Trusted-dealer options (honoured only with InsecureTrustedDealer). Null VerifyTriples means true.</summary>
    public sealed class DealerOptions
    {
        public bool? VerifyTriples;
        public int? Partners;
        public Spdz.DealerFault? Fault;
    }

    public sealed class MaliciousMpcConfig
    {
        public int? Q;
        public BigInteger? Seed;
        public List<Spdz.Deviation>? Deviations;
        public IOfflineProvider? Offline;
        public bool InsecureTrustedDealer;
        public DealerOptions? Dealer;
    }

    public sealed record MaliciousMpcResult(Compose.ComposedDecision Composed, int Parties, int Q, int Opens, int Multiplications, string OfflineMode,
        bool TriplesVerified, bool MacChecked);

    const int T_M = 3;

    public static MaliciousMpcResult ComposeSecureMalicious(IReadOnlyList<Party.DecisionVector?> vectors, MaliciousMpcConfig? cfg)
    {
        var c = cfg ?? new MaliciousMpcConfig();
        int n = vectors.Count;
        if (n == 0) throw new ArgumentException("composeSecureMalicious: no parties (fail closed)");
        int Q = c.Q ?? Party.DEFAULT_Q;
        Compose.AssertDecisionVectors(vectors, Q);
        Field.IFieldSource rng = c.Seed is null ? new Field.SecureFieldRng() : new Field.FieldRng(c.Seed.Value);

        if (c.Offline != null && c.InsecureTrustedDealer)
            throw new InvalidOperationException("composeSecureMalicious: offline and insecureTrustedDealer are mutually exclusive (fail closed)");
        if (c.Dealer != null && !c.InsecureTrustedDealer && c.Offline == null)
            throw new InvalidOperationException("composeSecureMalicious: dealer options require insecureTrustedDealer: true (fail closed)");
        var offline = c.Offline ?? (c.InsecureTrustedDealer ? null : Mascot.MakeNoDealerOffline(n, c.Seed));
        if (offline != null && offline.N() != n)
            throw new InvalidOperationException("composeSecureMalicious: offline provider party count != number of vectors");
        var ctx = offline != null ? offline.MacContext() : Spdz.SetupMac(n, rng);
        var engine = new Spdz.SpdzEngine(ctx, c.Deviations ?? new List<Spdz.Deviation>());
        int mults = 0;
        bool verify = c.Dealer == null || c.Dealer.VerifyTriples == null || c.Dealer.VerifyTriples.Value;

        Spdz.AuthTriple NextTriple()
        {
            if (offline != null) return offline.GenAuthTriple();
            if (!verify)
                return c.Dealer != null && c.Dealer.Fault != null
                    ? Spdz.GenTripleWithPartners(ctx, rng, 1, c.Dealer.Fault).Keep : Spdz.GenAuthTriple(ctx, rng);
            int partners = c.Dealer?.Partners ?? Spdz.SACRIFICE_PARTNERS;
            var dealt = Spdz.GenTripleWithPartners(ctx, rng, partners, c.Dealer?.Fault);
            return Spdz.SacrificeVerify(new List<Spdz.TripleWithPartners> { dealt }, ctx, rng, new List<Spdz.Deviation>())[0];
        }
        Spdz.AuthSV ShareBit(int bit, int owner) =>
            offline != null ? offline.AuthInput(new BigInteger(bit), owner) : Spdz.AuthShare(new BigInteger(bit), ctx, rng);
        Spdz.AuthSV And(List<Spdz.AuthSV> bits)
        {
            if (bits.Count == 0) return Spdz.AuthConstant(BigInteger.One, ctx);
            var acc = bits[0];
            for (int i = 1; i < bits.Count; i++)
            {
                acc = Spdz.BeaverMulAuth(acc, bits[i], NextTriple(), ctx, engine, "and" + i);
                mults++;
            }
            return acc;
        }
        Spdz.AuthSV Or(List<Spdz.AuthSV> bits)
        {
            if (bits.Count == 0) return Spdz.AuthConstant(BigInteger.Zero, ctx);
            var prod = Spdz.NotBitAuth(bits[0], ctx);
            for (int i = 1; i < bits.Count; i++)
            {
                prod = Spdz.BeaverMulAuth(prod, Spdz.NotBitAuth(bits[i], ctx), NextTriple(), ctx, engine, "or" + i);
                mults++;
            }
            return Spdz.NotBitAuth(prod, ctx);
        }

        var allowBits = new List<Spdz.AuthSV>();
        for (int p = 0; p < n; p++) allowBits.Add(ShareBit(vectors[p]!.Allow, p));
        var allowSV = And(allowBits);

        var tTherm = new int[n][];
        for (int p = 0; p < n; p++) tTherm[p] = Thermometer.ThermometerEncode(vectors[p]!.T, T_M);
        var tGe = new List<Spdz.AuthSV>();
        for (int k = 0; k < T_M; k++)
        {
            var bits = new List<Spdz.AuthSV>();
            for (int p = 0; p < n; p++) bits.Add(ShareBit(tTherm[p][k], p));
            tGe.Add(Or(bits));
        }
        var rTherm = new int[n][];
        for (int p = 0; p < n; p++) rTherm[p] = Thermometer.ThermometerEncode(vectors[p]!.RQuant, Q);
        var rGe = new List<Spdz.AuthSV>();
        for (int k = 0; k < Q; k++)
        {
            var bits = new List<Spdz.AuthSV>();
            for (int p = 0; p < n; p++) bits.Add(ShareBit(rTherm[p][k], p));
            rGe.Add(Or(bits));
        }

        var allowOpen = engine.Open(allowSV, "out:allow");
        var tOpen = new int[T_M];
        for (int k = 0; k < T_M; k++) tOpen[k] = engine.Open(tGe[k], "out:t.ge" + (k + 1)).IsOne ? 1 : 0;
        var rOpen = new int[Q];
        for (int k = 0; k < Q; k++) rOpen[k] = engine.Open(rGe[k], "out:r.ge" + (k + 1)).IsOne ? 1 : 0;

        engine.MacCheck(rng);

        int allow = allowOpen.IsOne ? 1 : 0;
        int t = Math.Min(3, Math.Max(1, Thermometer.ThermometerDecode(tOpen)));
        int rQuant = Thermometer.ThermometerDecode(rOpen);
        return new MaliciousMpcResult(new Compose.ComposedDecision(allow, t, rQuant), n, Q, engine.OpenCount(), mults,
            offline != null ? "no-dealer" : "trusted-dealer", offline != null || verify, true);
    }
}
