using System.Numerics;
using static AtlasPca.Mpc.Sharing;

namespace AtlasPca.Mpc;

/// <summary>
/// The simulated multi-party runner: all N parties in one process, exchanging shares and Beaver openings through inspectable structures.
/// <see cref="ComposeSecure"/> computes exactly <see cref="Compose.ComposeClear"/> under MPC.
/// </summary>
public static class Runner
{
    const int T_M = 3;

    /// <summary>The full additive sharing of one party's secret bit (test inspection only).</summary>
    public sealed record SharingRecord(string Label, int Party, BigInteger Secret, BigInteger[] Shares);

    /// <summary>One party's complete view (a semi-honest corruption of that party).</summary>
    public sealed record PartyView(int Party, List<BigInteger> HeldShares, List<Beaver.OpenedMsg> Opened, Compose.ComposedDecision Output);

    public sealed record MpcResult(Compose.ComposedDecision Composed, int Parties, int Q, List<Beaver.OpenedMsg> Opened, List<SharingRecord> Sharings,
        List<PartyView> Views, int Multiplications);

    /// <summary>Composes under MPC. <paramref name="seed"/> null means CSPRNG sharing randomness; a seed is for reproducible tests only.</summary>
    public static MpcResult ComposeSecure(IReadOnlyList<Party.DecisionVector?> vectors, int? Qopt, BigInteger? seed)
    {
        int n = vectors.Count;
        if (n == 0) throw new ArgumentException("composeSecure: no parties (fail closed)");
        int Q = Qopt ?? Party.DEFAULT_Q;
        Compose.AssertDecisionVectors(vectors, Q);
        Field.IFieldSource rng = seed is null ? new Field.SecureFieldRng() : new Field.FieldRng(seed.Value);

        var opened = new List<Beaver.OpenedMsg>();
        var sharings = new List<SharingRecord>();
        int mults = 0;

        BigInteger[] ShareBit(int bit, string label, int party)
        {
            var s = Share(new BigInteger(bit), n, rng);
            sharings.Add(new SharingRecord(label, party, new BigInteger(bit), (BigInteger[])s.Clone()));
            return s;
        }
        BigInteger[] And(List<BigInteger[]> bits)
        {
            if (bits.Count == 0) return ShareConstant(BigInteger.One, n);
            var acc = bits[0];
            for (int i = 1; i < bits.Count; i++)
            {
                acc = Beaver.BeaverMul(acc, bits[i], Beaver.GenTriple(n, rng), opened);
                mults++;
            }
            return acc;
        }
        BigInteger[] Or(List<BigInteger[]> bits)
        {
            if (bits.Count == 0) return ShareConstant(BigInteger.Zero, n);
            var prod = NotBitSV(bits[0]);
            for (int i = 1; i < bits.Count; i++)
            {
                prod = Beaver.BeaverMul(prod, NotBitSV(bits[i]), Beaver.GenTriple(n, rng), opened);
                mults++;
            }
            return NotBitSV(prod);
        }

        var allowBits = new List<BigInteger[]>();
        for (int p = 0; p < n; p++) allowBits.Add(ShareBit(vectors[p]!.Allow, "p" + p + ".allow", p));
        int allow = Reconstruct(And(allowBits)).IsOne ? 1 : 0;

        var tTherm = new int[n][];
        for (int p = 0; p < n; p++) tTherm[p] = Thermometer.ThermometerEncode(vectors[p]!.T, T_M);
        var tGe = new int[T_M];
        for (int k = 0; k < T_M; k++)
        {
            var bitsAtK = new List<BigInteger[]>();
            for (int p = 0; p < n; p++) bitsAtK.Add(ShareBit(tTherm[p][k], "p" + p + ".t.ge" + (k + 1), p));
            tGe[k] = Reconstruct(Or(bitsAtK)).IsOne ? 1 : 0;
        }
        int t = Math.Min(3, Math.Max(1, Thermometer.ThermometerDecode(tGe)));

        var rTherm = new int[n][];
        for (int p = 0; p < n; p++) rTherm[p] = Thermometer.ThermometerEncode(vectors[p]!.RQuant, Q);
        var rGe = new int[Q];
        for (int k = 0; k < Q; k++)
        {
            var bitsAtK = new List<BigInteger[]>();
            for (int p = 0; p < n; p++) bitsAtK.Add(ShareBit(rTherm[p][k], "p" + p + ".r.ge" + (k + 1), p));
            rGe[k] = Reconstruct(Or(bitsAtK)).IsOne ? 1 : 0;
        }
        int rQuant = Thermometer.ThermometerDecode(rGe);

        var composed = new Compose.ComposedDecision(allow, t, rQuant);
        var views = new List<PartyView>();
        for (int p = 0; p < n; p++)
        {
            var held = new List<BigInteger>();
            foreach (var s in sharings) held.Add(s.Shares[p]);
            views.Add(new PartyView(p, held, opened, composed));
        }
        return new MpcResult(composed, n, Q, opened, sharings, views, mults);
    }
}
