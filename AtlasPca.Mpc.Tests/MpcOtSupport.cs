using System.Numerics;
using AtlasPca.Corpus.Tests;
using AtlasPca.Mpc;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using static AtlasPca.Mpc.Tests.MpcSupport;

namespace AtlasPca.Mpc.Tests;

/// <summary>Argument decoding, result encoding and tamper selectors of the oblivious-transfer differential tests.</summary>
static class MpcOtSupport
{
    /// <summary>A plain base64url string argument.</summary>
    public static byte[] Raw(object? o) => Pca.B64uDecode(o) ?? throw new ArgumentException("bad base64url");

    public static int[] Words(object? o) => ((L)o!).Select(x => unchecked((int)(long)Dbl(x))).ToArray();

    public static L W(int[] w) => w.Select(x => (object?)(long)(uint)x).ToList();

    public static Ec.Point P(object? o)
    {
        var l = (L)o!;
        return new Ec.Point(B(l[0]), B(l[1]), B(l[2]), B(l[3]));
    }

    public static D Aff(Ec.Point p)
    {
        var xy = Ec.ToAffine(p);
        return M("x", S(xy[0]), "y", S(xy[1]));
    }

    public static L BL(byte[][] a) => a.Select(x => (object?)x).ToList();

    public static L Pairs(byte[][][] a) => a.Select(p => (object?)new L { p[0], p[1] }).ToList();

    public static byte[][][] ToPairs(object? o) =>
        ((L)o!).Select(p => new[] { Base.Bytes(((L)p!)[0]), Base.Bytes(((L)p!)[1]) }).ToArray();

    public static Ot.IOtRandom Orng(object? seed) => Ot.OtRandom(Ot.SplitMix64(B(seed)));

    static readonly Ec.Point Order2 = new(BigInteger.Zero, Ec.Q - 1, BigInteger.One, BigInteger.Zero);

    public static byte[] Flip(byte[] b, int mask)
    {
        var o = (byte[])b.Clone();
        for (int i = 0; i < o.Length; i++) o[i] ^= (byte)mask;
        return o;
    }

    public static Ot.BaseOtTamper? Tamper(string name)
    {
        var t = new Ot.BaseOtTamper();
        switch (name)
        {
            case "none": return null;
            case "S_identity": t.TamperS = p => Ec.IDENTITY; break;
            case "S_order2": t.TamperS = p => Order2; break;
            case "S_other": t.TamperS = p => Ec.AddPoints(p, Ec.BASE); break;
            case "proof_z": t.TamperProof = p => new Ec.SchnorrProof(p.U, (p.Z + 1) % Ec.L); break;
            case "proof_U": t.TamperProof = p => new Ec.SchnorrProof(Ec.AddPoints(p.U, Ec.BASE), p.Z); break;
            case "R0_identity": t.TamperR = r => r[0] = Ec.IDENTITY; break;
            case "R1_order2": t.TamperR = r => { if (r.Length > 1) r[1] = Order2; }; break;
            case "R_swap": t.TamperR = r => { if (r.Length > 1) (r[0], r[1]) = (r[1], r[0]); }; break;
            case "ct_flip": t.TamperCiphertext = ct => ct[0][0] = Flip(ct[0][0], 1); break;
            case "ct_flip1": t.TamperCiphertext = ct => ct[^1][1] = Flip(ct[^1][1], 0x80); break;
            default: throw new ArgumentException(name);
        }
        return t;
    }

    public static long Idx(object? o)
    {
        var d = Dbl(o);
        if (d != Math.Round(d)) throw new ArgumentException("not an integer");
        return (long)d;
    }

    public static Ot.BaseOtBinding Binding(object? sess, object? a, object? b, object? round) => new(Raw(sess), Idx(a), Idx(b), (string)round!);

    public static KemOt.KemMalTamper? KemTamper(string? tn)
    {
        var t = new KemOt.KemMalTamper();
        if (tn == "badKey") t.TamperOpenedKeys = pk => { var x = pk[0][0]; pk[0][0] = pk[0][1]; pk[0][1] = x; };
        else if (tn == "badSid") t.TamperReceiverSid = s => Flip(s, 1);
        else return null;
        return t;
    }

    public static byte[] Fill(int n, int v)
    {
        var b = new byte[n];
        Array.Fill(b, (byte)v);
        return b;
    }

    static D Decision(Compose.ComposedDecision d) => M("allow", d.Allow, "t", d.T, "rQuant", d.RQuant);

    /// <summary>Decodes a composeSecureMalicious config object (Q, seed, deviations, insecureTrustedDealer, dealer).</summary>
    public static SpdzRunner.MaliciousMpcConfig Config(D m)
    {
        var c = new SpdzRunner.MaliciousMpcConfig();
        if (m.GetValueOrDefault("Q") != null) c.Q = I(m["Q"]);
        if (m.GetValueOrDefault("seed") != null) c.Seed = B(m["seed"]);
        if (m.GetValueOrDefault("deviations") != null) c.Deviations = Devs(m["deviations"]);
        c.InsecureTrustedDealer = m.GetValueOrDefault("insecureTrustedDealer") is true;
        if (m.GetValueOrDefault("dealer") != null)
        {
            var d = Map(m["dealer"]);
            c.Dealer = new SpdzRunner.DealerOptions();
            if (d.GetValueOrDefault("verifyTriples") != null) c.Dealer.VerifyTriples = (bool)d["verifyTriples"]!;
            if (d.GetValueOrDefault("partners") != null) c.Dealer.Partners = I(d["partners"]);
            c.Dealer.Fault = Fault(d.GetValueOrDefault("fault"));
        }
        return c;
    }

    public static D Summary(SpdzRunner.MaliciousMpcResult r) =>
        M("composed", Decision(r.Composed), "parties", r.Parties, "Q", r.Q, "opens", r.Opens, "multiplications", r.Multiplications, "offlineMode", r.OfflineMode,
            "triplesVerified", r.TriplesVerified, "macChecked", r.MacChecked);
}
