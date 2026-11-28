using System.Numerics;
using AtlasPca.Corpus.Tests;
using AtlasPca.Mpc;
using Xunit;
using static AtlasPca.Mpc.Tests.MpcSupport;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Mpc.Tests;

/// <summary>Differential tests of the MPC deterministic layer against the TypeScript reference corpus (every draw from a seeded SplitMix64).</summary>
public class MpcDiffTests
{
    const string Mod = "ref-mpc";

    static L Opened(List<Beaver.OpenedMsg> l) => l.Select(m => (object?)M("label", m.Label, "value", S(m.Value), "shares", Ls(m.Shares))).ToList();

    static D Decision(Compose.ComposedDecision d) => M("allow", d.Allow, "t", d.T, "rQuant", d.RQuant);

    static D EncShare(Enc.EncShare e) => M("value", S(e.Value), "bits", Li(e.Bits));

    [Fact] public void Field()
    {
        Base.Check(Mod, "mod", a => S(Mpc.Field.Mod(B(a[0]))));
        Base.Check(Mod, "fneg", a => S(Mpc.Field.Fneg(B(a[0]))));
        Base.Check(Mod, "fadd", a => S(Mpc.Field.Fadd(B(a[0]), B(a[1]))));
        Base.Check(Mod, "fsub", a => S(Mpc.Field.Fsub(B(a[0]), B(a[1]))));
        Base.Check(Mod, "fmul", a => S(Mpc.Field.Fmul(B(a[0]), B(a[1]))));
        Base.Check(Mod, "fieldRng", a => { var g = Rng(a[0]); var o = new L(); for (int i = 0; i < I(a[1]); i++) o.Add(S(g.Next())); return o; });
        Base.Check(Mod, "fieldRngDefault", a => { var g = new Mpc.Field.FieldRng(); var o = new L(); for (int i = 0; i < I(a[0]); i++) o.Add(S(g.Next())); return o; });
    }

    [Fact] public void SharingOps()
    {
        Base.Check(Mod, "share", a => Ls(Sharing.Share(B(a[0]), I(a[1]), Rng(a[2]))));
        Base.Check(Mod, "reconstruct", a => S(Sharing.Reconstruct(BA(a[0]))));
        Base.Check(Mod, "shareConstant", a => Ls(Sharing.ShareConstant(B(a[0]), I(a[1]))));
        Base.Check(Mod, "sv", a =>
        {
            var op = (string)a[0]!;
            var x = BA(a[1]);
            return op switch
            {
                "add" => Ls(Sharing.AddSV(x, BA(a[2]))),
                "sub" => Ls(Sharing.SubSV(x, BA(a[2]))),
                "neg" => Ls(Sharing.NegSV(x)),
                "scale" => Ls(Sharing.ScaleSV(x, B(a[2]))),
                "addPublic" => Ls(Sharing.AddPublicSV(x, B(a[2]))),
                "notBit" => Ls(Sharing.NotBitSV(x)),
                _ => throw new ArgumentException(op),
            };
        });
    }

    [Fact] public void Gf()
    {
        Base.Check(Mod, "gf", a =>
        {
            var op = (string)a[0]!;
            var x = B(a[1]);
            return op switch
            {
                "add" => S(Gf128.Add(x, B(a[2]))),
                "mul" => S(Gf128.Mul(x, B(a[2]))),
                "mulX" => S(Gf128.MulX(x)),
                "mulByXi" => S(Gf128.MulByXi(x, I(a[2]))),
                _ => throw new ArgumentException(op),
            };
        });
    }

    [Fact] public void EncOps()
    {
        Base.Check(Mod, "encBits", a => Enc.EncBits(I(a[0])));
        Base.Check(Mod, "makeGadget", a => Ls(Enc.MakeGadget(I(a[0]), Rng(a[1]), a[2] is true)));
        Base.Check(Mod, "plainShare", a => EncShare(Enc.PlainShare(B(a[0]))));
        Base.Check(Mod, "plainGadget", a => Ls(Enc.PlainGadget()));
        Base.Check(Mod, "randomBits", a => Li(Enc.RandomBits(I(a[0]), Rng(a[1]))));
        Base.Check(Mod, "sampleEnc", a =>
        {
            var g = Rng(a[1]);
            var gad = Enc.MakeGadget(I(a[0]), g, true);
            var e = Enc.SampleEnc(gad, g);
            return M("gadget", Ls(gad), "e", EncShare(e));
        });
        Base.Check(Mod, "encValue", a => S(Enc.EncValue(BA(a[0]), IA(a[1]))));
    }

    [Fact] public void BeaverOps()
    {
        Base.Check(Mod, "genTriple", a => { var t = Beaver.GenTriple(I(a[0]), Rng(a[1])); return M("a", Ls(t.A), "b", Ls(t.B), "c", Ls(t.C)); });
        Base.Check(Mod, "beaverMul", a =>
        {
            var op = new List<Beaver.OpenedMsg>();
            var z = Beaver.BeaverMul(BA(a[0]), BA(a[1]), new Beaver.Triple(BA(a[2]), BA(a[3]), BA(a[4])), op);
            return M("z", Ls(z), "opened", Opened(op));
        });
    }

    [Fact] public void Composition()
    {
        Base.Check(Mod, "thermometerEncode", a => Li(Thermometer.ThermometerEncode(Dbl(a[0]), I(a[1]))));
        Base.Check(Mod, "thermometerDecode", a => Thermometer.ThermometerDecode(((L)a[0]!).Select(b => b is Num n && Dbl(n) == 1.0 ? 1 : 0).ToArray()));
        Base.Check(Mod, "quantizeR", a => Party.QuantizeR(Dbl(a[0]), I(a[1])));
        Base.Check(Mod, "composeClear", a => Decision(Compose.ComposeClear(Vectors(a[0]), I(a[1]))));
        Base.Check(Mod, "assertDecisionVectors", a => { Compose.AssertDecisionVectors(Vectors(a[0]), I(a[1])); return true; });
        Base.Check(Mod, "composeSecure", a =>
        {
            var r = Runner.ComposeSecure(Vectors(a[0]), I(a[1]), B(a[2]));
            var sh = r.Sharings.Select(s => (object?)M("label", s.Label, "party", s.Party, "secret", S(s.Secret), "shares", Ls(s.Shares))).ToList();
            var held = r.Views[0].HeldShares.Select(h => (object?)S(h)).ToList();
            return M("composed", Decision(r.Composed), "parties", r.Parties, "Q", r.Q, "multiplications", r.Multiplications, "opened", Opened(r.Opened),
                "sharings", sh, "heldShares0", held, "viewsLen", r.Views.Count);
        });
    }

    [Fact] public void SpdzAuthShares()
    {
        Base.Check(Mod, "setupMac", a => Ctx(Spdz.SetupMac(I(a[0]), Rng(a[1]), I(a[2]))));
        Base.Check(Mod, "macSoundnessBits", a => a.Count == 1 ? Spdz.MacSoundnessBits(I(a[0])) : Spdz.MacSoundnessBits(I(a[0]), B(a[1])));
        Base.Check(Mod, "authShare", a =>
        {
            var g = Rng(a[1]);
            var c = Spdz.SetupMac(I(a[0]), g);
            return M("ctx", Ctx(c), "sv", AuthSv(Spdz.AuthShare(B(a[2]), c, g)));
        });
        Base.Check(Mod, "authConstant", a => AuthSv(Spdz.AuthConstant(B(a[2]), Spdz.SetupMac(I(a[0]), Rng(a[1])))));
        Base.Check(Mod, "authOp", a =>
        {
            var op = (string)a[0]!;
            var g = Rng(a[2]);
            var c = Spdz.SetupMac(I(a[1]), g);
            var x = Spdz.AuthShare(B(a[3]), c, g);
            var y = Spdz.AuthShare(B(a[4]), c, g);
            var k = B(a[5]);
            if (op == "open") return M("val", S(Spdz.AuthValue(x)));
            var res = op switch
            {
                "add" => Spdz.AddAuth(x, y),
                "sub" => Spdz.SubAuth(x, y),
                "neg" => Spdz.NegAuth(x),
                "scale" => Spdz.ScaleAuth(x, k),
                "addPublic" => Spdz.AddPublicAuth(x, k, c),
                "notBit" => Spdz.NotBitAuth(x, c),
                _ => throw new ArgumentException(op),
            };
            var val = Spdz.AuthValue(res);
            var rows = new List<BigInteger[]> { res.Mac };
            rows.AddRange(res.ExtraMac);
            bool ok = true;
            var keys = Spdz.MacKeysOf(c);
            for (int l = 0; l < rows.Count; l++)
            {
                var sum = BigInteger.Zero;
                foreach (var m in rows[l]) sum = Mpc.Field.Fadd(sum, m);
                ok &= sum == Mpc.Field.Fmul(keys[l].Alpha, val);
            }
            return M("res", AuthSv(res), "val", S(val), "okMac", ok);
        });
        Base.Check(Mod, "genAuthTriple", a =>
        {
            var g = Rng(a[1]);
            return Triple(Spdz.GenAuthTriple(Spdz.SetupMac(I(a[0]), g), g));
        });
    }

    static D Partnered(Spdz.TripleWithPartners t) => M("keep", Triple(t.Keep), "partners", t.Partners.Select(p => (object?)Triple(p)).ToList());

    [Fact] public void SpdzTriples()
    {
        Base.Check(Mod, "genTripleWithPartners", a =>
        {
            if (a.Count == 2)
            {
                var g1 = Rng(a[1]);
                return Partnered(Spdz.GenTripleWithPartners(Spdz.SetupMac(I(a[0]), g1), g1));
            }
            var g = Rng(a[0]);
            return Partnered(Spdz.GenTripleWithPartners(Spdz.SetupMac(2, g), g, I(a[1]), Fault(a[2])));
        });
        Base.Check(Mod, "sacrifice", a =>
        {
            var g = Rng(a[1]);
            var c = Spdz.SetupMac(I(a[0]), g);
            var f = Fault(a[4]);
            var batch = new List<Spdz.TripleWithPartners>();
            for (int i = 0; i < I(a[2]); i++) batch.Add(Spdz.GenTripleWithPartners(c, g, I(a[3]), i == 0 ? f : null));
            var o = Spdz.SacrificeVerify(batch, c, g, Devs(a[5])).Select(t => (object?)Triple(t)).ToList();
            return M("certified", o);
        });
    }

    [Fact] public void SpdzEngineOps()
    {
        Base.Check(Mod, "engineRun", a =>
        {
            var g = Rng(a[1]);
            var c = Spdz.SetupMac(I(a[0]), g, a.Count > 4 ? I(a[4]) : Spdz.MAC_KEYS);
            var e = new Spdz.SpdzEngine(c, Devs(a[3]));
            var outs = new L();
            var values = (L)a[2]!;
            for (int i = 0; i < values.Count; i++) outs.Add(S(e.Open(Spdz.AuthShare(B(values[i]), c, g), "v" + i)));
            e.MacCheck(g);
            return M("outs", outs, "count", e.OpenCount());
        });
        Base.Check(Mod, "macResiduals", a =>
        {
            var op = new List<Spdz.OpenedValue>();
            foreach (var o in (L)a[2]!) { var m = Map(o); op.Add(new Spdz.OpenedValue(B(m["value"]), BAA(m["macShares"]), "")); }
            return LL(Spdz.MacResiduals(B(a[0]), BAA(a[1]), op, BAA(a[3])));
        });
        Base.Check(Mod, "beaverAuth", a =>
        {
            var g = Rng(a[1]);
            var c = Spdz.SetupMac(I(a[0]), g);
            var e = new Spdz.SpdzEngine(c, Devs(a[4]));
            var x = Spdz.AuthShare(B(a[2]), c, g);
            var y = Spdz.AuthShare(B(a[3]), c, g);
            var t = Spdz.GenAuthTriple(c, g);
            var z = Spdz.BeaverMulAuth(x, y, t, c, e, "m");
            var val = Spdz.AuthValue(z);
            var o = e.Open(z, "out");
            e.MacCheck(g);
            return M("z", AuthSv(z), "val", S(val), "out", S(o), "opens", e.OpenCount());
        });
    }

    /// <summary>Decodes a composeSecureMalicious config object (Q, seed, deviations, insecureTrustedDealer, dealer).</summary>
    static SpdzRunner.MaliciousMpcConfig Config(D m)
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

    static D Summary(SpdzRunner.MaliciousMpcResult r) =>
        M("composed", Decision(r.Composed), "parties", r.Parties, "Q", r.Q, "opens", r.Opens, "multiplications", r.Multiplications, "offlineMode", r.OfflineMode,
            "triplesVerified", r.TriplesVerified, "macChecked", r.MacChecked);

    [Fact] public void MaliciousRunnerTrustedDealer() =>
        Base.Check(Mod, "composeSecureMalicious", a => Summary(SpdzRunner.ComposeSecureMalicious(Vectors(a[0]), Config(Map(a[1])))));

    [Fact] public void Covers() { Base.Covers(Mod, new[]
    {
        "mod", "fneg", "fadd", "fsub", "fmul", "fieldRng", "fieldRngDefault", "share", "reconstruct", "shareConstant", "sv", "gf", "encBits", "makeGadget",
        "plainShare", "plainGadget", "randomBits", "sampleEnc", "encValue", "genTriple", "beaverMul", "thermometerEncode", "thermometerDecode", "quantizeR",
        "composeClear", "assertDecisionVectors", "composeSecure", "setupMac", "macSoundnessBits", "authShare", "authConstant", "authOp", "genAuthTriple",
        "genTripleWithPartners", "sacrifice", "engineRun", "macResiduals", "beaverAuth", "composeSecureMalicious",
    }); Assert.Equal(1570, Base.Total(Mod)); }
}
