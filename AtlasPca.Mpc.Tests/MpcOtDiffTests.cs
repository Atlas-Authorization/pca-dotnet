using System.Numerics;
using AtlasPca.Corpus.Tests;
using AtlasPca.Mpc;
using Xunit;
using static AtlasPca.Mpc.Tests.MpcOtSupport;
using static AtlasPca.Mpc.Tests.MpcSupport;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Mpc.Tests;

/// <summary>Differential tests of the MPC oblivious-transfer stack against the TypeScript reference corpus (every draw from a seeded stream).</summary>
public class MpcOtDiffTests
{
    const string Mod = "ref-mpc-ot";

    // ---- Ed25519 group ----
    [Fact] public void GenCorpusIsPresent() => Base.RequireGenCorpus(Mod);
    [Fact] public void EcGroup()
    {
        Base.Check(Mod, "ecOp", a =>
        {
            var op = (string)a[0]!;
            switch (op)
            {
                case "mulBase": { var p = Ec.MulBase(B(a[1])); return M("p", Aff(p), "enc", Ec.EncodePoint(p), "comp", Ec.CompressPoint(p)); }
                case "mul": return Aff(Ec.Mul(B(a[1]), P(a[2])));
                case "add": return Aff(Ec.AddPoints(P(a[1]), P(a[2])));
                case "sub": return Aff(Ec.Sub(P(a[1]), P(a[2])));
                case "neg": return Aff(Ec.Neg(P(a[1])));
                case "dbl": return Aff(Ec.Dbl(P(a[1])));
                case "decompress":
                {
                    var p = Ec.DecompressPoint(Base.Bytes(a[1]));
                    return M("p", Aff(p), "onCurve", Ec.IsOnCurve(p), "identity", Ec.IsIdentity(p), "prime", Ec.HasPrimeOrder(p), "inSub", Ec.IsInSubgroup(p));
                }
                default: throw new ArgumentException(op);
            }
        });
        Base.Check(Mod, "ecValidate", a =>
        {
            var p = P(a[0]);
            return M("onCurve", Ec.IsOnCurve(p), "identity", Ec.IsIdentity(p), "prime", Ec.HasPrimeOrder(p), "inSubgroup", Ec.IsInSubgroup(p));
        });
        Base.Check(Mod, "ecAssert", a => { Ec.AssertInSubgroup(P(a[0]), "p"); return true; });
        Base.Check(Mod, "schnorr", a =>
        {
            BigInteger y = B(a[0]), nonce = B(a[1]);
            var ctx = Raw(a[2]);
            var S0 = Ec.MulBase(y);
            var proof = Ec.SchnorrProve(y, S0, () => nonce, ctx);
            var other = System.Text.Encoding.UTF8.GetBytes("other-ctx");
            var forged = new Ec.SchnorrProof(proof.U, (proof.Z + 1) % Ec.L);
            var oor = new Ec.SchnorrProof(proof.U, Ec.L);
            return M("S", Aff(S0), "U", Aff(proof.U), "z", S(proof.Z), "ok", Ec.SchnorrVerify(S0, proof, ctx), "badCtx", Ec.SchnorrVerify(S0, proof, other),
                "forged", Ec.SchnorrVerify(S0, forged, ctx), "oor", Ec.SchnorrVerify(S0, oor, ctx), "wrongS", Ec.SchnorrVerify(Ec.MulBase(y + 1), proof, ctx),
                "identityS", Ec.SchnorrVerify(Ec.IDENTITY, proof, ctx));
        });
    }

    // ---- word-array kernels ----
    [Fact] public void Kernels()
    {
        Base.Check(Mod, "prg", a => W(Otx.PrgColumn(Raw(a[0]), (long)Dbl(a[1]), I(a[2]))));
        Base.Check(Mod, "maskTail", a => { var w = Words(a[0]); Otx.MaskTail(w, I(a[1])); return W(w); });
        Base.Check(Mod, "transpose32", a => { var w = Words(a[0]); Otx.Transpose32(w, 0); return W(w); });
        Base.Check(Mod, "transposeCols", a => W(Otx.TransposeCols(Words(a[0]), I(a[1]), I(a[2]))));
        Base.Check(Mod, "gfMulX", a => { var w = Words(a[0]); Otx.GfMulX(w); return W(w); });
        Base.Check(Mod, "gfXorInto", a => { var w = Words(a[0]); Otx.GfXorInto(w, Words(a[1]), 0); return W(w); });
        Base.Check(Mod, "gfBig", a => { var w = Words(a[0]); var v = Otx.GfToBig(w); return M("big", S(v), "back", W(Otx.GfFromBig(v))); });
        Base.Check(Mod, "accumColumn", a => { var c = Words(a[0]); var acc = new int[4]; Otx.AccumColumn(c, 0, c.Length, Words(a[1]), acc); return W(acc); });
        Base.Check(Mod, "kosCombine", a => W(Otx.KosCombine(Words(a[0]), I(a[1]), Words(a[2]))));
        Base.Check(Mod, "tmmo", a => W(Otx.TmmoCrh(Words(a[0]), I(a[1]), new Otx.OtTweak((long)Dbl(a[2]), Words(a[3])))));
        Base.Check(Mod, "tweakDomain", a => W(Otx.OtTweakDomain(Raw(a[0]))));
        Base.Check(Mod, "bigBytes", a => Otx.BigToBytes(B(a[0]), I(a[1])));
        Base.Check(Mod, "bytesBig", a => S(Otx.BytesToBig(Raw(a[0]))));
        Base.Check(Mod, "word64", a => S(Otx.Word64(Words(a[0]), I(a[1]))));
    }

    // ---- base OT, KOS extension ----
    [Fact] public void BaseOtReplay()
    {
        Base.Check(Mod, "bindingBytes", a => Ot.BindingBytes(Binding(a[0], a[1], a[2], a[3])));
        Base.Check(Mod, "baseOtKdf", a =>
        {
            var b0 = Ot.RandomBinding(Orng("4242"), "base-ot");
            var r = new[] { Ec.MulBase(5), Ec.MulBase(6) };
            var th = Ot.BaseOtTranscriptHash(b0, Ec.MulBase(3), r);
            return M("th", th, "k", Ot.BaseOtKdf(th, I(a[0]), r[0], Ec.MulBase(9)));
        });
        Base.Check(Mod, "randomOt", a =>
        {
            var r = Ot.MalBaseRandomOT(IA(a[0]), Orng(a[1]), Tamper((string)a[2]!), null);
            var rl = r.R.Select(p => (object?)Aff(p)).ToList();
            return M("S", Aff(r.S), "U", Aff(r.Proof.U), "z", S(r.Proof.Z), "R", rl, "senderPads", Pairs(r.SenderPads), "recvPads", BL(r.RecvPads));
        });
        Base.Check(Mod, "baseOt", a =>
        {
            var res = Ot.BaseOT(ToPairs(a[0]), IA(a[1]), Orng(a[2]), Tamper((string)a[3]!), null);
            var t = res.Transcript;
            var rl = t.R.Select(p => (object?)Aff(p)).ToList();
            return M("received", BL(res.Received), "S", Aff(t.S), "U", Aff(t.Proof.U), "z", S(t.Proof.Z), "R", rl, "ct", Pairs(t.Ct), "com", Pairs(t.Com));
        });
    }

    [Fact] public void Extension()
    {
        Base.Check(Mod, "channel", a =>
        {
            var ch = new Ot.OtChannel(Orng(a[3]));
            var tn = (string?)a[5];
            if (tn == "flip00") ch.TamperU = (u, round) => u[0] = u[0] ^ BigInteger.One;
            else if (tn == "flipLast") ch.TamperU = (u, round) => u[127] = u[127] ^ (BigInteger.One << 5);
            else if (tn == "oversize") ch.TamperU = (u, round) => u[3] = u[3] | (BigInteger.One << 5000);
            else if (tn == "negative") ch.TamperU = (u, round) => u[3] = BigInteger.MinusOne;
            else if (tn == "round2flip") ch.TamperU = (u, round) => { if (round == 1) u[10] = u[10] ^ new BigInteger(2); };
            var outs = new L();
            for (int k = 0; k < I(a[4]); k++)
            {
                var e = ch.Extend(IA(a[0]), BA(a[1]), BA(a[2]));
                outs.Add(M("received", Ls(e.Received), "uMatrix", Ls(e.UMatrix)));
            }
            object? bs = ch.BaseTranscript == null ? null : M("S", Aff(ch.BaseTranscript.S), "R", ch.BaseTranscript.R.Length);
            return M("selector", S(ch.Selector()), "outs", outs, "base", bs);
        });
        Base.Check(Mod, "kosChi", a =>
        {
            var b = Raw(a[0]);
            var u = BA(a[2]);
            int mExt = I(a[3]);
            var chi = Ot.KosChallenges(b, I(a[1]), u, mExt);
            return M("w", W(Ot.KosChiWords(b, I(a[1]), u, mExt, null)), "chi", Ls(chi));
        });
    }

    // ---- ML-KEM base OT, hybrid ----
    [Fact] public void KemAndHybrid()
    {
        Base.Check(Mod, "kemOt", a =>
        {
            var fn = (string)a[0]!;
            var g = Orng(a[3]);
            var choices = IA(a[2]);
            var tn = (string?)a[4];
            if (fn == "kemBaseOT")
            {
                var r = KemOt.KemBaseOT(ToPairs(a[1]), choices, g);
                var t = r.Transcript;
                return M("received", BL(r.Received), "transcript", M("publicKeys", Pairs(t.PublicKeys), "ciphertexts", Pairs(t.Ciphertexts), "encrypted", Pairs(t.Encrypted)));
            }
            if (fn == "kemBaseOtMal")
            {
                var r = KemOt.KemBaseOtMal(ToPairs(a[1]), choices, g, KemTamper(tn));
                var t = r.Transcript;
                return M("received", BL(r.Received), "transcript", M("rn", t.Rn, "commitments", BL(t.Commitments), "sn", t.Sn, "publicKeys", Pairs(t.PublicKeys),
                    "ciphertexts", Pairs(t.Ciphertexts), "encrypted", Pairs(t.Encrypted)));
            }
            var rr = KemOt.KemBaseOtMalRandom(choices, g, KemTamper(tn));
            var tr = rr.Transcript;
            return M("senderSecrets", Pairs(rr.SenderSecrets), "recvSecrets", BL(rr.RecvSecrets), "sid", rr.Sid, "transcript",
                M("rn", tr.Rn, "commitments", BL(tr.Commitments), "sn", tr.Sn, "publicKeys", Pairs(tr.PublicKeys), "ciphertexts", Pairs(tr.Ciphertexts)));
        });
        Base.Check(Mod, "kemPad", a =>
        {
            var ss = new byte[32];
            for (int k = 0; k < 32; k++) ss[k] = (byte)k;
            return a.Count == 1 ? KemOt.KemOtPad(0, 0, new byte[32], I(a[0])) : KemOt.KemOtPad(I(a[0]), I(a[1]), ss, I(a[2]));
        });
        Base.Check(Mod, "hybridOt", a =>
        {
            var tn = (string?)a[3];
            HybridOt.HybridBaseOtTamper? t = null;
            if (tn != null)
            {
                t = new HybridOt.HybridBaseOtTamper();
                if (tn == "ec") t.Ec = Tamper("ct_flip");
                else if (tn == "ecS") t.Ec = Tamper("S_identity");
                else if (tn == "enc") t.TamperEncrypted = e => e[0][0] = Flip(e[0][0], 1);
                else if (tn == "kem") t.Kem = KemTamper("badKey");
            }
            var r = HybridOt.HybridBaseOT(ToPairs(a[0]), IA(a[1]), Orng(a[2]), t);
            var tr = r.Transcript;
            return M("received", BL(r.Received), "sid", tr.Sid, "ecS", Aff(tr.EcS), "kemSid", tr.KemSid, "encrypted", Pairs(tr.Encrypted), "commitments", Pairs(tr.Commitments));
        });
        Base.Check(Mod, "hybridKey", a => HybridOt.HybridTransferKey(Fill(32, 1), 3, 1, Fill(16, 2), Fill(32, 3), I(a[0])));
    }

    // ---- MASCOT no-dealer offline phase and the no-dealer runner ----
    [Fact] public void MascotOffline()
    {
        Base.Check(Mod, "offline", a =>
        {
            int n = I(a[0]);
            var seed = B(a[1]);
            var what = (string)a[2]!;
            var o = a[3] == null ? null : Map(a[3]);
            Mascot.NoDealerOptions? opts = null;
            if (o != null)
            {
                opts = new Mascot.NoDealerOptions();
                if (o.GetValueOrDefault("sacrifice") != null) opts.Sacrifice = (bool)o["sacrifice"]!;
                if (o.GetValueOrDefault("partners") != null) opts.SacrificePartners = I(o["partners"]);
                if (o.GetValueOrDefault("keys") != null) opts.MacKeys = I(o["keys"]);
                if (o.GetValueOrDefault("statSec") != null) opts.StatSec = I(o["statSec"]);
                opts.UnsafeStatSec = o.GetValueOrDefault("unsafe") is true;
                if (o.GetValueOrDefault("dev") != null) { var d = (L)o["dev"]!; opts.Deviation = new Mascot.OfflineDeviation(I(d[0]), B(d[1])); }
            }
            var off = Mascot.MakeNoDealerOffline(n, seed, opts);
            var bs = M("n", off.N(), "statSec", off.StatSec, "ctx", Ctx(off.MacContext()));
            switch (what)
            {
                case "ctx": return bs;
                case "triple": bs["t"] = Triple(off.GenAuthTriple()); return bs;
                case "input": bs["v"] = AuthSv(off.AuthInput(B(o!["value"]), I(o["owner"]))); return bs;
                case "multiply":
                {
                    BigInteger[] x = BA(o!["x"]), y = BA(o["y"]);
                    var z = off.OtShareMultiply(x.Select(v => (object)v).ToList(), y);
                    BigInteger sum = BigInteger.Zero, sx = BigInteger.Zero, sy = BigInteger.Zero;
                    foreach (var v in z) sum = Field.Fadd(sum, v);
                    foreach (var v in x) sx = Field.Fadd(sx, v);
                    foreach (var v in y) sy = Field.Fadd(sy, v);
                    bs["z"] = Ls(z);
                    bs["sum"] = S(sum);
                    bs["expect"] = S(Field.Fmul(sx, sy));
                    return bs;
                }
                case "consistency":
                {
                    var values = (L)o!["values"]!;
                    var ins = new List<Spdz.AuthSV>();
                    for (int i = 0; i < values.Count; i++) ins.Add(off.AuthInput(B(values[i]), i % n));
                    if (o.GetValueOrDefault("tamper") is true) ins[0].Value[0] = Field.Fadd(ins[0].Value[0], BigInteger.One);
                    off.CheckInputConsistency(ins);
                    bs["ok"] = true;
                    return bs;
                }
                default: throw new ArgumentException(what);
            }
        });
        Base.Check(Mod, "offlineBlame", a =>
        {
            var opts = new Mascot.NoDealerOptions { Deviation = new Mascot.OfflineDeviation(I(a[2]), B(a[3])) };
            try
            {
                Mascot.MakeNoDealerOffline(I(a[0]), B(a[1]), opts).GenAuthTriple();
                return M("aborted", false);
            }
            catch (Mascot.OfflineCheatingAbort e)
            {
                var bl = e.Blamed().Select(x => (object?)x).ToList();
                return M("aborted", true, "name", "OfflineCheatingAbort", "blamed", bl);
            }
        });
        Base.Check(Mod, "noDealerRun", a => Summary(SpdzRunner.ComposeSecureMalicious(Vectors(a[0]), Config(Map(a[1])))));
    }

    [Fact] public void Covers() { Base.Covers(Mod, new[]
    {
        "ecOp", "ecValidate", "ecAssert", "schnorr", "prg", "maskTail", "transpose32", "transposeCols", "gfMulX", "gfXorInto", "gfBig", "accumColumn", "kosCombine",
        "tmmo", "tweakDomain", "bigBytes", "bytesBig", "word64", "bindingBytes", "baseOtKdf", "randomOt", "baseOt", "channel", "kosChi", "kemOt", "kemPad", "hybridOt",
        "hybridKey", "offline", "offlineBlame", "noDealerRun",
    }); Assert.Equal(440, Base.Total(Mod)); }
}
