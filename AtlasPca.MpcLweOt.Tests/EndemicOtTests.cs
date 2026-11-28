using System.Security.Cryptography;
using System.Text;
using AtlasPca.Corpus.Tests;
using AtlasPca.Mpc.LweOt;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.MpcLweOt.Tests;

/// <summary>Replays the reference corpus (test-data/ref-mpc-endemic.json.gz) through the native endemic OT over liblweot. liblweot must load (ATLAS_LWEOT_LIB).</summary>
public class EndemicOtTests
{
    const string M = "ref-mpc-endemic";

    public EndemicOtTests()
    {
        Assert.True(Lattice.Available(), "liblweot must load (ATLAS_LWEOT_LIB)");
    }

    static byte[] Seed(object? label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));

    static IOtRandom Rng(object? s) => OtRandom.SplitMix64(ulong.Parse((string)s!));

    static int[] Ints(object? o) => ((L)o!).Select(x => (int)Base.Long(x)).ToArray();

    static byte[][][] Pairs(object? o) => ((L)o!).Select(p => ((L)p!).Select(Base.Bytes).ToArray()).ToArray();

    static byte[] Flip(byte[] b) => b.Select(x => (byte)(x ^ 1)).ToArray();

    static byte[] Fill(int n, int k) { var b = new byte[n]; for (int i = 0; i < n; i++) b[i] = (byte)(i * 31 + k * 7 + (i >> 3)); return b; }

    static L J(byte[][] a) => a.Select(x => (object?)x).ToList();

    static L JJ(byte[][][] a) => a.Select(x => (object?)J(x)).ToList();

    [Fact] public void LweKeygenFips() => Base.Check(M, "lweKeygenFips", a =>
    {
        var k = Lattice.KeygenFips203(Seed(a[0]));
        return new D { ["pk"] = k.PublicKey, ["skSha256"] = Convert.ToHexString(SHA256.HashData(k.SecretKey)).ToLowerInvariant() };
    });

    [Fact] public void LweKeygen() => Base.Check(M, "lweKeygen", a =>
    {
        var k = Lattice.Keygen(Seed(a[0]));
        return new D { ["pk"] = k.PublicKey, ["skSha256"] = Convert.ToHexString(SHA256.HashData(k.SecretKey)).ToLowerInvariant() };
    });

    [Fact] public void LweEnc() => Base.Check(M, "lweEnc", a => Lattice.Enc(Lattice.Keygen(Seed(a[0])).PublicKey, Base.Bytes(a[1]), Base.Bytes(a[2])));

    [Fact] public void LweDec() => Base.Check(M, "lweDec", a => Lattice.Dec(Lattice.Keygen(Seed(a[0])).SecretKey, Base.Bytes(a[1])));

    [Fact] public void LweRing() => Base.Check(M, "lweRing", a =>
        (string)a[0]! == "add" ? Lattice.RingAdd(Base.Bytes(a[1]), Base.Bytes(a[2])) : Lattice.RingSub(Base.Bytes(a[1]), Base.Bytes(a[2])));

    [Fact] public void LweHash() => Base.Check(M, "lweHash", a => Lattice.HashToRing(Base.Bytes(a[0])));

    [Fact] public void RandomOt() => Base.Check(M, "randomOt", a =>
    {
        var rv = EndemicOt.Receive(Ints(a[0]), Rng(a[1]));
        var sm = EndemicOt.SendRandom(rv.Message, Rng(a[2]));
        return new D
        {
            ["rn"] = rv.Message.Rn, ["points"] = JJ(rv.Message.Points), ["rhos"] = J(rv.Message.Rhos),
            ["ciphertexts"] = JJ(sm.Ciphertexts), ["senderPads"] = JJ(sm.SenderPads), ["recvPads"] = J(EndemicOt.RecoverRandom(rv.State, sm)),
        };
    });

    [Fact] public void RandomOtTamper() => Base.Check(M, "randomOtTamper", a =>
    {
        var rv = EndemicOt.Receive(Ints(a[0]), Rng(a[1]));
        var sm = EndemicOt.SendRandom(rv.Message, Rng(a[2]), c => c[0][0] = c[0][0][..1087]);
        return J(EndemicOt.RecoverRandom(rv.State, sm));
    });

    [Fact] public void BaseOt() => Base.Check(M, "baseOt", a =>
    {
        var choices = Ints(a[1]);
        var t = (string)a[3]!;
        Action<byte[][][]>? tamper = t == "enc" ? e => e[0][0] = Flip(e[0][0]) : t == "encChosen" ? e => e[0][choices[0] & 1] = Flip(e[0][choices[0] & 1]) : null;
        var one = Rng(a[2]); // one generator serves the receiver and then the sender, as the reference does
        var r = EndemicOt.BaseOt(Pairs(a[0]), choices, one, one, tamper);
        return new D { ["received"] = J(r.Received), ["ciphertexts"] = JJ(r.Transcript.Ciphertexts), ["encrypted"] = JJ(r.Transcript.Encrypted), ["commitments"] = JJ(r.Transcript.Commitments) };
    });

    [Fact] public void SendMalformed() => Base.Check(M, "sendMalformed", a =>
    {
        var kind = (string)a[0]!;
        var m = EndemicOt.Receive([0, 1], Rng("77")).Message;
        var rn = m.Rn; var points = new[] { (byte[][])m.Points[0].Clone(), (byte[][])m.Points[1].Clone() }; var rhos = (byte[][])m.Rhos.Clone();
        if (kind == "nonce") rn = Fill(31, 1);
        if (kind == "count") rhos = rhos[1..];
        if (kind == "point") points[1][0] = Fill(1151, 1);
        if (kind == "rho") rhos[0] = Fill(33, 1);
        return EndemicOt.SendRandom(new ReceiverMessage(rn, points, rhos), Rng("78")).Ciphertexts.Length;
    });

    [Fact] public void RandomBaseOtGivesTheReceiverExactlyTheChosenPad()
    {
        var choices = new[] { 0, 1, 1, 0 };
        var r = EndemicOt.BaseOtRandom(choices, OtRandom.SplitMix64(11));
        Assert.Equal(choices.Length, r.RecvPads.Length);
        for (int i = 0; i < choices.Length; i++)
        {
            Assert.Equal(r.SenderPads[i][choices[i]], r.RecvPads[i]);
            Assert.NotEqual(r.SenderPads[i][1 - choices[i]], r.RecvPads[i]);
        }
        Assert.Equal(EndemicOt.SessionId(r.Message.Rn), r.Sid);
        var tampered = Assert.ThrowsAny<Exception>(() => EndemicOt.BaseOtRandom(choices, OtRandom.SplitMix64(12), c => c[0][0] = c[0][0][..1087]));
        Assert.IsType<EndemicAbortException>(tampered);
    }

    [Fact] public void TheBaseOtFnSeamIsTheChosenMessageOt()
    {
        var msgs = new[] { new[] { Fill(16, 1), Fill(16, 2) }, new[] { Fill(16, 3), Fill(16, 4) } };
        var got = EndemicOt.BaseOtFn(msgs, new[] { 1, 0 }, AtlasPca.Mpc.Ot.SecureOtRandom());
        Assert.Equal(msgs[0][1], got[0]);
        Assert.Equal(msgs[1][0], got[1]);
    }
}
