using System.Numerics;
using AtlasPca.Corpus.Tests;
using AtlasPca.Mpc;
using Xunit;
using static AtlasPca.Mpc.Tests.MpcSupport;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Mpc.Tests;

/// <summary>Differential tests of the pure parts of the MPC networked runner (wire codec, pairwise-authenticated shares, forensics, codecs).</summary>
public class MpcNetDiffTests
{
    const string Mod = "ref-mpc-net";

    static int? NullableInt(object? o) => o == null ? null : I(o);

    // ---- wire ----
    [Fact] public void Frames()
    {
        Base.Check(Mod, "encodeFrame", a =>
        {
            var f = Map(a[0]);
            return NetWire.EncodeFrame(new NetWire.Frame(f["v"], (string)f["ty"]!, (string)f["sid"]!, f["seq"], (string)f["rd"]!, f["d"]));
        });
        Base.Check(Mod, "split", a =>
        {
            var s = new NetWire.FrameSplitter();
            var o = new L();
            foreach (var c in (L)a[0]!) foreach (var fr in s.Push(Base.Bytes(c))) o.Add(fr);
            return M("frames", o);
        });
        Base.Check(Mod, "peekVersion", a => NetWire.PeekVersion(Base.Bytes(a[0])));
        Base.Check(Mod, "parseFrame", a => NetWire.ParseFrame(Base.Bytes(a[0])));
        Base.Check(Mod, "versionMismatch", a => NetWire.VersionMismatch(Base.Bytes(a[0])));
        Base.Check(Mod, "hx", a => NetWire.Hx(B(a[0])));
        Base.Check(Mod, "unhx", a => NetWire.Unhx(a[0]) is BigInteger v ? S(v) : null);
        Base.Check(Mod, "unhxArray", a => NetWire.UnhxArray(a[0], I(a[1])) is { } v ? Ls(v) : null);
        Base.Check(Mod, "netAbort", a =>
        {
            var cb = a[5];
            D? op = a[6] == null ? null : Map(a[6]);
            var e = new NetWire.NetAbort((string)a[0]!, NullableInt(a[1]), I(a[2]), (string)a[3]!, a[4] as string, cb is Num ? I(cb) : null,
                op == null ? null : op.GetValueOrDefault("reason") as string, op?.GetValueOrDefault("evidence"),
                op == null || op.GetValueOrDefault("deadlineMs") == null ? null : I(op["deadlineMs"]));
            return M("message", e.Message, "name", "NetAbort", "kind", e.Kind, "blamed", e.Blamed, "reporter", e.Reporter, "reason", e.Reason,
                "claimedKind", e.ClaimedKind, "claimedBlame", e.ClaimedBlame, "evidence", e.Evidence, "deadlineMs", e.DeadlineMs);
        });
        Base.Check(Mod, "abortKinds", a => NetWire.ABORT_KINDS.OrderBy(k => k, StringComparer.Ordinal).Select(k => (object?)k).ToList());
    }

    // ---- pairwise-authenticated shares ----
    static NetPa.PA Pa(object? o) { var m = Map(o); return new NetPa.PA(B(m["x"]), BA(m["tag"]), BA(m["key"])); }

    static NetPa.AW Aw(object? o)
    {
        var m = Map(o);
        var ms = (L)m["m"]!;
        return new NetPa.AW(Pa(m["v"]), ms.Select(Pa).ToArray());
    }

    static D PaJ(NetPa.PA p) => M("x", S(p.X), "tag", Ls(p.Tag), "key", Ls(p.Key));

    static D AwJ(NetPa.AW a) => M("v", PaJ(a.V), "m", a.M.Select(p => (object?)PaJ(p)).ToList());

    [Fact] public void PairwiseShares()
    {
        Base.Check(Mod, "pa", a =>
        {
            var op = (string)a[0]!;
            var p = Pa(a[1]);
            int n = p.Tag.Length;
            switch (op)
            {
                case "add": return PaJ(NetPa.PaAdd(p, Pa(a[2])));
                case "sub": return PaJ(NetPa.PaSub(p, Pa(a[2])));
                case "neg": return PaJ(NetPa.PaNeg(p));
                case "scale": return PaJ(NetPa.PaScale(p, B(a[2])));
                case "addPublic0": return PaJ(NetPa.PaAddPublic0(new NetPa.PaEnv(I(a[2]), n, B(a[3]), a[4] is true), p, B(a[5])));
                case "verify": return NetPa.PaVerify(new NetPa.PaEnv(I(a[2]), n, B(a[3]), true), p, I(a[4]), B(a[5]), B(a[6]));
                case "flat":
                {
                    int id = I(a[2]);
                    bool tg = a[3] is true;
                    var f = NetPa.PaFlat(p, id, n, tg);
                    return M("f", f.Select(x => (object?)S(x)).ToList(), "w", NetPa.PaWidth(n, tg), "back", PaJ(NetPa.PaParse(f, 0, id, n, tg)));
                }
                default: throw new ArgumentException(op);
            }
        });
        Base.Check(Mod, "aw", a =>
        {
            if (a.Count == 1) return NetCodec.SharingsPerTriple(I(a[0]));
            if (a.Count == 3)
            {
                var x1 = Aw(a[0]);
                int n1 = x1.V.Tag.Length, keys = x1.M.Length, id = I(a[1]);
                bool tg1 = a[2] is true;
                var f = NetPa.AwFlat(x1, id, n1, tg1);
                return M("f", f.Select(v => (object?)S(v)).ToList(), "w", NetPa.AwWidth(n1, keys, tg1), "back", AwJ(NetPa.AwParse(f, 0, id, n1, keys, tg1)));
            }
            var x = Aw(a[0]);
            var y = Aw(a[1]);
            int n = x.V.Tag.Length;
            var alpha = ((L)a[2]!).Select(Pa).ToArray();
            bool tg = a[3] is true;
            var c = B(a[4]);
            return M("add", AwJ(NetPa.WAdd(x, y)), "sub", AwJ(NetPa.WSub(x, y)), "neg", AwJ(NetPa.WNeg(x)), "scale", AwJ(NetPa.WScale(x, c)),
                "addPublic", AwJ(NetPa.WAddPublic(new NetPa.PaEnv(1, n, new BigInteger(7), tg), x, c, alpha)),
                "addPublic0", AwJ(NetPa.WAddPublic(new NetPa.PaEnv(0, n, new BigInteger(7), tg), x, c, alpha)));
        });
    }

    // ---- forensics ----
    static L SideJ(Dictionary<int, BigInteger[]> m) => m.Select(e => (object?)new L { e.Key, Ls(e.Value) }).ToList();

    static Dictionary<int, BigInteger[]> SideIn(object? o)
    {
        var m = new Dictionary<int, BigInteger[]>();
        foreach (var e in (L)o!) m[I(((L)e!)[0])] = BA(((L)e)[1]);
        return m;
    }

    static List<NetForensics.SlotDisclosure> Dis(object? o)
    {
        var r = new List<NetForensics.SlotDisclosure>();
        foreach (var so in (L)o!)
        {
            var s = Map(so);
            r.Add(new NetForensics.SlotDisclosure(IA(s["bits"]), B(s["y"]), B(s["z"]), SideIn(s["recv"]), SideIn(s["rho"])));
        }
        return r;
    }

    [Fact] public void Forensics() => Base.Check(Mod, "forensics", a =>
    {
        switch (a.Count)
        {
            case 1: return NetForensics.SlotsFor(I(a[0]));
            case 3:
            {
                if (a[0] is D all0)
                {
                    var all = new Dictionary<int, List<NetForensics.SlotDisclosure>>();
                    foreach (var e in all0) all[int.Parse(e.Key, System.Globalization.CultureInfo.InvariantCulture)] = Dis(e.Value);
                    if (a[2] != null) all.Remove(I(a[2]));
                    var res = NetForensics.AuditDisclosures(all, BA(a[1]));
                    var pb = res.PairBad.Select(p => (object?)new L { p[0], p[1] }).ToList();
                    var blame = new L();
                    for (int me = 0; me < 3; me++) blame.Add(NetForensics.BlameFrom(me, res));
                    return M("selfBad", res.SelfBad.OrderBy(x => x).Select(x => (object?)x).ToList(), "pairBad", pb, "blame", blame);
                }
                var sb = new HashSet<int>(((L)a[1]!).Select(I));
                var pairs = ((L)a[2]!).Select(x => new[] { I(((L)x!)[0]), I(((L)x)[1]) }).ToList();
                return NetForensics.BlameFrom(I(a[0]), new NetForensics.AuditResult(sb, pairs));
            }
            case 4:
            {
                var peers = ((L)a[3]!).Select(I).ToList();
                var dd = NetForensics.ParseDisclosure(a[0], I(a[1]), I(a[2]), peers);
                var ddj = dd.Select(s => (object?)M("bits", Li(s.Bits), "y", S(s.Y), "z", S(s.Z), "recv", SideJ(s.Recv), "rho", SideJ(s.Rho))).ToList();
                return M("dd", ddj, "back", NetForensics.WireDisclosure(dd));
            }
            case 6: return NetForensics.DisclosureCommit((string)a[0]!, I(a[1]), I(a[2]), (long)Dbl(a[3]), (string)a[4]!, a[5]);
            default: throw new ArgumentException("forensics arity");
        }
    });

    // ---- codecs ----
    [Fact] public void Codecs() => Base.Check(Mod, "codec", a =>
    {
        var op = (string)a[0]!;
        switch (op)
        {
            case "unb64": return NetCodec.Unb64(a[1], a[2] == null ? -1 : I(a[2]));
            case "b64": return NetCodec.B64(Base.Bytes(a[1]));
            case "hexBig": return S(NetCodec.HexBig(a[1]));
            case "jPt": return NetCodec.PtJ(NetCodec.JPt(a[1]));
            case "ptJ": return NetCodec.PtJ(Ec.MulBase(B(a[1])));
            case "gadgetCommit": return NetCodec.GadgetCommit((string)a[1]!, I(a[2]), Base.Bytes(a[3]));
            case "gadgetStatement": return NetCodec.GadgetStatement((string)a[1]!, (string)a[2]!, I(a[3]), (string)a[4]!);
            default: throw new ArgumentException(op);
        }
    });

    [Fact] public void Covers() { Base.Covers(Mod, new[]
    {
        "encodeFrame", "split", "peekVersion", "parseFrame", "versionMismatch", "hx", "unhx", "unhxArray", "netAbort", "abortKinds", "pa", "aw", "forensics", "codec",
    }); Assert.Equal(349, Base.Total(Mod)); }
}
