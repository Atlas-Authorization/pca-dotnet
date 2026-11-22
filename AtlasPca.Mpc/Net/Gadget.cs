using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mpc.Net;

/// <summary>
/// Agreement on the joint choice-bit gadget seeds: a signed commit-reveal with an echo round, so ONE corrupt party cannot make
/// honest parties derive different gadgets and then blame each other. Every commitment and opening is signed with the sender's
/// pinned TLS identity key; after the reveal each party echoes the signed values it got from every third party (round gd-e).
/// An echoed signature that does not verify blames the echoer; a verifying statement that differs from the one received
/// directly blames the signer with both statements as transferable evidence. With n = 2 the echo is skipped.
/// </summary>
public static class Gadget
{
    private static readonly Regex Hex64 = new(@"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex HexSig = new(@"\A[0-9a-f]{16,200}\z", RegexOptions.CultureInvariant);

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    private static bool IsSigned(object? x, Regex valueRe) =>
        x is JD m && m.GetValueOrDefault("v") is string v && valueRe.IsMatch(v) && m.GetValueOrDefault("s") is string s && HexSig.IsMatch(s);

    private static JD Signed(Mesh mesh, string round, string value)
    {
        byte[] sig = mesh.Sign(NetCodec.GadgetStatement(mesh.SessionId(), round, mesh.SelfId, value));
        return new JD { ["v"] = value, ["s"] = Hex(sig) };
    }

    private static bool Check(Mesh mesh, int signer, string round, JD m)
    {
        try
        {
            return mesh.Verify(signer, NetCodec.GadgetStatement(mesh.SessionId(), round, signer, (string)m["v"]!), Convert.FromHexString((string)m["s"]!));
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static int? IntOf(object? o)
    {
        if (o is not Num n || !double.TryParse(n.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out double d)) return null;
        return d == Math.Round(d) && Math.Abs(d) < 1e9 ? (int)d : null;
    }

    public static byte[][] AgreeGadgetSeeds(Mesh mesh, int n, IExchanger io) => AgreeGadgetSeeds(mesh, n, io, RandomNumberGenerator.GetBytes(32));

    /// <summary>Run the signed commit / reveal / echo and return every party's seed in party order (mine included). <paramref name="mySeed"/> is injectable for tests.</summary>
    public static byte[][] AgreeGadgetSeeds(Mesh mesh, int n, IExchanger io, byte[] mySeed)
    {
        int id = mesh.SelfId;
        string sid = mesh.SessionId();
        string myCommit = NetCodec.GadgetCommit(sid, id, mySeed);
        Dictionary<int, JD> commits = io.Exchange<JD>("gd-c", p => Signed(mesh, "gd-c", myCommit), (p, raw) =>
        {
            if (!IsSigned(raw, Hex64)) throw io.Bad(p, "bad gadget commitment");
            if (!Check(mesh, p, "gd-c", (JD)raw!)) throw io.Bad(p, "gadget commitment signature does not verify");
            return (JD)raw!;
        });
        string mySeedHex = Hex(mySeed);
        Dictionary<int, JD> opens = io.Exchange<JD>("gd-o", p => Signed(mesh, "gd-o", mySeedHex), (p, raw) =>
        {
            if (!IsSigned(raw, Hex64)) throw io.Bad(p, "bad gadget seed");
            var m = (JD)raw!;
            if (!Check(mesh, p, "gd-o", m)) throw io.Bad(p, "gadget seed signature does not verify");
            if (!string.Equals(NetCodec.GadgetCommit(sid, p, Convert.FromHexString((string)m["v"]!)), commits[p]["v"] as string, StringComparison.Ordinal))
                throw new NetWire.NetAbort("commitment", p, id, "party " + p + " opened a gadget seed that does not match its commitment");
            return m;
        });
        if (n >= 3)
        {
            var others = new List<int>();
            for (int i = 0; i < n; i++) if (i != id) others.Add(i);
            io.Exchange<bool>("gd-e", peer =>
            {
                var outp = new List<object?>();
                foreach (int j in others)
                {
                    if (j == peer) continue;
                    outp.Add(new JD { ["j"] = j, ["c"] = commits[j], ["o"] = opens[j] });
                }
                return outp;
            }, (p, raw) =>
            {
                var expect = new List<int>();
                foreach (int j in others) if (j != p) expect.Add(j);
                if (raw is not List<object?> list || list.Count != expect.Count) throw io.Bad(p, "bad gadget echo");
                for (int k = 0; k < expect.Count; k++)
                {
                    int j = expect[k];
                    if (list[k] is not JD e) throw io.Bad(p, "bad gadget echo entry");
                    int? ej = IntOf(e.GetValueOrDefault("j"));
                    if (ej == null || ej.Value != j || !IsSigned(e.GetValueOrDefault("c"), Hex64) || !IsSigned(e.GetValueOrDefault("o"), Hex64)) throw io.Bad(p, "bad gadget echo entry");
                    var ec = (JD)e["c"]!;
                    var eoo = (JD)e["o"]!;
                    // a statement that does not verify under j's pinned key was forged by the echoer p
                    if (!Check(mesh, j, "gd-c", ec) || !Check(mesh, j, "gd-o", eoo)) throw io.Bad(p, "gadget echo carries a statement that party " + j + " did not sign");
                    JD mineC = commits[j];
                    JD mineO = opens[j];
                    bool cDiff = !string.Equals(ec["v"] as string, mineC["v"] as string, StringComparison.Ordinal);
                    if (cDiff || !string.Equals(eoo["v"] as string, mineO["v"] as string, StringComparison.Ordinal))
                    {
                        // both statements verify under j's key and differ: j signed two values for one round
                        var ev = new JD
                        {
                            ["signer"] = j,
                            ["round"] = cDiff ? "gd-c" : "gd-o",
                            ["statements"] = cDiff ? new List<object?> { mineC, ec } : new List<object?> { mineO, eoo },
                        };
                        throw new NetWire.NetAbort("equivocation", j, id, "party " + j + " signed different gadget " + (cDiff ? "commitments" : "seeds")
                            + " for different parties (shown by party " + p + "'s echo)", evidence: ev);
                    }
                }
                return true;
            });
        }
        var result = new byte[n][];
        for (int p = 0; p < n; p++) result[p] = p == id ? (byte[])mySeed.Clone() : Convert.FromHexString((string)opens[p]["v"]!);
        return result;
    }
}
