using System.Collections;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using static AtlasPca.Mpc.Field;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mpc;

/// <summary>
/// Forensic disclosures of a failed offline triple: each party discloses its OT choice bits, operands, claimed product share and the per-peer OT
/// messages; the cross-check names the party whose own data are inconsistent or whose counterpart's transcript disagrees. This class holds the
/// pure parts (strict parsing, audit, blame, the commit-first binding); the timed exchange over the mesh is part of the networked driver.
/// </summary>
public static class NetForensics
{
    /// <summary>One product item's disclosure; Recv and Rho are keyed by peer index (insertion ordered: only ever added to).</summary>
    public sealed record SlotDisclosure(int[] Bits, BigInteger Y, BigInteger Z, Dictionary<int, BigInteger[]> Recv, Dictionary<int, BigInteger[]> Rho);

    public static int SlotsFor(int partners) => 1 + partners;

    /// <summary>The wire (JSON) form of a disclosure.</summary>
    public static List<object?> WireDisclosure(IReadOnlyList<SlotDisclosure> d)
    {
        var o = new List<object?>();
        foreach (var s in d)
        {
            var bits = new StringBuilder();
            foreach (var b in s.Bits) bits.Append(b.ToString(CultureInfo.InvariantCulture));
            o.Add(new D { ["bits"] = bits.ToString(), ["y"] = NetWire.Hx(s.Y), ["z"] = NetWire.Hx(s.Z), ["recv"] = Side(s.Recv), ["rho"] = Side(s.Rho) });
        }
        return o;
    }

    static List<object?> Side(Dictionary<int, BigInteger[]> x)
    {
        var o = new List<object?>();
        foreach (var (k, v) in x) o.Add(new List<object?> { k, v.Select(e => (object?)NetWire.Hx(e)).ToList() });
        return o;
    }

    static BigInteger FieldOf(object? s) => NetWire.Unhx(s) ?? throw new ArgumentException("bad field element");

    /// <summary>Strict parse of a peer's disclosure; throws on any deviation from the expected shape.</summary>
    public static List<SlotDisclosure> ParseDisclosure(object? raw, int slots, int rows, IReadOnlyList<int> peers)
    {
        if (rows < 0) throw new ArgumentException("bad choice bits");
        if (raw is not IList l || l.Count != slots) throw new ArgumentException("bad forensic disclosure");
        var o = new List<SlotDisclosure>();
        foreach (var e in l)
        {
            if (e is not IDictionary r) throw new ArgumentException("bad choice bits");
            if (!r.Contains("bits") || r["bits"] is not string bs || bs.Length != rows || !bs.All(c => c is '0' or '1')) throw new ArgumentException("bad choice bits");
            var bits = new int[bs.Length];
            for (int i = 0; i < bits.Length; i++) bits[i] = bs[i] == '1' ? 1 : 0;
            var y = FieldOf(r.Contains("y") ? r["y"] : null);
            var z = FieldOf(r.Contains("z") ? r["z"] : null);
            o.Add(new SlotDisclosure(bits, y, z, SideParse(r.Contains("recv") ? r["recv"] : null, rows, peers), SideParse(r.Contains("rho") ? r["rho"] : null, rows, peers)));
        }
        return o;
    }

    static Dictionary<int, BigInteger[]> SideParse(object? x, int rows, IReadOnlyList<int> peers)
    {
        if (x is not IList l || l.Count != peers.Count) throw new ArgumentException("bad peer table");
        var m = new Dictionary<int, BigInteger[]>();
        foreach (var e in l)
        {
            if (e is not IList pr || pr.Count != 2 || pr[0] is not Num pn) throw new ArgumentException("bad peer entry");
            if (!double.TryParse(pn.Raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var pd)) throw new ArgumentException("bad peer entry");
            int? p = pd == Math.Round(pd, MidpointRounding.ToEven) && Math.Abs(pd) < 1e9 ? (int)pd : null;
            if (p == null || !peers.Contains(p.Value) || m.ContainsKey(p.Value)) throw new ArgumentException("bad peer entry");
            if (pr[1] is not IList vals || vals.Count != rows) throw new ArgumentException("bad row table");
            var arr = new BigInteger[rows];
            for (int i = 0; i < rows; i++) arr[i] = FieldOf(vals[i]);
            m[p.Value] = arr;
        }
        return m;
    }

    /// <summary>SelfBad: parties whose own disclosure is inconsistent; PairBad: ordered [receiver, sender] pairs whose OT transcripts disagree.</summary>
    public sealed record AuditResult(HashSet<int> SelfBad, List<int[]> PairBad);

    /// <summary>Cross-checks every party's disclosure of one failed triple against the public gadget.</summary>
    public static AuditResult AuditDisclosures(Dictionary<int, List<SlotDisclosure>> all, BigInteger[] gadget)
    {
        var selfBad = new HashSet<int>();
        var pairBad = new List<int[]>();
        var parties = all.Keys.OrderBy(k => k).ToList();
        foreach (int i in parties)
        {
            var di = all[i];
            for (int s = 0; s < di.Count; s++)
            {
                var sd = di[s];
                var value = BigInteger.Zero;
                for (int k = 0; k < gadget.Length; k++) if (k < sd.Bits.Length && sd.Bits[k] == 1) value += gadget[k];
                var implied = Fmul(Mod(value), sd.Y);
                foreach (int p in parties)
                {
                    if (p == i) continue;
                    foreach (var v in sd.Recv[p]) implied = Fadd(implied, Mod(v));
                    foreach (var v in sd.Rho[p]) implied = Fsub(implied, v);
                }
                if (implied != sd.Z) selfBad.Add(i);
                foreach (int p in parties)
                {
                    if (p == i) continue;
                    var sp = all[p][s];
                    var rho = sp.Rho[i];
                    var got = sd.Recv[p];
                    var y = Mod(sp.Y);
                    bool bad = false;
                    for (int k = 0; k < gadget.Length && !bad; k++)
                    {
                        var want = Fadd(rho[k], k < sd.Bits.Length && sd.Bits[k] == 1 ? Fmul(gadget[k], y) : BigInteger.Zero);
                        if (Mod(got[k]) != want) bad = true;
                    }
                    if (bad) pairBad.Add(new[] { i, p });
                }
            }
        }
        return new AuditResult(selfBad, pairBad);
    }

    /// <summary>The party the verifier <paramref name="me"/> blames, or null when the evidence cannot name one.</summary>
    public static int? BlameFrom(int me, AuditResult r)
    {
        var own = r.SelfBad.Where(p => p != me).OrderBy(p => p).ToList();
        if (own.Count > 0) return own[0];
        foreach (var pr in r.PairBad)
        {
            if (pr[0] == me) return pr[1];
            if (pr[1] == me) return pr[0];
        }
        return null;
    }

    public const int DEFAULT_FORENSIC_DEADLINE_MS = 30_000;

    /// <summary>Binding commitment to a disclosure: session, party, triple index, deadline, a 256-bit nonce and the canonical wire form.</summary>
    public static string DisclosureCommit(string sessionId, int party, int tripleIndex, long deadlineMs, string nonce, object? wire)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        h.AppendData(Encoding.UTF8.GetBytes("atlas-pca-mpc/forensic-commit/v1\0"));
        h.AppendData(Encoding.UTF8.GetBytes(NetWire.Stringify(new List<object?> { sessionId, party, tripleIndex, deadlineMs, nonce, wire })));
        return Convert.ToHexString(h.GetHashAndReset()).ToLowerInvariant();
    }
}
