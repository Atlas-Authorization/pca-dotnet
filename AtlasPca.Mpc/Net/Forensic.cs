using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mpc.Net;

/// <summary>
/// Commit-first disclosure exchange for a failed triple (dealer-free mode). Nobody opens before every commitment is in hand
/// (round forensic-c completes first), so no party's disclosure can depend on another's; an opening that does not match its
/// commitment is blamed, a late or absent party times out at the shared deadline.
/// </summary>
public static class Forensic
{
    private static readonly Regex Hex64 = new(@"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);

    /// <summary>Every OTHER party's verified disclosure.</summary>
    public static Dictionary<int, List<NetForensics.SlotDisclosure>> ExchangeDisclosures(string sessionId, int id, int n, int tripleIndex, List<NetForensics.SlotDisclosure> mine,
        int slots, int rows, long deadlineMs, IExchanger io)
    {
        var wire = NetForensics.WireDisclosure(mine);
        string nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        string myCommit = NetForensics.DisclosureCommit(sessionId, id, tripleIndex, deadlineMs, nonce, wire);
        string deadlineText = deadlineMs.ToString(CultureInfo.InvariantCulture);
        Dictionary<int, string> commits = io.Exchange<string>("forensic-c", p => new JD { ["c"] = myCommit, ["d"] = deadlineMs }, (p, raw) =>
        {
            JD? o = raw as JD;
            if (o == null || o.GetValueOrDefault("c") is not string c || !Hex64.IsMatch(c)) throw io.Bad(p, "bad forensic commitment");
            if (o.GetValueOrDefault("d") is not Num dn || dn.Raw != deadlineText)
                throw io.Bad(p, "forensic deadline " + (o.GetValueOrDefault("d") is Num dd ? dd.Raw : "?") + " differs from the agreed " + deadlineMs);
            return c;
        }, deadlineMs);
        return io.Exchange<List<NetForensics.SlotDisclosure>>("forensic-o", p => new JD { ["w"] = wire, ["nonce"] = nonce }, (p, raw) =>
        {
            JD? o = raw as JD;
            if (o == null || o.GetValueOrDefault("nonce") is not string nc || !Hex64.IsMatch(nc)) throw io.Bad(p, "bad forensic opening");
            if (!string.Equals(NetForensics.DisclosureCommit(sessionId, p, tripleIndex, deadlineMs, nc, o.GetValueOrDefault("w")), commits[p], StringComparison.Ordinal))
                throw new NetWire.NetAbort("commitment", p, id, "party " + p + " opened a forensic disclosure that does not match its commitment");
            var peers = new List<int>();
            for (int q = 0; q < n; q++) if (q != p) peers.Add(q);
            return NetForensics.ParseDisclosure(o.GetValueOrDefault("w"), slots, rows, peers);
        }, deadlineMs);
    }
}
