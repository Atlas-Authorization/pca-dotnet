// Action receipts (the reference receipt.ts): the principal's own hash-chained log of what their agents did and how each action was
// verified. Each receipt commits to the previous one, so a dropped or altered entry is detectable. Pure (hashing only).
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The outcome of <see cref="ActionReceipts.VerifyReceiptChain"/>: <c>BrokenAt</c> is the seq of the first broken link.</summary>
public sealed record ReceiptChainCheck(bool Ok, long? BrokenAt = null, string? Reason = null);

public static class ActionReceipts
{
    const string Domain = "atlas-pca/receipt/v1";

    static JD Body(JD r) => new()
    {
        ["d"] = Domain, ["seq"] = r.GetValueOrDefault("seq"), ["at"] = r.GetValueOrDefault("at"), ["actionDigest"] = r.GetValueOrDefault("actionDigest"),
        ["verb"] = r.GetValueOrDefault("verb"), ["resource"] = r.GetValueOrDefault("resource"), ["outcome"] = r.GetValueOrDefault("outcome"),
        ["checks"] = r.GetValueOrDefault("checks"), ["prev"] = r.GetValueOrDefault("prev"),
    };

    /// <summary>The next receipt of a chain for a verified action: <paramref name="prevHash"/> is the previous receipt's hash (empty for the first),
    /// <paramref name="pcactn"/> the presented PCActn, <paramref name="checks"/> the verifier's per-check map (optional, for drill-down).</summary>
    public static JD ReceiptFor(string prevHash, long seq, JD pcactn, bool allow, IReadOnlyDictionary<string, string>? checks = null, long? at = null)
    {
        var action = pcactn.GetValueOrDefault("action") as JD ?? throw new ArgumentException("receiptFor: the PCActn has no action");
        var r = new JD
        {
            ["seq"] = new Num(seq.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            ["at"] = at is { } a ? new Num(a.ToString(System.Globalization.CultureInfo.InvariantCulture)) : pcactn["iat"],
            ["actionDigest"] = Pca.HashCanonical(pcactn),
            ["verb"] = action["verb"], ["resource"] = action["resource"], ["outcome"] = allow ? "allow" : "deny",
        };
        if (checks != null) r["checks"] = checks.ToDictionary(kv => kv.Key, kv => (object?)kv.Value);
        r["prev"] = prevHash;
        r["hash"] = Pca.HashCanonical(Body(r));
        return r;
    }

    /// <summary>Append a verified action to a receipt log (a new list), chaining to the last entry.</summary>
    public static List<JD> AppendReceipt(IReadOnlyList<JD> log, JD pcactn, bool allow, IReadOnlyDictionary<string, string>? checks = null, long? at = null)
    {
        var last = log.Count > 0 ? log[^1] : null;
        var seq = last == null ? 0 : (long)IntentJs.NumOf(last["seq"])! + 1;
        return new List<JD>(log) { ReceiptFor(last?["hash"] as string ?? "", seq, pcactn, allow, checks, at) };
    }

    /// <summary>The head hash of a log: one value that commits to the entire history (empty for an empty log).</summary>
    public static string ReceiptHead(IReadOnlyList<JD> log) => log.Count > 0 ? (log[^1]["hash"] as string ?? "") : "";

    /// <summary>Verify a receipt log is an intact hash chain: sequential, correctly linked, every hash matching its body.</summary>
    public static ReceiptChainCheck VerifyReceiptChain(IReadOnlyList<JD> log)
    {
        var prev = "";
        for (var i = 0; i < log.Count; i++)
        {
            var r = log[i];
            var seq = IntentJs.NumOf(r.GetValueOrDefault("seq"));
            var shown = seq is { } s ? (long)s : -1;
            if (seq != i) return new(false, shown, $"seq {shown} out of order (expected {i})");
            if (r.GetValueOrDefault("prev") as string != prev) return new(false, shown, $"prev link mismatch at seq {shown}");
            if (Pca.HashCanonical(Body(r)) != r.GetValueOrDefault("hash") as string) return new(false, shown, $"hash mismatch at seq {shown} (tampered body)");
            prev = (string)r["hash"]!;
        }
        return new(true);
    }
}
