// Detector receipts as tighten-only inputs (the reference detector-receipt.ts): content address, shape, policy check and the fold into a model
// signal. `suspicious` may lower a decision; `no_finding` is exactly equivalent to no receipt; an invalid receipt raises escalate, never ok.
// Signing and the vendor adapters are in Detectors.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Dataflow;

/// <summary>What <see cref="DetectorReceipts.Signal"/> reads. <see cref="Policy"/> is <c>{detectors:[{id, keys:[{pk, pq_pk?}], on_suspicious, categories?, max_age_ms}]}</c>.</summary>
public sealed class DetectorInput
{
    public IReadOnlyList<object?>? Receipts { get; init; }
    public object? Policy { get; init; }
    /// <summary>Digests (<see cref="Detectors.DetectorInputDigest"/>) of the content this action carries.</summary>
    public IReadOnlyList<string> InputDigests { get; init; } = Array.Empty<string>();
    public string? Session { get; init; }
    public long Now { get; init; }
}

/// <summary><see cref="Signal"/>: <c>ok</c>, <c>escalate</c> or <c>deny</c>, folded with <see cref="PcaDecision.Tighten"/>; <see cref="Detect"/> is the
/// <c>env.detect</c> object (<c>{id: flagged}</c> for every declared detector plus <c>invalid</c>: the rejected count).</summary>
public sealed record DetectorOutcome(string Signal, IReadOnlyDictionary<string, object?> Detect, IReadOnlyList<string> Flagged, IReadOnlyList<(int Index, string Reason)> Rejected);

public static class DetectorReceipts
{
    public const string RefDomain = "atlas-pca/detector-receipt-ref/v1";
    public const int MaxReceipts = 32;
    static System.Text.RegularExpressions.Regex IdRe => Rx.Get(@"\A[a-z][a-z0-9_]{0,63}\z", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>Content address of a receipt (signature included).</summary>
    public static string Ref(object? receipt) => Pca.HashCanonical(new D { ["d"] = RefDomain, ["receipt"] = receipt });

    /// <summary>Null when the receipt is well formed.</summary>
    public static string? ShapeError(object? r) => r is D d ? Detectors.ShapeError(d) : "receipt must be an object";

    static bool Ids(object? v) => v is string s && IdRe.IsMatch(s);

    /// <summary>Null when the policy is well formed.</summary>
    public static string? PolicyError(object? p)
    {
        if (p is not D pol || IntentArtifacts.ClosedMembers(pol, new[] { "detectors" }, Array.Empty<string>(), "policy") != null) return "policy must be {detectors}";
        if (pol["detectors"] is not L ds || ds.Count > 16) return "detectors must hold at most 16 entries";
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var o in ds)
        {
            if (o is not D d || IntentArtifacts.ClosedMembers(d, new[] { "id", "keys", "on_suspicious", "max_age_ms" }, new[] { "categories" }, "detector") != null) return "detector entry is malformed";
            if (d["id"] is not string id || !IdRe.IsMatch(id) || id == "invalid" || !ids.Add(id)) return "detector ids must be distinct ids other than \"invalid\"";
            if (d["keys"] is not L keys || keys.Count < 1 || keys.Count > 8 || !keys.All(k => k is D kd && kd.GetValueOrDefault("pk") is string && (!kd.ContainsKey("pq_pk") || kd["pq_pk"] is string)))
                return $"detector '{id}': keys must hold 1..8 pins";
            if (d["on_suspicious"] is not ("escalate" or "deny")) return $"detector '{id}': on_suspicious must be escalate or deny";
            if (d.ContainsKey("categories") && !(d["categories"] is L cs && cs.Count >= 1 && cs.All(Ids))) return $"detector '{id}': categories must be 1+ ids";
            if (!(IntentJs.IsSafeInteger(d["max_age_ms"]) && IntentJs.NumOf(d["max_age_ms"])!.Value is >= 1 and <= 86_400_000)) return $"detector '{id}': max_age_ms must be 1..86400000";
        }
        return null;
    }

    static int Rank(string s) => s switch { "ok" => 2, "escalate" => 1, _ => 0 };

    static string? ReceiptProblem(object? r, L detectors, IReadOnlyList<string> digests, string? session, long now)
    {
        var se = ShapeError(r);
        if (se != null) return "malformed: " + se;
        var rc = (D)r!;
        var det = (string)rc["detector"]!;
        var d = detectors.Cast<D>().FirstOrDefault(x => (string)x["id"]! == det);
        if (d == null) return $"undeclared detector '{det}'";
        var id = (string)d["id"]!;
        if (!((L)d["keys"]!).Cast<D>().Any(k => IntentArtifacts.VerifyArtifactSig(Detectors.ReceiptDomain, rc, k["pk"], k.GetValueOrDefault("pq_pk")))) return $"detector '{id}': no pinned key signed it";
        if (!digests.Contains((string)rc["input_digest"]!)) return $"detector '{id}': the receipt is about other content";
        if (rc.ContainsKey("session") && (string?)rc["session"] != session) return $"detector '{id}': bound to another session";
        var iat = IntentJs.NumOf(rc["iat"])!.Value;
        if (!(iat <= now)) return $"detector '{id}': from the future";
        if (!(now - iat <= IntentJs.NumOf(d["max_age_ms"])!.Value)) return $"detector '{id}': stale";
        return null;
    }

    /// <summary>The tighten-only fold of detector receipts. Total: a malformed policy is <c>deny</c>; per receipt: shape, declared detector, a pinned key's
    /// signature, content in the input digests, session, not from the future, not stale. A valid <c>suspicious</c> with an acting category lowers the
    /// signal to the detector's <c>on_suspicious</c>; a valid <c>no_finding</c> does nothing; an invalid receipt lowers it to <c>escalate</c>. The
    /// outcome with any receipts is at most the outcome with none.</summary>
    public static DetectorOutcome Signal(DetectorInput input)
    {
        var flagged = new SortedSet<string>(StringComparer.Ordinal);
        var rejected = new List<(int, string)>();
        var signal = "ok";
        void Lower(string s) { if (Rank(s) < Rank(signal)) signal = s; }
        var env = new Dictionary<string, object?>(StringComparer.Ordinal);
        try
        {
            var pe = PolicyError(input?.Policy);
            if (pe != null) return new DetectorOutcome("deny", new Dictionary<string, object?> { ["invalid"] = 0L }, Array.Empty<string>(), new List<(int, string)> { (-1, "policy: " + pe) });
            var detectors = (L)((D)input!.Policy!)["detectors"]!;
            foreach (D d in detectors) env[(string)d["id"]!] = false;
            var receipts = input.Receipts ?? Array.Empty<object?>();
            if (receipts.Count > MaxReceipts || input.Now < 0 || input.Now > Pca.MaxSafeInt)
            {
                Lower("escalate");
                rejected.Add((-1, "receipt list or clock malformed"));
            }
            else
            {
                for (var index = 0; index < receipts.Count; index++)
                {
                    var why = ReceiptProblem(receipts[index], detectors, input.InputDigests ?? Array.Empty<string>(), input.Session, input.Now);
                    if (why != null) { rejected.Add((index, why)); Lower("escalate"); continue; }
                    var rc = (D)receipts[index]!;
                    if ((string)rc["verdict"]! != "suspicious") continue;
                    var d = detectors.Cast<D>().First(x => (string)x["id"]! == (string)rc["detector"]!);
                    var cats = ((L)rc["categories"]!).Cast<string>().ToList();
                    if (d.ContainsKey("categories") && cats.Count > 0 && !cats.Any(c => ((L)d["categories"]!).Contains(c))) continue;
                    var did = (string)d["id"]!;
                    flagged.Add(did);
                    env[did] = true;
                    Lower((string)d["on_suspicious"]!);
                }
            }
        }
        catch (Exception e)
        {
            Lower("deny");
            rejected.Add((-1, "evaluation error (fail closed): " + e.Message));
        }
        env["invalid"] = (long)rejected.Count;
        return new DetectorOutcome(signal, env, flagged.ToList(), rejected);
    }
}
