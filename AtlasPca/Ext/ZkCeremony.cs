// Circuit provenance and trusted-setup ceremony bookkeeping of the zk module (the reference zk-ceremony): the verifying-key id, the provenance record of a
// circuit build and its check, the transcript digest, the well-formedness check of a multi-party ceremony transcript (contribution chain, random beacon, final
// key) and the single-party / multi-party classification of a verifying key. Pure: records and transcripts are parsed JSON trees, read as the reference reads
// them, so a hostile record is an answer, not an exception.
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class ZkCeremony
{
    public const string SingleParty = "single-party";
    public const string MultiParty = "multi-party";

    static bool H64(string s) => s.Length == 64 && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    /// <summary>The member, as text, is 64 lowercase hex characters (an absent member is not).</summary>
    static bool H64Of(D d, string k) => d.TryGetValue(k, out var v) && H64(JsX.Str(v));

    static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    /// <summary>The id of a verifying key: <c>vk_</c> and the SHA-256 (hex) of its canonical JSON.</summary>
    public static string VkId(object? vkey) => "vk_" + Hex(Pca.Sha(Pca.Canon(vkey)));

    /// <summary>The provenance record {circuit, sourceSha256, r1csSha256, vkId} of a circuit build. <paramref name="args"/> is {circuit, sourceSha256, r1csSha256, vkey};
    /// throws when a hash is not a SHA-256, the circuit id is empty or the key is absent.</summary>
    public static D CircuitProvenance(D args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (!H64Of(args, "sourceSha256") || !H64Of(args, "r1csSha256") || args.GetValueOrDefault("circuit") is "") throw new ArgumentException("circuitProvenance: bad circuit id or hash");
        if (!args.TryGetValue("vkey", out var vkey)) throw new ArgumentException("circuitProvenance: a verifying key is required");
        return new D { ["circuit"] = args.GetValueOrDefault("circuit"), ["sourceSha256"] = args["sourceSha256"], ["r1csSha256"] = args["r1csSha256"], ["vkId"] = VkId(vkey) };
    }

    /// <summary><see cref="CircuitProvenance(D)"/> from its parts.</summary>
    public static D CircuitProvenance(string circuit, string sourceSha256, string r1csSha256, object? vkey) =>
        CircuitProvenance(new D { ["circuit"] = circuit, ["sourceSha256"] = sourceSha256, ["r1csSha256"] = r1csSha256, ["vkey"] = vkey });

    /// <summary>The member of a record, or undefined: a member the pinned build lacks only equals one the record lacks too.</summary>
    static object? Member(D d, string k) => d.TryGetValue(k, out var v) ? v : JsX.Undef;

    /// <summary>Checks a provenance record against the pinned build <paramref name="expect"/> = {circuit, sourceSha256, r1csSha256?, vkey}: null when it matches,
    /// else the first reason, in the order circuit, sources, constraint system, key. The pinned build is read as given: a record never equals a circuit id or
    /// source hash the build does not carry, and a build without its key throws once the comparison reaches the key.</summary>
    public static string? CheckCircuitProvenance(object? prov, D expect)
    {
        var p = prov as D ?? (prov is L ? new D() : null);
        if (p == null) return "not a provenance record";
        ArgumentNullException.ThrowIfNull(expect);
        if (!Ledger.Same(Member(p, "circuit"), Member(expect, "circuit"))) return "record is for another circuit";
        if (!Ledger.Same(Member(p, "sourceSha256"), Member(expect, "sourceSha256"))) return "circuit sources differ from the pinned version";
        if (p.GetValueOrDefault("r1csSha256") is not string r1 || !H64(r1) || (expect.TryGetValue("r1csSha256", out var er) && !Ledger.Same(r1, er))) return "constraint system differs";
        if (!expect.TryGetValue("vkey", out var vkey)) throw new ArgumentException("checkCircuitProvenance: the pinned build carries no verifying key");
        if (p.GetValueOrDefault("vkId") as string != VkId(vkey)) return "verifying key is not the recorded one";
        return null;
    }

    /// <summary>The SHA-256 (hex) of a transcript's canonical JSON.</summary>
    public static string TranscriptSha256(object? transcript) => Hex(Pca.Sha(Pca.Canon(transcript)));

    /// <summary>Checks a version-1 ceremony transcript: null when it is well formed, else the first reason. <paramref name="opts"/> = {minContributions?, r1csSha256?,
    /// circuit?}; at least max(2, opts.minContributions, the transcript's own minContributions) contributions are required, each chaining from the previous key
    /// with a distinct name and key, then a random beacon applied after the last one whose output is the final key, and a verifying-key id. An
    /// opts.minContributions that is not a number is read as the number it converts to; one that converts to none leaves no minimum to compare.</summary>
    public static string? CheckTranscript(object? transcript, D? opts = null)
    {
        opts ??= new D();
        if (transcript is not D x || IntentJs.NumOf(x.GetValueOrDefault("version")) != 1) return "not a version-1 transcript";
        if (x.GetValueOrDefault("circuit") is not string circuit || circuit == "") return "no circuit id";
        if (opts.TryGetValue("circuit", out var oc) && !Ledger.Same(circuit, oc)) return "transcript is for another circuit";
        if (x.GetValueOrDefault("curve") is not ("bn128" or "bls12-381")) return "unknown curve";
        foreach (var k in new[] { "r1csSha256", "ptauSha256", "initZkeySha256" })
            if (!H64Of(x, k)) return k + " is not a SHA-256";
        if (opts.TryGetValue("r1csSha256", out var or1) && !Ledger.Same(x["r1csSha256"], or1)) return "transcript is for a different constraint system";
        double want = opts.GetValueOrDefault("minContributions") is { } om ? AtlasPca.Js.JsJson.ToJsNumber(om) : 2;
        var own = x.GetValueOrDefault("minContributions");
        // NaN (a minimum that is no number) makes the comparison below false, as in the reference: the count is then not checked
        double min = Math.Max(2, Math.Max(want, IntentJs.IsSafeInteger(own) ? IntentJs.NumOf(own)!.Value : 2));
        if (x.GetValueOrDefault("contributions") is not L cs || cs.Count < min) return $"fewer than {JsX.Str(min)} contributions";
        var names = new HashSet<string>(StringComparer.Ordinal);
        var keys = new HashSet<string>(StringComparer.Ordinal);
        object? prev = x["initZkeySha256"];
        for (int i = 0; i < cs.Count; i++)
        {
            if (cs[i] is not D c || IntentJs.NumOf(c.GetValueOrDefault("index")) is not double ix || ix != i || IntentJs.IsNegZero(ix) || c.GetValueOrDefault("name") is not string name || name == "")
                return $"contribution {i} is malformed";
            if (!H64Of(c, "zkeySha256") || !Ledger.Same(c.GetValueOrDefault("prevZkeySha256"), prev)) return $"contribution {i} does not chain from the previous key";
            var key = c["zkeySha256"];
            if (names.Contains(name) || (key is string ks && keys.Contains(ks))) return $"contribution {i} repeats a name or key";
            names.Add(name);
            if (key is string k2) keys.Add(k2);
            prev = key;
        }
        if (x.GetValueOrDefault("beacon") is not D b || !H64Of(b, "hashHex") || !IntentJs.IsSafeInteger(b.GetValueOrDefault("iterationsExp"))
            || IntentJs.NumOf(b["iterationsExp"]) is not double it || it < 10 || it > 63) return "no valid random beacon";
        if (!Ledger.Same(b.GetValueOrDefault("prevZkeySha256"), prev) || !H64Of(b, "zkeySha256")) return "beacon is not applied after the last contribution";
        if (!Ledger.Same(x.GetValueOrDefault("finalZkeySha256"), b["zkeySha256"])) return "final key is not the beacon output";
        if (x.GetValueOrDefault("vkId") is not string vk || vk.Length != 67 || !vk.StartsWith("vk_", StringComparison.Ordinal) || !H64(vk[3..])) return "no verifying-key id";
        return null;
    }

    /// <summary><c>multi-party</c> only when <paramref name="evidence"/> = {transcript, sha256, r1csSha256?, circuit?} holds a well-formed transcript whose digest
    /// is the pinned <c>sha256</c> and which names this verifying key (and the pinned constraint system and circuit when given); anything else, and any error,
    /// is <c>single-party</c>.</summary>
    public static string CeremonyOf(object? vkey, object? evidence = null)
    {
        try
        {
            if (!JsX.Truthy(vkey) || evidence is not D ev) return SingleParty;
            var opts = new D();
            if (ev.TryGetValue("r1csSha256", out var r1)) opts["r1csSha256"] = r1;
            if (ev.TryGetValue("circuit", out var circuit)) opts["circuit"] = circuit;
            if (ev.GetValueOrDefault("transcript") is not D t || CheckTranscript(t, opts) != null) return SingleParty;
            if (ev.GetValueOrDefault("sha256") as string != TranscriptSha256(t) || t.GetValueOrDefault("vkId") as string != VkId(vkey)) return SingleParty;
            return MultiParty;
        }
        catch (Exception) { return SingleParty; }
    }
}
