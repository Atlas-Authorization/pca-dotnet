// Building, chaining, sharding and upgrade-verifying signed action packs, and the transparency statement payload of a pack.
using System.Globalization;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using SC = AtlasPca.Scitt.Scitt;

namespace AtlasPca.ActionsKit;

public static class ActionPacks
{
    public const int DefaultShardDefs = 512;
    public const int MaxPackDefs = 4096;
    public const string PackShardKind = "pca-action-pack-shard";

    /// <summary>Shard names are the resource family (resource.type first segment) of the defs, split in order into chunks of <paramref name="max"/> (null = the default).
    /// Returns a list of {name, defs}.</summary>
    public static L ShardDefs(IEnumerable<D> defs, object? max = null)
    {
        double m = max == null ? DefaultShardDefs : (IntentJs.IsSafeInteger(max) ? IntentJs.NumOf(max)!.Value : double.NaN);
        if (double.IsNaN(m) || m < 1) throw new ActionKitError("bad_shard_size", "the shard size must be a positive integer");
        var mx = (int)Math.Min(m, int.MaxValue);
        var fam = new Dictionary<string, List<D>>();
        foreach (var d in defs)
        {
            var f = ((string)((D)d["resource"]!)["type"]!).Split('.')[0];
            if (!fam.TryGetValue(f, out var l)) fam[f] = l = new List<D>();
            l.Add(d);
        }
        var outp = new L();
        foreach (var f in fam.Keys.OrderBy(x => x, StringComparer.Ordinal))
        {
            var l = fam[f];
            for (int i = 0, n = 1; i < l.Count; i += mx, n++)
                outp.Add(new D { ["name"] = l.Count > mx ? $"{f}-{n}" : f, ["defs"] = new L(l.Skip(i).Take(mx)) });
        }
        return outp;
    }

    static string? SortedUniqueDefsError(List<D> defs)
    {
        for (int i = 0; i < defs.Count; i++)
        {
            var e = Actions.ValidateDef(defs[i]);
            if (e != null) return $"def {i}: {e}";
            if (i > 0 && !(string.CompareOrdinal((string)defs[i - 1]["verb"]!, (string)defs[i]["verb"]!) < 0)) return $"defs must be sorted by verb and unique (at '{defs[i]["verb"]}')";
        }
        return null;
    }

    /// <summary>Build, chain and sign a pack. <paramref name="a"/> holds ns, version, stability, defs, source, kid and optionally prev: {pack, shards?} and shard: true | {max?}.
    /// Returns {pack, shards}. Throws ActionKitError on any inconsistency.</summary>
    public static D BuildPack(D a, byte[] secret, Dictionary<string, D>? reg = null, Func<D, bool>? attestationVerified = null, Func<string, string>? shardUri = null)
    {
        reg ??= Actions.CoreRegistry;
        var defs = ((L)a["defs"]!).Select(x => (D)x!).OrderBy(d => (string)d["verb"]!, StringComparer.Ordinal).ToList();
        var de = SortedUniqueDefsError(defs);
        if (de != null) throw new ActionKitError("bad_pack", de);
        if (defs.Count == 0) throw new ActionKitError("empty_pack", "a pack has at least one def");
        var prev = a.GetValueOrDefault("prev") as D;
        var prevDefs = new List<D>();
        if (prev != null)
        {
            var pp = (D)prev["pack"]!;
            prevDefs = Actions.PackDefs(pp, prev.GetValueOrDefault("shards") as D).Select(x => (D)x!).ToList();
            if (!IntentJs.JsonEquals(pp["ns"], a["ns"])) throw new ActionKitError("bad_chain", "the previous pack is of another namespace");
            if (Actions.CompareVersions((string)a["version"]!, (string)pp["version"]!) <= 0) throw new ActionKitError("bad_chain", "the version must increase");
        }
        var kid = (string)a["kid"]!;
        var records = ActionEvolve.EvolutionRecords((string)a["ns"]!, prevDefs, defs, reg, attestationVerified);
        var evolution = ActionEvolve.SignEvolution(records.Select(x => (D)x!), kid, secret);
        var root = Actions.PackRoot(defs.Select(Actions.DefDigest).ToList());
        var shardOpt = a.GetValueOrDefault("shard");
        var wantShards = a.ContainsKey("shard") && !(shardOpt is false) ? true : defs.Count > MaxPackDefs;
        var shards = new D();
        object body = new L(defs);
        if (wantShards)
        {
            var opts = shardOpt as D ?? new D();
            var refs = new L();
            foreach (var s0 in ShardDefs(defs, opts.GetValueOrDefault("max")))
            {
                var s = (D)s0!;
                var name = (string)s["name"]!;
                var doc = new D { ["v"] = 1L, ["kind"] = PackShardKind, ["ns"] = a["ns"], ["version"] = a["version"], ["name"] = name, ["defs"] = s["defs"] };
                shards[name] = doc;
                refs.Add(new D { ["name"] = name, ["digest"] = Actions.ShardDigest(doc), ["uri"] = shardUri != null ? shardUri(name) : $"shards/{name}.json" });
            }
            body = new D { ["shards"] = refs };
        }
        var unsigned = new D
        {
            ["v"] = 1L, ["kind"] = Actions.ActionPackKind, ["ns"] = a["ns"], ["version"] = a["version"], ["stability"] = a["stability"],
            ["traits_digest"] = Actions.TraitsDigest(reg), ["roles_digest"] = Actions.TablesDigest(), ["rules_digest"] = Actions.RulesDigest(),
            ["root"] = root, ["defs"] = body, ["source"] = a["source"], ["prev"] = prev != null ? Actions.PackDigest((D)prev["pack"]!) : null, ["evolution"] = evolution,
        };
        var pe = Actions.PackShapeError(unsigned, false);
        if (pe != null) throw new ActionKitError("bad_pack", pe);
        var sig = new D { ["alg"] = "ed25519", ["kid"] = kid, ["value"] = Pca.B64u(EdKey.FromSeed(secret).Sign(IntentJs.Message(Actions.PackSigDomain, unsigned))) };
        var pack = new D(unsigned) { ["sig"] = sig };
        return new D { ["pack"] = pack, ["shards"] = shards };
    }

    /// <summary>Verify <paramref name="next"/> as the successor of <paramref name="prev"/>: both verify, same namespace, next.prev is prev's digest, the version
    /// increases, and the signed evolution is EXACTLY the computed change. The vocabulary is the core trait registry.</summary>
    public static D VerifyUpgrade(object? prev, object? next, object? keys, D? prevShards = null, D? shards = null, Func<D, bool>? attestationVerified = null)
    {
        D Fail(string r) => new() { ["ok"] = false, ["reason"] = r };
        var a = Actions.VerifyPack(prev, keys, prevShards);
        if (a["ok"] is not true) return Fail("previous pack: " + a["reason"]);
        var b = Actions.VerifyPack(next, keys, shards);
        if (b["ok"] is not true) return Fail("pack: " + b["reason"]);
        var p = (D)prev!; var n = (D)next!;
        if (!IntentJs.JsonEquals(n["ns"], p["ns"])) return Fail("the packs are of different namespaces");
        if (!IntentJs.JsonEquals(n["prev"], a["digest"])) return Fail("chain gap: prev does not name the previous pack");
        if (Actions.CompareVersions((string)n["version"]!, (string)p["version"]!) <= 0) return Fail("the version does not increase");
        var ee = ActionEvolve.EvolutionError((string)n["ns"]!, ((L)a["defs"]!).Select(x => (D)x!), ((L)b["defs"]!).Select(x => (D)x!), (L)n["evolution"]!, keys, Actions.CoreRegistry, attestationVerified);
        return ee == null ? new D { ["ok"] = true } : Fail(ee);
    }
}

public static class ActionTransparency
{
    public const string PackStatementContentType = "application/pca-action-pack+json";

    /// <summary>The payload the registry signs into the log (small: the digest, not the pack).</summary>
    public static D PackStatementPayload(D p) => new()
    {
        ["v"] = 1L, ["kind"] = "pca-action-pack-statement", ["ns"] = p["ns"], ["version"] = p["version"], ["digest"] = Actions.PackDigest(p), ["root"] = p["root"], ["prev"] = p["prev"],
    };

    /// <summary>What <see cref="AppendPackToLog"/> returns.</summary>
    public sealed record PackLogEntry(byte[] Statement, byte[] Receipt, long Index, string Root);

    /// <summary>Sign the pack's statement with the registry's COSE key and register it in the log.</summary>
    public static PackLogEntry AppendPackToLog(D pack, AtlasPca.Scitt.TransparencyService service, string alg, AtlasPca.Scitt.CoseKey key, string issuer)
    {
        var statement = SC.SignStatement(PackStatementPayload(pack),
            new AtlasPca.Scitt.SignStatementOpts(alg, key, issuer, $"{pack["ns"]}@{pack["version"]}", PackStatementContentType));
        var r = AtlasPca.Scitt.TransparencyService.RegisterStatement(statement, service);
        return new PackLogEntry(statement, r.Receipt, r.Index, r.Root);
    }

    /// <summary>Does the entry prove <paramref name="pack"/> is in the log? The statement must be the pack's own and signed by the registry, the receipt by the log. Never throws.</summary>
    public static bool VerifyPackLogEntry(D pack, byte[] statement, byte[] receipt, AtlasPca.Scitt.CoseKey registry, AtlasPca.Scitt.CoseKey log, string? treeRoot = null)
    {
        try
        {
            return SC.VerifyReceipt(receipt, statement, new AtlasPca.Scitt.VerifyReceiptOpts(treeRoot, log, registry))
                && SC.StatementPayload(statement).AsSpan().SequenceEqual(Pca.Canon(PackStatementPayload(pack)));
        }
        catch (Exception) { return false; }
    }
}
