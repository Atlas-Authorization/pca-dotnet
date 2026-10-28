// Action-kit registry layer (native port, mirrors atlas_pca/actions_registry.py): signed evolution records, principal re-approvals, the grant pin
// decision, signed packs (with shards), pack inclusion proofs, the rollback tracker and rule 22 over a whole v2 document. Natives verify
// signatures, digests and pins; they do NOT recompute the semantic diff. Pure and total: malformed input is a refusal.
using System.Text.RegularExpressions;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static partial class Actions
{
    public const string ActionPackKind = "pca-action-pack";
    public const string EvolutionRecordKind = "pca-evolution-record";
    public const string ReapprovalKind = "pca-reapproval";
    public const string EvolutionDomain = "atlas-pca/action-evolution/v1\0";
    public const string EvolutionDiffDomain = "atlas-pca/action-evolution-diff/v1";
    public const string ReapprovalDomain = "atlas-pca/action-reapproval/v1\0";
    public const string PackSigDomain = "atlas-pca/action-pack/v1\0";
    public const string PackRefDomain = "atlas-pca/action-pack-ref/v1";
    public const string PackShardDomain = "atlas-pca/action-pack-shard/v1";
    public const string RulesDigestDomain = "atlas-pca/action-rules/v1";
    public const string PackShardKind = "pca-action-pack-shard";
    const int MaxEvolutionSteps = 32, MaxEvolutionRecords = 65536;
    static readonly string[] EvolutionClasses = { "equal", "narrow", "widen", "incomparable", "added", "removed" };
    static readonly string[] Stabilities = { "draft", "beta", "stable" };

    static readonly Regex B64u43 = new(@"\A[A-Za-z0-9_-]{43}\z", RegexOptions.CultureInvariant);
    static readonly Regex NsRe = new(@"\A[a-z0-9_]+(?:\.[a-z0-9_]+){0,5}\z", RegexOptions.CultureInvariant);
    static readonly Regex RegVerbRe = new(@"\A[a-z0-9_]+(?:\.[a-z0-9_]+){1,5}\z", RegexOptions.CultureInvariant);
    static readonly Regex SemverRe = new(@"\A(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\z", RegexOptions.CultureInvariant);
    static readonly Regex ShardNameRe = new(@"\A[a-z0-9_]+(?:[.-][a-z0-9_]+){0,7}\z", RegexOptions.CultureInvariant);

    static bool Sha(object? x) => x is string s && B64u43.IsMatch(s);
    static bool Is1(object? v) => IsInt(v) && I(v) == 1;
    static bool Tier(object? x) => IsInt(x) && I(x) >= 0 && I(x) <= 3;
    static string? Closed(D o, params string[] allowed) { foreach (var k in o.Keys) if (!allowed.Contains(k)) return $"unknown member '{k}'"; return null; }
    static string[] With(string[] a, bool extra, string e) => extra ? a.Append(e).ToArray() : a;
    static D Without(D o, string k) { var b = new D(o); b.Remove(k); return b; }
    static int Utf16Cmp(string a, string b) => string.CompareOrdinal(a, b);

    // ---- evolution records ---------------------------------------------------------------------------------------------------------
    public static string? EvolutionRecordError(object? xo, bool signed = true)
    {
        if (xo is not D x) return "evolution record must be an object";
        var u = Closed(x, With(new[] { "v", "kind", "ns", "verb", "from", "to", "class", "reasons" }, signed, "sig"));
        if (u != null) return "evolution record: " + u;
        if (!Is1(G(x, "v")) || G(x, "kind") as string != EvolutionRecordKind) return "evolution record: bad v/kind";
        if (G(x, "ns") is not string ns || !NsRe.IsMatch(ns)) return "evolution record: bad ns";
        if (G(x, "verb") is not string vb || !RegVerbRe.IsMatch(vb)) return "evolution record: bad verb";
        if (G(x, "from") != null && !Sha(G(x, "from"))) return "evolution record: bad from";
        if (G(x, "to") != null && !Sha(G(x, "to"))) return "evolution record: bad to";
        if (G(x, "class") is not string c || !EvolutionClasses.Contains(c)) return "evolution record: bad class";
        if ((c == "added") != (G(x, "from") == null) || (c == "removed") != (G(x, "to") == null)) return "evolution record: endpoints do not match the class";
        if (G(x, "reasons") is not L r || r.Count > 64 || r.Any(e => e is not string s || s.Length > 512)) return "evolution record: bad reasons";
        if (signed)
        {
            if (G(x, "sig") is not D s || Closed(s, "alg", "kid", "value", "pq_value") != null) return "evolution record: bad sig";
            if (G(s, "kid") is not string kid || kid.Length == 0 || kid.Length > 128 || G(s, "value") is not string || G(s, "alg") is not string) return "evolution record: bad sig";
            if (s.ContainsKey("pq_value") && s["pq_value"] is not string) return "evolution record: bad sig";
        }
        try { Pca.HashCanonical(Without(x, "sig")); } catch (Exception e) { return "evolution record: " + e.Message; }
        return null;
    }

    public static string EvolutionDiffDigest(D r) =>
        Pca.HashCanonical(new D { ["d"] = EvolutionDiffDomain, ["ns"] = r["ns"], ["verb"] = r["verb"], ["from"] = r["from"], ["to"] = r["to"], ["class"] = r["class"], ["reasons"] = r["reasons"] });

    /// <summary>Verify a registry-signed body under <paramref name="domain"/> against the pinned registry keys (suite from the KEY entry). Null = valid, else the reason. Total.</summary>
    public static string? VerifyRegistrySig(string domain, D body, D sig, object? keys)
    {
        try
        {
            if (keys is not L kl) return "the registry keys must be an array";
            var key = kl.Select(k => k as D).FirstOrDefault(k => k != null && G(k, "kid") is string kid && kid == G(sig, "kid") as string);
            if (key == null) return $"no registry key with kid '{G(sig, "kid")}'";
            if (key.ContainsKey("pq_pk") && key["pq_pk"] is not string) return "the registry key pq_pk must be a string";
            if (Pca.B64uDecode(G(key, "pk"), 32) == null) return "registry key pk is not canonical base64url (32 bytes)";
            var ka = IntentJs.SuiteOf(key);
            if (ka == null || ka != IntentJs.SuiteOf(sig)) return "sig.alg does not match the pinned key suite";
            var pk = (string)key["pk"]!;
            var pin = key.ContainsKey("pq_pk") ? IntentJs.Pin(pk, key["pq_pk"]) : null;
            if (!IntentJs.VerifyPinnedSuite(ka, true, pk, G(key, "pq_pk"), IntentJs.Message(domain, body), G(sig, "value"), G(sig, "pq_value"), pin)) return "signature invalid";
            return null;
        }
        catch (Exception e) { return "verification error: " + e.Message; }
    }

    /// <summary>Null = the record is well formed and signed by a pinned registry key.</summary>
    public static string? VerifyEvolutionRecord(object? rec, object? keys)
    {
        var bad = EvolutionRecordError(rec);
        if (bad != null) return bad;
        var r = (D)rec!;
        return VerifyRegistrySig(EvolutionDomain, Without(r, "sig"), (D)r["sig"]!, keys);
    }

    public static bool ReapprovalValid(object? ro, object? grantId, object? issuer, object? verb, object? diff)
    {
        try
        {
            if (ro is not D r || Closed(r, "v", "kind", "grant", "verb", "diff", "sig") != null) return false;
            if (!Is1(G(r, "v")) || G(r, "kind") as string != ReapprovalKind || !Eq(r, "grant", grantId) || !Eq(r, "verb", verb) || !Eq(r, "diff", diff)) return false;
            if (G(r, "sig") is not D s || Closed(s, "alg", "value") != null || G(s, "alg") as string != "ed25519" || G(s, "value") is not string || issuer is not string iss) return false;
            return IntentJs.VerifyPinnedSuite("ed25519", false, iss, null, IntentJs.Message(ReapprovalDomain, Without(r, "sig")), s["value"], null, null);
        }
        catch { return false; }
    }
    static bool Eq(D o, string k, object? want) => o.TryGetValue(k, out var v) && v is string a && want is string b && a == b;

    // ---- the pin ---------------------------------------------------------------------------------------------------------------------
    public static string? ActionPinError(object? xo)
    {
        if (xo is not D x) return "actions must be an object";
        var u = Closed(x, "pack", "defs", "on_new_action", "max_esc", "preauth_esc", "caveats");
        if (u != null) return "actions: " + u;
        if (G(x, "pack") is not D p || Closed(p, "ns", "root") != null) return "actions.pack must be {ns, root}";
        if (G(p, "ns") is not string ns || !NsRe.IsMatch(ns)) return "actions.pack.ns is not a namespace";
        if (!Sha(G(p, "root"))) return "actions.pack.root must be a base64url digest";
        if (G(x, "on_new_action") is not string on || (on != "deny" && on != "escalate")) return "actions.on_new_action must be 'deny' or 'escalate'";
        if (x.ContainsKey("max_esc") && !Tier(x["max_esc"])) return "actions.max_esc must be an integer tier 0..3";
        if (x.ContainsKey("preauth_esc") && !Tier(x["preauth_esc"])) return "actions.preauth_esc must be an integer tier 0..3";
        if (Tier(G(x, "max_esc")) && Tier(G(x, "preauth_esc")) && I(x["preauth_esc"]) > I(x["max_esc"])) return "actions.preauth_esc exceeds actions.max_esc";
        if (x.ContainsKey("caveats"))
        {
            if (x["caveats"] is not L c || c.Any(k => k is not string s || !CaveatKinds.Contains(s)) || c.Distinct().Count() != c.Count) return "actions.caveats must be distinct caveat kinds";
        }
        if (x.ContainsKey("defs"))
        {
            if (x["defs"] is not D ds) return "actions.defs must be an object";
            foreach (var (verb, d) in ds)
            {
                if (!RegVerbRe.IsMatch(verb)) return $"actions.defs: '{verb}' is not a verb";
                if (!Sha(d)) return $"actions.defs.{verb} must be a base64url digest";
            }
        }
        return null;
    }

    static D Deny(string code, string reason, bool escalate = false, string? needs = null)
    {
        var o = new D { ["ok"] = false, ["code"] = code, ["escalate"] = escalate, ["reason"] = reason };
        if (needs != null) o["needs_reapproval"] = needs;
        return o;
    }

    /// <summary>Decide the pin for one verb: exact digest, pack root, or a chain of verified equal/narrow (or principal-approved) evolution steps. Input keys: pin, doc, verb, records, keys, reapprovals, grant.</summary>
    public static D DecidePin(D i)
    {
        try
        {
            var pe = ActionPinError(G(i, "pin"));
            if (pe != null) return Deny("bad_pin", pe);
            var pin = (D)i["pin"]!;
            var pack = (D)pin["pack"]!;
            var doc = i["doc"];
            var verb = (string)i["verb"]!;
            var v = G(doc, "verbs") is L vs ? vs.Select(x => x as D).FirstOrDefault(x => x != null && G(x, "verb") is string s && s == verb) : null;
            if (v == null) return Deny("unknown_verb", $"the accepted schema does not declare '{verb}'");
            var pk = G(doc, "pack") as D;
            if (pk == null || !(G(pk, "ns") is string pns && pns == (string)pack["ns"]!)) return Deny("pack_mismatch", $"the schema does not come from the pinned pack '{pack["ns"]}'");
            if (!pin.ContainsKey("defs"))
                return G(pk, "root") is string r && r == (string)pack["root"]! ? new D { ["ok"] = true, ["via"] = "pack" } : Deny("pack_mismatch", "the pack root differs from the pinned root (the grant pins the pack as a whole)");
            var defs = (D)pin["defs"]!;
            if (!defs.ContainsKey(verb)) return Deny("new_action", $"the grant does not name '{verb}' (on_new_action: {pin["on_new_action"]})", (string)pin["on_new_action"]! == "escalate");
            var pinned = (string)defs[verb]!;
            if (G(v, "def") is not string presented) return Deny("def_changed", "the schema verb carries no definition digest");
            if (presented == pinned) return new D { ["ok"] = true, ["via"] = "exact" };
            var edges = new Dictionary<string, List<(string To, string? Blocked)>>();
            var keys = G(i, "keys");
            var grant = (D)i["grant"]!;
            var reaps = G(i, "reapprovals") as L ?? new L();
            foreach (var ro in G(i, "records") as L ?? new L())
            {
                if (VerifyEvolutionRecord(ro, keys) != null) continue;
                var r = (D)ro!;
                if ((string)r["ns"]! != (string)pack["ns"]! || (string)r["verb"]! != verb || r["from"] == null || r["to"] == null) continue;
                var diff = EvolutionDiffDigest(r);
                var cls = (string)r["class"]!;
                bool approved = cls == "equal" || cls == "narrow" || reaps.Any(a => ReapprovalValid(a, G(grant, "id"), G(grant, "issuer"), verb, diff));
                var from = (string)r["from"]!;
                if (!edges.TryGetValue(from, out var list)) edges[from] = list = new();
                list.Add(((string)r["to"]!, approved ? null : diff));
            }
            Dictionary<string, (string From, string? Blocked)> Search(bool usableOnly)
            {
                var parent = new Dictionary<string, (string, string?)>();
                var seen = new HashSet<string> { pinned };
                var frontier = new List<string> { pinned };
                for (int step = 0; step < MaxEvolutionSteps && frontier.Count > 0 && !parent.ContainsKey(presented); step++)
                {
                    var next = new List<string>();
                    foreach (var f in frontier)
                        foreach (var e in edges.GetValueOrDefault(f) ?? new())
                        {
                            if (seen.Contains(e.To) || (usableOnly && e.Blocked != null)) continue;
                            seen.Add(e.To);
                            parent[e.To] = (f, e.Blocked);
                            next.Add(e.To);
                        }
                    frontier = next;
                }
                return parent;
            }
            if (Search(true).ContainsKey(presented)) return new D { ["ok"] = true, ["via"] = "chain" };
            var all = Search(false);
            if (all.ContainsKey(presented))
            {
                string? first = null;
                for (var cur = presented; cur != pinned;) { var p = all[cur]; if (p.Blocked != null) first = p.Blocked; cur = p.From; }
                return Deny("def_changed", "the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve", false, first);
            }
            return Deny("def_changed", "the definition differs from the pinned digest and no signed evolution record chains to it");
        }
        catch (Exception e) { return Deny("bad_pin", "pin evaluation error (fail closed): " + e.Message); }
    }

    // ---- signed packs ----------------------------------------------------------------------------------------------------------------
    public static int CompareVersions(string a, string b)
    {
        var pa = SemverRe.Match(a); var pb = SemverRe.Match(b);
        if (!pa.Success || !pb.Success) throw new ActionKitError("bad_version", $"'{(!pa.Success ? a : b)}' is not MAJOR.MINOR.PATCH");
        for (int k = 1; k <= 3; k++) { int d = int.Parse(pa.Groups[k].Value) - int.Parse(pb.Groups[k].Value); if (d != 0) return d; }
        return 0;
    }

    public static string RulesDigest() => Pca.HashCanonical(new D { ["d"] = RulesDigestDomain, ["prules"] = ToL(ParamRuleIds), ["caveats"] = ToL(CaveatKinds), ["context"] = ToL(ContextKeys) });
    public static string PackDigest(D p) => Pca.HashCanonical(new D { ["d"] = PackRefDomain, ["p"] = p });
    public static string ShardDigest(D s) => Pca.HashCanonical(new D { ["d"] = PackShardDomain, ["s"] = s });

    static string? SortedUniqueDefsError(IList<object?> defs)
    {
        for (int i = 0; i < defs.Count; i++)
        {
            var e = ValidateDef(defs[i]);
            if (e != null) return $"def {i}: {e}";
            if (i > 0 && !(Utf16Cmp((string)((D)defs[i - 1]!)["verb"]!, (string)((D)defs[i]!)["verb"]!) < 0)) return $"defs must be sorted by verb and unique (at '{((D)defs[i]!)["verb"]}')";
        }
        return null;
    }

    public static string? PackShapeError(object? xo, bool signed = true)
    {
        try
        {
            if (xo is not D x) return "pack must be an object";
            var e = Closed(x, With(new[] { "v", "kind", "ns", "version", "stability", "traits_digest", "roles_digest", "rules_digest", "root", "defs", "source", "prev", "evolution" }, signed, "sig"));
            if (e != null) return "pack: " + e;
            if (!Is1(G(x, "v")) || G(x, "kind") as string != ActionPackKind) return "pack: bad v/kind";
            if (G(x, "ns") is not string ns || !NsRe.IsMatch(ns)) return "pack: bad ns";
            if (G(x, "version") is not string ver || !SemverRe.IsMatch(ver)) return "pack: version must be MAJOR.MINOR.PATCH";
            if (G(x, "stability") is not string st || !Stabilities.Contains(st)) return "pack: bad stability";
            foreach (var k in new[] { "traits_digest", "roles_digest", "rules_digest", "root" }) if (!Sha(G(x, k))) return $"pack: {k} must be a base64url digest";
            if (G(x, "prev") != null && !Sha(G(x, "prev"))) return "pack: bad prev";
            if (G(x, "source") is not D s || Closed(s, "kind", "uri", "spec_digest", "licence", "licence_notes") != null) return "pack: source must be {kind, uri, spec_digest, licence, licence_notes}";
            foreach (var k in new[] { "kind", "uri", "spec_digest", "licence", "licence_notes" })
                if (G(s, k) is not string sv || (k != "licence_notes" && sv.Length == 0) || sv.Length > 2048) return $"pack: source.{k} is not a string of 1..2048 characters";
            var d = G(x, "defs");
            if (d is L dl)
            {
                if (dl.Count == 0 || dl.Count > 4096) return "pack: inline defs must number 1..4096 (larger packs are sharded)";
                var de = SortedUniqueDefsError(dl);
                if (de != null) return "pack: " + de;
            }
            else
            {
                if (d is not D dd || Closed(dd, "shards") != null || G(dd, "shards") is not L sh || sh.Count == 0 || sh.Count > 4096) return "pack: defs must be a list of defs or {shards}";
                var names = new HashSet<string>();
                foreach (var ro in sh)
                {
                    if (ro is not D r || Closed(r, "name", "digest", "uri") != null) return "pack: bad shard ref";
                    if (G(r, "name") is not string nm || !ShardNameRe.IsMatch(nm) || !names.Add(nm)) return "pack: shard names must be distinct simple names";
                    if (!Sha(G(r, "digest")) || G(r, "uri") is not string uri || uri.Length == 0 || uri.Length > 2048) return "pack: bad shard digest or uri";
                }
            }
            if (G(x, "evolution") is not L ev || ev.Count > MaxEvolutionRecords) return "pack: evolution must be a list of records";
            foreach (var r in ev) { var re = EvolutionRecordError(r); if (re != null) return "pack: " + re; }
            if (signed && (G(x, "sig") is not D g || Closed(g, "alg", "kid", "value", "pq_value") != null || G(g, "kid") is not string || G(g, "value") is not string || G(g, "alg") is not string)) return "pack: bad sig";
            Pca.HashCanonical(Without(x, "sig"));
            return null;
        }
        catch (Exception err) { return "pack: " + err.Message; }
    }

    public static List<object?> PackDefs(D pack, D? shards = null)
    {
        if (pack["defs"] is L l) return new List<object?>(l);
        var all = new List<object?>();
        foreach (var ro in (L)((D)pack["defs"]!)["shards"]!)
        {
            var r = (D)ro!;
            var name = (string)r["name"]!;
            if (shards == null || !shards.TryGetValue(name, out var so) || so is not D s) throw new ActionKitError("missing_shard", $"shard '{name}' was not supplied");
            if (ShardDigest(s) != (string)r["digest"]!) throw new ActionKitError("shard_digest_mismatch", $"shard '{name}' does not match its digest");
            if (!Is1(G(s, "v")) || G(s, "kind") as string != PackShardKind || !Eq(s, "ns", pack["ns"]) || !Eq(s, "version", pack["version"]) || !Eq(s, "name", name) || G(s, "defs") is not L) throw new ActionKitError("bad_shard", $"shard '{name}' is not a shard of this pack");
            all.AddRange((L)s["defs"]!);
        }
        all.Sort((a, b) => Utf16Cmp((string)((D)a!)["verb"]!, (string)((D)b!)["verb"]!));
        return all;
    }

    /// <summary>Shape, signature under the pinned registry keys, vocabulary digests, shards, defs, the recomputed Merkle root and every evolution record. Returns {ok, digest, defs} or {ok:false, reason}.</summary>
    public static D VerifyPack(object? packo, object? keys, D? shards = null)
    {
        D Fail(string r) => new() { ["ok"] = false, ["reason"] = r };
        try
        {
            var se = PackShapeError(packo);
            if (se != null) return Fail(se);
            var pack = (D)packo!;
            var v = VerifyRegistrySig(PackSigDomain, Without(pack, "sig"), (D)pack["sig"]!, keys);
            if (v != null) return Fail("pack signature: " + v);
            if ((string)pack["traits_digest"]! != TraitsDigest(CoreRegistry)) return Fail("traits_digest does not match the trait registry");
            if ((string)pack["roles_digest"]! != TablesDigest()) return Fail("roles_digest does not match the vocabulary tables");
            if ((string)pack["rules_digest"]! != RulesDigest()) return Fail("rules_digest does not match the rule tables");
            List<object?> defs;
            try { defs = PackDefs(pack, shards); } catch (ActionKitError e) { return Fail(e.Message); }
            var de = SortedUniqueDefsError(defs);
            if (de != null) return Fail(de);
            if (defs.Count == 0 || defs.Count > 1_000_000) return Fail("the pack lists no defs or too many");
            var digests = defs.Select(d => DefDigest((D)d!)).ToList();
            if (PackRoot(digests) != (string)pack["root"]!) return Fail("the Merkle root does not match the defs");
            var have = new HashSet<string>(digests);
            foreach (var ro in (L)pack["evolution"]!)
            {
                var rv = VerifyEvolutionRecord(ro, keys);
                if (rv != null) return Fail("evolution record: " + rv);
                var r = (D)ro!;
                if ((string)r["ns"]! != (string)pack["ns"]!) return Fail("evolution record of another namespace");
                if (r["to"] is string to && !have.Contains(to)) return Fail($"evolution record for '{r["verb"]}' names a definition that is not in the pack");
            }
            return new D { ["ok"] = true, ["defs"] = defs, ["digest"] = PackDigest(pack) };
        }
        catch (Exception e) { return Fail("pack verification error: " + e.Message); }
    }

    /// <summary>The verifier's view of a registry: refuses rollback, fork and chain gap. The semantic diff of an upgrade is not recomputed natively.</summary>
    public sealed class PackTracker
    {
        readonly object? _keys;
        readonly Dictionary<string, (string Version, string Digest)> _seen = new();
        public PackTracker(object? keys) { _keys = keys; }

        public D Accept(D pack, D? shards = null)
        {
            var v = VerifyPack(pack, _keys, shards);
            if (v["ok"] is not true) return new D { ["ok"] = false, ["code"] = "bad_pack", ["reason"] = v["reason"] };
            var ns = (string)pack["ns"]!; var ver = (string)pack["version"]!; var dig = (string)v["digest"]!;
            if (!_seen.TryGetValue(ns, out var cur)) { _seen[ns] = (ver, dig); return new D { ["ok"] = true, ["status"] = "first" }; }
            if (cur.Digest == dig) return new D { ["ok"] = true, ["status"] = "same" };
            int c = CompareVersions(ver, cur.Version);
            if (c < 0) return new D { ["ok"] = false, ["code"] = "rollback", ["reason"] = "older than the accepted version" };
            if (c == 0) return new D { ["ok"] = false, ["code"] = "fork", ["reason"] = "two different packs claim one version" };
            if (G(pack, "prev") as string != cur.Digest) return new D { ["ok"] = false, ["code"] = "chain_gap", ["reason"] = "prev does not name the accepted pack" };
            _seen[ns] = (ver, dig);
            return new D { ["ok"] = true, ["status"] = "upgrade" };
        }
    }

    // ---- rule 22 over a whole document ------------------------------------------------------------------------------------------------
    static readonly string[] Rule22Codes = { "schema_floor_forged", "schema_traits_forged", "unknown_trait", "traits_digest_mismatch", "bad_registry" };

    /// <summary>Null = consistent, else the code of the refusal. <paramref name="reviewers"/>: the verifier's pinned reviewer keys (<c>{keys, traits_digests?}</c>); absent = no verb is confirmed.</summary>
    public static string? Rule22Integrity(D doc, object? reviewers = null)
    {
        var e = SchemaFloorError(doc, reviewers);
        return e == null ? null : Rule22Codes.FirstOrDefault(c => e.Contains(c)) ?? "unknown";
    }

    public static string Rule22Decide(D doc, string verb, D grant, L context)
    {
        try
        {
            var v = (G(doc, "verbs") as L)?.Select(x => x as D).FirstOrDefault(x => x != null && G(x, "verb") as string == verb);
            if (v == null || ProfileError(G(v, "floors")) != null) return "deny";
            var kinds = ((L)grant["caveats"]!).Where(k => k is string s && CaveatKinds.Contains(s)).Cast<string>();
            var ctx = context.Where(IsContextKey).Cast<string>();
            return FloorDecision(new D { ["caveats"] = ToL(kinds), ["max_esc"] = grant["max_esc"], ["preauth_esc"] = grant["preauth_esc"] }, new D { ["context"] = ToL(ctx) }, (D)v["floors"]!);
        }
        catch { return "deny"; }
    }
}
