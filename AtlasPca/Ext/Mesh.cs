// Cross-domain mesh proofs (the agent mesh, mesh.ts verifyMeshProof). A MeshProof carries a capability chain, one witnessed head per
// issuing domain, per-hop log inclusion and revocation non-membership proofs, and a signed leaf action. VerifyMeshProof checks all
// of it offline and returns the reference's reason and failing hop. Scope: everything verifyMeshProof does, including RFC 9162
// consistency proofs from a pinned head. The witness side (cosigning, heads publication) is not here: a verifier only needs to
// check what they produced.
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The result of <see cref="Mesh.Verify"/>. Hop is -1 when no hop is named.</summary>
public readonly record struct MeshVerdict(bool Ok, string Reason, int Hop);

public static class Mesh
{
    public const string HeadDomain = "atlas-pca/mesh-head/v1\0";
    public const string CosigDomain = "atlas-pca/mesh-cosig/v1\0";
    public const string BindingDomain = "atlas-pca/mesh-binding/v1\0";
    public const string ActionDomain = "atlas-pca/mesh-action/v1\0";
    const double DefaultMaxHeadAgeMs = 5 * 60_000, DefaultMaxSkewMs = 60_000;
    const long DefaultMaxChain = 64;
    const int MaxCosigs = 256, MaxPath = 128;

    static MeshVerdict Fail(string reason, int hop) => new(false, reason, hop);

    static bool Nat(object? x) => IntentJs.IsNonNeg(x);
    static long NatV(object? x) => IntentJs.IsSafeInteger(x) ? IntentJs.Lng(x) : 0;
    static bool Num_(object? x) => IntentJs.NumOf(x) is double f && double.IsFinite(f);
    static double F(object? x) => IntentJs.NumOf(x) ?? double.NaN;
    static D? Rec(object? x) => x as D;
    static string? Str(object? x) => x as string;

    /// <summary>domain || strict-canonical(body); null when the body is not strictly canonicalizable.</summary>
    static byte[]? Msg(string domain, object? body)
    {
        try { return IntentJs.Message(domain, body); }
        catch (Exception) { return null; }
    }

    static bool VerifyEd(object? pub, byte[]? msg, object? sig) => msg != null && Pca.VerifyEdInternal(pub, msg, sig);

    static bool ValidHead(object? h)
    {
        if (h is not D m) return false;
        if (Str(m.GetValueOrDefault("domain")) == null || Str(m.GetValueOrDefault("root")) is not { } root || Str(m.GetValueOrDefault("rev_root")) == null) return false;
        if (!Nat(m.GetValueOrDefault("size")) || !Nat(m.GetValueOrDefault("rev_size")) || !Num_(m.GetValueOrDefault("timestamp"))) return false;
        return (NatV(m["size"]) == 0) == (root == "");
    }

    static D? ValidConsistency(object? c)
    {
        if (c is not D m || !Nat(m.GetValueOrDefault("oldSize")) || !Nat(m.GetValueOrDefault("newSize"))) return null;
        if (m.GetValueOrDefault("path") is not L path || path.Count > MaxPath || path.Any(p => p is not string)) return null;
        return m;
    }

    static D? ValidInclusion(object? i)
    {
        if (i is not D m || !Nat(m.GetValueOrDefault("index")) || !Nat(m.GetValueOrDefault("size"))) return null;
        return m.GetValueOrDefault("path") is L path && path.Count <= MaxPath ? m : null;
    }

    static D? ValidAction(object? a)
    {
        if (a is not D m) return null;
        foreach (var k in new[] { "type", "resource", "service_domain", "nonce" }) if (Str(m.GetValueOrDefault(k)) == null) return null;
        if (!Num_(m.GetValueOrDefault("at"))) return null;
        if (m.TryGetValue("amount", out var v) && !Num_(v)) return null;
        return m;
    }

    // ---- effective authority

    sealed class Authority
    {
        public List<string>? Actions; public List<string> Prefixes = new();
        public double? MaxAmount, ExpiresAt, MaxHops; public List<string>? Audience;
    }

    static List<string> Intersect(List<string>? a, List<string> b)
    {
        if (a == null) return IntentJs.SortedUtf8(b.Distinct(StringComparer.Ordinal));
        return a.Where(x => b.Contains(x)).ToList();
    }

    static List<string>? Strings(object? v) => v is L l && l.All(x => x is string) ? l.Cast<string>().ToList() : null;

    static double Min(double? cur, double v) => cur is double c ? Math.Min(c, v) : v;

    /// <summary>effectiveAuthority: the conjunction of the caveats; an unknown or malformed caveat is an error.</summary>
    static (Authority E, string? Why) Effective(object? caveats)
    {
        var e = new Authority();
        if (caveats is not L arr) return (e, "malformed proof");
        foreach (var cv in arr)
        {
            if (cv is not D c) return (e, "malformed proof");
            switch (c.GetValueOrDefault("type") as string)
            {
                case "scope":
                    {
                        var a = Strings(c.GetValueOrDefault("actions"));
                        if (a == null) return (e, "malformed scope caveat");
                        e.Actions = Intersect(e.Actions, a); break;
                    }
                case "resource":
                    {
                        if (Str(c.GetValueOrDefault("prefix")) is not { } p) return (e, "malformed resource caveat");
                        e.Prefixes.Add(p); break;
                    }
                case "max_amount":
                    if (!Num_(c.GetValueOrDefault("max"))) return (e, "malformed max_amount caveat");
                    e.MaxAmount = Min(e.MaxAmount, F(c["max"])); break;
                case "expires":
                    if (!Num_(c.GetValueOrDefault("at"))) return (e, "malformed expires caveat");
                    e.ExpiresAt = Min(e.ExpiresAt, F(c["at"])); break;
                case "audience":
                    {
                        var d = Strings(c.GetValueOrDefault("domains"));
                        if (d == null) return (e, "malformed audience caveat");
                        e.Audience = Intersect(e.Audience, d); break;
                    }
                case "max_hops":
                    if (!Num_(c.GetValueOrDefault("n"))) return (e, "malformed max_hops caveat");
                    e.MaxHops = Min(e.MaxHops, F(c["n"])); break;
                default:
                    return (e, $"unknown caveat type \"{IntentRevocation.JsText(c.GetValueOrDefault("type"), c.ContainsKey("type"))}\" (fail closed)");
            }
        }
        return (e, null);
    }

    static bool Subset(IEnumerable<string> child, List<string> parent) => child.All(parent.Contains);

    static bool Narrows(Authority child, Authority parent)
    {
        if (parent.Actions != null && (child.Actions == null || !Subset(child.Actions, parent.Actions))) return false;
        if (parent.Audience != null && (child.Audience == null || !Subset(child.Audience, parent.Audience))) return false;
        if (parent.MaxAmount != null && (child.MaxAmount == null || child.MaxAmount > parent.MaxAmount)) return false;
        if (parent.ExpiresAt != null && (child.ExpiresAt == null || child.ExpiresAt > parent.ExpiresAt)) return false;
        if (parent.MaxHops != null && (child.MaxHops == null || child.MaxHops > parent.MaxHops)) return false;
        return Subset(parent.Prefixes, child.Prefixes);
    }

    static string? Admits(Authority e, D a, double now, int chainLen)
    {
        var typ = a.GetValueOrDefault("type") as string ?? ""; var res = a.GetValueOrDefault("resource") as string ?? ""; var svc = a.GetValueOrDefault("service_domain") as string ?? "";
        if (e.Actions != null && !Subset(new[] { typ }, e.Actions)) return $"action \"{typ}\" not in scope";
        foreach (var p in e.Prefixes) if (!res.StartsWith(p, StringComparison.Ordinal)) return $"resource \"{res}\" outside prefix \"{p}\"";
        if (e.MaxAmount is double ma)
        {
            if (!a.TryGetValue("amount", out var amt) || F(amt) > ma) return $"amount exceeds ceiling {JsCanon.NumberString(ma)}";
        }
        if (e.ExpiresAt is double ex && now > ex) return "capability expired";
        if (e.Audience != null && !Subset(new[] { svc }, e.Audience)) return "service domain not in audience";
        if (e.MaxHops is double mh && chainLen > mh) return $"chain exceeds max_hops {JsCanon.NumberString(mh)}";
        return null;
    }

    // ---- revocation sets and Merkle proofs

    static string EmptyRevTree() => Pca.B64u(Pca.Sha256Of(Array.Empty<byte>()));

    static string? BindRevRoot(double size, string tree)
    {
        if (!(size == Math.Truncate(size) && Math.Abs(size) <= Pca.MaxSafeInt)) return null;
        try
        {
            var tail = IntentJs.CanonBytes(new D { ["size"] = IntentJs.OfLong((long)size), ["tree"] = tree });
            return Pca.B64u(Pca.Sha256Of(Encoding.UTF8.GetBytes("pca-revset/v1\0"), tail));
        }
        catch (Exception) { return null; }
    }

    static byte[] Node(byte[] l, byte[] r) => Pca.Sha256Of(new byte[] { 0x01 }, l, r);

    static bool LeafOk(string root, long size, string id, D proof)
    {
        if (!IntentJs.IsSafeInteger(proof.GetValueOrDefault("size")) || !IntentJs.IsSafeInteger(proof.GetValueOrDefault("index"))) return false;
        long psize = IntentJs.Lng(proof["size"]), index = IntentJs.Lng(proof["index"]);
        if (psize != size || index < 0 || index >= size) return false;
        var sides = Pca.PathShapeOf(index, size);
        if (proof.GetValueOrDefault("path") is not L path || path.Count != sides.Count) return false;
        byte[] h;
        try { h = Pca.Sha256Of(new byte[] { 0x00 }, IntentJs.CanonBytes(id)); } catch (Exception) { return false; }
        for (int i = 0; i < path.Count; i++)
        {
            if (path[i] is not D step) return false;
            var side = Str(step.GetValueOrDefault("side")) ?? "";
            var sib = Pca.B64uDecode(step.GetValueOrDefault("hash"), 32);
            if (side != sides[i].ToString() || sib == null) return false;
            h = side == "L" ? Node(sib, h) : Node(h, sib);
        }
        var bound = BindRevRoot(size, Pca.B64u(h));
        return bound != null && bound == root;
    }

    /// <summary>verifyNonMembership over an expanded proof {size, lo?, hi?}.</summary>
    internal static bool NonMembership(string root, D? nm, string id)
    {
        if (nm == null) return false;
        if (!IntentJs.IsSafeInteger(nm.GetValueOrDefault("size")) || IntentJs.Lng(nm["size"]) < 0) return false;
        long size = IntentJs.Lng(nm["size"]);
        var lo = nm.GetValueOrDefault("lo") as D; var hi = nm.GetValueOrDefault("hi") as D;
        if (size == 0) return lo == null && hi == null && BindRevRoot(0, EmptyRevTree()) == root;
        if (lo == null && hi == null) return false;
        long loIdx = 0, hiIdx = 0;
        if (lo != null)
        {
            var loId = Str(lo.GetValueOrDefault("id")) ?? "";
            if (lo.GetValueOrDefault("proof") is not D lp || !(IntentJs.CompareUtf8(loId, id) < 0) || !LeafOk(root, size, loId, lp)) return false;
            loIdx = NatV(lp.GetValueOrDefault("index"));
            if (hi == null && loIdx != size - 1) return false;
        }
        if (hi != null)
        {
            var hiId = Str(hi.GetValueOrDefault("id")) ?? "";
            if (hi.GetValueOrDefault("proof") is not D hp || !(IntentJs.CompareUtf8(id, hiId) < 0) || !LeafOk(root, size, hiId, hp)) return false;
            hiIdx = NatV(hp.GetValueOrDefault("index"));
            if (lo == null && hiIdx != 0) return false;
        }
        if (lo != null && hi != null && hiIdx != loIdx + 1) return false;
        return true;
    }

    /// <summary>verifyLedgerConsistency (RFC 9162 section 2.1.4.2), with strict 32-byte base64url hashes.</summary>
    static bool Consistency(string oldRoot, string newRoot, D proof)
    {
        if (!IntentJs.IsSafeInteger(proof.GetValueOrDefault("oldSize")) || !IntentJs.IsSafeInteger(proof.GetValueOrDefault("newSize"))) return false;
        long first = IntentJs.Lng(proof["oldSize"]), second = IntentJs.Lng(proof["newSize"]);
        if (first < 0 || first > second) return false;
        var raw = proof.GetValueOrDefault("path") as L ?? new L();
        if (raw.Count > MaxPath) return false;
        var empty = EmptyRevTree();
        if (first == 0)
        {
            if (raw.Count != 0 || oldRoot != empty) return false;
            return second == 0 ? newRoot == empty : true;
        }
        if (first == second) return raw.Count == 0 && oldRoot == newRoot;
        var path = new List<byte[]>();
        if ((first & (first - 1)) == 0)
        {
            var o = Pca.B64uDecode(oldRoot, 32);
            if (o == null) return false;
            path.Add(o);
        }
        foreach (var p in raw)
        {
            var b = Pca.B64uDecode(p as string ?? "", 32);
            if (b == null) return false;
            path.Add(b);
        }
        if (path.Count == 0) return false;
        long fn = first - 1, sn = second - 1;
        while ((fn & 1) == 1) { fn >>= 1; sn >>= 1; }
        byte[] fr = path[0], sr = path[0];
        foreach (var c in path.Skip(1))
        {
            if (sn == 0) return false;
            if ((fn & 1) == 1 || fn == sn)
            {
                fr = Node(c, fr); sr = Node(c, sr);
                while ((fn & 1) == 0 && fn != 0) { fn >>= 1; sn >>= 1; }
            }
            else sr = Node(sr, c);
            fn >>= 1; sn >>= 1;
        }
        return sn == 0 && Pca.B64u(fr) == oldRoot && Pca.B64u(sr) == newRoot;
    }

    // ---- heads

    static string? CheckHeadAdvance(object? prev, object? next, object? proof)
    {
        if (!ValidHead(prev) || !ValidHead(next)) return "malformed head";
        var p = (D)prev!; var n = (D)next!;
        if (!Equals(p["domain"], n["domain"])) return "head is for a different domain";
        if (NatV(n["size"]) < NatV(p["size"]) || NatV(n["rev_size"]) < NatV(p["rev_size"])) return "head rolls back";
        if (NatV(n["size"]) == NatV(p["size"]))
        {
            if (!Equals(n["root"], p["root"])) return "equivocation (same size, different log)";
        }
        else
        {
            var c = ValidConsistency(proof);
            if (c == null || NatV(c["oldSize"]) != NatV(p["size"]) || NatV(c["newSize"]) != NatV(n["size"])) return "consistency proof required for a larger head";
            if (!Consistency((string)p["root"]!, (string)n["root"]!, c)) return "head is not consistent with the previous head (fork or rewrite)";
        }
        if (NatV(n["rev_size"]) == NatV(p["rev_size"]) && !Equals(n["rev_root"], p["rev_root"])) return "equivocation (revocation set)";
        return null;
    }

    sealed class Trust
    {
        public string Human = ""; public HashSet<string> Witnesses = new(StringComparer.Ordinal); public long Threshold;
        public double Now, MaxHeadAge, MaxSkew, MaxActionAge; public bool HasActionAge; public long MaxChain;
        public List<string> Allowed = new(); public string RootDomain = ""; public D? IssuerDoms; public D? Pinned; public Dictionary<string, string>? PqPins;
    }

    static double? Opt(D t, string k, double def)
    {
        if (!t.TryGetValue(k, out var v)) return def;
        return !Num_(v) || F(v) < 0 ? null : F(v);
    }

    static (Trust? T, string? Bad) ValidTrust(object? traw)
    {
        if (traw is not D t) return (null, "invalid trust configuration");
        var human = Str(t.GetValueOrDefault("humanPrincipal")); var ws = Strings(t.GetValueOrDefault("witnesses"));
        if (human == null || ws == null) return (null, "invalid trust configuration");
        var c = new Trust { Human = human, Witnesses = ws.ToHashSet(StringComparer.Ordinal) };
        if (!Nat(t.GetValueOrDefault("threshold")) || NatV(t["threshold"]) < 1 || NatV(t["threshold"]) > c.Witnesses.Count) return (null, "invalid trust configuration: threshold");
        c.Threshold = NatV(t["threshold"]);
        if (!Num_(t.GetValueOrDefault("now"))) return (null, "invalid trust configuration: now");
        c.Now = F(t["now"]);
        if (Opt(t, "maxHeadAgeMs", DefaultMaxHeadAgeMs) is not double mha) return (null, "invalid trust configuration: maxHeadAgeMs");
        c.MaxHeadAge = mha;
        if (Opt(t, "maxClockSkewMs", DefaultMaxSkewMs) is not double msk) return (null, "invalid trust configuration: maxClockSkewMs");
        c.MaxSkew = msk;
        if (t.ContainsKey("maxActionAgeMs"))
        {
            if (Opt(t, "maxActionAgeMs", 0) is not double maa) return (null, "invalid trust configuration: maxActionAgeMs");
            c.MaxActionAge = maa; c.HasActionAge = true;
        }
        c.MaxChain = DefaultMaxChain;
        if (t.TryGetValue("maxChainLength", out var mc))
        {
            if (!Nat(mc) || NatV(mc) < 1) return (null, "invalid trust configuration: maxChainLength");
            c.MaxChain = NatV(mc);
        }
        var ad = Strings(t.GetValueOrDefault("allowedDomains"));
        if (ad == null || ad.Count == 0) return (null, "invalid trust configuration: allowedDomains is required");
        c.Allowed = ad;
        var rd = Str(t.GetValueOrDefault("rootDomain"));
        if (rd == null || !ad.Contains(rd)) return (null, "invalid trust configuration: rootDomain is required and must be in allowedDomains");
        c.RootDomain = rd;
        if (t.TryGetValue("issuerDomains", out var idv))
        {
            if (idv is not D m || m.Values.Any(x => x is not string)) return (null, "invalid trust configuration: issuerDomains");
            c.IssuerDoms = m;
        }
        if (t.TryGetValue("pinnedHeads", out var ph))
        {
            if (ph is not D m) return (null, "invalid trust configuration: pinnedHeads");
            c.Pinned = m;
        }
        if (t.TryGetValue("pqPins", out var pq) && pq is D pm)
            c.PqPins = pm.Where(kv => kv.Value is string).ToDictionary(kv => kv.Key, kv => (string)kv.Value!);
        return (c, null);
    }

    static string? CheckCosignedHead(object? ch, string expectedDomain, Trust t, object? pinProof)
    {
        var chm = Rec(ch);
        if (Rec(chm?.GetValueOrDefault("head")) is not D h || !Equals(h.GetValueOrDefault("domain"), expectedDomain)) return "head is for a different domain";
        if (!ValidHead(h)) return "malformed head";
        if (Str(chm!.GetValueOrDefault("sig")) is not { } sig) return "malformed head";
        var domain = (string)h["domain"]!;
        if (!VerifyEd(domain, Msg(HeadDomain, h), sig)) return "head not signed by its domain key";
        if (chm.GetValueOrDefault("cosigs") is not L cosigs || cosigs.Count > MaxCosigs) return "malformed head";
        var good = new HashSet<string>(StringComparer.Ordinal);
        var cm = Msg(CosigDomain, h);
        foreach (var c in cosigs)
        {
            if (c is not D cr) continue;
            if (Str(cr.GetValueOrDefault("witness")) is { } w && Str(cr.GetValueOrDefault("sig")) is { } s && t.Witnesses.Contains(w) && !good.Contains(w) && VerifyEd(w, cm, s)) good.Add(w);
        }
        if (good.Count < t.Threshold) return $"head has {good.Count}/{t.Threshold} trusted witness cosignatures";
        var ts = F(h["timestamp"]);
        if (ts > t.Now + t.MaxSkew) return "head timestamp is in the future";
        if (t.Now - ts > t.MaxHeadAge) return "head is stale";
        if (t.Pinned != null && t.Pinned.TryGetValue(domain, out var pin) && IntentRevocation.Truthy(pin))
        {
            var why = CheckHeadAdvance(pin, h, pinProof);
            if (why != null) return why + " (vs pinned head)";
        }
        return null;
    }

    static D? ExpandNM(object? c, L leaves)
    {
        if (c is not D m || !Nat(m.GetValueOrDefault("size"))) return null;
        var o = new D { ["size"] = m["size"] };
        foreach (var side in new[] { "lo", "hi" })
        {
            if (!m.TryGetValue(side, out var ix)) continue;
            if (!Nat(ix) || NatV(ix) >= leaves.Count) return null;
            o[side] = leaves[(int)NatV(ix)];
        }
        return o;
    }

    /// <summary>Verifies a mesh proof end to end, offline. Both arguments are parsed JSON. Total: any malformed input is a verdict,
    /// never an exception.</summary>
    public static MeshVerdict Verify(object? proof, object? trust)
    {
        try { return VerifyInner(proof, trust); }
        catch (Exception) { return Fail("malformed proof", -1); }
    }

    static MeshVerdict VerifyInner(object? proofO, object? trust)
    {
        var (t, bad) = ValidTrust(trust);
        if (bad != null) return Fail(bad, -1);
        if (proofO is not D p) return Fail("malformed proof", -1);
        if (p.GetValueOrDefault("chain") is not L chain || p.GetValueOrDefault("hops") is not L hops || p.GetValueOrDefault("heads") is not L heads
            || p.GetValueOrDefault("rev_leaves") is not L revLeaves) return Fail("malformed proof", -1);
        var actionSig = Str(p.GetValueOrDefault("action_sig"));
        var action = ValidAction(p.GetValueOrDefault("action"));
        if (actionSig == null || action == null) return Fail("malformed action", -1);
        if (p.TryGetValue("pin_proofs", out var pp))
        {
            if (pp is not L arr || arr.Count > MaxCosigs) return Fail("malformed pin proofs", -1);
            foreach (var x in arr)
                if (x is not D xm || Str(xm.GetValueOrDefault("domain")) == null || ValidConsistency(xm.GetValueOrDefault("proof")) == null) return Fail("malformed pin proofs", -1);
        }
        if (chain.Count < 1 || chain.Count > t!.MaxChain) return Fail("chain length out of bounds", -1);
        if (heads.Count > chain.Count || revLeaves.Count > 2 * chain.Count) return Fail("evidence tables exceed chain size", -1);
        var (why0, ok0) = Pca.VerifyChain(chain, t.Human, true, null, t.PqPins, null);
        if (!ok0) return Fail("chain: " + why0, -1);
        if (hops.Count != chain.Count) return Fail("hop evidence count does not match chain length", -1);
        foreach (var l in revLeaves)
            if (l is not D lm || Str(lm.GetValueOrDefault("id")) == null || ValidInclusion(lm.GetValueOrDefault("proof")) == null) return Fail("malformed revocation leaves", -1);
        var used = new HashSet<long>();
        foreach (var h in hops) if (h is D ev && Nat(ev.GetValueOrDefault("head"))) used.Add(NatV(ev["head"]));
        if (used.Count != heads.Count) return Fail("unreferenced or missing head in evidence table", -1);

        var headErrs = new Dictionary<long, string?>();
        Authority? prev = null;
        for (int i = 0; i < chain.Count; i++)
        {
            var cap = chain[i] as D ?? new D();
            if (hops[i] is not D ev) return Fail("malformed hop evidence", i);
            var domain = Str(ev.GetValueOrDefault("domain"));
            if (domain == null || !Nat(ev.GetValueOrDefault("head")) || NatV(ev["head"]) >= heads.Count || ev.GetValueOrDefault("revocation") is not D) return Fail("malformed hop evidence", i);
            if (!t.Allowed.Contains(domain)) return Fail("issuing domain not allowed by policy", i);
            if (i == 0 && domain != t.RootDomain) return Fail("root capability must be anchored in the pinned root domain", i);
            var issuer = Str(cap.GetValueOrDefault("issuer")) ?? "";
            if (i > 0 && t.IssuerDoms != null && t.IssuerDoms.TryGetValue(issuer, out var pin) && !Equals(pin, domain)) return Fail("issuer key is pinned to a different domain", i);
            long hi = NatV(ev["head"]);
            var ch = heads[(int)hi];
            if (!headErrs.ContainsKey(hi))
            {
                var chm = Rec(ch);
                var dom = Rec(chm?.GetValueOrDefault("head")) is D hm && hm.GetValueOrDefault("domain") is string dm ? dm : "";
                object? pinProof = null;
                if (p.GetValueOrDefault("pin_proofs") is L pps)
                    foreach (var x in pps)
                        if (x is D xm && Equals(xm.GetValueOrDefault("domain"), dom)) { pinProof = xm.GetValueOrDefault("proof"); break; }
                headErrs[hi] = CheckCosignedHead(ch, dom, t, pinProof);
            }
            var chd = Rec(ch);
            if (chd == null || !chd.TryGetValue("head", out var hv) || hv == null) return Fail("malformed proof", -1); // `ch.head.domain` throws in the reference
            if (hv is not D headM || !Equals(headM.GetValueOrDefault("domain"), domain)) return Fail("source-domain anchor: head is for a different domain", i);
            if (headErrs[hi] is { } he) return Fail("source-domain anchor: " + he, i);

            var incl = ValidInclusion(ev.GetValueOrDefault("inclusion"));
            if (incl == null || NatV(incl["size"]) != NatV(headM.GetValueOrDefault("size"))) return Fail("hop not included in the issuing domain log", i);
            string capDigest;
            try { capDigest = Pca.CapHash(cap); } catch (Exception) { return Fail("hop not included in the issuing domain log", i); }
            if (!Pca.VerifyInclusion(headM.GetValueOrDefault("root") as string ?? "", incl, capDigest)) return Fail("hop not included in the issuing domain log", i);

            if (i > 0)
            {
                var b = Rec(ev.GetValueOrDefault("binding"));
                var role = Str(b?.GetValueOrDefault("role")); var bsig = Str(b?.GetValueOrDefault("sig"));
                if (b == null || role == null || bsig == null || !Equals(b.GetValueOrDefault("agent"), cap.GetValueOrDefault("issuer")) || !Equals(b.GetValueOrDefault("domain"), ev.GetValueOrDefault("domain")))
                    return Fail("missing or mismatched domain binding for issuer", i);
                var m = Msg(BindingDomain, new D { ["agent"] = b["agent"], ["domain"] = b["domain"], ["role"] = role });
                if (!VerifyEd(domain, m, bsig)) return Fail("domain binding signature invalid", i);
            }

            var rev = (D)ev["revocation"]!;
            var revRoot = headM.GetValueOrDefault("rev_root") as string ?? "";
            var id = cap.GetValueOrDefault("id") as string ?? "";
            var nmCap = ExpandNM(rev.GetValueOrDefault("cap"), revLeaves);
            if (nmCap == null || !NonMembership(revRoot, nmCap, id)) return Fail("capability revoked (or revocation proof invalid)", i);
            var nmKey = ExpandNM(rev.GetValueOrDefault("issuer_key"), revLeaves);
            if (nmKey == null || !NonMembership(revRoot, nmKey, "key:" + issuer)) return Fail("issuer key revoked (or revocation proof invalid)", i);

            var (eff, why) = Effective(cap.GetValueOrDefault("caveats"));
            if (why != null) return Fail(why, i);
            if (prev != null && !Narrows(eff, prev)) return Fail("hop widens authority", i);
            prev = eff;
        }

        double actTs = F(action!["at"]);
        if (actTs > t.Now + t.MaxSkew) return Fail("action timestamp is in the future", -1);
        if (t.HasActionAge && t.Now - actTs > t.MaxActionAge) return Fail("action is stale", -1);
        var tip = chain[^1] as D ?? new D();
        string? tipHash = null;
        try { tipHash = Pca.CapHash(tip); } catch (Exception) { /* verdict below */ }
        var holder = tip.GetValueOrDefault("holder") as string;
        var am = tipHash == null ? null : Msg(ActionDomain, new D { ["action"] = action, ["tip"] = tipHash });
        if (holder == null || !VerifyEd(holder, am, actionSig)) return Fail("action not signed by the chain tip holder", -1);
        var denied = Admits(prev!, action, t.Now, chain.Count);
        if (denied != null) return Fail("action not admitted: " + denied, -1);
        return new MeshVerdict(true, "", -1);
    }
}
