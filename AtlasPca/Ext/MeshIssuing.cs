// The rest of the mesh module of the reference: key revocation ids, the public effective authority, proof size and revocation latency models, the worked
// example and the fork demonstration, cross-domain capability translation, the federated budget tree and the cross-reference commitments. Values are the
// JSON tree the verifier side already uses; a reference throw is an exception, and a member that is absent is "undefined" (a read of a member of null or
// undefined throws, as in the reference).
using System.Text;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static partial class Mesh
{
    const string XcapDomain = "atlas-pca/mesh-xcap/v1\0";
    const string XanchorDomain = "atlas-pca/mesh-xanchor/v1\0";
    const string ActionDigestDomain = "atlas-pca/mesh-action-digest/v1\0";
    const int MaxBudgetDepth = 64;

    // ---- JavaScript value helpers

    static readonly object Undef = new();
    static bool Has(object? v) => !ReferenceEquals(v, Undef);

    /// <summary>A member read: null or undefined throw, an absent member (or a read of a non-object) is undefined.</summary>
    static object? Prop(object? o, string k)
    {
        if (o == null || !Has(o)) throw new InvalidOperationException($"Cannot read properties of {(o == null ? "null" : "undefined")} (reading '{k}')");
        return o is D d && d.TryGetValue(k, out var v) ? v : Undef;
    }

    /// <summary>A member read with optional chaining: null and undefined give undefined.</summary>
    static object? PropOpt(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : Undef;

    static bool Truthy(object? v) => v switch
    {
        null => false,
        bool b => b,
        string s => s.Length > 0,
        _ => !Has(v) ? false : IntentJs.NumOf(v) is double d ? !(d == 0 || double.IsNaN(d)) : true,
    };

    /// <summary>obj[key] for an array or an object; an array is read by canonical index only.</summary>
    static object? Index(object? c, object? key)
    {
        if (c == null || !Has(c)) throw new InvalidOperationException("Cannot read properties of " + (c == null ? "null" : "undefined"));
        var k = !Has(key) ? "undefined" : JsJson.ToJsString(key);
        if (c is L l) return uint.TryParse(k, out var i) && i.ToString() == k && i < l.Count ? l[(int)i] : Undef;
        return c is D d && d.TryGetValue(k, out var v) ? v : Undef;
    }

    static bool IsNum(object? x) => IntentJs.IsFinite(x);

    /// <summary>A binary64 as a JSON number: a safe integer or its JavaScript spelling; a non-finite value stays a double (JSON cannot carry it).</summary>
    static object NumOut(double d) => double.IsFinite(d) ? Facade.JsNumber(d) : d;

    static int Bytes(object? x) => Pca.Canon(x).Length;

    static EdKey KeyOf(object? secret)
    {
        if (secret is not string s || Pca.B64uDecode(s) is not { Length: 32 } b) throw new ArgumentException("a secret key is a 32-byte seed");
        return EdKey.FromSeed(b);
    }

    static bool IsCaveatArray(object? x) => x is L l && l.All(c => c is D d && d.GetValueOrDefault("type") is string);

    static L CloneCanonical(object? v) => (L)Pca.ParseJson(Pca.Canonicalize(v))!;

    // ---- constants, key revocation ids, the effective authority

    /// <summary>The default freshness and chain bounds of the mesh verifier.</summary>
    public static D Constants() => new()
    {
        ["DEFAULT_MAX_HEAD_AGE_MS"] = IntentJs.OfLong((long)DefaultMaxHeadAgeMs), ["DEFAULT_MAX_CLOCK_SKEW_MS"] = IntentJs.OfLong((long)DefaultMaxSkewMs),
        ["DEFAULT_MAX_CHAIN_LENGTH"] = IntentJs.OfLong(DefaultMaxChain),
    };

    /// <summary>The revocation-set id of an agent key: <c>"key:" + agentPublic</c> (JavaScript string coercion for a value that is not a string).</summary>
    public static string KeyRevocationId(object? agentPublic) => "key:" + JsJson.ToJsString(agentPublic);

    static D AuthorityJson(Authority a)
    {
        var o = new D();
        if (a.Actions != null) o["actions"] = a.Actions.Cast<object?>().ToList();
        o["prefixes"] = a.Prefixes.Cast<object?>().ToList();
        if (a.MaxAmount is double m) o["maxAmount"] = NumOut(m);
        if (a.ExpiresAt is double e) o["expiresAt"] = NumOut(e);
        if (a.Audience != null) o["audience"] = a.Audience.Cast<object?>().ToList();
        if (a.MaxHops is double h) o["maxHops"] = NumOut(h);
        return o;
    }

    /// <summary>The conjunction of a caveat list as one authority <c>{actions?, prefixes, maxAmount?, expiresAt?, audience?, maxHops?}</c>; an unknown or malformed
    /// caveat is <c>{error}</c>. Throws when <paramref name="caveats"/> is not a list or holds a null.</summary>
    public static D EffectiveAuthority(object? caveats)
    {
        if (caveats is not L) throw new ArgumentException("caveats is not iterable");
        var (e, why) = Effective(caveats);
        if (why == "malformed proof") throw new InvalidOperationException("Cannot read properties of null (reading 'type')");
        return why != null ? new D { ["error"] = why } : AuthorityJson(e);
    }

    // ---- size and latency models

    /// <summary>Byte accounting of a proof (canonical JSON lengths): <c>{total_bytes, chain_bytes, heads_bytes, rev_leaves_bytes, hops_bytes, uncompacted_bytes}</c>,
    /// the last being the size had every hop carried its own head and inline revocation leaves. Throws on a value that is not a proof.</summary>
    public static D MeshProofSize(object? p)
    {
        D Expand(object? c, object? lv)
        {
            var o = new D { ["size"] = Prop(c, "size") };
            foreach (var k in new[] { "lo", "hi" })
            {
                var ix = Prop(c, k);
                if (Has(ix) && Truthy(Index(lv, ix))) o[k] = Index(lv, ix);
            }
            return o;
        }
        long uncompacted = Bytes(Prop(p, "chain")) + Bytes(Prop(p, "action")) + Bytes(Prop(p, "action_sig"));
        if (Prop(p, "hops") is not L hops) throw new InvalidOperationException("p.hops.reduce is not a function");
        var heads = Prop(p, "heads");
        var leaves = Prop(p, "rev_leaves");
        foreach (var h in hops)
        {
            var m = h is D hd ? new D(hd) : new D();
            m["head"] = Index(heads, Prop(h, "head"));
            var rev = Prop(h, "revocation");
            m["revocation"] = new D { ["cap"] = Expand(Prop(rev, "cap"), leaves), ["issuer_key"] = Expand(Prop(rev, "issuer_key"), leaves) };
            uncompacted += Bytes(m);
        }
        return new D
        {
            ["total_bytes"] = IntentJs.OfLong(Bytes(p)), ["chain_bytes"] = IntentJs.OfLong(Bytes(Prop(p, "chain"))), ["heads_bytes"] = IntentJs.OfLong(Bytes(heads)),
            ["rev_leaves_bytes"] = IntentJs.OfLong(Bytes(leaves)), ["hops_bytes"] = IntentJs.OfLong(Bytes(Prop(p, "hops"))), ["uncompacted_bytes"] = IntentJs.OfLong(uncompacted),
        };
    }

    /// <summary>Worst-case time from a revocation to its enforcement: <c>{published_ms, unpinned_ms, pinned_ms, honest_provers_viable}</c> from
    /// <c>{maxHeadAgeMs, headIntervalMs, maxClockSkewMs?, pinRefreshMs?}</c>. An input that is not a finite number &gt;= 0 gives infinite bounds and not viable.</summary>
    public static D RevocationLatencyBound(object? p)
    {
        static bool Ok(object? x) => IntentJs.NumOf(x) is double d && double.IsFinite(d) && d >= 0;
        var age = PropOpt(p, "maxHeadAgeMs"); var interval = PropOpt(p, "headIntervalMs"); var skewO = PropOpt(p, "maxClockSkewMs"); var pinO = PropOpt(p, "pinRefreshMs");
        if (!Ok(age) || !Ok(interval) || (Has(skewO) && !Ok(skewO)) || (Has(pinO) && !Ok(pinO)))
            return new D { ["published_ms"] = double.PositiveInfinity, ["unpinned_ms"] = double.PositiveInfinity, ["pinned_ms"] = double.PositiveInfinity, ["honest_provers_viable"] = false };
        double skew = Has(skewO) ? F(skewO) : 0, unpinned = F(age) + skew;
        return new D
        {
            ["published_ms"] = NumOut(F(interval)), ["unpinned_ms"] = NumOut(unpinned), ["pinned_ms"] = NumOut(Has(pinO) ? Math.Min(unpinned, F(pinO)) : unpinned),
            ["honest_provers_viable"] = F(interval) + skew < F(age),
        };
    }

    // ---- the worked example and the fork demonstration

    /// <summary>The example's seed keys are the first 32 BYTES OF THE TEXT of the hash (not a decoded digest).</summary>
    static EdKey SeedKey(string label) =>
        EdKey.FromSeed(Encoding.UTF8.GetBytes(Pca.HashCanonical(new D { ["seed"] = "atlas-pca/mesh-example/" + label })).Take(32).ToArray());

    static D Cav(string type, string member, object? value) => new() { ["type"] = type, [member] = value };

    static L Strs(params string[] xs) => xs.Cast<object?>().ToList();

    /// <summary>Four hops across three organisations, as <c>{trust, proof, evidence, chain, heads: {A0, A, B, C}, bindings: {orchestrator, tool, service}, domains: {A, B, C}
    /// (ids), witnesses (ids)}</c>; no key leaves the call. <paramref name="now"/> defaults to 1 800 000 000 000.</summary>
    public static D BuildMeshExample(double? now = null)
    {
        double t = now ?? 1_800_000_000_000;
        object T(double v) => StoreJs.Number(v);
        var human = SeedKey("human"); var orch = SeedKey("orchestrator"); var tool = SeedKey("tool"); var service = SeedKey("service"); var leaf = SeedKey("leaf");
        var a = new MeshDomain("org-A", SeedKey("domain-A")); var b = new MeshDomain("org-B", SeedKey("domain-B")); var c = new MeshDomain("org-C", SeedKey("domain-C"));
        var ws = new List<MeshWitness> { new(SeedKey("witness-1")), new(SeedKey("witness-2")), new(SeedKey("witness-3")) };
        var root = Issue.MintRoot(SuiteKey.Ed25519(human), orch.Id, null, new L
        {
            Cav("scope", "actions", Strs("payments.refund", "payments.read", "orders.read")), Cav("resource", "prefix", "/orders/"), Cav("max_amount", "max", T(500)),
            Cav("expires", "at", T(t + 3_600_000)), Cav("audience", "domains", Strs(c.Id)),
        });
        var c1 = Issue.Delegate(root, tool.Id, new L { Cav("scope", "actions", Strs("payments.refund", "payments.read")), Cav("max_amount", "max", T(100)) }, SuiteKey.Ed25519(orch));
        var c2 = Issue.Delegate(c1, service.Id, new L { Cav("resource", "prefix", "/orders/42"), Cav("max_hops", "n", T(4)) }, SuiteKey.Ed25519(tool));
        var c3 = Issue.Delegate(c2, leaf.Id, new L { Cav("scope", "actions", Strs("payments.refund")), Cav("max_amount", "max", T(50)) }, SuiteKey.Ed25519(service));
        var chain = new List<D> { root, c1, c2, c3 };
        a.Record(root);
        var hA0 = a.PublishHead(ws, t - 2_000);
        a.Record(c1);
        var hA = a.PublishHead(ws, t - 1_000); // size 1 -> 2: every witness verifies the consistency proof
        b.Record(c2);
        c.Record(c3);
        var hB = b.PublishHead(ws, t - 1_000);
        var hC = c.PublishHead(ws, t - 1_000);
        var bOrch = a.Enroll(orch.Id, "orchestrator"); var bTool = b.Enroll(tool.Id, "tool-agent"); var bSvc = c.Enroll(service.Id, "service-agent");
        var evidence = new List<D> { a.Evidence(root, hA, null), a.Evidence(c1, hA, bOrch), b.Evidence(c2, hB, bTool), c.Evidence(c3, hC, bSvc) };
        var action = new D { ["type"] = "payments.refund", ["resource"] = "/orders/42/line/1", ["amount"] = T(25), ["service_domain"] = c.Id, ["nonce"] = "n-0001", ["at"] = T(t) };
        var proof = Signers.AssembleMeshProof(chain, evidence, action, leaf);
        var trust = new D
        {
            ["humanPrincipal"] = human.Id, ["witnesses"] = ws.Select(w => (object?)w.Id).ToList(), ["threshold"] = T(2), ["now"] = T(t),
            ["allowedDomains"] = Strs(a.Id, b.Id, c.Id), ["rootDomain"] = a.Id,
        };
        return new D
        {
            ["trust"] = trust, ["proof"] = proof, ["evidence"] = evidence.Cast<object?>().ToList(), ["chain"] = chain.Cast<object?>().ToList(),
            ["heads"] = new D { ["A0"] = hA0, ["A"] = hA, ["B"] = hB, ["C"] = hC },
            ["bindings"] = new D { ["orchestrator"] = bOrch, ["tool"] = bTool, ["service"] = bSvc },
            ["domains"] = new D { ["A"] = a.Id, ["B"] = b.Id, ["C"] = c.Id }, ["witnesses"] = ws.Select(w => (object?)w.Id).ToList(),
        };
    }

    /// <summary>A malicious domain rewrites an early log entry and grows the forked log past the size a witness last saw: a size-only check would accept it, the
    /// consistency proof does not. <c>{honest_extension_cosigned, fork_larger_than_prior, size_only_check_would_accept, fork_rejected, fork_reason}</c>.</summary>
    public static D DemonstrateForkRejection()
    {
        var k = SeedKey("fork-domain"); var hk = SeedKey("fork-human");
        D Mk(int n) => Issue.MintRoot(SuiteKey.Ed25519(hk), hk.Id, null, new L { Cav("scope", "actions", Strs("a" + n)) });
        var w = new MeshWitness(SeedKey("fork-witness"));
        var honest = new MeshDomain("X", k);
        honest.Record(Mk(0));
        honest.Record(Mk(1));
        honest.PublishHead(new[] { w }, 100);
        honest.Record(Mk(2));
        var honestOk = true;
        try { honest.PublishHead(new[] { w }, 200); } catch (Exception) { honestOk = false; }
        var prior = w.LastSeen(honest.Id)!;
        var fork = new MeshDomain("X", k); // same key, rewritten history (entry 0 differs), grown past the prior size
        foreach (var n in new[] { 100, 1, 2, 3 }) fork.Record(Mk(n));
        var reason = "";
        var rejected = false;
        try { fork.PublishHead(new[] { w }, 300); } catch (Exception e) { rejected = true; reason = e.Message; }
        var ps = IntentJs.Lng(prior["size"]);
        return new D
        {
            ["honest_extension_cosigned"] = honestOk, ["fork_larger_than_prior"] = 4 > ps, ["size_only_check_would_accept"] = 4 >= ps,
            ["fork_rejected"] = rejected, ["fork_reason"] = reason,
        };
    }

    // ---- cross-domain capability translation

    static D XcapBody(object? fromG, object? toG, object? tip, object? caveats, object? issuedAt) =>
        new() { ["v"] = "atlas-pca/mesh-xcap/v1", ["from"] = fromG, ["to"] = toG, ["source_tip"] = tip, ["caveats"] = caveats, ["issued_at"] = issuedAt };

    static IReadOnlyDictionary<string, string>? Pins(object? v) =>
        v is D d ? d.Where(e => e.Value is string).ToDictionary(e => e.Key, e => (string)e.Value!) : null;

    /// <summary>A capability chain rooted in one guardian's grant, attenuated for another guardian's domain and signed by the bridge: the translated caveats are the
    /// source tip's followed by <c>additionalCaveats</c> (append only). <paramref name="args"/>: <c>{fromGuardian, toGuardian, additionalCaveats?, bridgeSecret (a 32-byte
    /// seed, base64url), issued_at, pqPins?}</c>. Throws on an invalid source chain, malformed additional caveats or an unhashable value.</summary>
    public static D TranslateCapability(object? chain, object? args)
    {
        var pins = Pins(Prop(args, "pqPins"));
        if (chain is not L cl) throw new ArgumentException("translateCapability: invalid source chain: malformed capability chain");
        var (why, ok) = Pca.VerifyChain(cl, null, false, null, pins);
        if (!ok) throw new ArgumentException("translateCapability: invalid source chain: " + why);
        var add = Prop(args, "additionalCaveats");
        if (Has(add) && !IsCaveatArray(add)) throw new ArgumentException("translateCapability: additionalCaveats must be an array of caveats");
        var tip = (D)cl[^1]!;
        var caveats = CloneCanonical(tip["caveats"]);
        if (Has(add)) caveats.AddRange(CloneCanonical(add));
        var sourceTip = Pca.CapHash(tip);
        var fromG = Prop(args, "fromGuardian"); var toG = Prop(args, "toGuardian"); var issuedAt = Prop(args, "issued_at");
        var bridge = KeyOf(Prop(args, "bridgeSecret"));
        var body = XcapBody(fromG, toG, sourceTip, caveats, issuedAt);
        return new D
        {
            ["source"] = cl, ["fromGuardian"] = fromG, ["toGuardian"] = toG, ["bridge"] = bridge.Id, ["source_tip"] = sourceTip, ["caveats"] = caveats, ["issued_at"] = issuedAt,
            ["sig"] = Pca.B64u(bridge.Sign(IntentJs.Message(XcapDomain, body))),
        };
    }

    /// <summary>The effective authority of a translated capability's caveats, or <c>{error}</c>.</summary>
    public static D TranslatedEffectiveAuthority(object? tc) =>
        tc is D d && IsCaveatArray(d.GetValueOrDefault("caveats")) ? EffectiveAuthority(d["caveats"]) : new D { ["error"] = "malformed translated capability" };

    /// <summary>Verify a translation offline, fail closed: shape, the source chain (with the root issuer pin), the guardian and bridge pins, source tip, append-only
    /// prefix (by canonical hash), the bridge signature, monotone narrowing against the source tip, and expiry at <c>opts.now</c>. Never throws.
    /// <paramref name="opts"/>: <c>{pqPins?, fromGuardian?, toGuardian?, bridge?, rootIssuer?, now?}</c> (null is malformed; another non-object is no options).</summary>
    public static D VerifyTranslatedCapability(object? tc, object? opts)
    {
        static D Fail(string reason) => new() { ["ok"] = false, ["reason"] = reason };
        try
        {
            if (tc is not D t || t.GetValueOrDefault("source") is not L source || t.GetValueOrDefault("fromGuardian") is not string fromG || t.GetValueOrDefault("toGuardian") is not string toG)
                return Fail("malformed translated capability");
            if (t.GetValueOrDefault("bridge") is not string bridge || t.GetValueOrDefault("source_tip") is not string sourceTip || t.GetValueOrDefault("sig") is not string sig
                || !IsNum(t.GetValueOrDefault("issued_at")) || t.GetValueOrDefault("caveats") is not L caveats || !IsCaveatArray(caveats))
                return Fail("malformed translated capability");

            var rootIssuer = Prop(opts, "rootIssuer");
            var (cwhy, cok) = Pca.VerifyChain(source, Has(rootIssuer) ? rootIssuer : null, Has(rootIssuer), null, Pins(Prop(opts, "pqPins")));
            if (!cok) return Fail("source chain: " + cwhy);

            static bool Differs(object? pin, string value) => Has(pin) && !(pin is string s && s == value);
            if (Differs(Prop(opts, "fromGuardian"), fromG)) return Fail("source guardian mismatch");
            if (Differs(Prop(opts, "toGuardian"), toG)) return Fail("target guardian mismatch");
            if (Differs(Prop(opts, "bridge"), bridge)) return Fail("bridge key mismatch");
            if (fromG == toG) return Fail("translation does not cross a domain boundary");

            var tip = (D)source[^1]!;
            if (sourceTip != Pca.CapHash(tip)) return Fail("source_tip does not match the source chain tip");

            var tipCaveats = (L)tip["caveats"]!;
            if (caveats.Count < tipCaveats.Count) return Fail("translation drops a source caveat (widening)");
            for (int j = 0; j < tipCaveats.Count; j++)
                if (Pca.HashCanonical(caveats[j]) != Pca.HashCanonical(tipCaveats[j])) return Fail($"translation altered or reordered source caveat {j} (widening)");

            var body = XcapBody(fromG, toG, sourceTip, caveats, t["issued_at"]);
            if (!Pca.VerifyEdInternal(bridge, IntentJs.Message(XcapDomain, body), sig)) return Fail("translation not signed by the declared bridge key");

            var (effS, whyS) = Effective(tipCaveats);
            if (whyS != null) return Fail("source caveats: " + whyS);
            var (effT, whyT) = Effective(caveats);
            if (whyT != null) return Fail(whyT);
            if (!Narrows(effT, effS)) return Fail("translated authority widens the source authority");

            var now = Prop(opts, "now");
            if (Has(now) && effT.ExpiresAt is double exp && !(JsJson.ToJsNumber(now) <= exp)) return Fail("translated capability expired");

            return new D { ["ok"] = true, ["from"] = fromG, ["to"] = toG, ["bridge"] = bridge, ["effective"] = AuthorityJson(effT) };
        }
        catch (Exception) { return Fail("malformed translated capability"); }
    }

    // ---- the federated budget tree

    static D Refused(string reason) => new() { ["ok"] = false, ["reason"] = reason };
    static D Granted(D state) => new() { ["ok"] = true, ["state"] = state };

    /// <summary>The root of a budget tree that spans domains: <c>{ok, state}</c> or <c>{ok: false, reason}</c>.</summary>
    public static D CreateFederatedBudget(object? args)
    {
        if (args is not D a || a.GetValueOrDefault("rootId") is not string rootId || a.GetValueOrDefault("rootDomain") is not string rootDomain) return Refused("malformed root");
        var kappa = a.GetValueOrDefault("kappa"); var bMax = a.GetValueOrDefault("bMax"); var b0 = a.GetValueOrDefault("B0");
        if (!IsNum(kappa) || F(kappa) <= 0) return Refused("kappa must be finite and > 0");
        if (!IsNum(bMax) || F(bMax) < 0) return Refused("bMax must be finite and >= 0");
        if (!IsNum(b0) || F(b0) < 0) return Refused("B0 must be finite and >= 0");
        if (F(b0) > F(bMax)) return Refused("B0 exceeds bMax");
        return Granted(new D
        {
            ["nodes"] = new D { [rootId] = new D { ["domain"] = rootDomain, ["B"] = NumOut(F(b0)) } }, ["root"] = rootId, ["kappa"] = NumOut(F(kappa)), ["bMax"] = NumOut(F(bMax)),
        });
    }

    static bool ValidBudgetState(object? s)
    {
        if (s is not D sd || sd.GetValueOrDefault("nodes") is not D nodes || sd.GetValueOrDefault("root") is not string root) return false;
        if (!IsNum(sd.GetValueOrDefault("kappa")) || !IsNum(sd.GetValueOrDefault("bMax"))) return false;
        if (F(sd["kappa"]) <= 0 || F(sd["bMax"]) < 0 || !nodes.ContainsKey(root)) return false;
        foreach (var n in nodes.Values)
        {
            if (n is not D nd || nd.GetValueOrDefault("domain") is not string || !IsNum(nd.GetValueOrDefault("B")) || F(nd["B"]) < 0) return false;
            if (nd.TryGetValue("parent", out var pr) && pr is not string) return false;
        }
        return true;
    }

    /// <summary>A sub-budget ceiling under an existing node: <c>alloc</c> may not exceed the parent's CURRENT remaining budget, and the parent is not reduced.</summary>
    public static D AllocateSub(object? state, object? args)
    {
        if (!ValidBudgetState(state)) return Refused("malformed budget state");
        if (args is not D a || a.GetValueOrDefault("id") is not string id || a.GetValueOrDefault("domain") is not string domain || a.GetValueOrDefault("parent") is not string parent)
            return Refused("malformed allocation");
        var s = (D)state!; var nodes = (D)s["nodes"]!;
        if (nodes.ContainsKey(id)) return Refused("node id already exists");
        if (!nodes.TryGetValue(parent, out var pn)) return Refused("unknown parent");
        var alloc = a.GetValueOrDefault("alloc");
        if (!IsNum(alloc) || F(alloc) < 0) return Refused("allocation must be finite and >= 0");
        if (F(alloc) > F(((D)pn!)["B"])) return Refused("allocation exceeds parent remaining budget");
        var next = new D(nodes) { [id] = new D { ["domain"] = domain, ["parent"] = parent, ["B"] = NumOut(F(alloc)) } };
        return Granted(new D(s) { ["nodes"] = next });
    }

    /// <summary>Spend from a node: every ancestor strictly between it and the root must cover the cost, then the root and the spender are debited together. Atomic;
    /// the tree is at most 64 deep and a cycle or a node that is not under the root is refused.</summary>
    public static D SpendFederated(object? state, object? nodeId, object? c)
    {
        if (!ValidBudgetState(state)) return Refused("malformed budget state");
        if (nodeId is not string id) return Refused("malformed node id");
        if (!IsNum(c) || F(c) < 0) return Refused("spend must be finite and >= 0");
        var s = (D)state!; var nodes = (D)s["nodes"]!; var root = (string)s["root"]!;
        var path = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string? cur = id;
        while (cur != null)
        {
            if (!nodes.TryGetValue(cur, out var nv)) return Refused("unknown node");
            if (seen.Contains(cur)) return Refused("cycle in budget tree");
            if (path.Count >= MaxBudgetDepth) return Refused("budget tree too deep");
            seen.Add(cur);
            path.Add(cur);
            cur = ((D)nv!).GetValueOrDefault("parent") as string;
        }
        if (path[^1] != root) return Refused("node is not rooted at the budget root");
        double cost = F(c);
        double B(string n) => F(((D)nodes[n]!)["B"]);
        D With(string n, double b) => new((D)nodes[n]!) { ["B"] = NumOut(b) };
        var next = new D(nodes);
        if (id == root)
        {
            if (B(root) < cost) return Refused("root budget insufficient");
            next[root] = With(root, Risk.Debit(new TrustBudget(B(root), 0), cost).B);
            return Granted(new D(s) { ["nodes"] = next });
        }
        var interior = path.Skip(1).Take(path.Count - 2).ToList();
        foreach (var n in interior) if (B(n) < cost) return Refused($"ancestor \"{n}\" budget insufficient");
        var dc = Risk.DebitConsolidated(new TrustBudget(B(root), 0), new TrustBudget(B(id), 0), cost);
        if (!dc.Ok) return Refused(dc.Reason!);
        next[id] = With(id, dc.Nodes![1].B);
        next[root] = With(root, dc.Nodes[0].B);
        foreach (var n in interior) next[n] = With(n, Risk.Debit(new TrustBudget(B(n), 0), cost).B);
        return Granted(new D(s) { ["nodes"] = next });
    }

    /// <summary>The bound bMax / kappa on the total risk of machine-only actions between two human recharges; 0 for a value that is not <c>{bMax, kappa}</c> numbers.</summary>
    public static object FederatedSafetyBound(object? p)
    {
        if (p is not D d || !IsNum(d.GetValueOrDefault("bMax")) || !IsNum(d.GetValueOrDefault("kappa"))) return IntentJs.OfLong(0);
        double kappa = F(d["kappa"]);
        return kappa > 0 ? NumOut(Math.Max(0, F(d["bMax"])) / kappa) : IntentJs.OfLong(0);
    }

    // ---- cross-reference commitments

    /// <summary>The digest a guardian anchors for a cross-domain action: SHA-256 over <c>{v, action}</c> under the strict canonical form (throws on an unhashable value).</summary>
    public static string MeshActionDigest(object? action) => Pca.HashCanonical(new D { ["v"] = ActionDigestDomain, ["action"] = action });

    /// <summary>The commitment both guardians anchor: it binds <c>{action_digest, fromGuardian, toGuardian, nonce, at}</c>.</summary>
    public static string CrossReferenceCommit(object? x) => Pca.HashCanonical(new D
    {
        ["v"] = "atlas-pca/mesh-xref/v1", ["action_digest"] = Prop(x, "action_digest"), ["from"] = Prop(x, "fromGuardian"), ["to"] = Prop(x, "toGuardian"),
        ["nonce"] = Prop(x, "nonce"), ["at"] = Prop(x, "at"),
    });

    /// <summary>A guardian's signed anchor <c>{domain, commit, seq, sig}</c> of a commitment (a 32-byte seed, base64url). The signature covers <c>{commit, seq}</c>; a
    /// fractional or negative <c>seq</c> is signed here and refused only by <see cref="VerifyCrossReference"/>.</summary>
    public static D AnchorCrossReference(object? domainSecret, object? commit, object? seq)
    {
        var key = KeyOf(domainSecret);
        return new D
        {
            ["domain"] = key.Id, ["commit"] = commit, ["seq"] = seq,
            ["sig"] = Pca.B64u(key.Sign(IntentJs.Message(XanchorDomain, new D { ["commit"] = commit, ["seq"] = seq }))),
        };
    }

    static bool ValidAnchor(object? a) =>
        a is D d && d.GetValueOrDefault("domain") is string && d.GetValueOrDefault("commit") is string && IntentJs.IsNonNeg(d.GetValueOrDefault("seq")) && d.GetValueOrDefault("sig") is string;

    /// <summary>Both guardians anchored the same cross-domain action: <c>{ok, commit}</c> or <c>{ok: false, reason}</c>. Never throws.</summary>
    public static D VerifyCrossReference(object? x, object? anchors)
    {
        static D Fail(string reason) => new() { ["ok"] = false, ["reason"] = reason };
        try
        {
            if (x is not D xd || xd.GetValueOrDefault("action_digest") is not string || xd.GetValueOrDefault("fromGuardian") is not string fromG || xd.GetValueOrDefault("toGuardian") is not string toG
                || xd.GetValueOrDefault("nonce") is not string || !IsNum(xd.GetValueOrDefault("at")))
                return Fail("malformed cross-reference");
            if (anchors is not D an || !ValidAnchor(an.GetValueOrDefault("from")) || !ValidAnchor(an.GetValueOrDefault("to"))) return Fail("malformed anchors");
            if (fromG == toG) return Fail("cross-reference must span two distinct domains");
            var af = (D)an["from"]!; var at = (D)an["to"]!;
            var expected = CrossReferenceCommit(x);
            if ((string)af["domain"]! != fromG) return Fail("source anchor domain does not match the cross-reference");
            if ((string)at["domain"]! != toG) return Fail("target anchor domain does not match the cross-reference");
            if ((string)af["commit"]! != expected) return Fail("source anchor commits a different action");
            if ((string)at["commit"]! != expected) return Fail("target anchor commits a different action");
            if (!Pca.VerifyEdInternal(af["domain"], IntentJs.Message(XanchorDomain, new D { ["commit"] = af["commit"], ["seq"] = af["seq"] }), af["sig"])) return Fail("source anchor signature invalid");
            if (!Pca.VerifyEdInternal(at["domain"], IntentJs.Message(XanchorDomain, new D { ["commit"] = at["commit"], ["seq"] = at["seq"] }), at["sig"])) return Fail("target anchor signature invalid");
            return new D { ["ok"] = true, ["commit"] = expected };
        }
        catch (Exception) { return Fail("malformed cross-reference"); }
    }
}
