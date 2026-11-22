using static AtlasPca.PolicyCi.CiJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.PolicyCi;

/// <summary>Input detection and normalization. A policy may be a bare predicate and caveat set, a compiled policy, a signed envelope or a
/// minted grant; they all reduce to one effective authority <c>{predicates, caveats, riskPolicy?, kind}</c>.</summary>
public static class CiNormalize
{
    /// <summary>The caveat type that carries the signed envelope payload inside a grant.</summary>
    public const string EnvelopeCaveatType = "envelope";

    /// <summary>A minted grant or delegation hop: the content-addressed, signed shape of a capability.</summary>
    public static bool IsCapability(object? x) =>
        x is D && G(x, "id") is string && G(x, "issuer") is string && G(x, "holder") is string && G(x, "body_digest") is string && G(x, "sig") is string && G(x, "caveats") is L;

    /// <summary>A signed policy envelope (the root intent grant payload).</summary>
    public static bool IsEnvelope(object? x) =>
        x is D && G(x, "goal_commit") is string && G(x, "predicates") is L && G(x, "caveats") is L && G(x, "agent_binding") is D && G(x, "risk_policy") is D;

    static bool IsCompiledPolicy(object? x) => x is D && G(x, "predicates") is L && G(x, "caveats") is L && G(x, "riskPolicy") is D && G(x, "actions") is L;

    static bool IsBarePolicy(object? x) => x is D && G(x, "predicates") is L;

    /// <summary>Drops the envelope-carrying caveat; keeps the runtime gate caveats (and any appended attenuation).</summary>
    static L RuntimeCaveats(L caveats) => new(caveats.Where(c => IsObject(c) && !(c is D && G(c, "type") is string t && t == EnvelopeCaveatType)));

    static D Ok(D policy) => Obj(("ok", true), ("policy", policy));
    static D Fail(string reason) => Obj(("ok", false), ("reason", reason));

    static D Policy(object? predicates, object? caveats, object? riskPolicy, bool hasRisk, string kind)
    {
        var p = Obj(("predicates", predicates), ("caveats", caveats));
        if (hasRisk) p["riskPolicy"] = riskPolicy;
        p["kind"] = kind;
        return p;
    }

    /// <summary>Reduces a grant to its effective authority: its predicates and baseline gate caveats live inside its first envelope caveat,
    /// and delegation appends further gate caveats to the grant's own caveats, so the effective gates are both lists together.</summary>
    public static D FromGrant(object? grant)
    {
        var env = Pca.ReadEnvelope(grant);
        if (env == null) return Fail("grant has no readable `envelope` caveat (malformed or unsigned payload)");
        var caveats = new L((L)env["caveats"]!);
        caveats.AddRange(RuntimeCaveats(G(grant, "caveats") is L gc ? gc : new L()));
        return Ok(Policy(env["predicates"], caveats, env.GetValueOrDefault("risk_policy"), true, "grant"));
    }

    /// <summary>Normalizes any single-policy input to its effective authority: <c>{ok: true, policy}</c> or <c>{ok: false, reason}</c>.</summary>
    public static D NormalizePolicyInput(object? input)
    {
        if (IsCapability(input)) return FromGrant(input);
        if (IsEnvelope(input)) return Ok(Policy(G(input, "predicates"), G(input, "caveats"), G(input, "risk_policy"), true, "envelope"));
        if (IsCompiledPolicy(input)) return Ok(Policy(G(input, "predicates"), G(input, "caveats"), G(input, "riskPolicy"), true, "compiled"));
        if (IsBarePolicy(input)) return Ok(Policy(G(input, "predicates"), G(input, "caveats") is L c ? c : new L(), null, false, "bare"));
        return Fail("unrecognized policy shape (expected an envelope, grant, compiled policy, or { predicates, caveats })");
    }

    /// <summary>Normalizes a delegation chain (root to leaf) to one effective policy per hop: <c>{ok: true, hops}</c> or <c>{ok: false, reason}</c>.
    /// A chain of grants shares the root envelope's predicates and each hop's gates are the envelope's caveats plus that hop's appended ones;
    /// a chain of already-effective policies is taken as it is.</summary>
    public static D NormalizeChain(IReadOnlyList<object?> chain)
    {
        if (chain.Count == 0) return Fail("empty chain");
        if (chain.All(IsCapability))
        {
            var env = Pca.ReadEnvelope(chain[0]);
            if (env == null) return Fail("root grant has no readable `envelope` caveat");
            var hops = new L();
            foreach (var cap in chain)
            {
                var caveats = new L((L)env["caveats"]!);
                caveats.AddRange(RuntimeCaveats(G(cap, "caveats") is L cc ? cc : new L()));
                hops.Add(Policy(env["predicates"], caveats, env.GetValueOrDefault("risk_policy"), true, "chain-hop"));
            }
            return Obj(("ok", true), ("hops", hops));
        }
        var outHops = new L();
        for (int i = 0; i < chain.Count; i++)
        {
            var r = NormalizePolicyInput(chain[i]);
            if (r["ok"] is not true) return Fail($"hop {i}: {Str(r["reason"])}");
            var p = Copy((D)r["policy"]!);
            p["kind"] = "chain-hop";
            outHops.Add(p);
        }
        return Obj(("ok", true), ("hops", outHops));
    }
}
