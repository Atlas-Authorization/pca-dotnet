// Policy links and role templates (the reference policy-link.ts createLink / slotsDigest / linkDigest and policy-templates.ts): a link is a reference to a
// signed template plus the slots that fill it; role templates are conservative starting points a request maps onto before it is compiled through the facade
// (so what you author is exactly what the verifier enforces); PolicyBuilder composes the same thing with a typed, chainable builder. Pure.
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static partial class PolicyAuthoring
{
    /// <summary>The digest a <c>bind_params_digest</c> reference cites: the canonical hash of the slot object.</summary>
    public static string SlotsDigest(object? slots) => Pca.HashCanonical(slots); // any value: the reference hashes whatever it is given

    /// <summary>The digest of a template reference.</summary>
    public static string LinkDigest(JD templateRef) => Pca.HashCanonical(templateRef);

    /// <summary>A reference to <paramref name="def"/> filled with <paramref name="slots"/> (the slots are validated by instantiating the template first; throws
    /// <see cref="ArgumentException"/> when they do not fit). With <paramref name="bindParams"/> the reference carries only the slots' digest.</summary>
    public static JD CreateLink(JD def, JD slots, bool bindParams = false)
    {
        var (policy, reason) = InstantiateTemplate(def, slots);
        if (policy == null) throw new ArgumentException("createLink: " + reason);
        var r = new JD { ["template_id"] = def["id"], ["version_digest"] = TemplateDigest(def) };
        if (bindParams) r["bind_params_digest"] = SlotsDigest(slots); else r["slots"] = Issue.NormJ(slots);
        return r;
    }
}

/// <summary>A named role template: <c>Permissions</c> (connector to actions), optional <c>Limits</c> (<c>verb: "50/day"</c>) and a partial risk policy.</summary>
public sealed record PolicyTemplate(string Name, string Description, JD Permissions, IReadOnlyDictionary<string, string>? Limits = null, JD? RiskPolicy = null);

/// <summary>What <see cref="PolicyTemplates.FromTemplate"/> needs. <c>Overrides</c> narrow or extend the template before minting.</summary>
public sealed class FromTemplateOptions
{
    public SuiteKey Principal = null!;
    public string Goal = "";
    public string? Aud;
    public SuiteKey? Holder;
    public long? Now;
    public JD? OverridePermissions;
    public IReadOnlyDictionary<string, string>? OverrideLimits;
    public JD? OverrideRiskPolicy;
    public JD? OverrideAgentBinding;
    public string? OverrideBudgetModel;
}

public static class PolicyTemplates
{
    static JD Perms(params (string Connector, string[] Actions)[] p) { var d = new JD(); foreach (var (c, a) in p) d[c] = new JL(a.Cast<object?>()); return d; }

    /// <summary>Built-in role templates: conservative starting points, meant to be narrowed, not widened.</summary>
    public static IReadOnlyDictionary<string, PolicyTemplate> Templates { get; } = new Dictionary<string, PolicyTemplate>
    {
        ["read-only"] = new("read-only", "Read access only — no side effects anywhere.", Perms(("github", new[] { "read" }), ("slack", new[] { "read" }), ("files", new[] { "read" }), ("http", new[] { "get" }))),
        ["support-agent"] = new("support-agent", "Draft + send customer email and post to Slack, rate-limited.", Perms(("gmail", new[] { "draft", "send" }), ("slack", new[] { "post_message" })),
            new Dictionary<string, string> { ["send"] = "50/day", ["post_message"] = "100/day" }),
        ["finance-bot"] = new("finance-bot", "Issue reversible refunds within a daily cap; no payouts.", Perms(("stripe", new[] { "refund" })), new Dictionary<string, string> { ["refund"] = "$500/day" }),
        ["dev-assistant"] = new("dev-assistant", "Read repos, open PRs and comment — never merge or delete.", Perms(("github", new[] { "read", "create_pr", "comment" })), new Dictionary<string, string> { ["create_pr"] = "20/day" }),
    };

    public static IReadOnlyList<PolicyTemplate> ListTemplates() => Templates.Values.ToList();

    /// <summary>Mint an agent from a named template. Throws <see cref="ArgumentException"/> on an unknown template.</summary>
    public static AgentHandle FromTemplate(string name, FromTemplateOptions o)
    {
        if (!Templates.TryGetValue(name, out var t)) throw new ArgumentException($"fromTemplate: unknown template '{name}' (have: {string.Join(", ", Templates.Keys)})");
        return Agent.FromPrincipal(new AgentOptions
        {
            Principal = o.Principal, Goal = o.Goal, Permissions = o.OverridePermissions ?? t.Permissions, Limits = o.OverrideLimits ?? t.Limits,
            RiskPolicy = o.OverrideRiskPolicy ?? t.RiskPolicy, AgentBinding = o.OverrideAgentBinding, BudgetModel = o.OverrideBudgetModel, Aud = o.Aud, Holder = o.Holder, Now = o.Now,
        });
    }
}

/// <summary>The result of <see cref="PolicyBuilder.Build"/>.</summary>
public sealed record BuiltPolicy(JD Permissions, IReadOnlyDictionary<string, string> Limits, JD? RiskPolicy);

/// <summary>A typed, chainable policy builder: <c>new PolicyBuilder().Allow("stripe", "refund").Limit("refund", "$500/day")</c>.</summary>
public sealed class PolicyBuilder
{
    readonly JD _perms = new();
    readonly Dictionary<string, string> _limits = new();
    JD? _risk;

    /// <summary>Start from a named template (its permissions, limits and risk seed the builder).</summary>
    public static PolicyBuilder From(string name)
    {
        if (!PolicyTemplates.Templates.TryGetValue(name, out var t)) throw new ArgumentException($"PolicyBuilder.from: unknown template '{name}'");
        var b = new PolicyBuilder();
        foreach (var (c, acts) in t.Permissions) b.Allow(c, ((JL)acts!).Cast<string>().ToArray());
        if (t.Limits != null) foreach (var (k, v) in t.Limits) b.Limit(k, v);
        if (t.RiskPolicy != null) b.Risk(t.RiskPolicy);
        return b;
    }

    public PolicyBuilder Allow(string connector, params string[] actions)
    {
        var cur = _perms.TryGetValue(connector, out var v) && v is JL l ? l.Cast<string>() : Enumerable.Empty<string>();
        _perms[connector] = new JL(cur.Concat(actions).Distinct(StringComparer.Ordinal).Cast<object?>());
        return this;
    }

    public PolicyBuilder Limit(string verbOrAction, string spec) { _limits[verbOrAction] = spec; return this; }

    public PolicyBuilder Risk(JD partial)
    {
        _risk = new JD(_risk ?? new JD());
        foreach (var (k, v) in partial) _risk[k] = v;
        return this;
    }

    /// <summary>The built policy; throws <see cref="InvalidOperationException"/> when no permission was added.</summary>
    public BuiltPolicy Build()
    {
        if (_perms.Count == 0) throw new InvalidOperationException("PolicyBuilder: no permissions added");
        return new BuiltPolicy((JD)Issue.Norm(_perms)!, new Dictionary<string, string>(_limits), _risk == null ? null : new JD(_risk));
    }

    /// <summary>Mint an agent directly from the built policy.</summary>
    public AgentHandle Agent(SuiteKey principal, string goal, string? aud = null, SuiteKey? holder = null, long? now = null)
    {
        var b = Build();
        return AtlasPca.Agent.FromPrincipal(new AgentOptions { Principal = principal, Goal = goal, Permissions = b.Permissions, Limits = b.Limits, RiskPolicy = b.RiskPolicy, Aud = aud, Holder = holder, Now = now });
    }
}
