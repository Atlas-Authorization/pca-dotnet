// Small public helpers of the policy layer (packages/pca policy-vm.ts and pq.ts): the tool call derived from an action, the agent caveat context, THE reversibility
// class of an action and the PQ key type test.
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static partial class Pca
{
    /// <summary>The tool call an action context stands for: <c>tool</c> the action's verb (empty when it is not a string), <c>args</c> its params object (empty when absent or not an
    /// object) and the signed tool-signature digest when the context carries <c>toolBinding</c>. A tool-schema caveat is checked against exactly this call, so an action cannot
    /// present different tool arguments than the ones it signed.</summary>
    public static ToolCall ToolCallOf(D? actionContext)
    {
        var a = actionContext?.GetValueOrDefault("action") as D;
        var prms = a?.GetValueOrDefault("params") as D ?? new D();
        return new ToolCall(a?.GetValueOrDefault("verb") as string ?? "", prms, actionContext?.GetValueOrDefault("toolBinding") as string);
    }

    /// <summary>A stock caveat context extended with the action: a COPY of <paramref name="baseContext"/> whose <c>action</c> is <paramref name="actionContext"/> (applied last, so a
    /// caller-supplied context can never substitute a different action) and the derived tool call, which <see cref="EvaluateAgentCaveats"/> takes beside it.</summary>
    public static (D Context, ToolCall ToolCall) AgentCaveatContext(D baseContext, D actionContext)
    {
        var ctx = new D(baseContext) { ["action"] = actionContext };
        return (ctx, ToolCallOf(actionContext));
    }

    /// <summary>THE reversibility class of an action, shared by every path that evaluates <c>reversibility_max</c> caveats: the action's own class, else the class of the plan node the
    /// action is bound to (<paramref name="nodeId"/>, the SIGNED <c>plan.node_id</c> on the server path), else null, which no <c>reversibility_max</c> caveat accepts and which is
    /// not fast-path eligible (fail closed). A node id that is not a string never guesses a node.</summary>
    public static object? ResolveReversibilityClass(D? actionContext, IEnumerable<object?>? plan, string? nodeId)
    {
        var own = (actionContext?.GetValueOrDefault("action") as D)?.GetValueOrDefault("reversibility_class");
        if (own != null) return own;
        if (nodeId == null) return null;
        return plan?.OfType<D>().FirstOrDefault(n => Equals(n.GetValueOrDefault("id"), nodeId))?.GetValueOrDefault("reversibility_class");
    }

    /// <summary>True for a verification key minted by the key-resolution choke point (<c>PinnedPq.Resolve</c>, a pinned or committed key) and never for a key read off an artifact.
    /// The type has no public constructor, so no caller can forge one.</summary>
    public static bool IsPinnedPqKey(object? x) => x is PinnedPq;
}
