// Generic structural tool wrapper (the shape of a LlamaIndex FunctionTool: metadata plus call), for any framework whose tool is a name and an
// async call. Wrapping a tool makes every call first build a PCActn (fast-failing on the agent's local dry run), hand the proof to OnProof so it
// can be forwarded to the resource server, then run the original; the wrapper keeps the metadata unchanged.
// HONEST: this does not authorize. It attaches a proof-carrying action; the resource server's verifier decides.
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Adapters;

/// <summary>What a tool says about itself: name, optional description and parameter schema (kept as given).</summary>
public sealed record ToolMetadata(string Name, string? Description = null, object? Parameters = null);

/// <summary>The structural tool shape: metadata and an async call over a JSON-object input.</summary>
public interface IPcaTool
{
    ToolMetadata Metadata { get; }
    Task<object?> Call(D input);
}

/// <summary>A tool whose every call is guarded; same metadata as the tool it wraps.</summary>
public sealed class GuardedTool : IPcaTool
{
    readonly Func<D, ActOptions?, Task<object?>> _run;

    GuardedTool(IPcaTool inner, Func<D, ActOptions?, Task<object?>> run) { Inner = inner; _run = run; }

    public IPcaTool Inner { get; }
    public ToolMetadata Metadata => Inner.Metadata;

    /// <summary>Guarded call: throws <see cref="PcaDenied"/> on a failing local dry run (when the spec is fail-fast).</summary>
    public Task<object?> Call(D input) => _run(input, null);

    /// <summary>Guarded call with a per-call counter / issue time.</summary>
    public Task<object?> Call(D input, ActOptions? opts) => _run(input, opts);

    /// <summary>Wrap <paramref name="tool"/> so each call emits and attaches a PCActn before the original runs; <paramref name="onProof"/> receives the proof and the input.</summary>
    public static GuardedTool WithPca(AgentHandle agent, GuardSpec spec, IPcaTool tool, Action<PcaCall, D>? onProof = null)
    {
        ArgumentNullException.ThrowIfNull(agent);
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(tool);
        var run = PcaAdapters.Guard<object?>(agent, spec, async (args, pca) =>
        {
            onProof?.Invoke(pca, args);
            return await tool.Call(args).ConfigureAwait(false);
        });
        return new GuardedTool(tool, run);
    }
}
