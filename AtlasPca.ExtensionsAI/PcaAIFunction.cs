// Microsoft.Extensions.AI adapter. FunctionInvokingChatClient runs the AIFunctions in ChatOptions.Tools when the model asks for them; wrapping each
// of those functions in a PcaAIFunction makes every call a proof-carrying action:
//
//   options.Tools = options.Tools.Select(t => t is AIFunction f ? PcaAIFunction.Wrap(agent, map, f) : t).ToList();
//
// For each call the wrapper maps the function to a PCA (verb, resource) and builds the PCActn with the agent. A function the mapping declines is
// REFUSED, never run, and so is a call the agent's local dry run rejects (a fast offline reject; the resource server still decides). The PCActn is
// available to the running function through PcaAIFunction.CurrentCall (and OnProof), and what the function returns is recorded as UNTRUSTED tool
// output in the agent's provenance chain, so a later sensitive action sees it.
//
// HONEST: this does not authorize. It attaches a proof-carrying action; the resource server's verifier decides.
using System.Text.Json;
using AtlasPca.Adapters;
using Microsoft.Extensions.AI;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.ExtensionsAI;

/// <summary>Thrown by <see cref="PcaAIFunction"/> when it refuses a call (unmapped function, unreadable arguments, or a local dry-run deny). The function did not run.</summary>
public sealed class PcaToolDenied(string function, string reason) : Exception($"PCA refused function {function}: {reason}")
{
    public string Function { get; } = function;
    public string Reason { get; } = reason;
}

public sealed class PcaAIFunctionOptions
{
    /// <summary>Refuse a call whose local dry run rejects it before the function runs (default true).</summary>
    public bool FailFast { get; init; } = true;
    /// <summary>True (default): a refusal throws <see cref="PcaToolDenied"/>. False: the refusal text is returned as the function's result and the function does not run.</summary>
    public bool ThrowOnRefusal { get; init; } = true;
    /// <summary>Audience override (else the agent's default).</summary>
    public string? Aud { get; init; }
    /// <summary>Receives the proof and the arguments (as a JSON tree) before the function runs, so the call can forward the proof to the resource server.</summary>
    public Action<PcaCall, D>? OnProof { get; init; }
}

/// <summary>An AIFunction whose every call is a proof-carrying action; same name, description and schema as the function it wraps.</summary>
public sealed class PcaAIFunction : DelegatingAIFunction
{
    static readonly AsyncLocal<PcaCall?> Current = new();

    readonly AgentHandle _agent;
    readonly Func<AgentToolCall, (string Verb, string Resource)?> _map;
    readonly PcaAIFunctionOptions _opts;

    public PcaAIFunction(AgentHandle agent, Func<AgentToolCall, (string Verb, string Resource)?> map, AIFunction inner, PcaAIFunctionOptions? options = null) : base(inner)
    {
        _agent = agent ?? throw new ArgumentNullException(nameof(agent));
        _map = map ?? throw new ArgumentNullException(nameof(map));
        _opts = options ?? new PcaAIFunctionOptions();
    }

    /// <summary>Wrap <paramref name="inner"/> (see the type's remarks).</summary>
    public static PcaAIFunction Wrap(AgentHandle agent, Func<AgentToolCall, (string Verb, string Resource)?> map, AIFunction inner, PcaAIFunctionOptions? options = null) =>
        new(agent, map, inner, options);

    /// <summary>The PCActn built for the call running on this async flow (null outside a guarded call).</summary>
    public static PcaCall? CurrentCall => Current.Value;

    protected override async ValueTask<object?> InvokeCoreAsync(AIFunctionArguments arguments, CancellationToken cancellationToken)
    {
        var refusal = Build(arguments, out var call, out var args, out var verb);
        if (refusal != null)
        {
            if (_opts.ThrowOnRefusal) throw new PcaToolDenied(Name, refusal);
            return $"PCA refused function {Name}: {refusal}";
        }
        _opts.OnProof?.Invoke(call!, args!);
        Current.Value = call;
        object? result;
        try
        {
            result = await base.InvokeCoreAsync(arguments, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            // a function's error text reaches the model too, and a function can put anything in it
            PcaAdapters.RecordToolResult(_agent, verb!, e.Message);
            throw;
        }
        finally { Current.Value = null; }
        PcaAdapters.RecordToolResult(_agent, verb!, Jsonish(result));
        return result;
    }

    // null when the call is allowed (call, args and verb set), else the refusal reason
    string? Build(AIFunctionArguments arguments, out PcaCall? call, out D? args, out string? verb)
    {
        call = null; args = null; verb = null;
        D a;
        try
        {
            a = new D();
            foreach (var kv in arguments) a[kv.Key] = Jsonish(kv.Value);
        }
        catch (Exception e) { return "arguments are not JSON-serializable (" + e.GetType().Name + ")"; }
        if (_map(new AgentToolCall(Name, a)) is not { } m) return "no PCA verb is mapped for this function";
        ActResult r;
        try { r = _agent.Act(m.Verb, m.Resource, a, new ActOptions { Aud = _opts.Aud }); }
        catch (Exception e) { return "the action could not be built: " + e.Message; }
        if (_opts.FailFast && !r.DryRun.Allowed) return r.DryRun.Reason ?? "denied by the local dry run";
        verb = m.Verb;
        args = a;
        call = new PcaCall(r.PCActn, r.Encoded, PcaAdapters.PcaHeaders(r.Encoded, r.Provenance), r.Provenance);
        return null;
    }

    // a value as a JSON tree (strings, numbers, bools, lists, objects); throws for what System.Text.Json cannot serialize
    internal static object? Jsonish(object? v) => v switch
    {
        null => null,
        string s => s,
        JsonElement e => Pca.ParseJson(e.GetRawText()),
        _ => Pca.ParseJson(JsonSerializer.Serialize(v, v.GetType())),
    };
}
