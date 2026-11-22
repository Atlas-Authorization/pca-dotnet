// Semantic Kernel adapter: an IFunctionInvocationFilter that makes every kernel function call a proof-carrying action.
//
//   kernel.UsePca(agent, call => call.Plugin == "stripe" && call.Function == "refund" ? ("stripe.refund", "charge:" + call.Arguments["id"]) : null);
//
// For each call the filter maps the function to a PCA (verb, resource) and builds the PCActn with the agent. A function the mapping declines
// is REFUSED, never run, and so is a call the agent's local dry run rejects (a fast offline reject; the resource server still decides).
// The PCActn rides to the function in the KernelArguments (PcaFunctionFilter.CallOf), and what the function returns is recorded as UNTRUSTED
// tool output in the agent's provenance chain, so a later sensitive action sees it.
//
// HONEST: this does not authorize. It attaches a proof-carrying action; the resource server's verifier decides.
using System.Text.Json;
using AtlasPca;
using AtlasPca.Adapters;
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.ChatCompletion;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.SemanticKernel;

/// <summary>A kernel function call as the mapping sees it: the plugin (null when the function is not in one), the function name, and its arguments as a JSON tree.</summary>
public sealed record PcaFunctionCall(string? Plugin, string Function, D Arguments);

/// <summary>Thrown by <see cref="PcaFunctionFilter"/> when it refuses a call (unmapped function, unreadable arguments, or a local dry-run deny). The function did not run.</summary>
public sealed class PcaFunctionDenied(string function, string reason) : Exception($"PCA refused kernel function {function}: {reason}")
{
    public string Function { get; } = function;
    public string Reason { get; } = reason;
}

public sealed class PcaFunctionFilterOptions
{
    /// <summary>Refuse a call whose local dry run rejects it before the function runs (default true).</summary>
    public bool FailFast { get; init; } = true;
    /// <summary>True (default): a refusal throws <see cref="PcaFunctionDenied"/>. False: the function's result is set to the refusal text and the function does not run.</summary>
    public bool ThrowOnRefusal { get; init; } = true;
    /// <summary>Audience override (else the agent's default).</summary>
    public string? Aud { get; init; }
}

public sealed class PcaFunctionFilter : IFunctionInvocationFilter
{
    /// <summary>The KernelArguments key under which the function finds its <see cref="PcaCall"/>.</summary>
    public const string CallKey = "__pca_call";

    readonly AgentHandle _agent;
    readonly Func<PcaFunctionCall, (string Verb, string Resource)?> _map;
    readonly PcaFunctionFilterOptions _opts;

    public PcaFunctionFilter(AgentHandle agent, Func<PcaFunctionCall, (string Verb, string Resource)?> map, PcaFunctionFilterOptions? options = null)
    {
        _agent = agent ?? throw new ArgumentNullException(nameof(agent));
        _map = map ?? throw new ArgumentNullException(nameof(map));
        _opts = options ?? new PcaFunctionFilterOptions();
    }

    /// <summary>The PCActn this filter built for the running call (null outside a guarded call).</summary>
    public static PcaCall? CallOf(KernelArguments? arguments) => arguments != null && arguments.TryGetValue(CallKey, out var v) ? v as PcaCall : null;

    public async Task OnFunctionInvocationAsync(FunctionInvocationContext context, Func<FunctionInvocationContext, Task> next)
    {
        var plugin = context.Function.PluginName;
        var fn = context.Function.Name;
        var full = string.IsNullOrEmpty(plugin) ? fn : plugin + "-" + fn;
        var refusal = Build(context, plugin, fn, out var call, out var verb);
        if (refusal != null)
        {
            if (_opts.ThrowOnRefusal) throw new PcaFunctionDenied(full, refusal);
            context.Result = new FunctionResult(context.Function, $"PCA refused kernel function {full}: {refusal}");
            return;
        }
        context.Arguments[CallKey] = call;
        try
        {
            await next(context).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            // a function's error text reaches the model too, and a function can put anything in it
            PcaAdapters.RecordToolResult(_agent, verb!, e.Message);
            throw;
        }
        finally
        {
            context.Arguments.Remove(CallKey);
        }
        PcaAdapters.RecordToolResult(_agent, verb!, JsonishOf(context.Result.GetValue<object>()));
    }

    // null when the call is allowed (call and verb set), else the refusal reason
    string? Build(FunctionInvocationContext context, string? plugin, string fn, out PcaCall? call, out string? verb)
    {
        call = null;
        verb = null;
        D args;
        try
        {
            args = new D();
            foreach (var kv in context.Arguments)
                if (kv.Key != CallKey) args[kv.Key] = JsonishOf(kv.Value);
        }
        catch (Exception e) { return "arguments are not JSON-serializable (" + e.GetType().Name + ")"; }
        if (_map(new PcaFunctionCall(plugin, fn, args)) is not { } m) return "no PCA verb is mapped for this function";
        ActResult r;
        try { r = _agent.Act(m.Verb, m.Resource, args, new ActOptions { Aud = _opts.Aud }); }
        catch (Exception e) { return "the action could not be built: " + e.Message; }
        if (_opts.FailFast && !r.DryRun.Allowed) return r.DryRun.Reason ?? "denied by the local dry run";
        verb = m.Verb;
        call = new PcaCall(r.PCActn, r.Encoded, PcaAdapters.PcaHeaders(r.Encoded, r.Provenance), r.Provenance);
        return null;
    }

    // a value as a JSON tree (strings, numbers, bools, lists, objects); throws for what System.Text.Json cannot serialize
    static object? JsonishOf(object? v) => v switch
    {
        null => null,
        string s => s,
        _ => Pca.ParseJson(JsonSerializer.Serialize(v, v.GetType())),
    };
}

public static class PcaSemanticKernelExtensions
{
    /// <summary>Add a <see cref="PcaFunctionFilter"/> to the kernel and return it.</summary>
    public static PcaFunctionFilter UsePca(this Kernel kernel, AgentHandle agent, Func<PcaFunctionCall, (string Verb, string Resource)?> map, PcaFunctionFilterOptions? options = null)
    {
        var f = new PcaFunctionFilter(agent, map, options);
        kernel.FunctionInvocationFilters.Add(f);
        return f;
    }

    /// <summary>Record a chat history's new messages in the agent's provenance chain (call it with the whole history before each model turn;
    /// messages already recorded are skipped). User text is the principal; tool output and anything of an unknown role is untrusted;
    /// assistant and system turns add nothing.</summary>
    public static void RecordChatHistory(this AgentHandle agent, IEnumerable<ChatMessageContent> history) =>
        PcaAdapters.RecordMessages(agent, history.Select(m => (object?)new D { ["role"] = m.Role.Label, ["content"] = m.Content ?? "" }).ToList());
}
