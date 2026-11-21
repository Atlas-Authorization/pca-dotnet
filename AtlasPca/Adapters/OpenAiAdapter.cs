// OpenAI chat adapter. Turn an OpenAI chat tool_call into a PCActn (via PcaAdapters.BridgeToolCall), run your tool handler with the proof
// attached, and hand back the {role: "tool", ...} message the app feeds to the next model turn: parse arguments, build and sign the proof,
// run the handler, serialize the result. Structural: only the tool-call shape the model returns is modelled, no vendor package.
//
// HONEST: this does NOT authorize. It attaches a proof-carrying action; the resource server's verifier decides. BridgeToolCall does not
// dry-run or fast-fail, so an over-cap call still produces a (signed) PCActn here and is rejected server-side.
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Adapters;

/// <summary>The shape OpenAI chat completions return for a function tool call: <c>{id, type?, function: {name, arguments}}</c>; Arguments is JSON text.</summary>
public sealed record OpenAIToolCall(string Id, string Name, string? Arguments)
{
    /// <summary>Read the wire shape; null when it has no string function name (a call that cannot be mapped).</summary>
    public static OpenAIToolCall? FromTree(object? tree)
    {
        if (tree is not D d || d.GetValueOrDefault("function") is not D f || f.GetValueOrDefault("name") is not string name) return null;
        return new OpenAIToolCall(d.GetValueOrDefault("id") as string ?? "", name, f.GetValueOrDefault("arguments") as string);
    }
}

/// <summary>The tool message the app returns to the model after running the tool.</summary>
public sealed record OpenAIToolMessage(string ToolCallId, string Content)
{
    /// <summary>The wire shape <c>{role: "tool", tool_call_id, content}</c>.</summary>
    public D ToTree() => new() { ["role"] = "tool", ["tool_call_id"] = ToolCallId, ["content"] = Content };
}

public static class OpenAiAdapter
{
    /// <summary>Parse a tool call's arguments (JSON text; null, empty or whitespace is {}). Anything but a JSON object throws.</summary>
    public static D ParseArguments(string? raw)
    {
        if (raw == null) return new D();
        var trimmed = JsX.JsTrim(raw);
        if (trimmed.Length == 0) return new D();
        return Pca.ParseJson(trimmed) as D ?? throw new InvalidOperationException("dispatchToolCall: tool_call arguments must be a JSON object");
    }

    /// <summary>Dispatch one tool call: build and sign a PCActn, run the mapped handler with the proof, return the tool message for the next
    /// model turn (content: the result's JSON, or <c>{"pca": encoded}</c> when the handler returns nothing or is missing). Throws when the
    /// mapping declines the tool: a tool we cannot produce a PCActn for never runs.</summary>
    public static async Task<OpenAIToolMessage> DispatchToolCall(AgentHandle agent, OpenAIToolCall call, Func<AgentToolCall, (string Verb, string Resource)?> map,
        IReadOnlyDictionary<string, AgentToolHandler> handlers, ActOptions? opts = null)
    {
        var args = ParseArguments(call.Arguments);
        var pca = PcaAdapters.BridgeToolCall(agent, new AgentToolCall(call.Name, args), map, opts)
            ?? throw new InvalidOperationException($"dispatchToolCall: no PCActn for unmapped tool \"{call.Name}\" (the mapping declined)");
        var result = handlers.TryGetValue(call.Name, out var handler) ? await handler(args, pca).ConfigureAwait(false) : null;
        var content = JsJson.Stringify(result ?? new D { ["pca"] = pca.Encoded });
        // the tool message re-enters the model's context: untrusted from here on (provenance by default)
        PcaAdapters.RecordToolResult(agent, call.Name, content);
        return new OpenAIToolMessage(call.Id, content);
    }

    /// <summary>Dispatch tool calls sequentially (a model turn may return several). When <c>opts.Counter</c> is given it is incremented per call
    /// so each PCActn carries a distinct monotonic counter.</summary>
    public static async Task<List<OpenAIToolMessage>> DispatchToolCalls(AgentHandle agent, IEnumerable<OpenAIToolCall> calls, Func<AgentToolCall, (string Verb, string Resource)?> map,
        IReadOnlyDictionary<string, AgentToolHandler> handlers, ActOptions? opts = null)
    {
        var res = new List<OpenAIToolMessage>();
        long i = 0;
        foreach (var call in calls)
        {
            var perCall = opts?.Counter is long c ? new ActOptions { Aud = opts.Aud, Counter = c + i, Now = opts.Now } : opts;
            res.Add(await DispatchToolCall(agent, call, map, handlers, perCall).ConfigureAwait(false));
            i++;
        }
        return res;
    }

    /// <summary>Provenance by default: wrap <c>client.chat.completions.create</c> (or any call taking <c>{messages}</c>) so every model turn first
    /// records the conversation's new messages (user turns are the principal, tool turns untrusted).</summary>
    public static Func<D, TResult> WithPcaCompletions<TResult>(AgentHandle agent, Func<D, TResult> create) =>
        prms =>
        {
            if (prms.GetValueOrDefault("messages") is L messages) PcaAdapters.RecordMessages(agent, messages);
            return create(prms);
        };
}
