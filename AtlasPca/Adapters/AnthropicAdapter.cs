// Anthropic (Claude) adapter. Claude's tool use is a conversation: an assistant message carries content blocks, and a tool_use block
// ({type, id, name, input}) asks your app to run a tool; your app replies with a user message holding a matching tool_result block
// ({tool_use_id, content}). This adapter sits in that gap: it turns a tool_use block into a PCActn (via PcaAdapters.BridgeToolCall), runs
// your handler with the proof in hand, and hands back the tool_result, including the error-shaped result Claude expects when a tool refuses.
//
// Structural: only the block shapes are modelled (as JSON trees), so it works with any Anthropic client and needs no vendor package.
// HONEST: this does not authorize. It attaches a proof-carrying action; the resource server's verifier decides.
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Adapters;

/// <summary>Your tool implementation: gets the model's input and the PCActn so it can carry the proof downstream. Return a JSON tree
/// (D, L, string, bool, number) or null.</summary>
public delegate Task<object?> AgentToolHandler(D input, PcaCall pca);

/// <summary>A Claude tool_use content block: what the model emits to call a tool.</summary>
public sealed record ToolUseBlock(string Id, string Name, D Input);

/// <summary>A Claude tool_result content block: what your app replies with.</summary>
public sealed record ToolResultBlock(string ToolUseId, string Content, bool IsError = false)
{
    /// <summary>The wire shape <c>{type, tool_use_id, content, is_error?}</c>.</summary>
    public D ToTree()
    {
        var d = new D { ["type"] = "tool_result", ["tool_use_id"] = ToolUseId, ["content"] = Content };
        if (IsError) d["is_error"] = true;
        return d;
    }
}

public static class AnthropicAdapter
{
    /// <summary>Handle one tool_use block: build its PCActn, run the mapped handler, return the tool_result. A tool the mapping declines, or
    /// one with no handler, never runs: Claude gets an <c>is_error</c> result. A handler that throws likewise. On success the content is the
    /// result's JSON, or <c>{"pca": encoded}</c> when the handler returns nothing. Every content that goes back to Claude is recorded as untrusted tool output.</summary>
    public static async Task<ToolResultBlock> HandleToolUse(AgentHandle agent, ToolUseBlock block, Func<AgentToolCall, (string Verb, string Resource)?> map,
        IReadOnlyDictionary<string, AgentToolHandler> handlers, ActOptions? opts = null)
    {
        var pca = PcaAdapters.BridgeToolCall(agent, new AgentToolCall(block.Name, block.Input), map, opts);
        if (pca == null)
            return new ToolResultBlock(block.Id, $"No proof-carrying authority is mapped for tool \"{block.Name}\".", true);
        if (!handlers.TryGetValue(block.Name, out var handler))
            return new ToolResultBlock(block.Id, $"No handler registered for tool \"{block.Name}\".", true);
        try
        {
            var result = await handler(block.Input, pca).ConfigureAwait(false);
            var content = JsJson.Stringify(result ?? new D { ["pca"] = pca.Encoded });
            // the tool_result re-enters Claude's context: untrusted from here on (provenance by default)
            PcaAdapters.RecordToolResult(agent, block.Name, content);
            return new ToolResultBlock(block.Id, content);
        }
        catch (Exception err)
        {
            // a tool's error text reaches Claude too, and a tool can put anything in it
            PcaAdapters.RecordToolResult(agent, block.Name, err.Message);
            return new ToolResultBlock(block.Id, err.Message, true);
        }
    }

    /// <summary>Handle many tool_use blocks (e.g. all of one assistant turn), results in order.</summary>
    public static async Task<List<ToolResultBlock>> HandleToolUses(AgentHandle agent, IEnumerable<ToolUseBlock> blocks, Func<AgentToolCall, (string Verb, string Resource)?> map,
        IReadOnlyDictionary<string, AgentToolHandler> handlers, ActOptions? opts = null) =>
        (await Task.WhenAll(blocks.ToList().Select(b => HandleToolUse(agent, b, map, handlers, opts))).ConfigureAwait(false)).ToList();

    /// <summary>Pull the tool_use blocks out of an assistant message's content array (text and other blocks are ignored). A block without a
    /// string id or name keeps an empty one, and a missing or non-object input is {}: the mapping then declines it and Claude sees an error.</summary>
    public static List<ToolUseBlock> ExtractToolUses(IEnumerable<object?>? content)
    {
        var res = new List<ToolUseBlock>();
        if (content == null) return res;
        foreach (var b in content)
            if (b is D d && d.GetValueOrDefault("type") is "tool_use")
                res.Add(new ToolUseBlock(d.GetValueOrDefault("id") as string ?? "", d.GetValueOrDefault("name") as string ?? "", d.GetValueOrDefault("input") as D ?? new D()));
        return res;
    }

    /// <summary>Provenance by default: wrap <c>client.messages.create</c> (or any call taking <c>{messages}</c>) so every model turn first
    /// records the conversation's new messages (user text is the principal; tool_result blocks are untrusted).</summary>
    public static Func<D, TResult> WithPcaMessages<TResult>(AgentHandle agent, Func<D, TResult> create) =>
        prms =>
        {
            if (prms.GetValueOrDefault("messages") is L messages) PcaAdapters.RecordMessages(agent, messages);
            return create(prms);
        };
}
