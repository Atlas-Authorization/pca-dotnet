// A delegating chat client that records the conversation in the agent's provenance chain before every model turn: user text is the PRINCIPAL
// (trusted), tool results are UNTRUSTED, assistant and system turns add nothing. Put it BELOW FunctionInvokingChatClient (next to the model), so
// it sees the whole history, tool results included, on each turn; messages already recorded are skipped.
using System.Text.Json;
using AtlasPca.Adapters;
using Microsoft.Extensions.AI;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.ExtensionsAI;

public sealed class PcaProvenanceChatClient : DelegatingChatClient
{
    readonly AgentHandle _agent;

    public PcaProvenanceChatClient(IChatClient inner, AgentHandle agent) : base(inner) => _agent = agent ?? throw new ArgumentNullException(nameof(agent));

    public override Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
    {
        var list = messages.ToList();
        Record(list);
        return base.GetResponseAsync(list, options, cancellationToken);
    }

    public override IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
    {
        var list = messages.ToList();
        Record(list);
        return base.GetStreamingResponseAsync(list, options, cancellationToken);
    }

    void Record(IReadOnlyList<ChatMessage> messages) =>
        PcaAdapters.RecordMessages(_agent, messages.Select(m => (object?)new D { ["role"] = m.Role.Value, ["content"] = ContentOf(m) }).ToList());

    static string ContentOf(ChatMessage m)
    {
        if (m.Role != ChatRole.Tool) return m.Text;
        // a tool turn is its function results (untrusted), whatever else it carries
        return string.Join("\n", m.Contents.OfType<FunctionResultContent>().Select(r => r.Result switch
        {
            null => "",
            string s => s,
            JsonElement e => e.GetRawText(),
            var o => JsonSerializer.Serialize(o),
        }));
    }
}
