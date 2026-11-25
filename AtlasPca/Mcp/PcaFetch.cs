// The agent side of an MCP server that requires a PCActn per tool call (packages/pca-mcp fetch.ts pcaFetch): an HTTP message handler for the MCP client transport that, for every
// JSON-RPC tools/call request, builds a fresh PCActn for that call (verb and resource from your mapping, the tool arguments committed by digest, a new counter) and adds it as the
// PCA-Action header (and PCA-Provenance). Every other request passes through unchanged. It decides nothing: the server's verifier does. By default every tools/call response is
// recorded in the agent's provenance chain as UNTRUSTED tool output before it is returned.
using AtlasPca.Adapters;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Mcp;

public sealed class PcaFetch : DelegatingHandler
{
    readonly AgentHandle _agent;
    readonly Mcp.ToolActionMap _toolAction;
    readonly string? _aud;

    /// <param name="agent">The agent whose provenance recorder labels the tool output.</param>
    /// <param name="toolAction">Which PCA action an MCP tool call is; null sends the call without a proof.</param>
    /// <param name="inner">The handler to wrap (for example a <see cref="HttpClientHandler"/>).</param>
    /// <param name="aud">Audience override for the proofs (else the agent's default).</param>
    public PcaFetch(AgentHandle agent, Mcp.ToolActionMap toolAction, HttpMessageHandler inner, string? aud = null) : base(inner ?? throw new ArgumentNullException(nameof(inner)))
    {
        _agent = agent ?? throw new ArgumentNullException(nameof(agent));
        _toolAction = toolAction ?? throw new ArgumentNullException(nameof(toolAction));
        _aud = aud;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content == null ? null : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var call = Mcp.ToolCallOf(body);
        if (call == null) return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var name = (string)call["name"]!;
        var proof = PcaAdapters.BridgeToolCall(_agent, new AgentToolCall(name, (D)call["arguments"]!), c => _toolAction(c.Name, c.Arguments), _aud != null ? new ActOptions { Aud = _aud } : null);
        if (proof == null) return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        foreach (var (k, v) in proof.Headers)
        {
            request.Headers.Remove(k);
            request.Headers.TryAddWithoutValidation(k, v);
        }
        var res = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        // the tool result enters the model's context: record it (untrusted) BEFORE the caller can act on it. A JSON body is recorded by its bytes; a stream is recorded at once
        // by its origin (its label does not depend on its bytes).
        object content = new D { ["tool"] = name, ["stream"] = request.RequestUri?.ToString() ?? "" };
        var ct = res.Content?.Headers.ContentType?.MediaType ?? "";
        if (res.Content != null && !ct.Contains("event-stream", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                await res.Content.LoadIntoBufferAsync().ConfigureAwait(false);
                content = await res.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception) { /* unreadable: keep the origin-only record */ }
        }
        PcaAdapters.RecordToolResult(_agent, name, content);
        return res;
    }
}
