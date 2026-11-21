// Network-token providers and issuance (the reference network-token.ts issueBoundNetworkToken, suspendOnRevoke and the two partner adapters). The provider
// surface is generic: <c>Issue</c> and <c>Suspend</c> plus the controls derived from the rail limits (the network is a SECOND enforcement point; PCA remains the
// policy source). The partner adapters are GENERIC, MOCK-TESTED mappings of PCA controls onto a neutral control shape: they make NO network call, the path and
// field names are placeholders (the partner references are partner-gated) and go live only by swapping the transport.
using System.Globalization;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Payments;

/// <summary>An agent payment network-token provider. <c>IssueAsync</c> issues or activates a token whose own controls equal <c>controls</c> and returns its
/// opaque reference; <c>SuspendAsync</c> suspends it (idempotent).</summary>
public interface INetworkTokenProvider
{
    string Id { get; }
    Task<string> IssueAsync(JD controls, string agentId);
    Task SuspendAsync(string tokenRef, string reason);
}

/// <summary>The partner HTTP surface the adapters call: <c>POST path body -&gt; response object</c>.</summary>
public interface IPartnerTransport
{
    Task<JD> PostAsync(string path, JD body);
}

public static partial class NetworkTokens
{
    sealed class PartnerAdapter(string id, string scopeKey, IPartnerTransport transport) : INetworkTokenProvider
    {
        public string Id => id;

        public async Task<string> IssueAsync(JD controls, string agentId)
        {
            var scope = new JD
            {
                ["currency"] = controls["currency"], ["per_authorization_max"] = controls["perAuthorizationMax"], ["total_max"] = controls["totalMax"],
                ["merchant_categories"] = controls["categories"], ["merchants"] = controls["merchants"],
            };
            if (controls.ContainsKey("expiresAt")) scope["expires_at"] = controls["expiresAt"];
            var r = await transport.PostAsync("/tokens", new JD { ["agent_id"] = agentId, [scopeKey] = scope, ["metadata"] = controls["metadata"] }).ConfigureAwait(false);
            var reference = r.GetValueOrDefault("token_ref");
            var e = TokenRefError(reference);
            if (e != null) throw new InvalidOperationException($"{id}: provider returned {e}");
            return (string)reference!;
        }

        public Task SuspendAsync(string tokenRef, string reason) => transport.PostAsync($"/tokens/{Uri.EscapeDataString(tokenRef)}/suspend", new JD { ["reason"] = reason });
    }

    /// <summary>Visa Intelligent Commerce, generic mapping (partner-gated; unverified field names).</summary>
    public static INetworkTokenProvider VisaIntelligentCommerceAdapter(IPartnerTransport transport) => new PartnerAdapter("visa_ic", "instructions", transport);

    /// <summary>Mastercard Agent Pay (agentic tokens over MDES), generic mapping (partner-gated; unverified field names).</summary>
    public static INetworkTokenProvider MastercardAgentPayAdapter(IPartnerTransport transport) => new PartnerAdapter("mastercard_agent_pay", "session_scope", transport);

    /// <summary>Issuance gate: PCA authorises an issuance only when the requested controls are no wider than the rail limits (they are derived from them). Returns the
    /// binding and the controls actually sent. Refuses a provider response whose <c>token_ref</c> is malformed or PAN-shaped. <paramref name="o"/>:
    /// <c>{limits, grant, agentId, holderSecret, holderPublic, issuerNonce}</c>.</summary>
    public static async Task<(JD Binding, JD Controls)> IssueBoundNetworkTokenAsync(INetworkTokenProvider provider, JD o)
    {
        var controls = ControlsFromLimits(o["limits"], o["grant"]);
        var tokenRef = await provider.IssueAsync(controls, (string)o["agentId"]!).ConfigureAwait(false);
        var binding = BindNetworkToken(new JD
        {
            ["provider"] = provider.Id, ["tokenRef"] = tokenRef, ["grant"] = o["grant"], ["issuerNonce"] = o["issuerNonce"], ["holderSecret"] = o["holderSecret"], ["holderPublic"] = o["holderPublic"],
        });
        return (binding, controls);
    }

    /// <summary>Grant revoked: suspend the token. Provider errors propagate (the caller must retry; a failed suspend is not a success).</summary>
    public static Task SuspendOnRevokeAsync(INetworkTokenProvider provider, JD binding) => provider.SuspendAsync((string)binding["token_ref"]!, "grant_revoked");
}
