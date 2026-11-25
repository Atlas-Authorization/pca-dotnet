// Typed refusals of the outbound token vault. Branch on VaultError.Code; the codes are stable.
namespace AtlasPca.Connect;

/// <summary>Base class for every typed refusal the outbound token vault raises. <see cref="Code"/> is one of not_authorized, scope_exceeded,
/// expired_no_refresh, refresh_failed, unknown_connection, store_error, unknown_action, unconfirmed_action, request_mismatch,
/// bearer_release_disabled, proxy_failed.</summary>
public class VaultError : Exception
{
    public string Code { get; }
    /// <summary>The class name the error is known by (NotAuthorizedError, ...).</summary>
    public string ErrorName { get; }

    public VaultError(string code, string message) : this(code, "VaultError", message) { }

    internal VaultError(string code, string name, string message) : base(message)
    {
        Code = code;
        ErrorName = name;
    }
}

/// <summary>The PCActn is not a valid, provider-bound authorization for this connection.</summary>
public sealed class NotAuthorizedError : VaultError
{
    /// <summary>The verifier's per-check verdicts when the refusal came from PCActn verification (else null).</summary>
    public IReadOnlyDictionary<string, bool>? Checks { get; }
    public NotAuthorizedError(string message, IReadOnlyDictionary<string, bool>? checks = null) : base("not_authorized", "NotAuthorizedError", message) { Checks = checks; }
}

/// <summary>The requested scopes are not a subset of what the capability chain grants.</summary>
public sealed class ScopeExceededError : VaultError
{
    public string Provider { get; }
    public IReadOnlyList<string> Requested { get; }
    public IReadOnlyList<string> Granted { get; }
    public IReadOnlyList<string> Missing { get; }
    public ScopeExceededError(string provider, IReadOnlyList<string> requested, IReadOnlyList<string> granted, IReadOnlyList<string> missing)
        : base("scope_exceeded", "ScopeExceededError", $"requested scopes exceed the capability's grant for '{provider}': not granted [{string.Join(", ", missing)}]")
    {
        Provider = provider;
        Requested = requested;
        Granted = granted;
        Missing = missing;
    }
}

/// <summary>The access token is stale and there is no refresh token.</summary>
public sealed class ExpiredNoRefreshError : VaultError
{
    public string Provider { get; }
    public string ConnectionId { get; }
    public ExpiredNoRefreshError(string provider, string connectionId)
        : base("expired_no_refresh", "ExpiredNoRefreshError", $"connection '{provider}/{connectionId}' token is expired and has no refresh token")
    {
        Provider = provider;
        ConnectionId = connectionId;
    }
}

/// <summary>A refresh was attempted but the provider token endpoint call did not yield a usable token.</summary>
public sealed class RefreshFailedError : VaultError
{
    public string Provider { get; }
    /// <summary>The HTTP status when the failure was a non-2xx response, else null.</summary>
    public int? Status { get; }
    public RefreshFailedError(string provider, string detail, int? status = null) : base("refresh_failed", "RefreshFailedError", $"refresh for '{provider}' failed: {detail}")
    {
        Provider = provider;
        Status = status;
    }
}

/// <summary>No stored connection for this agent + provider + connectionId.</summary>
public sealed class UnknownConnectionError : VaultError
{
    public string AgentId { get; }
    public string Provider { get; }
    public string ConnectionId { get; }
    public UnknownConnectionError(string agentId, string provider, string connectionId)
        : base("unknown_connection", "UnknownConnectionError", $"no connection for agent '{agentId}' provider '{provider}' id '{connectionId}'")
    {
        AgentId = agentId;
        Provider = provider;
        ConnectionId = connectionId;
    }
}

/// <summary>The connection store or its encryption failed. The message never carries the underlying error text.</summary>
public sealed class StoreError : VaultError
{
    public StoreError(string message = "the connection store failed") : base("store_error", "StoreError", message) { }
}

/// <summary>The action definition for the PCActn's verb is unknown, so no scope can be derived.</summary>
public sealed class UnknownActionError : VaultError
{
    public UnknownActionError(string verb) : base("unknown_action", "UnknownActionError", $"no pinned action definition for verb '{verb}': refusing to release a credential") { }
}

/// <summary>The action definition has no valid signed confirmation: unconfirmed means maximally dangerous.</summary>
public sealed class UnconfirmedActionError : VaultError
{
    public UnconfirmedActionError(string verb) : base("unconfirmed_action", "UnconfirmedActionError", $"the definition of '{verb}' has no valid signed confirmation: refusing to release a credential") { }
}

/// <summary>The outbound request does not re-derive the signed params digest.</summary>
public sealed class RequestMismatchError : VaultError
{
    public RequestMismatchError(string message) : base("request_mismatch", "RequestMismatchError", message) { }
}

/// <summary>A bare bearer token was requested without the explicit insecure opt-in.</summary>
public sealed class BearerReleaseDisabledError : VaultError
{
    public BearerReleaseDisabledError()
        : base("bearer_release_disabled", "BearerReleaseDisabledError",
            "this vault does not release bearer tokens to callers; use proxyCall(), or construct it with insecureBearerRelease: true (insecure: the caller can use the token for anything inside its scopes until it expires)") { }
}

/// <summary>The proxied call failed after the action was spent.</summary>
public sealed class ProxyFailedError : VaultError
{
    public ProxyFailedError(string message) : base("proxy_failed", "ProxyFailedError", message) { }
}
