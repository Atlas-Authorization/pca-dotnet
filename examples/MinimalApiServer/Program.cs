using AtlasPca;
using AtlasPca.AspNetCore;

var builder = WebApplication.CreateBuilder(args);
// Where the server's trusted settings live. Tests replace this; a real server fills it from its own store.
builder.Services.AddSingleton(new ServerSettings());
var app = builder.Build();

var settings = app.Services.GetRequiredService<ServerSettings>();
var pca = PcaProtect.Create(settings.Audience, settings.Grants, settings.Operation, o =>
{
    o.Clock = settings.Clock;
    // provenance by default: a refund is sensitive, so the request presents a provenance bundle (PCA-Provenance header) recorded under a
    // pinned mediator key; without one the call escalates to the principal.
    o.Authorize!.ProvenanceFlow = new ArgProvenanceOptions { Mediators = settings.Mediators };
});
app.UsePcaProtect(pca);

// Reached only when the proof is valid for exactly this refund.
app.MapPost("/refunds", (HttpContext ctx) =>
{
    var allowed = (PcaAuthResult)ctx.Items["pca"]!;
    return Results.Ok(new { refunded = true, operation = allowed.Operation?.Id });
});

app.Run();

/// <summary>The audience, the grants this server accepts (looked up by id, never taken from the request) and how a request maps to its operation.</summary>
public sealed class ServerSettings
{
    public string Audience { get; init; } = "ins_example";
    public List<Dictionary<string, object?>> Grants { get; init; } = new();
    public Func<long> Clock { get; init; } = () => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    /// <summary>The pinned keys of the mediators (your agent runtime or app UI) that record provenance bundles.</summary>
    public List<ProvMediatorPin> Mediators { get; init; } = new();

    /// <summary>The operation this route executes, read from the request body {"charge": "ch_1", ...}; never from the proof.</summary>
    public Func<HttpContext, Task<Operation?>> Operation { get; init; } = async ctx =>
    {
        ctx.Request.EnableBuffering();
        using var reader = new StreamReader(ctx.Request.Body, leaveOpen: true);
        var text = await reader.ReadToEndAsync();
        ctx.Request.Body.Position = 0;
        var body = Pca.ParseJson(text) as Dictionary<string, object?>;
        return body?.GetValueOrDefault("charge") is string charge ? new Operation("stripe.refund", "charge:" + charge, body) : null;
    };
}

public partial class Program { }
