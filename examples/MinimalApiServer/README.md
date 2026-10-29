# Minimal API server protected by PCA

An ASP.NET Core minimal API with one route, `POST /refunds`, guarded by `PcaProtect.Create`. The route runs only when the request
carries a valid PCA proof (header `PCA-Action`) for exactly that refund, signed under a grant this server knows.

```csharp
var pca = PcaProtect.Create(audience, grants, operationOf);   // grants come from your store, never from the request
app.UsePcaProtect(pca);
app.MapPost("/refunds", ...);
pca.Revoke(grantId);                                          // refuse everything under a grant from now on
```

A refund is a sensitive action, so the request also presents a provenance bundle (header `PCA-Provenance`) recorded by your app or
agent harness under a mediator key the server pins (`ServerSettings.Mediators`); without one the call escalates to the principal.

A refusal is a 401 or 403 with `{ "error", "error_description", "doc" }`; `doc` links the page that explains the failed check.

Run it with `dotnet run`. To use the library in your own project, reference the `AtlasPca.AspNetCore` package. The test project next to
it sends a signed proof through the real pipeline and checks both the allow and the refusal.
