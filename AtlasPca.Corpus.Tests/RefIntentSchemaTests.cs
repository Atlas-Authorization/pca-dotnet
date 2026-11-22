using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the outcome space derived from a site action schema (wallet floor, canonical projection, default pinning)
/// against the TypeScript reference (test-data/ref-intent-schema.json.gz). A reference throw requires the native to throw.</summary>
public class RefIntentSchemaTests
{
    const string M = "ref-intent-schema";

    static D? Floor(L a) => a.Count > 1 ? a[1] as D : null;

    [Fact] public void DeriveSchemaOmegaFn() => Base.Check(M, "deriveSchemaOmega", a => IntentSchema.DeriveOmegaFromSchema((D)a[0]!).ToJson());
    [Fact] public void CanonValueFn() => Base.Check(M, "canonValue", a => IntentSchema.CanonValue((D)a[0]!, a[1]));
    [Fact] public void EffectiveSensitivityFn() => Base.Check(M, "effectiveSensitivity", a => IntentSchema.EffectiveSensitivity((D)a[0]!, Floor(a)));
    [Fact] public void VerbReversibilityFn() => Base.Check(M, "verbReversibility", a => IntentSchema.VerbReversibility((D)a[0]!));

    [Fact]
    public void WalletFloorOverridesFn() => Base.Check(M, "walletFloorOverrides", a =>
        IntentSchema.WalletFloorOverrides((L)a[0]!, Floor(a)).Select(x => (object?)x).ToList());

    [Fact] public void AllFnsHandled() { Base.Covers(M, new[] { "deriveSchemaOmega", "canonValue", "effectiveSensitivity", "verbReversibility", "walletFloorOverrides" }); Assert.Equal(267, Base.Total(M)); }
}
