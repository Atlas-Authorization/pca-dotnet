using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the action data modules (built-in and domain defs, legacy tables, starter templates) against the TypeScript reference.</summary>
public class RefActionsDataTests
{
    const string M = "ref-actions-data";

    static StarterTemplate T(object? id) => ActionTemplates.StarterTemplateById((string)id!) ?? throw new InvalidOperationException("TypeError: unknown template");

    [Fact] public void BuiltinDefs() => Base.Check(M, "builtinDefs", a => ActionBuiltin.BuiltinDefs());
    [Fact] public void DomainDefs() => Base.Check(M, "domainDefs", a => ActionBuiltin.DomainDefs());
    [Fact] public void CorePackDefs() => Base.Check(M, "corePackDefs", a => ActionBuiltin.CorePackDefs());
    [Fact] public void LegacyCatalog() => Base.Check(M, "legacyCatalog", a => ActionBuiltin.LegacyCatalog());
    [Fact] public void LegacyOntologyEffect() => Base.Check(M, "legacyOntologyEffect", a => ActionBuiltin.LegacyOntologyEffect());
    [Fact] public void Resolutions() => Base.Check(M, "resolutions", a => ActionBuiltin.Resolutions());
    [Fact] public void DomainBindings() => Base.Check(M, "domainBindings", a => ActionBuiltin.DomainVerbBindings());
    [Fact] public void CoreDigests() => Base.Check(M, "coreDigests", a => ActionBuiltin.CorePackDefs().Select(d => new L { ((D)d!)["verb"], Actions.DefDigest((D)d!) }).ToList());
    [Fact] public void DomainVerbs() => Base.Check(M, "domainVerbs", a => ActionBuiltin.DomainVerbs((string)a[0]!));
    [Fact] public void DomainRoles() => Base.Check(M, "domainRoles", a => ActionBuiltin.DomainRoles((string)a[0]!));
    [Fact] public void ReleasedBuiltinDefs() => Base.Check(M, "releasedBuiltinDefs", a => IntentJs.JsonEquals(ActionBuiltin.ReleasedBuiltinDefs(), ActionBuiltin.BuiltinDefs()));
    [Fact] public void BuiltinConfirmed() => Base.Check(M, "builtinConfirmed", a => ActionBuiltin.BuiltinReviewerPins() != null);
    [Fact] public void StarterTemplates() => Base.Check(M, "starterTemplates", a => ActionTemplates.StarterTemplates().Select(t => t.Summary()).ToList());
    [Fact] public void TemplateList() => Base.Check(M, "templateList", a => ActionTemplates.StarterTemplates().Select(t => t.Summary()).ToList());
    [Fact] public void StarterTemplateOne() => Base.Check(M, "starterTemplate", a => ActionTemplates.StarterTemplateById((string)a[0]!)?.Summary());
    [Fact] public void TemplateYaml() => Base.Check(M, "templateYaml", a => T(a[0]).Yaml(a[1]));
    [Fact] public void TemplateTraits() => Base.Check(M, "templateTraits", a => T(a[0]).Traits(a[1]));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "builtinDefs", "domainDefs", "corePackDefs", "legacyCatalog", "legacyOntologyEffect", "resolutions", "domainBindings", "coreDigests", "domainVerbs", "domainRoles", "releasedBuiltinDefs", "builtinConfirmed", "starterTemplates", "templateList", "starterTemplate", "templateYaml", "templateTraits" }); Assert.Equal(331, Base.Total(M)); }
}
