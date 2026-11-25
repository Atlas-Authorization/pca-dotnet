using AtlasPca.IntentPkg;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the natural-language facade compiler (grounding prompt, strict parser, compiler) against the TypeScript reference.</summary>
public class RefIntentNlTests
{
    const string M = "ref-intent-nl-java";

    static Catalog CatalogOf(object? extras)
    {
        if (extras == null) return Catalog.Default;
        var specs = new List<CatalogAction>(Catalog.Builtin);
        foreach (var eo in (L)extras)
        {
            var e = (D)eo!;
            string connector = (string)e["connector"]!, action = (string)e["action"]!;
            var aliases = e.GetValueOrDefault("aliases") is L al ? al.Select(x => (string)x!).ToList() : new List<string>();
            specs.Add(new CatalogAction(connector, action, connector + "." + action, (string)e["reversibility"]!, IntentOmega.Dbl(e["blastRadius"]), e.GetValueOrDefault("amountField") as string,
                (string)e["description"]!, aliases, Array.Empty<string>()));
        }
        return new Catalog(specs);
    }

    static IIntentCompiler Compiler(string raw, Action<string> seen) => IntentCompilers.NlFacadeCompiler("nl", "fam", p =>
    {
        seen(p);
        if (raw == "THROWS") throw new InvalidOperationException("llm down");
        return raw;
    });

    static D Input(object? text, Catalog cat) => new() { ["text"] = text, ["catalog"] = cat };

    [Fact] public void NlPrompt() => Base.Check(M, "nlPrompt", a => IntentCompilers.NlPrompt((string)a[0]!, CatalogOf(a[1])));

    [Fact] public void ParseNLPolicy() => Base.Check(M, "parseNLPolicy", a => IntentCompilers.ParseNlPolicy((string)a[0]!, CatalogOf(a[1])));

    [Fact]
    public void NlCompile() => Base.Check(M, "nlCompile", a =>
    {
        string prompt = "";
        var output = Compiler((string)a[1]!, p => prompt = p).Compile(Input(a[0], CatalogOf(a[2])));
        return new D { ["prompt"] = prompt, ["output"] = output };
    });

    [Fact]
    public void NlRun() => Base.Check(M, "nlRun", a => IntentCompilers.RunCompilers(Input(a[0], CatalogOf(a[2])), new[] { Compiler((string)a[1]!, _ => { }) }));

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "nlPrompt", "parseNLPolicy", "nlCompile", "nlRun" }); Assert.Equal(250, Base.Total(M)); }
}
