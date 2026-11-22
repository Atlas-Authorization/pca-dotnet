using System.Text.RegularExpressions;
using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the authoring-file text loader (YAML 1.2 core and JSON, with source positions) against the reference corpus. A syntax error is
/// compared by class (the parser's wording is its own); a result where this loader is deliberately STRICTER than the reference (see ActionsText) must be
/// a single "not YAML" refusal on a text that uses one of the documented constructs, never a different successful value.</summary>
public class RefActionsYamlLoadTests
{
    const string M = "ref-actions-yaml-load-py";
    static readonly Regex Stricter = new(@"(^|\s)!(?!!(str|map|seq)\b)\S|\? \[|\r(?!\n)|!!binary");

    static D Norm(D r)
    {
        var o = new D();
        foreach (var k in new[] { "defs", "notes", "errors", "locs", "rules", "ns" }) if (r.ContainsKey(k)) o[k] = r[k];
        return o;
    }

    [Fact]
    public void LoadActionsText() => Base.Check(M, "loadActionsText", a => ActionsText.LoadActionsText((string)a[0]!, (string)a[1]!), (c, have) =>
    {
        var args = Base.Args(c);
        string text = (string)args[0]!, fmt = (string)args[1]!;
        var got = (D)have!; var exp = (D)c["out"]!;
        var gotErrors = (L)got["errors"]!;
        var e0 = (exp.GetValueOrDefault("errors") as L)?.FirstOrDefault() is D d0 && d0.GetValueOrDefault("message") is string m0 ? m0 : "";
        if (e0.StartsWith("not YAML", StringComparison.Ordinal) || e0.StartsWith("YAML warning", StringComparison.Ordinal) || e0.StartsWith("not JSON", StringComparison.Ordinal))
        {
            var msg = gotErrors.Count == 1 ? (string)((D)gotErrors[0]!)["message"]! : "";
            var prefixOk = fmt == "yaml" ? msg.StartsWith("not YAML", StringComparison.Ordinal) || msg.StartsWith("YAML warning", StringComparison.Ordinal) : msg.StartsWith("not JSON", StringComparison.Ordinal);
            return gotErrors.Count == 1 && ((L)got["defs"]!).Count == 0 && prefixOk;
        }
        if (Base.Eq(Norm(exp), Norm(got))) return true;
        return Stricter.IsMatch(text) && gotErrors.Count == 1 && ((string)((D)gotErrors[0]!)["message"]!).StartsWith("not YAML", StringComparison.Ordinal) && ((L)got["defs"]!).Count == 0;
    });

    [Fact] public void Covers() { Base.Covers(M, new[] { "loadActionsText" }); Assert.Equal(105, Base.Total(M)); }
}
