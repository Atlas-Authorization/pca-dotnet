using AtlasPca.ActionsKit;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the action authoring forms (shorthands, expansion, loader, typed constructors) against the TypeScript reference.</summary>
public class RefActionsAuthorTests
{
    const string M = "ref-actions-author";

    static D? Dx(L a, int i) => a.Count > i ? a[i] as D : null;
    static object? At(L a, int i) => a.Count > i ? a[i] : null;

    [Fact] public void ParamShorthand() => Base.Check(M, "parseParamShorthand", a => ActionAuthor.ParseParamShorthand((string)a[0]!));
    [Fact] public void ResourceShorthand() => Base.Check(M, "parseResourceShorthand", a => ActionAuthor.ParseResourceShorthand((string)a[0]!));
    [Fact] public void DefaultTitle() => Base.Check(M, "defaultTitle", a => ActionAuthor.DefaultTitle((string)a[0]!));
    [Fact] public void ExpandAction() => Base.Check(M, "expandAction", a => ActionAuthor.ExpandAction(a[0], a.Count > 1 ? a[1] as string : null));
    [Fact] public void LoadActionsValue() => Base.Check(M, "loadActionsValue", a => ActionAuthor.LoadActionsValue(a[0]));
    [Fact] public void Action() => Base.Check(M, "action", a => ActionAuthor.Action((string)a[0]!, (D)a[1]!));

    [Fact]
    public void Builder() => Base.Check(M, "builder", a =>
    {
        var n = (string)a[0]!;
        return n switch
        {
            "email" => ActionAuthor.P.Email(Dx(a, 1)),
            "phone" => ActionAuthor.P.Phone(Dx(a, 1)),
            "url" => ActionAuthor.P.Url(Dx(a, 1)),
            "uuid" => ActionAuthor.P.Uuid(Dx(a, 1)),
            "ccy" => ActionAuthor.P.Ccy(Dx(a, 1)),
            "country" => ActionAuthor.P.Country(Dx(a, 1)),
            "secret" => ActionAuthor.P.Secret(Dx(a, 1)),
            "bool" => ActionAuthor.P.Bool(Dx(a, 1)),
            "date" => ActionAuthor.P.Date(Dx(a, 1)),
            "datetime" => ActionAuthor.P.Datetime(Dx(a, 1)),
            "duration" => ActionAuthor.P.Duration(At(a, 1), Dx(a, 2)),
            "message" => ActionAuthor.P.Message(At(a, 1), Dx(a, 2)),
            "text" => ActionAuthor.P.Text(At(a, 1), Dx(a, 2)),
            "int" => ActionAuthor.P.IntRange(At(a, 1), At(a, 2), Dx(a, 3)),
            "count" => ActionAuthor.P.Count(At(a, 1), Dx(a, 2)),
            "money" => ActionAuthor.P.Money(a[1]!, Dx(a, 2), Dx(a, 3)),
            "id" => ActionAuthor.P.Id((string)a[1]!, Dx(a, 2)),
            "enum" => ActionAuthor.P.EnumOf(((L)a[1]!).Select(v => (string)v!), Dx(a, 2)),
            "set" => ActionAuthor.P.SetOf(((L)a[1]!).Select(v => (string)v!), Dx(a, 2)),
            "array" => ActionAuthor.P.ArrayOf((string)a[1]!, At(a, 2), Dx(a, 3)),
            "optional" => ActionAuthor.P.Optional((D)a[1]!),
            _ => throw new InvalidOperationException("unknown builder " + n),
        };
    });

    [Fact]
    public void Covers() { Base.Covers(M, new[] { "parseParamShorthand", "parseResourceShorthand", "defaultTitle", "expandAction", "loadActionsValue", "builder", "action" }); Assert.Equal(654, Base.Total(M)); }
}
