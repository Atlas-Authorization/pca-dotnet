using System.Text.RegularExpressions;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>base differential oracle of signed action schemas (test-data/base-actionschema.json.gz, TS reference packages/pca/src/action-schema.ts):
/// variants of a fully populated v2 and v1 schema (every member deleted / retyped / at its byte limit), every collection limit, parameter
/// paths, declaration rules per type, reversibility_by, the confirmation and floors shapes, paramValueViolation over every type and v2
/// format, and formatCheck. Exact strings; the strict canonicalizer's own message is language-specific (only the
/// "malformed schema: canonicalize: " prefix is compared) and four value-domain reasons carry the bound only in TS (mapped by <see cref="Reason"/>).</summary>
public class BaseActionSchemaDiffTests
{
    const string M = "actionschema";
    const string Malformed = "malformed schema: canonicalize: ";

    static bool PrefixEq(D c, object? have) =>
        c["out"] is string w && w.StartsWith(Malformed, StringComparison.Ordinal) && have is string h && h.StartsWith(Malformed, StringComparison.Ordinal) && !h.EndsWith("null", StringComparison.Ordinal)
        || Base.Eq(c["out"], have);

    // as ActionSchemaDifferentialTests.Reason (and Java's K042ActionSchemaTest.javaReason)
    static string? Reason(string? ts) => ts; // the native now words these refusals exactly as the reference (the byte limit and the bound are named)

    [Fact] public void Shape() => Base.Check(M, "shape", a => ActionSchema.ShapeError(a[0]), eq: PrefixEq, min: 9450);
    [Fact] public void ShapeUnsigned() => Base.Check(M, "shapeUnsigned", a => ActionSchema.ShapeError(a[0], false), eq: PrefixEq, min: 6);
    [Fact] public void Confirmation() => Base.Check(M, "confirmation", a => ActionSchema.ConfirmationShapeError(a[0]), eq: PrefixEq, min: 380);
    [Fact] public void Floors() => Base.Check(M, "floors", a => ActionSchema.SchemaFloorsError(a[0]), eq: PrefixEq, min: 350);

    [Fact]
    public void ParamValueViolation() => Base.Check(M, "pvv", a =>
    {
        var r = ActionSchema.ParamValueViolation((D)a[0]!, a[1]);
        return r == null ? null : new D { ["code"] = r.Value.Code, ["reason"] = r.Value.Reason };
    }, eq: (c, h) =>
    {
        var want = c["out"] is D o ? new D { ["code"] = o.GetValueOrDefault("code"), ["reason"] = Reason(o.GetValueOrDefault("reason") as string) } : c["out"];
        return Base.Eq(want, h);
    }, min: 2720);

    [Fact]
    public void Format() => Base.Check(M, "format", a =>
    {
        var ck = ActionSchema.FormatCheck((string)a[0]!);
        return ck == null ? "unknown" : (object)ck((string)a[1]!);
    }, min: 1600);

    [Fact]
    public void EveryFn() { Base.Covers(M, new[] { "shape", "shapeUnsigned", "confirmation", "floors", "pvv", "format" }); Assert.Equal(16139, Base.Total(M)); }
}
