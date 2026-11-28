using AtlasPca;
using Xunit;

namespace AtlasPca.Corpus.Tests;

/// <summary>Constant-time scalar arithmetic: replays the reference vectors (edge values around L, random values, length bounds).</summary>
public class RefCtScalarTests
{
    const string M = "ref-ct-scalar";

    [Fact] public void Reduce() => Base.Check(M, "reduce", a => CtScalar.Reduce(Base.Bytes(a[0])));
    [Fact] public void Add() => Base.Check(M, "add", a => CtScalar.Add(Base.Bytes(a[0]), Base.Bytes(a[1])));
    [Fact] public void Sub() => Base.Check(M, "sub", a => CtScalar.Sub(Base.Bytes(a[0]), Base.Bytes(a[1])));
    [Fact] public void Mul() => Base.Check(M, "mul", a => CtScalar.Mul(Base.Bytes(a[0]), Base.Bytes(a[1])));
    [Fact] public void IsZero() => Base.Check(M, "isZero", a => CtScalar.IsZero(Base.Bytes(a[0])));

    [Fact] public void Covers() { Base.Covers(M, new[] { "reduce", "add", "sub", "mul", "isZero" }); Assert.Equal(798, Base.Total(M)); }
}
