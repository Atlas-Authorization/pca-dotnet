using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>base differential oracle of undo windows, the pure layer (test-data/base-undo.json.gz, TS reference packages/pca/src/undo.ts).
/// Secrets are the base64url of a 32-byte Ed25519 seed.</summary>
public class BaseUndoDiffTests
{
    const string M = "undo";

    static byte[] Seed(object? a) => Pca.B64uDecode(a) ?? Array.Empty<byte>();
    // a typed record parameter: a JS property read of a non-object yields undefined (an empty map); of null, a TypeError
    static D Rec(object? a) => a is D d ? d : a == null ? null! : new D();

    [Fact] public void CompensationDigest() => Base.Check(M, "compensationDigest", a => a[0] is D d ? UndoWindows.CompensationDigest(d) : Base.Refused);
    [Fact] public void SignToken() => Base.Check(M, "signUndoToken", a => a[0] is D d ? UndoWindows.SignToken(d, Seed(a[1])) : Base.Refused);
    [Fact] public void TokenCheck() => Base.Check(M, "undoTokenCheck", a => UndoWindows.TokenCheck(a[0], (string)a[1]!, Rec(a[2]), a[3]));
    [Fact] public void EncodeToken() => Base.Check(M, "encodeUndoToken", a => UndoWindows.EncodeToken((D)a[0]!));
    [Fact] public void TokenDigest() => Base.Check(M, "undoTokenDigest", a => UndoWindows.TokenDigest((D)a[0]!));

    [Fact] public void DecodeToken() => Base.Check(M, "decodeUndoToken", a => UndoWindows.DecodeToken(a[0]));

    [Fact] public void SignReceipt() => Base.Check(M, "signUndoReceipt", a => UndoWindows.SignReceipt((D)a[0]!, Seed(a[1])));
    [Fact] public void ReceiptDigest() => Base.Check(M, "undoReceiptDigest", a => UndoWindows.ReceiptDigest((D)a[0]!));
    [Fact] public void VerifyReceipt() => Base.Check(M, "verifyUndoReceipt", a => UndoWindows.VerifyReceipt(a[0], (string)a[1]!));
    [Fact] public void ReceiptChainError() => Base.Check(M, "undoReceiptChainError", a => UndoWindows.ReceiptChainError((D)a[0]!, (string)a[1]!));

    [Fact]
    public void Transition() => Base.Check(M, "undoTransition", a =>
    {
        var r = UndoWindows.Transition(a[0], a[1], a[2]);
        var o = new D { ["outcome"] = r.Outcome };
        if (r.Outcome == "refused") { o["code"] = r.Code; o["reason"] = r.Reason; }
        else o["record"] = r.Record;
        if (r.Outcome == "applied") o["receipt"] = new D { ["event"] = r.Event, ["note"] = r.Note };
        return o;
    });

    [Fact]
    public void ResolveWindow() => Base.Check(M, "resolveUndoWindow", a =>
    {
        var p = (D)a[1]!;
        double? P(string k) => p.TryGetValue(k, out var v) ? IntentJs.NumOf(v) : null;
        return UndoWindows.ResolveWindow(a[0], P("minMs"), P("maxMs"), P("defaultMs"));
    });

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "compensationDigest", "signUndoToken", "undoTokenCheck", "encodeUndoToken", "undoTokenDigest", "decodeUndoToken", "signUndoReceipt",
        "undoReceiptDigest", "verifyUndoReceipt", "undoReceiptChainError", "undoTransition", "resolveUndoWindow",
    }); Assert.Equal(5985, Base.Total(M)); }
}
