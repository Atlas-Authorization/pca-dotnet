using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 differential oracle of undo windows, the pure layer (test-data/k05-undo.json.gz, TS reference packages/pca/src/undo.ts).
/// Secrets are the base64url of a 32-byte Ed25519 seed.</summary>
public class K05UndoDiffTests
{
    const string M = "undo";

    static byte[] Seed(object? a) => Pca.B64uDecode(a) ?? Array.Empty<byte>();
    // a typed record parameter: a JS property read of a non-object yields undefined (an empty map); of null, a TypeError
    static D Rec(object? a) => a is D d ? d : a == null ? null! : new D();

    [Fact] public void CompensationDigest() => K05.Check(M, "compensationDigest", a => a[0] is D d ? UndoWindows.CompensationDigest(d) : K05.Refused);
    [Fact] public void SignToken() => K05.Check(M, "signUndoToken", a => a[0] is D d ? UndoWindows.SignToken(d, Seed(a[1])) : K05.Refused);
    [Fact] public void TokenCheck() => K05.Check(M, "undoTokenCheck", a => UndoWindows.TokenCheck(a[0], (string)a[1]!, Rec(a[2]), a[3]));
    [Fact] public void EncodeToken() => K05.Check(M, "encodeUndoToken", a => UndoWindows.EncodeToken((D)a[0]!));
    [Fact] public void TokenDigest() => K05.Check(M, "undoTokenDigest", a => UndoWindows.TokenDigest((D)a[0]!));

    [Fact] public void DecodeToken() => K05.Check(M, "decodeUndoToken", a => UndoWindows.DecodeToken(a[0]));

    [Fact] public void SignReceipt() => K05.Check(M, "signUndoReceipt", a => UndoWindows.SignReceipt((D)a[0]!, Seed(a[1])));
    [Fact] public void ReceiptDigest() => K05.Check(M, "undoReceiptDigest", a => UndoWindows.ReceiptDigest((D)a[0]!));
    [Fact] public void VerifyReceipt() => K05.Check(M, "verifyUndoReceipt", a => UndoWindows.VerifyReceipt(a[0], (string)a[1]!));
    [Fact] public void ReceiptChainError() => K05.Check(M, "undoReceiptChainError", a => UndoWindows.ReceiptChainError((D)a[0]!, (string)a[1]!));

    [Fact]
    public void Transition() => K05.Check(M, "undoTransition", a =>
    {
        var r = UndoWindows.Transition(a[0], a[1], a[2]);
        var o = new D { ["outcome"] = r.Outcome };
        if (r.Outcome == "refused") { o["code"] = r.Code; o["reason"] = r.Reason; }
        else o["record"] = r.Record;
        if (r.Outcome == "applied") o["receipt"] = new D { ["event"] = r.Event, ["note"] = r.Note };
        return o;
    });

    [Fact]
    public void ResolveWindow() => K05.Check(M, "resolveUndoWindow", a =>
    {
        var p = (D)a[1]!;
        double? P(string k) => p.TryGetValue(k, out var v) ? IntentJs.NumOf(v) : null;
        return UndoWindows.ResolveWindow(a[0], P("minMs"), P("maxMs"), P("defaultMs"));
    });

    [Fact]
    public void EveryFn() => K05.Covers(M, new[]
    {
        "compensationDigest", "signUndoToken", "undoTokenCheck", "encodeUndoToken", "undoTokenDigest", "decodeUndoToken", "signUndoReceipt",
        "undoReceiptDigest", "verifyUndoReceipt", "undoReceiptChainError", "undoTransition", "resolveUndoWindow",
    });
}
