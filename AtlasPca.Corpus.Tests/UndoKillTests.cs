using AtlasPca;
using Xunit;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Mutation kills for the undo windows pure layer: the order of the token checks (each code first), the inclusive expiry, the
// receipt member count, the chain links (prev at 0, time order, last state), every transition edge, the window clamp edges and
// the undo_window obligation parameters.
public class UndoKillTests
{
    static readonly byte[] Seed = UndoVectorTests.Seed;
    static readonly byte[] Other = Enumerable.Repeat((byte)9, 32).ToArray();
    static readonly string Signer = UndoVectorTests.Signer;
    const long End = 1_800_000_900_000;

    static JD Rec(string id = "op_1") => new()
    {
        ["id"] = id, ["aud"] = "rs", ["principal"] = "P", ["compensation_digest"] = "C", ["render_digest"] = "R", ["window_end"] = IntentJs.OfLong(End),
    };
    static Num At(long v) => IntentJs.OfLong(v);
    static string Check(object? t, JD? rec = null, object? now = null, string? signer = null) => UndoWindows.TokenCheck(t, signer ?? Signer, rec ?? Rec(), now ?? At(End - 1));

    // ---- token: each code is the FIRST failing check

    [Fact]
    public void TokenCheckOrder()
    {
        var t = UndoWindows.SignToken(Rec(), Seed);
        Assert.Equal("ok", Check(t));
        // malformed before signer: an extra member under a wrong expected signer
        Assert.Equal("malformed", Check(new JD(t) { ["x"] = 1L }, signer: "other"));
        Assert.Equal("malformed", Check(new JD(t) { ["v"] = 2L }));
        Assert.Equal("malformed", Check(new JD(t) { ["exp"] = new Num("1.5") }));
        Assert.Equal("malformed", Check(new JD(t) { ["record"] = "" }));
        Assert.Equal("malformed", Check(new JD(t) { ["record"] = "a\u001fb" }));
        Assert.Equal("malformed", Check(new JD(t) { ["record"] = new string('r', 257) }));
        Assert.Equal("malformed", Check(new JD(t) { ["sig"] = "x" }));
        Assert.Equal("malformed", Check(new JD(t) { ["render_digest"] = null }));
        var missing = new JD(t); missing.Remove("aud");
        Assert.Equal("malformed", Check(missing));
        // signer before signature: a tampered token under a wrong expected signer
        Assert.Equal("signer", Check(new JD(t) { ["aud"] = "x" }, signer: EdKey.FromSeed(Other).Id));
        // signature before record: a tampered record id
        Assert.Equal("signature", Check(new JD(t) { ["record"] = "op_2" }));
        // record before binding: another record and another audience
        var other = UndoWindows.SignToken(new JD(Rec("op_2")) { ["aud"] = "x" }, Seed);
        Assert.Equal("record", Check(other));
        // binding before expiry: each bound member, checked after the window closed
        foreach (var (k, v) in new (string, object?)[] { ("aud", "x"), ("principal", "x"), ("compensation_digest", "x"), ("render_digest", "x"), ("window_end", At(End + 1)) })
            Assert.Equal("binding", Check(UndoWindows.SignToken(new JD(Rec()) { [k] = v }, Seed), now: At(End + 10)));
        // an absent render digest binds the empty string
        var noRender = Rec(); noRender.Remove("render_digest");
        var tn = UndoWindows.SignToken(noRender, Seed);
        Assert.Equal("", tn["render_digest"]);
        Assert.Equal("ok", Check(tn, noRender));
        Assert.Equal("binding", Check(tn));
        // a 129..256-character id is a valid token record id; 1 character too
        Assert.Equal("ok", Check(UndoWindows.SignToken(Rec(new string('r', 256)), Seed), Rec(new string('r', 256))));
        Assert.Equal("ok", Check(UndoWindows.SignToken(Rec("r"), Seed), Rec("r")));
    }

    [Fact]
    public void TokenExpiryIsInclusive()
    {
        var t = UndoWindows.SignToken(Rec(), Seed);
        Assert.Equal("ok", Check(t, now: At(End)));
        Assert.Equal("expired", Check(t, now: At(End + 1)));
        Assert.Equal("ok", Check(t, now: At(0)));
        Assert.Equal("expired", Check(t, now: new Num("1.5")));
        Assert.Equal("expired", Check(t, now: "1"));
        Assert.Throws<ArgumentException>(() => UndoWindows.SignToken(Rec(), new byte[31]));
    }

    [Fact]
    public void TokenEncodingIsStrict()
    {
        var t = UndoWindows.SignToken(Rec(), Seed);
        var enc = UndoWindows.EncodeToken(t);
        Assert.Equal(Pca.Canonicalize(t), Pca.Canonicalize(UndoWindows.DecodeToken(enc)));
        Assert.Null(UndoWindows.DecodeToken(""));
        Assert.Null(UndoWindows.DecodeToken(new string('A', 4097)));
        Assert.Null(UndoWindows.DecodeToken(enc + "="));
        Assert.Null(UndoWindows.DecodeToken(null));
        Assert.Null(UndoWindows.DecodeToken(Pca.B64u(System.Text.Encoding.UTF8.GetBytes("[1]"))));
        Assert.Null(UndoWindows.DecodeToken(Pca.B64u(new byte[] { 0x7b, 0xff, 0x7d })));
        Assert.NotEqual(UndoWindows.TokenDigest(t), UndoWindows.TokenDigest(new JD(t) { ["exp"] = At(End + 1) }));
    }

    // ---- receipts and chains

    static JD R(string ev, string state, long at, string prev, JD? extra = null)
    {
        var b = new JD { ["record"] = "op_1", ["event"] = ev, ["state"] = state, ["at"] = At(at), ["compensation_digest"] = "C", ["prev"] = prev, ["note"] = "" };
        if (extra != null) foreach (var (k, v) in extra) b[k] = v;
        return UndoWindows.SignReceipt(b, Seed);
    }

    [Fact]
    public void ReceiptMemberCount()
    {
        var r = R("opened", "open", 1, "");
        Assert.Equal(11, r.Count);
        Assert.True(UndoWindows.VerifyReceipt(r, Signer));
        Assert.False(UndoWindows.VerifyReceipt(new JD(r) { ["x"] = 1L }, Signer));
        var less = new JD(r); less.Remove("note");
        Assert.False(UndoWindows.VerifyReceipt(less, Signer));
        Assert.False(UndoWindows.VerifyReceipt(new JD(r) { ["note"] = "tampered" }, Signer));
        Assert.False(UndoWindows.VerifyReceipt(new JD(r) { ["event"] = "exploded" }, Signer));
        Assert.False(UndoWindows.VerifyReceipt(new JD(r) { ["state"] = "pending" }, Signer));
        Assert.False(UndoWindows.VerifyReceipt(r, EdKey.FromSeed(Other).Id));
        Assert.False(UndoWindows.VerifyReceipt("receipt", Signer));
    }

    [Fact]
    public void ChainLinks()
    {
        JD Chain(string state, params JD[] rs) => new() { ["id"] = "op_1", ["compensation_digest"] = "C", ["state"] = state, ["receipts"] = rs.Select(x => (object?)x).ToList() };
        var r0 = R("opened", "open", 10, "");
        var r1 = R("vetoed", "vetoed", 10, UndoWindows.ReceiptDigest(r0)); // the same instant is not going back
        Assert.Null(UndoWindows.ReceiptChainError(Chain("vetoed", r0, r1), Signer));
        // prev at index 0 must be ''
        Assert.Equal("receipt 0 does not link to the previous one", UndoWindows.ReceiptChainError(Chain("open", R("opened", "open", 10, UndoWindows.ReceiptDigest(r0))), Signer));
        Assert.Equal("receipt 1 does not link to the previous one", UndoWindows.ReceiptChainError(Chain("vetoed", r0, R("vetoed", "vetoed", 10, "")), Signer));
        Assert.Equal("receipt 1 goes back in time", UndoWindows.ReceiptChainError(Chain("vetoed", r0, R("vetoed", "vetoed", 9, UndoWindows.ReceiptDigest(r0))), Signer));
        Assert.Equal("the last receipt does not state the record state", UndoWindows.ReceiptChainError(Chain("open", r0, r1), Signer));
        Assert.Equal("the first receipt is not opened", UndoWindows.ReceiptChainError(Chain("open", R("effect", "open", 10, "")), Signer));
        Assert.Equal("no receipts", UndoWindows.ReceiptChainError(Chain("open"), Signer));
        Assert.Equal("receipt 0 is for another record", UndoWindows.ReceiptChainError(new JD(Chain("open", r0)) { ["id"] = "op_2" }, Signer));
        // withReceipt builds exactly this chain
        var rec = new JD { ["id"] = "op_1", ["compensation_digest"] = "C", ["state"] = "open", ["receipts"] = new JL() };
        rec = UndoWindows.WithReceipt(rec, "opened", "", 10, Seed);
        rec["state"] = "vetoed";
        rec = UndoWindows.WithReceipt(rec, "vetoed", "token", 11, Seed);
        Assert.Null(UndoWindows.ReceiptChainError(rec, Signer));
        Assert.Equal(UndoWindows.ReceiptDigest((JD)((JL)rec["receipts"]!)[0]!), ((JD)((JL)rec["receipts"]!)[1]!)["prev"]);
    }

    // ---- transitions

    static JD T(string state, long attempt = 0, bool effect = false, JD? outcome = null)
    {
        var r = new JD { ["state"] = state, ["window_end"] = At(End), ["ver"] = At(3), ["attempt"] = At(attempt), ["receipts"] = new JL() };
        if (effect) r["effect"] = new JD { ["at"] = At(1) };
        if (outcome != null) r["outcome"] = outcome;
        return r;
    }
    static JD Veto(string via = "token") => new() { ["kind"] = "veto", ["veto"] = new JD { ["at"] = At(1), ["via"] = via, ["by"] = "P" } };

    [Fact]
    public void TransitionEdges()
    {
        var open = T("open");
        var v = UndoWindows.Transition(open, Veto("operator"), At(End));
        Assert.Equal(("applied", "vetoed", "operator", "vetoed"), (v.Outcome, (string)v.Record!["state"]!, v.Note, v.Event));
        Assert.Equal(4L, IntentJs.Lng(v.Record["ver"]));
        Assert.Equal("open", open["state"]); // the input is not modified
        Assert.Equal(3L, IntentJs.Lng(open["ver"]));
        Assert.Equal("window_closed", UndoWindows.Transition(open, Veto(), At(End + 1)).Code);
        foreach (var bad in new object?[] { null, new JD { ["kind"] = "veto" }, new JD { ["kind"] = "veto", ["veto"] = new JD { ["at"] = new Num("1.5"), ["via"] = "token", ["by"] = "P" } } })
            Assert.Equal("invalid", UndoWindows.Transition(open, bad, At(1)).Code);
        // finalize: strictly after window_end
        Assert.Equal("window_open", UndoWindows.Transition(open, new JD { ["kind"] = "finalize" }, At(End)).Code);
        var fin = UndoWindows.Transition(open, new JD { ["kind"] = "finalize" }, At(End + 1));
        Assert.Equal(("finalized", "finalized"), ((string)fin.Record!["state"]!, (string)((JD)fin.Record["outcome"]!)["status"]!));
        Assert.Equal(End + 1, IntentJs.Lng(((JD)fin.Record["outcome"]!)["at"]));
        // abort: the reason is clipped (512 stored, 128 in the receipt note)
        var ab = UndoWindows.Transition(open, new JD { ["kind"] = "abort", ["reason"] = new string('x', 600) }, At(1));
        Assert.Equal((512, 128), (((string)((JD)ab.Record!["outcome"]!)["reason"]!).Length, ab.Note!.Length));
        Assert.Equal("undefined", UndoWindows.Transition(open, new JD { ["kind"] = "abort" }, At(1)).Note);
        Assert.Equal("effect_recorded", UndoWindows.Transition(T("vetoed", effect: true), new JD { ["kind"] = "abort", ["reason"] = "x" }, At(1)).Code);
        Assert.Equal("replayed", UndoWindows.Transition(T("finalized", outcome: new JD { ["status"] = "aborted" }), new JD { ["kind"] = "abort", ["reason"] = "x" }, At(1)).Outcome);
        Assert.Equal("finalized", UndoWindows.Transition(T("compensated"), new JD { ["kind"] = "abort", ["reason"] = "x" }, At(1)).Code);
        // effect: result kept when present (null included), absent otherwise
        var ef = UndoWindows.Transition(open, new JD { ["kind"] = "effect", ["result"] = null }, At(7));
        Assert.True(((JD)ef.Record!["effect"]!).ContainsKey("result"));
        Assert.False(((JD)UndoWindows.Transition(open, new JD { ["kind"] = "effect" }, At(7)).Record!["effect"]!).ContainsKey("result"));
        Assert.Equal("finalized", UndoWindows.Transition(T("compensated"), new JD { ["kind"] = "effect" }, At(7)).Code);
        // compensation
        Assert.Equal("not_vetoed", UndoWindows.Transition(T("finalized"), new JD { ["kind"] = "compensated" }, At(1)).Code);
        Assert.Equal("not_vetoed", UndoWindows.Transition(T("compensated"), new JD { ["kind"] = "compensation_failed", ["reason"] = "x" }, At(1)).Code);
        Assert.Equal("replayed", UndoWindows.Transition(T("compensation_failed"), new JD { ["kind"] = "compensation_failed", ["reason"] = "x" }, At(1)).Outcome);
        // retry bumps the attempt; a record without a safe-integer attempt is not retried
        var rt = UndoWindows.Transition(T("compensation_failed", attempt: 5), new JD { ["kind"] = "retry" }, At(1));
        Assert.Equal((6L, "retried"), (IntentJs.Lng(rt.Record!["attempt"]), rt.Event));
        var noAttempt = T("compensation_failed"); noAttempt.Remove("attempt");
        Assert.Equal("invalid", UndoWindows.Transition(noAttempt, new JD { ["kind"] = "retry" }, At(1)).Code);
        // malformed records and clocks
        Assert.Equal("invalid", UndoWindows.Transition(new JD(open) { ["ver"] = new Num("1.5") }, Veto(), At(1)).Code);
        Assert.Equal("invalid", UndoWindows.Transition(new JD(open) { ["window_end"] = "x" }, Veto(), At(1)).Code);
        Assert.Equal("invalid", UndoWindows.Transition("record", Veto(), At(1)).Code);
        Assert.Equal("invalid", UndoWindows.Transition(open, Veto(), null).Code);
    }

    // ---- window and obligation

    [Fact]
    public void WindowClampEdges()
    {
        Assert.Equal(UndoWindows.MaxWindowMs, UndoWindows.ResolveWindow(IntentJs.OfLong(UndoWindows.MaxWindowMs)));
        Assert.Equal(UndoWindows.MaxWindowMs, UndoWindows.ResolveWindow(IntentJs.OfLong(UndoWindows.MaxWindowMs + 1)));
        Assert.Equal(UndoWindows.MinWindowMs, UndoWindows.ResolveWindow(IntentJs.OfLong(UndoWindows.MinWindowMs - 1)));
        Assert.Equal(UndoWindows.MinWindowMs + 1, UndoWindows.ResolveWindow(IntentJs.OfLong(UndoWindows.MinWindowMs + 1)));
        Assert.Equal(UndoWindows.DefaultWindowMs, UndoWindows.ResolveWindow(null));
        Assert.Equal(UndoWindows.DefaultWindowMs, UndoWindows.ResolveWindow("60000"));
        Assert.Equal(60_000, UndoWindows.ResolveWindow(new Num("60000.9")));
        Assert.Equal(UndoWindows.MaxWindowMs, UndoWindows.ResolveWindow(null, defaultMs: 1e12));
        Assert.Equal(UndoWindows.MaxWindowMs, UndoWindows.ResolveWindow(null, maxMs: 1e12, defaultMs: 1e12));
        Assert.Equal(40_000, UndoWindows.ResolveWindow(IntentJs.OfLong(1), minMs: 40_000));
    }

    static string? Ob(JD prms) => Obligations.ObligationError(new JD { ["kind"] = "undo_window", ["params"] = prms });

    [Fact]
    public void ObligationParams()
    {
        Assert.Null(Ob(new JD { ["id"] = new string('i', 128), ["window_end"] = At(0) }));
        Assert.NotNull(Ob(new JD { ["id"] = new string('i', 129), ["window_end"] = At(0) }));
        Assert.NotNull(Ob(new JD { ["id"] = "", ["window_end"] = At(0) }));
        Assert.NotNull(Ob(new JD { ["id"] = "i", ["window_end"] = At(-1) }));
        Assert.NotNull(Ob(new JD { ["id"] = "i", ["window_end"] = new Num("1.5") }));
        Assert.NotNull(Ob(new JD { ["id"] = "i", ["window_end"] = At(1), ["by"] = "x" }));
        Assert.Equal("unknown parameter 'by' for 'undo_window'", Ob(new JD { ["id"] = "i", ["window_end"] = At(1), ["by"] = "x" }));
        Assert.Equal("undo_window needs id (a non-empty string of at most 128 characters) and window_end (a non-negative safe integer)", Ob(new JD { ["id"] = "i" }));
        Assert.NotNull(Obligations.ObligationError(new JD { ["kind"] = "undo_window", ["params"] = new JD { ["id"] = "i", ["window_end"] = At(1) }, ["due"] = At(-1) }));
        Assert.Contains("undo_window", Obligations.Kinds);
    }
}
