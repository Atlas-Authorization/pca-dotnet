using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Mutation kills for Undo.cs and ActionsRegistry.cs: exact refusal messages, the fail-closed catches (reached through crafted
// dictionaries whose key comparer throws or hides a member), the String(x) rendering of event reasons, the surrogate-safe clip,
// the evolution-chain parent choice, the pack tracker reasons and the 1 000 000-def cap.
public class UndoRegistryKillTests
{
    // ---- crafted inputs

    /// <summary>A key comparer that throws <see cref="Boom"/>'s exception on a lookup (armed after construction).</summary>
    sealed class Trap : IEqualityComparer<string>
    {
        public Func<string, Exception?> Boom = _ => null;
        public bool Equals(string? x, string? y) => string.Equals(x, y, StringComparison.Ordinal);
        public int GetHashCode(string s) => Boom(s) is { } e ? throw e : StringComparer.Ordinal.GetHashCode(s);
    }
    static D Trapped(D src, Func<string, Exception?> boom) { var t = new Trap(); var d = new D(src, t); t.Boom = boom; return d; }

    /// <summary>A key comparer under which a lookup for which <see cref="Hidden"/> says true finds nothing.</summary>
    sealed class Hide : IEqualityComparer<string>
    {
        public Func<string, bool> Hidden = _ => false;
        bool _hide;
        public int GetHashCode(string s) { _hide = Hidden(s); return 0; }
        public bool Equals(string? x, string? y) => !_hide && string.Equals(x, y, StringComparison.Ordinal);
    }

    sealed class NullText { public override string ToString() => null!; }
    sealed class EqualsAnyString { public override bool Equals(object? o) => o is string; public override int GetHashCode() => 0; }

    static object? Priv(Type t, string name, params object?[] args)
    {
        try { return t.GetMethod(name, BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, args); }
        catch (TargetInvocationException e) { throw e.InnerException!; }
    }

    // ================================================================================================================ Undo.cs

    static readonly byte[] Seed = UndoVectorTests.Seed;
    static readonly string Signer = UndoVectorTests.Signer;
    const long End = 1_800_000_900_000;
    static Num At(long v) => IntentJs.OfLong(v);
    static D TokRec() => new() { ["id"] = "op_1", ["aud"] = "rs", ["principal"] = "P", ["compensation_digest"] = "C", ["render_digest"] = "R", ["window_end"] = At(End) };
    static D Opened() => UndoWindows.SignReceipt(new D
    {
        ["record"] = "op_1", ["event"] = "opened", ["state"] = "open", ["at"] = At(10), ["compensation_digest"] = "C", ["prev"] = "", ["note"] = "",
    }, Seed);

    [Fact]
    public void ExactArgumentMessages()
    {
        var c = new D { ["resource"] = "r", ["params"] = new D(), ["undo_of"] = "u", ["def_digest"] = "d" };
        Assert.Equal("missing member 'verb'", Assert.Throws<ArgumentException>(() => UndoWindows.CompensationDigest(c)).Message);
        const string seedMsg = "signer_missing: the undo service key must be a 32-byte Ed25519 secret";
        var body = new D { ["record"] = "op_1", ["event"] = "opened", ["state"] = "open", ["at"] = At(1), ["compensation_digest"] = "C", ["prev"] = "", ["note"] = "" };
        Assert.Equal(seedMsg, Assert.Throws<ArgumentException>(() => UndoWindows.SignReceipt(body, new byte[31])).Message);
        Assert.Equal(seedMsg, Assert.Throws<ArgumentException>(() => UndoWindows.SignToken(TokRec(), new byte[33])).Message);
    }

    // TokenMembers.All: a token whose "aud" is not found by the member scan (but is by every later read) is malformed
    [Fact]
    public void TokenMemberScanNeedsEveryMember()
    {
        var signed = UndoWindows.SignToken(TokRec(), Seed);
        Assert.Equal("ok", UndoWindows.TokenCheck(signed, Signer, TokRec(), At(End)));
        var h = new Hide();
        var t = new D(signed, h);
        int n = 0;
        h.Hidden = k => ++n <= 4 && k == "aud";   // lookups 1..4 are the scan's v, kind, record, aud
        Assert.Equal("malformed", UndoWindows.TokenCheck(t, Signer, TokRec(), At(End)));
    }

    static D Resign(D receipt, string k, object? v)
    {
        var key = EdKey.FromSeed(Seed);
        var r = new D(receipt) { [k] = v };
        r.Remove("sig");
        r["sig"] = Pca.B64u(key.Sign(IntentJs.Message(UndoWindows.ReceiptDomain, r)));
        return r;
    }

    // each of v, kind, record refuses on its own, even correctly signed
    [Fact]
    public void ReceiptHeaderChecksAreIndependent()
    {
        var r = Opened();
        Assert.True(UndoWindows.VerifyReceipt(r, Signer));
        Assert.True(UndoWindows.VerifyReceipt(Resign(r, "note", "n"), Signer));
        Assert.False(UndoWindows.VerifyReceipt(Resign(r, "v", At(2)), Signer));
        Assert.False(UndoWindows.VerifyReceipt(Resign(r, "kind", UndoWindows.TokenKind), Signer));
        Assert.False(UndoWindows.VerifyReceipt(Resign(r, "record", ""), Signer));
    }

    [Fact]
    public void ReceiptChainEvaluationErrorIsMalformed()
    {
        var rec = new D { ["id"] = "op_1", ["compensation_digest"] = "C", ["state"] = "open", ["receipts"] = new L { Opened() } };
        Assert.Null(UndoWindows.ReceiptChainError(rec, Signer));
        var trapped = Trapped(rec, k => k == "id" ? new InvalidOperationException("boom") : null);
        Assert.Equal("malformed receipt chain (fail closed)", UndoWindows.ReceiptChainError(trapped, Signer));
    }

    static D Open() => new() { ["state"] = "open", ["window_end"] = At(End), ["ver"] = At(3), ["attempt"] = At(0), ["receipts"] = new L() };
    static UndoTransitionResult Abort(object? reason) => UndoWindows.Transition(Open(), new D { ["kind"] = "abort", ["reason"] = reason }, At(1));

    // JavaScript String(x) of the reason
    [Fact]
    public void ReasonText()
    {
        Assert.Equal("true", Abort(true).Note);
        Assert.Equal("false", Abort(false).Note);
        Assert.Equal("a,,b", Abort(new L { "a", null, "b" }).Note);
        Assert.Equal("5", Abort(5L).Note);
        var nt = Abort(new NullText());
        Assert.Equal(("applied", ""), (nt.Outcome, nt.Note));
    }

    [Fact]
    public void ClipEdges()
    {
        // exactly n units ending in a high surrogate: kept whole (s[n] does not exist)
        var hi = new string('r', 127) + "\uD83D";
        var a = Abort(hi);
        Assert.Equal(("applied", hi), (a.Outcome, a.Note));
        // a lone LOW surrogate at the cut: not a pair, cut at n
        var lo = new string('r', 128) + "\uDE00";
        var b = Abort(lo);
        Assert.Equal(new string('r', 128), b.Note);
        Assert.Equal(lo, ((D)b.Record!["outcome"]!)["reason"]);
        // n = 0 never reads s[-1]
        Assert.Equal("", Priv(typeof(UndoWindows), "Clip", "ab", 0));
    }

    [Fact]
    public void TransitionEvaluationErrorIsInvalid()
    {
        var ev = Trapped(new D { ["kind"] = "finalize" }, k => k == "kind" ? new InvalidOperationException("boom") : null);
        var r = UndoWindows.Transition(Open(), ev, At(End + 1));
        Assert.Equal(("refused", "invalid", "evaluation error (fail closed)"), (r.Outcome, r.Code, r.Reason));
    }

    // ================================================================================================================ ActionsRegistry.cs

    static readonly EdKey Reg = EdKey.FromSeed(Enumerable.Repeat((byte)7, 32).ToArray());
    static readonly EdKey Rk = EdKey.FromSeed(Enumerable.Repeat((byte)8, 32).ToArray());
    static readonly L Keys = new() { new D { ["kid"] = "kt", ["alg"] = "ed25519", ["pk"] = Reg.Id } };
    static readonly Num One = IntentJs.OfLong(1);
    static string H(string s) => Pca.HashCanonical(s);
    static readonly string Pinned = H("pinned"), Presented = H("presented");
    static D RegSig(string domain, D body) => new() { ["alg"] = "ed25519", ["kid"] = "kt", ["value"] = Pca.B64u(Reg.Sign(IntentJs.Message(domain, body))) };

    [Fact]
    public void JsEqAndWith()
    {
        Assert.Equal(true, Priv(typeof(Actions), "JsEq", null, null));
        Assert.Equal(false, Priv(typeof(Actions), "JsEq", null, "x"));
        Assert.Equal(true, Priv(typeof(Actions), "JsEq", IntentJs.OfLong(1), 1L));
        Assert.Equal(true, Priv(typeof(Actions), "JsEq", new EqualsAnyString(), "x"));
        Assert.Equal(new[] { "a", "b" }, (string[])Priv(typeof(Actions), "With", new[] { "a" }, true, "b")!);
    }

    static D Evo(string cls, params string[] reasons)
    {
        var r = new D
        {
            ["v"] = One, ["kind"] = Actions.EvolutionRecordKind, ["ns"] = "acme", ["verb"] = "acme.do", ["from"] = Pinned, ["to"] = Presented, ["class"] = cls,
            ["reasons"] = reasons.Select(x => (object?)x).ToList(),
        };
        r["sig"] = RegSig(Actions.EvolutionDomain, r);
        return r;
    }

    static D PinIn(object? records, object? reaps = null, object? grant = null) => new()
    {
        ["pin"] = new D { ["pack"] = new D { ["ns"] = "acme", ["root"] = H("root") }, ["defs"] = new D { ["acme.do"] = Pinned }, ["on_new_action"] = "deny" },
        ["doc"] = new D { ["verbs"] = new L { new D { ["verb"] = "acme.do", ["def"] = Presented } }, ["pack"] = new D { ["ns"] = "acme" } },
        ["verb"] = "acme.do", ["records"] = records, ["keys"] = Keys, ["reapprovals"] = reaps, ["grant"] = grant,
    };

    [Fact]
    public void DecidePinFailClosedMessages()
    {
        const string pre = "pin evaluation error (fail closed): ";
        Assert.Equal("chain", Actions.DecidePin(PinIn(new L { Evo("narrow") }))["via"]);
        var d = Actions.DecidePin(PinIn(At(5)));
        Assert.Equal((false, "bad_pin", pre + "records is not iterable"), ((bool)d["ok"]!, (string)d["code"]!, (string)d["reason"]!));
        Assert.Equal(pre + "reapprovals.some is not a function", Actions.DecidePin(PinIn(new L { Evo("widen", "a") }, At(5)))["reason"]);
        Assert.Equal(pre + "Cannot read properties of null (reading 'id')", Actions.DecidePin(PinIn(new L { Evo("widen", "a") }, new L { "r" }))["reason"]);
    }

    // two blocked edges to the same definition: the FIRST one found is the parent (a node is discovered once)
    [Fact]
    public void FirstBlockedEdgeNamesTheReapproval()
    {
        var first = Evo("widen", "a");
        var second = Evo("widen", "b");
        Assert.NotEqual(Actions.EvolutionDiffDigest(first), Actions.EvolutionDiffDigest(second));
        var d = Actions.DecidePin(PinIn(new L { first, second }));
        Assert.Equal("def_changed", d["code"]);
        Assert.Equal(Actions.EvolutionDiffDigest(first), d["needs_reapproval"]);
    }

    static D Reap(object v, string verb = "acme.do", bool sign = true)
    {
        var r = new D { ["v"] = v, ["kind"] = Actions.ReapprovalKind, ["grant"] = "g1", ["verb"] = verb, ["diff"] = "d1" };
        r["sig"] = new D { ["alg"] = "ed25519", ["value"] = sign ? Pca.B64u(Rk.Sign(IntentJs.Message(Actions.ReapprovalDomain, r))) : "x" };
        return r;
    }

    [Fact]
    public void ReapprovalChecks()
    {
        Assert.True(Actions.ReapprovalValid(Reap(One), "g1", Rk.Id, "acme.do", "d1"));
        Assert.False(Actions.ReapprovalValid(Reap(IntentJs.OfLong(2)), "g1", Rk.Id, "acme.do", "d1"));
        // canonicalizing a lone surrogate throws: the catch refuses
        Assert.False(Actions.ReapprovalValid(Reap(One, "a\uD800", sign: false), "g1", Rk.Id, "a\uD800", "d1"));
    }

    [Fact]
    public void VersionMessages()
    {
        Assert.Equal(-1, Math.Sign(Actions.CompareVersions("1.0.0", "1.0.1")));
        Assert.Equal(0, Actions.CompareVersions("1.2.3", "1.2.3"));
        var a = Assert.Throws<ActionKitError>(() => Actions.CompareVersions("x", "1.0.0"));
        Assert.Equal(("bad_version", "'x' is not MAJOR.MINOR.PATCH"), (a.Code, a.Message));
        var b = Assert.Throws<ActionKitError>(() => Actions.CompareVersions("1.0.0", "y"));
        Assert.Equal(("bad_version", "'y' is not MAJOR.MINOR.PATCH"), (b.Code, b.Message));
    }

    [Fact]
    public void ShardDigestAndBadShard()
    {
        var so = new D { ["v"] = One, ["kind"] = "nope", ["ns"] = "acme", ["version"] = "1.0.0", ["name"] = "s1", ["defs"] = new L() };
        Assert.Equal(Pca.HashCanonical(new D { ["d"] = "atlas-pca/action-pack-shard/v1", ["s"] = so }), Actions.ShardDigest(so));
        var pack = new D
        {
            ["ns"] = "acme", ["version"] = "1.0.0",
            ["defs"] = new D { ["shards"] = new L { new D { ["name"] = "s1", ["digest"] = Actions.ShardDigest(so), ["uri"] = "u" } } },
        };
        var e = Assert.Throws<ActionKitError>(() => Actions.PackDefs(pack, new D { ["s1"] = so }));
        Assert.Equal(("bad_shard", "shard 's1' is not a shard of this pack"), (e.Code, e.Message));
    }

    // ---- signed packs

    static readonly L ReadEffects = new() { "read" };
    static readonly D AnyResource = new() { ["type"] = "acme", ["id"] = "*", ["scope"] = "one" };
    static readonly D NoParams = new();
    static readonly D Authored = new() { ["state"] = "authored" };
    static D MinDef(string verb) => new()
    {
        ["v"] = One, ["kind"] = Actions.ActionDefKind, ["verb"] = verb, ["title"] = "t", ["effects"] = ReadEffects, ["resource"] = AnyResource,
        ["params"] = NoParams, ["review"] = Authored,
    };

    static D Pack(string version, object? prev, object defs, string root, string stability = "stable")
    {
        var p = new D
        {
            ["v"] = One, ["kind"] = Actions.ActionPackKind, ["ns"] = "acme", ["version"] = version, ["stability"] = stability,
            ["traits_digest"] = Actions.TraitsDigest(Actions.CoreRegistry), ["roles_digest"] = Actions.TablesDigest(), ["rules_digest"] = Actions.RulesDigest(),
            ["root"] = root, ["defs"] = defs,
            ["source"] = new D { ["kind"] = "hand", ["uri"] = "u", ["spec_digest"] = "s", ["licence"] = "MIT", ["licence_notes"] = "" },
            ["prev"] = prev, ["evolution"] = new L(),
        };
        p["sig"] = RegSig(Actions.PackSigDomain, p);
        return p;
    }
    static D Inline(string version, object? prev, string stability = "stable")
    {
        var d = MinDef("acme.do");
        return Pack(version, prev, new L { d }, Actions.PackRoot(new[] { Actions.DefDigest(d) }), stability);
    }

    static void Refused(D r, string code, string reason) => Assert.Equal((false, code, reason), ((bool)r["ok"]!, (string)r["code"]!, (string)r["reason"]!));

    [Fact]
    public void TrackerReasons()
    {
        var a = Inline("1.0.0", null);
        Assert.Equal(true, Actions.VerifyPack(a, Keys)["ok"]);
        var t = new Actions.PackTracker(Keys);
        Assert.Equal("first", t.Accept(a)["status"]);
        Refused(t.Accept(Inline("1.0.0", null, "beta")), "fork", "two different packs claim one version");
        Refused(t.Accept(Inline("1.1.0", null)), "chain_gap", "prev does not name the accepted pack");
        Assert.Equal("upgrade", t.Accept(Inline("1.1.0", Actions.PackDigest(a)))["status"]);
        Refused(t.Accept(a), "rollback", "older than the accepted version");
    }

    [Fact]
    public void VerifyPackEvaluationError()
    {
        int n = 0;
        // the 1st traits_digest read is the shape check's, the 2nd the registry comparison's
        var tp = Trapped(Inline("1.0.0", null), k => k == "traits_digest" && ++n >= 2 ? new InvalidOperationException("boom") : null);
        var r = Actions.VerifyPack(tp, Keys);
        Assert.Equal((false, "pack verification error: boom"), ((bool)r["ok"]!, (string)r["reason"]!));
    }

    static bool InActionsNormalize() =>
        new StackTrace(false).GetFrames().Any(f => f.GetMethod() is MethodBase m && m.Name == "Normalize" && m.DeclaringType == typeof(Actions));

    // exactly 1 000 000 defs is within the cap. The first def throws once the digests start (Actions.Normalize), so the original
    // stops right after the cap check instead of digesting a million defs; without the trap it would report the wrong root.
    [Fact]
    public void VerifyPackAcceptsExactlyTheDefCap()
    {
        const int Per = 4000, Count = 250;
        var boom = new InvalidOperationException("boom");
        var shards = new D();
        var refs = new L();
        for (int s = 0; s < Count; s++)
        {
            var defs = new L(Per);
            for (int j = 0; j < Per; j++)
            {
                var def = MinDef("acme.v" + (s * Per + j).ToString("D7", CultureInfo.InvariantCulture));
                defs.Add(s == 0 && j == 0 ? Trapped(def, k => k == "resource" && InActionsNormalize() ? boom : null) : def);
            }
            var name = "s" + s.ToString("D3", CultureInfo.InvariantCulture);
            var so = new D { ["v"] = One, ["kind"] = Actions.PackShardKind, ["ns"] = "acme", ["version"] = "1.0.0", ["name"] = name, ["defs"] = defs };
            shards[name] = so;
            refs.Add(new D { ["name"] = name, ["digest"] = Actions.ShardDigest(so), ["uri"] = "u" });
        }
        var r = Actions.VerifyPack(Pack("1.0.0", null, new D { ["shards"] = refs }, H("not the root")), Keys, shards);
        Assert.Equal(false, r["ok"]);
        Assert.Contains((string)r["reason"]!, new[] { "pack verification error: boom", "the Merkle root does not match the defs" });
    }

    // an ActionKitError whose code is none of rule 22's maps to "unknown"
    [Fact]
    public void Rule22UnknownCode()
    {
        var doc = Trapped(new D { ["verbs"] = new L() }, k => k == "trait_defs" ? new ActionKitError("custom_code", "boom") : null);
        Assert.Equal("unknown", Actions.Rule22Integrity(doc));
    }
}
