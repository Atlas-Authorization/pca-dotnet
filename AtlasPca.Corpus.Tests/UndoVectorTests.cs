using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Undo windows, the pure layer, replaying packages/pca/conformance/undo-vectors.json (a missing file fails): compensation digests,
// the signed token (re-signed byte for byte, encoded, digest, every check code), receipts (re-signed, digests), chains, every
// transition row, the window clamp and the undo_window obligation.
public class UndoVectorTests
{
    static readonly JD Doc = Load("undo-vectors.json");
    internal static readonly byte[] Seed = SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca/undo-vectors/signer"));
    internal static readonly string Signer = EdKey.FromSeed(Seed).Id;

    [Fact]
    public void FormatAndSigner()
    {
        Assert.Equal("pca-undo-vectors", Doc["format"]);
        Assert.Equal(1L, N(Doc["ver"]));
        Assert.Equal((string)D(Doc["signer"])["public"]!, Signer);
    }

    [Fact]
    public void CompensationDigests()
    {
        Assert.Equal(3, L(Doc["compensation"]).Count);
        foreach (var c in L(Doc["compensation"]).Select(D))
            Assert.True(UndoWindows.CompensationDigest(D(c["compensation"])) == (string)c["digest"]!, $"compensation {c["name"]}");
    }

    [Fact]
    public void TokenSignsEncodesAndDigestsLikeTheReference()
    {
        var t = D(Doc["token"]);
        var signed = UndoWindows.SignToken(D(t["record"]), Seed);
        Assert.Equal(Pca.Canonicalize(t["token"]), Pca.Canonicalize(signed));
        Assert.Equal((string)t["encoded"]!, UndoWindows.EncodeToken(signed));
        Assert.Equal((string)t["digest"]!, UndoWindows.TokenDigest(signed));
        Assert.Equal(Pca.Canonicalize(t["token"]), Pca.Canonicalize(UndoWindows.DecodeToken(t["encoded"])));
        Assert.Equal("ok", UndoWindows.TokenCheck(UndoWindows.DecodeToken(t["encoded"]), Signer, D(t["record"]), IntentJs.OfLong(N(D(t["record"])["window_end"]))));
    }

    [Fact]
    public void TokenChecks()
    {
        var checks = L(D(Doc["token"])["checks"]).Select(D).ToList();
        Assert.Equal(12, checks.Count);
        foreach (var c in checks)
            Assert.True(UndoWindows.TokenCheck(c["token"], (string)c["signer"]!, D(c["record"]), c["now"]) == (string)c["expect"]!,
                $"token {c["name"]}: {UndoWindows.TokenCheck(c["token"], (string)c["signer"]!, D(c["record"]), c["now"])}");
    }

    [Fact]
    public void ReceiptsSignAndDigestLikeTheReference()
    {
        var list = L(D(Doc["receipts"])["list"]).Select(D).ToList();
        Assert.Equal(4, list.Count);
        foreach (var x in list)
        {
            var r = D(x["receipt"]);
            var body = new JD { ["record"] = r["record"], ["event"] = r["event"], ["state"] = r["state"], ["at"] = r["at"], ["compensation_digest"] = r["compensation_digest"], ["prev"] = r["prev"], ["note"] = r["note"] };
            Assert.Equal(Pca.Canonicalize(r), Pca.Canonicalize(UndoWindows.SignReceipt(body, Seed)));
            Assert.Equal((string)x["digest"]!, UndoWindows.ReceiptDigest(r));
            Assert.True(UndoWindows.VerifyReceipt(r, Signer));
        }
    }

    [Fact]
    public void Chains()
    {
        var chains = L(D(Doc["receipts"])["chains"]).Select(D).ToList();
        Assert.Equal(12, chains.Count);
        foreach (var c in chains)
        {
            var rec = new JD(D(c["record"])) { ["receipts"] = c["receipts"] };
            var err = UndoWindows.ReceiptChainError(rec, (string)c["signer"]!);
            Assert.True((err == null) == (bool)D(c["expect"])["ok"]!, $"chain {c["name"]}: {err}");
        }
    }

    [Fact]
    public void Transitions()
    {
        var rows = L(Doc["transitions"]).Select(D).ToList();
        Assert.Equal(33, rows.Count);
        foreach (var t in rows)
        {
            var e = D(t["expect"]);
            var rec = new JD(D(t["record"])) { ["receipts"] = new JL() };
            var r = UndoWindows.Transition(rec, t["event"], t["now"]);
            var got = new JD { ["outcome"] = r.Outcome };
            if (r.Outcome == "applied")
            {
                got["state"] = r.Record!["state"];
                got["ver"] = r.Record["ver"];
                if (e.ContainsKey("attempt")) got["attempt"] = r.Record["attempt"];
            }
            else if (r.Outcome == "refused") got["code"] = r.Code;
            Assert.True(Pca.Canonicalize(e) == Pca.Canonicalize(got), $"transition {t["name"]}: {Pca.Canonicalize(got)}");
        }
    }

    internal static double? Opt(JD policy, string k) => IntentJs.NumOf(policy.GetValueOrDefault(k));

    [Fact]
    public void Window()
    {
        var rows = L(Doc["window"]).Select(D).ToList();
        Assert.Equal(9, rows.Count);
        foreach (var w in rows)
        {
            var p = D(w["policy"]);
            Assert.True(UndoWindows.ResolveWindow(w["requested"], Opt(p, "minMs"), Opt(p, "maxMs"), Opt(p, "defaultMs")) == N(w["expect"]), $"window {w["name"]}");
        }
    }

    [Fact]
    public void Obligation()
    {
        var rows = L(Doc["obligation"]).Select(D).ToList();
        Assert.Equal(6, rows.Count);
        foreach (var o in rows)
            Assert.True((Obligations.ObligationsError(new JL { o["obligation"] }) == null) == (bool)D(o["expect"])["ok"]!, $"obligation {o["name"]}");
        // the obligation an admission produces is the valid vector's
        var valid = D(rows.First(o => (string)o["name"]! == "valid")["obligation"]);
        var adm = new UndoAdmission("op_1", N(D(valid["params"])["window_end"]), new UndoCompensationRef("drafts.delete", "drafts:box1"));
        Assert.Equal(Pca.Canonicalize(valid), Pca.Canonicalize(UndoWindows.Obligation(adm)));
    }
}
