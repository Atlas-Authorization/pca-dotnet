using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// The action-kit vectors (packages/pca-conformance/vectors/actions): every vector must reproduce its recorded outcome exactly
// (compared as strict canonical JSON, so key order never matters and a number is judged by its lexeme). Nothing is skipped.
public class ActionsVectorTests
{
    static List<D> Cases() =>
        Directory.EnumerateFiles(ActionsDir(), "*.json").OrderBy(f => f, StringComparer.Ordinal).Select(f => (D)Pca.ParseJson(File.ReadAllText(f))!).ToList();

    static string? CodeOf(string? e) => e?.Split(':')[0].Split(' ')[0];
    static D Ok(string? code) => code == null ? new D { ["ok"] = true } : new D { ["ok"] = false, ["code"] = code };

    static object? Replay(D c)
    {
        var i = (D)c["input"]!;
        var pins = i.GetValueOrDefault("pins"); // the verifier's pinned reviewer keys; absent = nothing is confirmed
        switch ((string)c["kind"]!)
        {
            case "parse": return new D { ["ok"] = Actions.ValidateDef(i["def"]) == null };
            case "digest": return new D { ["digest"] = Actions.DefDigest((D)i["def"]!), ["normalized"] = Actions.Normalize((D)i["def"]!) };
            case "effective":
                {
                    var e = Actions.Effective((D)i["def"]!, Actions.CoreRegistry, pins);
                    return new D { ["confirmed"] = e["confirmed"], ["traits"] = e["traits"], ["closure"] = e["closure"], ["eff"] = e["eff"] };
                }
            case "expand":
            case "schema_verb":
                try
                {
                    var reg = i.TryGetValue("custom_traits", out var ct) && ct is L cl && cl.Count > 0 ? Actions.ExtendRegistry(Actions.CoreRegistry, cl) : Actions.CoreRegistry;
                    if ((string)c["kind"]! == "expand")
                    {
                        var ids = (L)i["traits"]!;
                        return new D { ["closure"] = Actions.Closure(reg, ids).Cast<object?>().ToList(), ["floor"] = Actions.FloorOf(reg, ids) };
                    }
                    return Ok(CodeOf(Actions.SchemaVerbFloorError((D)i["verb"]!, reg, pins)));
                }
                catch (ActionKitError) { return new D { ["error"] = true }; }
            case "floor": return new D { ["decision"] = Actions.FloorDecision((D)i["grant"]!, (D)i["call"]!, (D)i["profile"]!) };
            case "conform":
                {
                    var r = ActionSchema.ConformAction(i["schema"], (string)i["verb"]!, i["params"]);
                    return r.Ok ? Ok(null) : Ok(r.Code);
                }
            case "pack":
                {
                    var ds = ((L)i["digests"]!).Cast<string>().ToList();
                    return new D { ["root"] = Actions.PackRoot(ds), ["proof"] = Actions.PackProof(ds, ds[(int)N(i["index"])]) };
                }
            case "schema_shape": return new D { ["ok"] = ActionSchema.ShapeError(i["doc"], signed: false) == null };
            case "rule22_schema": return Ok(Actions.Rule22Integrity((D)i["doc"]!, pins));
            case "rule22":
                {
                    var g = Actions.Rule22Integrity((D)i["doc"]!, pins);
                    if (g != null) return new D { ["integrity"] = g, ["decision"] = "deny" };
                    return new D { ["integrity"] = "ok", ["decision"] = Actions.Rule22Decide((D)i["doc"]!, (string)i["verb"]!, (D)i["grant"]!, (L)i["context"]!) };
                }
            case "pack_verify":
                {
                    var v = Actions.VerifyPack(i["pack"], i["keys"], i.TryGetValue("shards", out var sh) ? sh as D : null);
                    return v["ok"] is true ? new D { ["ok"] = true, ["digest"] = v["digest"], ["defs"] = IntentJs.OfLong(((List<object?>)v["defs"]!).Count) } : new D { ["ok"] = false };
                }
            case "evolution_verify":
                {
                    object? dg = null;
                    try { dg = Actions.EvolutionDiffDigest((D)i["record"]!); } catch { }
                    return new D { ["ok"] = Actions.VerifyEvolutionRecord(i["record"], i["keys"]) == null, ["diff"] = dg };
                }
            case "reapproval_verify":
                {
                    var g = (D)i["grant"]!;
                    return new D { ["ok"] = Actions.ReapprovalValid(i["reapproval"], g["id"], g["issuer"], i["verb"], i["diff"]) };
                }
            case "pin":
                {
                    var d = Actions.DecidePin(i);
                    if (d["ok"] is true) return new D { ["ok"] = true, ["via"] = d["via"] };
                    var o = new D { ["ok"] = false, ["code"] = d["code"], ["escalate"] = d["escalate"] };
                    if (d.ContainsKey("needs_reapproval")) o["needs_reapproval"] = d["needs_reapproval"];
                    return o;
                }
            case "pack_proof_verify": return new D { ["ok"] = Actions.VerifyPackProof((string)i["root"]!, (D)i["proof"]!, (string)i["digest"]!) };
            case "tracker":
                {
                    var t = new Actions.PackTracker(i["keys"]);
                    var res = new L();
                    foreach (var so in (L)i["steps"]!)
                    {
                        var st = (D)so!;
                        var r = t.Accept((D)st["pack"]!, st.TryGetValue("shards", out var sh2) ? sh2 as D : null);
                        res.Add(r["ok"] is true ? new D { ["ok"] = true, ["status"] = r["status"] } : new D { ["ok"] = false, ["code"] = r["code"] });
                    }
                    return res;
                }
            case "approval_render":
                try
                {
                    var r = Approval.Render((D)i["def"]!, i["params"], i.GetValueOrDefault("confirmed") is true);
                    var d = Approval.RenderDigest(r);
                    return new D { ["ok"] = true, ["render"] = r, ["digest"] = d, ["words"] = Approval.BindingWords(d) };
                }
                catch (ActionKitError e) { return Ok(e.Code); }
            case "approval_digest":
                return Approval.RenderShapeError(i["render"]) != null ? new D { ["ok"] = false } : new D { ["ok"] = true, ["digest"] = Approval.RenderDigest(i["render"]) };
            case "approval_challenge":
                try { return new D { ["ok"] = true, ["challenge"] = Approval.Challenge(i["action_digest"], i["render_digest"]) }; }
                catch (ArgumentException) { return new D { ["ok"] = false }; }
            case "approval_escalation":
                {
                    var b = (D)i["bind"]!;
                    var signers = ((L)i["principals"]!).Select(x => new PinnedSigner((string)x!)).ToList();
                    var v = Escalation.Verify(i["answer"], signers, new EscalationBinding((string)b["policy_digest"]!, (string)b["action_digest"]!, (string)b["history_head"]!, b.GetValueOrDefault("render_digest") as string), N(i["now"]));
                    return v.Ok ? new D { ["ok"] = true, ["decision"] = v.Decision } : new D { ["ok"] = false, ["reason"] = v.Reason };
                }
        }
        throw new InvalidOperationException("unknown vector kind " + c["kind"]);
    }

    static object? ReplayProfile(D c)
    {
        var i = (D)c["input"]!;
        try
        {
            switch ((string)c["kind"]!)
            {
                case "approval_psd2": return new D { ["ok"] = true, ["linking"] = Approval.Psd2Linking((D)i["render"]!) };
                case "approval_batch":
                    {
                        var b = Approval.Batch((L)i["items"]!);
                        return new D { ["ok"] = true, ["batch"] = b["batch"], ["action_digest"] = b["action_digest"], ["render_digest"] = b["render_digest"], ["challenge"] = b["challenge"], ["words"] = b["words"] };
                    }
            }
        }
        catch (ActionKitError e) { return Ok(e.Code); }
        throw new InvalidOperationException("unknown approval profile vector kind " + c["kind"]);
    }

    [Fact]
    public void ApprovalProfileVectorsReplay()
    {
        var dir = ApprovalProfilesDir();
        var files = Directory.EnumerateFiles(dir, "*.json").OrderBy(f => f, StringComparer.Ordinal).ToList();
        Assert.True(files.Count >= 12, "approval profile vectors " + files.Count);
        foreach (var f in files)
        {
            var c = (D)Pca.ParseJson(File.ReadAllText(f))!;
            Assert.True(Pca.Canonicalize(ReplayProfile(c)) == Pca.Canonicalize(c["expect"]), (string)c["id"]!);
        }
    }

    [Fact]
    public void EveryVectorReplays()
    {
        var cases = Cases();
        Assert.True(cases.Count >= 781, "vector count " + cases.Count);
        var kinds = new Dictionary<string, int>();
        foreach (var c in cases)
        {
            var k = (string)c["kind"]!;
            kinds[k] = kinds.GetValueOrDefault(k) + 1;
            Assert.True(Pca.Canonicalize(Replay(c)) == Pca.Canonicalize(c["expect"]), (string)c["id"]!);
        }
        foreach (var k in new[] { "parse", "digest", "effective", "expand", "floor", "conform", "pack", "schema_verb", "schema_shape", "rule22", "rule22_schema", "pack_verify", "evolution_verify", "reapproval_verify", "pin", "pack_proof_verify", "tracker", "approval_render", "approval_digest", "approval_challenge", "approval_escalation" })
            Assert.True(kinds.GetValueOrDefault(k) >= 8, k);
    }

    [Fact]
    public void PinnedDigests()
    {
        Assert.Equal("W2xe4TXZKavAeEpzGVYC8pp-ZhOxDv-_3TF76MveweM", Actions.TraitsDigest(Actions.CoreRegistry));
        Assert.Equal("I7nxRoiVhU18WNY_EaUqegG7KeBYtfP8gMmibsfXJtU", Actions.TablesDigest());
    }

    [Fact]
    public void PackProofVerifiesAndTamperFails()
    {
        var c = Cases().First(x => (string)x["id"]! == "pack-builtin");
        var ds = ((L)((D)c["input"]!)["digests"]!).Cast<string>().ToList();
        var root = (string)((D)c["expect"]!)["root"]!;
        foreach (var d in ds) Assert.True(Actions.VerifyPackProof(root, Actions.PackProof(ds, d), d));
        Assert.False(Actions.VerifyPackProof(root, Actions.PackProof(ds, ds[0]), ds[1]));
    }

    [Fact]
    public void WholeDocumentRule22()
    {
        var c = Cases().First(x => (string)x["id"]! == "schema-verb-adv-honest");
        var doc = new D { ["verbs"] = new L { ((D)c["input"]!)["verb"] } };
        Assert.Null(Actions.SchemaFloorError(doc));
        doc["traits_digest"] = new string('A', 43);
        Assert.StartsWith("traits_digest_mismatch", Actions.SchemaFloorError(doc));
    }

    // An unconfirmed def (even one authored by hand, or with a forged `confirmed` state) has EVERY trait of the registry.
    [Fact]
    public void UnconfirmedMeansTop()
    {
        var c = Cases().First(x => (string)x["id"]! == "effective-confirmed-builtin-000");
        var i = (D)c["input"]!;
        var def = (D)i["def"]!;
        var all = Actions.CoreRegistry.Keys.OrderBy(k => k, StringComparer.Ordinal).Cast<object?>().ToList();
        Assert.True((bool)Actions.Effective(def, Actions.CoreRegistry, i["pins"])["confirmed"]!);
        foreach (var pins in new object?[] { null, new D { ["keys"] = new L() } })
        {
            var e = Actions.Effective(def, Actions.CoreRegistry, pins);
            Assert.False((bool)e["confirmed"]!);
            Assert.Equal(all, ((L)e["traits"]!));
        }
        ((D)def["review"]!)["state"] = "authored";
        Assert.False((bool)Actions.Effective(def, Actions.CoreRegistry, i["pins"])["confirmed"]!);
    }

    // Differential oracle for expand/floor (the closure is eight rounds of one-step implication; the decision is the stated three-way rule).
    [Fact]
    public void ExpandAndFloorMatchIndependentOracles()
    {
        var reg = Actions.CoreRegistry;
        var ids = reg.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        for (int a = 0; a < ids.Count; a++)
            for (int b = a; b < ids.Count; b += 3)
            {
                var set = new HashSet<string> { ids[a], ids[b] };
                for (int r = 0; r < 8; r++) foreach (var t in set.ToList()) foreach (var u in ((L)reg[t]["implies"]!).Cast<string>()) set.Add(u);
                var want = set.OrderBy(x => x, StringComparer.Ordinal).ToList();
                Assert.Equal(want, Actions.Closure(reg, new object?[] { ids[a], ids[b] }));
                var fl = Actions.FloorOf(reg, new object?[] { ids[a], ids[b] });
                foreach (var t in want) Assert.True(Actions.Leq((D)reg[t]["floor"]!, fl));
                var g = new D { ["caveats"] = new L(), ["max_esc"] = 3L, ["preauth_esc"] = 3L };
                var e = (long)fl["esc"]!;
                var dec = Actions.FloorDecision(g, new D { ["context"] = new L() }, fl);
                var noneNeeded = ((L)fl["caveats"]!).Count == 0 && ((L)fl["context"]!).Count == 0;
                Assert.Equal(noneNeeded ? "allow" : "escalate", dec);
                Assert.Equal("deny", Actions.FloorDecision(new D { ["caveats"] = new L(), ["max_esc"] = e - 1, ["preauth_esc"] = e - 1 }, new D { ["context"] = new L() }, fl) is var x && e == 0 ? "deny" : x);
            }
    }
}
