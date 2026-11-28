using System.Text.RegularExpressions;
using AtlasPca.Gnap;
using Gn = AtlasPca.Gnap.Gnap;
using Ix = AtlasPca.Gnap.Interaction;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the GNAP bridge oracle (test-data/ref-gnap.json.gz, TS reference @atlasauth/pca-gnap): access rights, grant requests,
/// chains, jwsd proofs, step-up and the interaction layer. An InteractionException carries the reference's stable code.</summary>
public class RefGnapTests
{
    const string M = "ref-gnap";

    static object? Unbytes(object? x) => Base.IsBytes(x) ? Base.Bytes(x) : x;
    static D? Opt(L a, int i) => a.Count > i ? (D?)a[i] : null;

    [Fact]
    public void Constants() => Base.Check(M, "constants", _ => new D
    {
        ["GNAP_GRANT_CAVEAT"] = Gn.GnapGrantCaveat, ["GNAP_ACCESS_CAVEAT"] = Gn.GnapAccessCaveat, ["MAX_DETACHED_JWS_CHARS"] = Gn.MaxDetachedJwsChars,
        ["START_MODES"] = new L(Ix.StartModes.Select(x => (object?)x)), ["FINISH_METHODS"] = new L(Ix.FinishMethods.Select(x => (object?)x)),
        ["HASH_METHODS"] = new L(Ix.HashMethods.Select(x => (object?)x)),
    });

    [Fact] public void AgentGnapProfile() => Base.Check(M, "AGENT_GNAP_PROFILE", _ => Gn.AgentGnapProfile());
    [Fact] public void GnapActionResource() => Base.Check(M, "gnapActionResource", a => Gn.GnapActionResource((string)a[0]!, (string)a[1]!));
    [Fact] public void NormalizeAccess() => Base.Check(M, "normalizeAccess", a => Gn.NormalizeAccess(a[0]));
    [Fact] public void AccessToPredicates() => Base.Check(M, "accessToPredicates", a => Gn.AccessToPredicates((D)a[0]!));
    [Fact] public void AccessContains() => Base.Check(M, "accessContains", a => Gn.AccessContains((D)a[0]!, (D)a[1]!));
    [Fact] public void AccessWithin() => Base.Check(M, "accessWithin", a => Gn.AccessWithin((L)a[0]!, (D)a[1]!));
    [Fact] public void ClampAccess() => Base.Check(M, "clampAccess", a => Gn.ClampAccess((L)a[0]!, (L)a[1]!));
    [Fact] public void GrantedAccessOf() => Base.Check(M, "grantedAccessOf", a => Gn.GrantedAccessOf(a[0]));
    [Fact] public void ResolveHolder() => Base.Check(M, "resolveHolder", a => Gn.ResolveHolder(a[0], a.Count > 1 ? a[1] : Gn.Absent));
    [Fact] public void HolderJwk() => Base.Check(M, "holderJwk", a => Gn.HolderJwk((string)a[0]!));

    [Fact] public void GrantRequestToCapability() => Base.Check(M, "grantRequestToCapability", a => Gn.GrantRequestToCapability(a[0], (D)a[1]!));
    [Fact] public void AuthorizeGnapAction() => Base.Check(M, "authorizeGnapAction", a => Gn.AuthorizeGnapAction(a[0], (D)a[1]!, Opt(a, 2)));
    [Fact] public void EncodeBoundToken() => Base.Check(M, "encodeBoundToken", a => Gn.EncodeBoundToken(a[0]));
    [Fact] public void CapabilityToGrantResponse() => Base.Check(M, "capabilityToGrantResponse", a => Gn.CapabilityToGrantResponse(a[0], Opt(a, 1)));
    [Fact] public void VerifyGnapToken() => Base.Check(M, "verifyGnapToken", a => Gn.VerifyGnapToken(a[0], Opt(a, 1)));

    [Fact] public void GnapContentDigest() => Base.Check(M, "gnapContentDigest", a => Gn.GnapContentDigest(Unbytes(a[0])));
    [Fact] public void GnapContentDigestAbsent() => Base.Check(M, "gnapContentDigestAbsent", _ => Gn.GnapContentDigest(Gn.Absent));

    [Fact]
    public void SignGnapRequest() => Base.Check(M, "signGnapRequest", a =>
    {
        var args = new D((D)a[0]!);
        if (args.ContainsKey("body")) args["body"] = Unbytes(args["body"]);
        return Gn.SignGnapRequest(args);
    });

    [Fact]
    public void VerifyGnapRequest() => Base.Check(M, "verifyGnapRequest", a =>
    {
        var args = new D((D)a[0]!);
        args.Remove("seenProofMode", out var mode);
        if (args.ContainsKey("body")) args["body"] = Unbytes(args["body"]);
        var seen = new L();
        if (mode != null)
        {
            args["seenProof"] = new Gn.SeenProof((id, exp) =>
            {
                seen.Add(new L { id, exp });
                switch ((string)mode)
                {
                    case "fresh": return false;
                    case "replayed": return true;
                    case "throws": throw new InvalidOperationException("store down");
                    default: return null; // returns nothing: replayed
                }
            });
        }
        return new D { ["result"] = Gn.VerifyGnapRequest(args), ["seen"] = seen };
    });

    [Fact] public void GnapRequestRequiresStepUp() => Base.Check(M, "gnapRequestRequiresStepUp", a => Gn.GnapRequestRequiresStepUp(a[0], Opt(a, 1)));
    [Fact] public void BeginGnapContinuation() => Base.Check(M, "beginGnapContinuation", a => Gn.BeginGnapContinuation((D)a[0]!));
    [Fact] public void GnapStepUpShare() => Base.Check(M, "gnapStepUpShare", a => Gn.GnapStepUpShare((D)a[0]!, (string)a[1]!, a[2], a[3], a[4]));
    [Fact] public void CompleteGnapContinuation() => Base.Check(M, "completeGnapContinuation", a => Gn.CompleteGnapContinuation((D)a[0]!));

    // ---- interaction ----

    [Fact] public void CallbackUriOk() => Base.Check(M, "callbackUriOk", a => Ix.CallbackUriOk(a[0]));
    [Fact] public void ValidateInteractRequest() => Base.Check(M, "validateInteractRequest", a => Ix.ValidateInteractRequest(a[0]));
    [Fact] public void InteractionHash() => Base.Check(M, "interactionHash", a => Ix.InteractionHash((D)a[0]!));
    [Fact] public void VerifyInteractionHash() => Base.Check(M, "verifyInteractionHash", a => Ix.VerifyInteractionHash(a[0], (D)a[1]!));
    [Fact] public void AcceptFinish() => Base.Check(M, "acceptFinish", a => Ix.AcceptFinish((D)a[0]!, (D)a[1]!));
    [Fact] public void AccessToNeeds() => Base.Check(M, "accessToNeeds", a => Ix.AccessToNeeds((L)a[0]!));

    // only the refusals of newUserCode are recorded (the output is random)
    [Fact] public void NewUserCodeRefusals() => Base.Check(M, "newUserCode", a => Ix.NewUserCode((int)IntentJs.NumOf(a[0])!.Value));

    [Fact]
    public void NewUserCodeShape()
    {
        var re = new Regex(@"\A[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}\z");
        for (int i = 0; i < 200; i++) Assert.Matches(re, Ix.NewUserCode());
        for (int n = 6; n <= 12; n++) Assert.Equal(n, Ix.NewUserCode(n).Length);
        Assert.ThrowsAny<Exception>(() => Ix.NewUserCode(5));
        Assert.ThrowsAny<Exception>(() => Ix.NewUserCode(13));
    }

    // ---- the AS state machine as scripted scenarios (random values replaced by tokens) ----

    static object? Redact(object? v, List<(string? From, string To)> map)
    {
        switch (v)
        {
            case string s:
                foreach (var (f, t) in map) if (!string.IsNullOrEmpty(f)) s = s.Replace(f, t, StringComparison.Ordinal);
                return s;
            case L l: return new L(l.Select(x => Redact(x, map)));
            case D m: return m.ToDictionary(e => e.Key, e => Redact(e.Value, map));
            default: return v;
        }
    }

    static object? StateMap(Ix.State? s) => s?.ToMap();

    static object Scenario(D s)
    {
        long[] clock = { 1000 };
        var opts = (D)s["opts"]!;
        var ge = opts.ContainsKey("grantEndpoint") ? (string)opts["grantEndpoint"]! : "https://as.example/tx";
        var supports = ((L)opts["supports"]!).Select(x => (string)x!).ToList();
        Func<string, string>? app = opts.GetValueOrDefault("app") is true ? id => "app://as/" + id : null;
        long? ttl = opts.ContainsKey("ttlSec") ? IntentJs.Lng(opts["ttlSec"]) : null;
        var srv = new Ix.Server(ge, supports, id => "https://as.example/i/" + id, app, (string?)opts.GetValueOrDefault("userCodeUri"), ttl, () => clock[0]);
        var v = new Dictionary<string, string>();
        var started = new List<(string Id, string Code, string AsNonce)>();
        D? lastReq = null;
        var trace = new L();
        string Sub(object? x)
        {
            if (x is not string str || !str.StartsWith('$')) return (string)x!;
            var k = str[1..];
            var code = v.GetValueOrDefault("code", "");
            if (k == "code:lower") return code.ToLowerInvariant();
            if (k == "code:spaced") return code[..Math.Min(4, code.Length)] + " - " + code[Math.Min(4, code.Length)..];
            return v.GetValueOrDefault(k, str);
        }
        foreach (var so in (L)s["steps"]!)
        {
            var st = (D)so!;
            var op = (string)st["op"]!;
            var entry = new D { ["op"] = op };
            try
            {
                object? value = null;
                switch (op)
                {
                    case "start":
                        {
                            lastReq = (D)st["req"]!;
                            var (it, response) = srv.Start(lastReq);
                            v["id"] = it.Id;
                            v["code"] = it.UserCode ?? "";
                            v["asnonce"] = it.Finish != null ? (string)it.Finish["asNonce"]! : "";
                            started.Add((v["id"], v["code"], v["asnonce"]));
                            value = new D { ["interaction"] = it.ToMap(), ["response"] = response };
                            break;
                        }
                    case "lookup": value = StateMap(srv.LookupUserCode(Sub(st["code"]))); break;
                    case "approve":
                        {
                            var r = srv.Approve(Sub(st["id"]));
                            v["ref"] = (string)r["interactRef"]!;
                            var it = srv.Get(v["id"]);
                            string? h = null;
                            var fin = r.GetValueOrDefault("finish") as D;
                            if (fin != null && fin["method"] is "push") h = (string)((D)fin["body"]!)["hash"]!;
                            else if (fin != null && fin.GetValueOrDefault("url") is string url) { var mt = Regex.Match(url, "[?&]hash=([^&]+)"); if (mt.Success) h = mt.Groups[1].Value; }
                            v["hash"] = h ?? "";
                            string? expected = null;
                            if (it != null && it.Finish != null)
                                expected = Ix.InteractionHash(new D
                                {
                                    ["clientNonce"] = it.Finish["clientNonce"], ["asNonce"] = it.Finish["asNonce"], ["interactRef"] = r["interactRef"],
                                    ["grantEndpoint"] = it.GrantEndpoint, ["hashMethod"] = it.Finish["hashMethod"],
                                });
                            value = new D { ["result"] = r, ["hashOk"] = h == expected };
                            break;
                        }
                    case "consume": value = StateMap(srv.Consume(Sub(st["ref"]))); break;
                    case "finalize": srv.FinalizeInteraction(Sub(st["id"])); break;
                    case "get": value = StateMap(srv.Get(Sub(st["id"]))); break;
                    case "advance": clock[0] += IntentJs.Lng(st["sec"]); value = clock[0]; break;
                    case "accept":
                        {
                            var fin = (D)lastReq!["finish"]!;
                            var ctx = new D { ["clientNonce"] = fin["nonce"], ["asNonce"] = v["asnonce"], ["grantEndpoint"] = ge };
                            if (fin.GetValueOrDefault("hash_method") != null) ctx["hashMethod"] = fin["hash_method"];
                            value = Ix.AcceptFinish(new D { ["hash"] = Sub(st["hash"]), ["interact_ref"] = Sub(st["ref"]) }, ctx);
                            break;
                        }
                    default: throw new InvalidOperationException("unknown step " + op);
                }
                var tokens = new List<(string?, string)>
                {
                    (v.GetValueOrDefault("ref"), "<REF>"), (v.GetValueOrDefault("hash"), "<HASH>"), (v.GetValueOrDefault("asnonce"), "<ASNONCE>"),
                    (v.GetValueOrDefault("id"), "<ID>"), (v.GetValueOrDefault("code"), "<CODE>"),
                };
                // every earlier interaction's id, code and AS nonce is redacted too, by its start number: the latest keeps the plain tokens
                for (int n = 0; n < started.Count - 1; n++)
                {
                    tokens.Add((started[n].Id, $"<ID:{n}>")); tokens.Add((started[n].Code, $"<CODE:{n}>")); tokens.Add((started[n].AsNonce, $"<ASNONCE:{n}>"));
                }
                entry["ok"] = true;
                entry["value"] = Redact(Base.Json(value), tokens);
            }
            catch (InteractionException e)
            {
                entry["ok"] = false;
                entry["code"] = e.Code;
            }
            catch (Exception)
            {
                entry["ok"] = false;
                entry["code"] = "other";
            }
            trace.Add(entry);
        }
        return trace;
    }

    [Fact] public void InteractionScenario() => Base.Check(M, "interactionScenario", a => Scenario((D)a[0]!));

    [Fact]
    public void EveryFnIsCovered() { Base.Covers(M, new[]
    {
        "constants", "AGENT_GNAP_PROFILE", "gnapActionResource", "normalizeAccess", "accessToPredicates", "accessContains", "accessWithin", "clampAccess",
        "grantedAccessOf", "resolveHolder", "holderJwk", "grantRequestToCapability", "authorizeGnapAction", "encodeBoundToken", "capabilityToGrantResponse",
        "verifyGnapToken", "gnapContentDigest", "gnapContentDigestAbsent", "signGnapRequest", "verifyGnapRequest", "gnapRequestRequiresStepUp",
        "beginGnapContinuation", "gnapStepUpShare", "completeGnapContinuation", "callbackUriOk", "validateInteractRequest", "interactionHash",
        "verifyInteractionHash", "acceptFinish", "accessToNeeds", "newUserCode", "interactionScenario",
    }); Assert.Equal(2120, Base.Total(M)); }
}
