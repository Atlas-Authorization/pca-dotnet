using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using AtlasPca.Grants;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential oracle of the pca-grants operational plane (test-data/ref-grants.json.gz): signing, bundles, decision log and replay,
/// consistency tokens, shadow rollout, list-authorized, the grant service and its HTTP binding, lease renewal and HTTP, blueprint kill and admission.
/// Stateful objects are driven by the scenario each case carries; a key is a label (seed = sha256 of "atlas-pca-conformance/" + label).</summary>
public class RefGrantsTests
{
    const string M = "ref-grants";
    static readonly long T0 = Base.OracleT0; // the scripted clock of the scenario oracle

    static EdKey Key(string label) => EdKey.FromSeed(SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label)));
    static string Pub(string label) => Key(label).Id;
    static string S(object? o) => (string)o!;
    static List<string> Strs(object? o) => ((L)o!).Select(x => x is string s ? s : "￿<non-string>").ToList();
    static object? Get(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : null;
    static bool Has(object? o, string k) => o is D d && d.ContainsKey(k);
    static Num N(long v) => new(v.ToString());

    static object? Resolve(object? v)
    {
        switch (v)
        {
            case string s: return s.StartsWith("$key:", StringComparison.Ordinal) ? Pub(s[5..]) : s;
            case L l: return l.Select(Resolve).ToList();
            case D d:
                if (d.TryGetValue("$sign", out var sg) && sg is D m)
                {
                    var key = Key(S(m["label"]));
                    var fields = Resolve(m["fields"]);
                    return S(m["kind"]) switch
                    {
                        "lease" => GrantSigning.SignLease(key, fields),
                        "leaseOver" => GrantSigning.SignLeaseUnsafeOverCap(key, fields),
                        "revocation" => GrantSigning.SignLeaseRevocation(key, fields),
                        "blueprint" => GrantSigning.SignBlueprint(key, fields),
                        "breakglass" => GrantSigning.SignBreakGlass(key, fields),
                        "review" => GrantSigning.SignBreakGlassReview(key, fields),
                        _ => throw new InvalidOperationException("bad sign kind"),
                    };
                }
                return d.ToDictionary(e => e.Key, e => Resolve(e.Value));
            default: return v;
        }
    }

    static D Err(Exception e) => new() { ["$err"] = e is CodedException c ? c.Code : "x" };
    static D ErrTrue() => new() { ["$err"] = true };

    // ---- pure signing ----
    [Fact] public void SignLease() => Base.Check(M, "signLease", a => GrantSigning.SignLease(Key(S(a[0])), a[1]));
    [Fact] public void SignLeaseUnsafeOverCap() => Base.Check(M, "signLeaseUnsafeOverCap", a => GrantSigning.SignLeaseUnsafeOverCap(Key(S(a[0])), a[1]));
    [Fact] public void SignLeaseRevocation() => Base.Check(M, "signLeaseRevocation", a => GrantSigning.SignLeaseRevocation(Key(S(a[0])), a[1]));
    [Fact] public void SignBlueprint() => Base.Check(M, "signBlueprint", a => GrantSigning.SignBlueprint(Key(S(a[0])), a[1]));
    [Fact] public void SignBreakGlass() => Base.Check(M, "signBreakGlass", a => GrantSigning.SignBreakGlass(Key(S(a[0])), a[1]));
    [Fact] public void SignBreakGlassReview() => Base.Check(M, "signBreakGlassReview", a => GrantSigning.SignBreakGlassReview(Key(S(a[0])), a[1]));
    [Fact] public void SignerOf() => Base.Check(M, "signerOf", a => Sig.SignerOf(Key(S(a[0]))));
    [Fact] public void SignBody() => Base.Check(M, "signBody", a => Sig.SignBody(S(a[0]), a[1], Key(S(a[2]))));
    [Fact] public void VerifyBody() => Base.Check(M, "verifyBody", a => Sig.VerifyBody(S(a[0]), a[1], a[2], a[3]));
    [Fact] public void SignBundle() => Base.Check(M, "signBundle", a => Bundle.SignBundle(a[0], Key(S(a[1]))));
    [Fact] public void AssembleBundle() => Base.Check(M, "assembleBundle", a => Bundle.AssembleBundle((D)a[0]!, (L)a[1]!));
    [Fact] public void MaskRecord() => Base.Check(M, "maskRecord", a => Bundle.MaskRecord((D)a[0]!, Strs(a[1])));

    // ---- decision log ----
    static D BatchJson(BatchVerdict v) => v.Ok ? new D { ["ok"] = true, ["next"] = N(v.Next), ["lastCommit"] = v.LastCommit } : new D { ["ok"] = false, ["reason"] = v.Reason };

    static object? LogScenario(D spec)
    {
        var label = S(spec["label"]);
        var log = new Bundle.DecisionLog(Key(label), spec.ContainsKey("mask") ? Strs(spec["mask"]) : new List<string>());
        var recs = ((L)spec["records"]!).Select(r => log.Append((D)r!)).ToList();
        var signer = Pub(label);
        var now = Base.Long(spec["now"]);
        var head = log.Head(now);
        var o = new D { ["recs"] = recs, ["head"] = head, ["size"] = N(log.Size) };
        var proofIdx = spec.ContainsKey("proofs") ? ((L)spec["proofs"]!).Select(Base.Long).ToList() : new List<long>();
        var proofs = proofIdx.Select(i => { try { return (object?)log.Proof(i); } catch (Exception) { return ErrTrue(); } }).ToList();
        o["proofs"] = proofs;
        o["incl"] = proofIdx.Select((i, k) => proofs[k] is D { } p && p.ContainsKey("$err") ? ErrTrue() : (object?)K3.VerifyRecordInclusion(recs[(int)i], proofs[k], head, signer)).ToList();
        var batches = new L();
        foreach (var bx in spec.ContainsKey("batches") ? (L)spec["batches"]! : new L())
        {
            var b = (D)bx!;
            try
            {
                var from = Base.Long(b["from"]);
                var bt = Bundle.NextBatch(log, from, Base.Long(b["max"]), now);
                var lastCommit = from == 0 ? "" : K3.RecordCommit(recs[(int)from - 1])!;
                var records = (L)bt["records"]!;
                var tampered = bt;
                if (records.Count > 0)
                {
                    var first = new D((D)records[0]!) { ["at"] = N(1) };
                    tampered = new D(bt) { ["records"] = new L { first }.Concat(records.Skip(1)).ToList() };
                }
                batches.Add(new D
                {
                    ["bt"] = bt, ["verdict"] = BatchJson(K3.VerifyBatch(bt, from, lastCommit, signer)), ["tampered"] = BatchJson(K3.VerifyBatch(tampered, from, lastCommit, signer)),
                    ["wrong"] = BatchJson(K3.VerifyBatch(bt, from, lastCommit, Pub("zz"))),
                });
            }
            catch (Exception) { batches.Add(ErrTrue()); }
        }
        o["batches"] = batches;
        return o;
    }

    [Fact] public void LogScenarioFn() => Base.Check(M, "logScenario", a => LogScenario((D)a[0]!));

    // ---- replay ----
    static object? ReplayScenario(D spec)
    {
        var cases = ((L)spec["cases"]!).Select(c => (S(Get(c, "action_digest")), Get(c, "input"))).ToList();
        Func<D, Func<object?, string?>> dec = t => i => t.TryGetValue(S(i), out var v) ? v as string : null;
        var revT = (D)spec["revT"]!;
        return new D
        {
            ["diff"] = Bundle.SemanticDiff(cases, dec((D)spec["oldT"]!), dec((D)spec["newT"]!)),
            ["audit"] = Bundle.AuditReplay(((L)spec["records"]!).Select(r => (D)r!), cases, (i, rev) => revT.TryGetValue($"{i}@{rev}", out var v) ? v as string : null),
        };
    }

    [Fact] public void ReplayScenarioFn() => Base.Check(M, "replayScenario", a => ReplayScenario((D)a[0]!));

    // ---- consistency tokens ----
    [Fact] public void MergeFreshAt() => Base.Check(M, "mergeFreshAt", a => FreshAtOps.MergeFreshAt((D)a[0]!, (D)a[1]!));
    [Fact] public void GateDecision() => Base.Check(M, "gateDecision", a => FreshAtOps.GateDecision(S(a[0]), S(Get(a[1], "decision"))));

    static D VerdictJson(FreshAtVerdict v)
    {
        var o = new D { ["decision"] = v.Decision };
        if (v.Code != null) o["code"] = v.Code;
        if (v.Decision == "escalate") o["behind"] = v.Behind.Cast<object?>().ToList();
        return o;
    }

    static object? FreshScenario(D spec)
    {
        var iss = new FreshAtIssuer(Key(S(spec["label"])), S(spec["scope"]), (D)spec["init"]!);
        var o = new L();
        D? last = null;
        foreach (var sx in (L)spec["steps"]!)
        {
            var s = (D)sx!;
            try
            {
                switch (S(s["op"]))
                {
                    case "advance": last = iss.Advance((D)s["patch"]!, Base.Long(s["now"])); o.Add(last); break;
                    case "check":
                        var tok = s["token"] is "last" ? last : s["token"];
                        o.Add(VerdictJson(iss.Check(tok, Base.Long(s["now"]), Has(s, "maxAge") && s["maxAge"] != null ? Base.Long(s["maxAge"]) : null)));
                        break;
                    case "current": o.Add(iss.Current); break;
                    case "tamper":
                        o.Add(VerdictJson(iss.Check(new D(last!) { ["policy_revision"] = N(Base.Long(last!["policy_revision"]) + 1) }, Base.Long(s["now"]))));
                        break;
                }
            }
            catch (Exception) { o.Add(ErrTrue()); }
        }
        return o;
    }

    [Fact] public void FreshScenarioFn() => Base.Check(M, "freshScenario", a => FreshScenario((D)a[0]!));

    // ---- shadow ----
    static object? ShadowScenario(D spec)
    {
        var log = new Shadow.ShadowLog(Key(S(spec["label"])));
        Func<D, Func<object?, string?>> T = t => i =>
        {
            var d = t.TryGetValue(S(i), out var v) ? v as string : null;
            if (d == "throw") throw new InvalidOperationException("boom");
            return d == "junk" ? "weird" : d;
        };
        var cands = ((L)spec["cands"]!).Cast<D>().ToList();
        var candidates = cands.Select(c => new ShadowCandidate(S(c["digest"]), T((D)c["T"]!))).ToList();
        var o = new D();
        var runs = new L();
        var enforcedDigest = S(spec["enforcedDigest"]);
        foreach (var obx in (L)spec["obs"]!)
        {
            var ob = (D)obx!;
            var run = Shadow.RunShadow(ob["input"], T((D)spec["enforcedT"]!), candidates);
            runs.Add(new D { ["decision"] = run.Decision, ["shadow"] = run.Outcomes.Select(x => (object?)x.ToJson()).ToList() });
            foreach (var oc in run.Outcomes) log.Observe(enforcedDigest, S(ob["action_digest"]), run.Decision, oc, Base.Long(ob["at"]));
        }
        o["runs"] = runs;
        var diffs = new D();
        var stats = new D();
        foreach (var c in cands) stats[S(c["digest"])] = log.Stats(S(c["digest"]));
        foreach (var c in cands) diffs[S(c["digest"])] = log.Diffs(S(c["digest"])).Cast<object?>().ToList();
        o["diffs"] = diffs;
        o["stats"] = stats;
        o["verify"] = diffs.Values.SelectMany(x => (L)x!).Select(dx =>
        {
            var d = (D)dx!;
            return (object?)new L
            {
                Shadow.VerifyShadowDiff(d, log.Signer), Shadow.VerifyShadowDiff(d), Shadow.VerifyShadowDiff(d, Pub("zz")),
                Shadow.VerifyShadowDiff(new D(d) { ["sig"] = S(d["sig"])[1..] + "A" }, log.Signer),
                Shadow.VerifyShadowDiff(new D(d) { ["at"] = N(Base.Long(d["at"]) + 1) }),
            };
        }).ToList();
        o["signer"] = log.Signer;
        if (spec.TryGetValue("gate", out var gx) && gx is D g)
        {
            var principals = (g.ContainsKey("principals") ? (L)g["principals"]! : new L()).Select(p => (object?)Pub(S(p))).ToList();
            var explanations = (g.ContainsKey("explain") ? (L)g["explain"]! : new L()).Select(ex =>
            {
                var e = (D)ex!;
                return (object?)Shadow.SignWideningExplanation(Key(S(e["label"])), S(e["shadow_digest"]), S(e["action_digest"]), S(e["reason_digest"]));
            }).ToList();
            D? approval = null;
            if (g.TryGetValue("approval", out var ax) && ax is D ap)
                approval = Shadow.SignPromotionApproval(Key(S(ap["label"])), S(ap["shadow_digest"]), S(ap["enforced_digest"]), Base.Long(ap["at"]));
            o["explanations"] = explanations;
            o["approval"] = approval;
            var opts = g.TryGetValue("options", out var ox) && ox is D od ? new D(od) : new D();
            if (!opts.TryGetValue("principals", out var pv) || pv == null) opts["principals"] = principals;
            if (!opts.TryGetValue("explanations", out var ev) || ev == null) opts["explanations"] = explanations;
            if (approval != null) opts["approval"] = approval;
            var gate = Shadow.PromotionGate(log, opts);
            o["gate"] = gate;
            if (spec.TryGetValue("promote", out var px) && px is D pr)
            {
                try
                {
                    var useGate = !(pr.TryGetValue("useGate", out var ug) && ug is false);
                    var failed = new D { ["ok"] = false, ["code"] = "bad_input", ["reason"] = "x" };
                    o["promoted"] = Shadow.PromoteShadow((D)pr["enforced"]!, (D)pr["candidate"]!, useGate ? gate : failed, pr["now"]);
                }
                catch (Exception) { o["promoted"] = ErrTrue(); }
            }
        }
        return o;
    }

    [Fact] public void ShadowScenarioFn() => Base.Check(M, "shadowScenario", a => ShadowScenario((D)a[0]!));

    // ---- list-authorized ----
    static object? ListScenario(D spec)
    {
        var acc = new WindowReadAccumulator(Base.Long(spec["cap"]), Base.Long(spec["windowMs"]));
        var universe = Strs(spec["universe"]);
        var overfetch = spec.TryGetValue("overfetch", out var of) && of is true;
        var emptyNext = spec.TryGetValue("emptyNext", out var en) && en is true;
        CandidatePage PageOf(List<string> list, string? cursor, int limit)
        {
            var idx = cursor == null ? 0 : (int)double.Parse(cursor, System.Globalization.CultureInfo.InvariantCulture);
            var objects = list.Skip(idx).Take(limit + (overfetch ? 3 : 0)).ToList();
            var next = idx + limit < list.Count ? (idx + limit).ToString() : emptyNext ? "" : null;
            return new CandidatePage(objects, next);
        }
        var relSpec = spec.TryGetValue("relation", out var rs) && rs is D r0 ? r0 : null;
        var allowed = new HashSet<string>(relSpec != null && relSpec.ContainsKey("allowed") ? Strs(relSpec["allowed"]) : new List<string>());
        var useList = relSpec != null && relSpec.TryGetValue("useList", out var ul) && ul is true;
        var rel = new RelationSource
        {
            Check = (s, r, o) => allowed.Contains(o),
            ListObjects = useList ? (s, r, type, cursor, limit) => PageOf(relSpec!.ContainsKey("listed") ? Strs(relSpec["listed"]) : universe, cursor, limit) : null,
        };
        var permitted = spec.ContainsKey("permitted") ? new HashSet<string>(Strs(spec["permitted"])) : null;
        var outp = new L();
        string? cursor2 = null;
        var pages = (int)Base.Long(spec["pages"]);
        for (int p = 0; p < pages; p++)
        {
            var t = spec.TryGetValue("tamper", out var tx) && tx is D td && Base.Long(td["page"]) == p ? td : null;
            try
            {
                var candidates = relSpec != null && relSpec.TryGetValue("asCandidates", out var ac) && ac is true
                    ? ListAuthorized.CandidatesFromRelation(rel, S(spec["subject"]), S(relSpec["name"]))
                    : (type, cur, limit) => PageOf(universe, cur, limit);
                var dropCursor = t != null && t.TryGetValue("dropCursor", out var dc) && dc is true;
                string? passCursor = dropCursor || cursor2 == null ? null : t != null && t.TryGetValue("cursor", out var tc) && tc is string tcs ? tcs : cursor2;
                var args = new ListAuthorizedArgs
                {
                    Subject = t != null && t.TryGetValue("subject", out var ts) ? S(ts) : S(spec["subject"]),
                    ResourceType = S(spec["type"]),
                    Permits = x => permitted == null || permitted.Contains(x),
                    Candidates = candidates,
                    Relation = relSpec != null ? (rel, t != null && t.TryGetValue("relation", out var tr) ? S(tr) : S(relSpec["name"])) : null,
                    FilterId = t != null && t.TryGetValue("filterId", out var tf) ? S(tf) : S(spec["filterId"]),
                    PolicyDigest = S(spec["policyDigest"]),
                    FreshAtDigest = S(spec["freshAt"]),
                    Cursor = passCursor,
                    Limit = t != null && t.TryGetValue("limit", out var tl) ? Base.Long(tl) : Base.Long(spec["limit"]),
                    Reads = acc,
                    Now = T0 + p * (spec.TryGetValue("nowStep", out var ns) ? Base.Long(ns) : 1),
                    SigningKey = Key(t != null && t.TryGetValue("label", out var tlab) ? S(tlab) : S(spec["label"])),
                    MaxScan = spec.TryGetValue("maxScan", out var ms) ? Base.Long(ms) : null,
                };
                var r = ListAuthorized.Run(args);
                outp.Add(r);
                cursor2 = r.TryGetValue("next_cursor", out var nc) ? S(nc) : null;
            }
            catch (Exception e)
            {
                outp.Add(new D { ["$err"] = e is CodedException c ? c.Code : "x" });
                if (t == null) break;
            }
        }
        return outp;
    }

    [Fact] public void ListScenarioFn() => Base.Check(M, "listScenario", a => ListScenario((D)a[0]!));

    [Fact]
    public void WindowAcc() => Base.Check(M, "windowAcc", a =>
    {
        var acc = new WindowReadAccumulator(Base.Long(a[0]), Base.Long(a[1]));
        return ((L)a[2]!).Select(x => (object?)acc.Charge(S(Get(x, "key")), Base.Long(Get(x, "units")), Base.Long(Get(x, "now")))).ToList();
    });

    // ---- grant service ----
    static GrantCaller? Caller(object? who) => who is D d ? new GrantCaller(Get(d, "principal") as string, Get(d, "admin") is true) : null;

    static GrantHttpRequest HttpReq(D s)
    {
        var q = Get(s, "query") is D qd ? qd.ToDictionary(e => e.Key, e => e.Value as string) : null;
        return new GrantHttpRequest(S(s["method"]), S(s["path"]), q, s.GetValueOrDefault("body"), s.GetValueOrDefault("who"));
    }

    static D HttpJson(GrantHttpResponse r) => new() { ["status"] = N(r.Status), ["body"] = r.Body };

    static EdKey Sec(string by) => by switch { "principal" => Key("$P"), "holder" => Key("$A"), "wrongkey" => Key("$X"), _ => throw new InvalidOperationException("no key") };

    static object? GrantScenario(D spec)
    {
        var store = new MemoryGrantStore();
        var events = new L();
        int gc = 0, nc = 0;
        var svc = new GrantService(new GrantServiceOptions
        {
            Store = store, Now = () => T0, NewId = k => k == "grant" ? $"g_{++gc}" : $"n_{++nc}",
            Providers = spec.ContainsKey("providers") ? new GrantProviders
            {
                Usage = g => new D { ["rev"] = g["rev"] }, RemainingBudget = _ => new D { ["left"] = N(5) }, Residual = g => new D { ["id"] = g["id"] },
            } : null,
            VerifyStepUp = spec.ContainsKey("stepUp") ? (r, _) => r == "ok-step" : null,
            OnRevoke = (ids, scope, root) => events.Add(new D { ["revoked"] = ids.Cast<object?>().ToList(), ["scope"] = scope, ["root"] = root["id"] }),
            OnChange = (kind, g) => events.Add(new D { ["change"] = kind, ["id"] = g["id"], ["rev"] = g["rev"] }),
            ValidateNeed = spec.ContainsKey("validateNeed") ? nd => Get(nd, "verb") is "forbidden" ? "verb not allowed" : null : null,
        });
        var handler = GrantHttp.Handler(svc, req => Caller(req.Context));
        var outp = new L();
        foreach (var raw in (L)spec["steps"]!)
        {
            var s = (D)Resolve(raw)!;
            try
            {
                object? r;
                switch (S(s["op"]))
                {
                    case "register": r = svc.Register((D)s["grant"]!); break;
                    case "list":
                    {
                        var f = Get(s, "filter") as D ?? new D();
                        r = svc.List(new GrantListFilter(Get(f, "principal") as string, Get(f, "agent") as string, Get(f, "status") as string,
                            Get(f, "limit") is Num ln ? IntentJs.NumOf(ln) : null, Get(f, "cursor") as string));
                        break;
                    }
                    case "inspect": r = svc.Inspect(S(s["id"])); break;
                    case "amend":
                    {
                        var g = svc.Inspect(S(s["id"]));
                        var authority = s["authority"];
                        var action = S(s["action"]);
                        var req = new D { ["action"] = action, ["authority"] = authority };
                        var by = S(s["by"]);
                        if (by != "none")
                        {
                            req["signed_by"] = Get(s, "signed_by") ?? (by == "holder" ? "holder" : "principal");
                            if (K3.AuthorityDigest(authority) == null) throw new InvalidOperationException("authority digest");
                            req["sig"] = Sig.SignBody(K3.GrantAmendDomain, K3.AmendMessage(g, action, (D)authority!), Sec(by));
                        }
                        if (Get(s, "stepUp") is string su && su.Length > 0) req["step_up_ref"] = su;
                        var (grant, created) = svc.Amend(S(s["id"]), req);
                        r = new D { ["grant"] = grant, ["created"] = created };
                        break;
                    }
                    case "revoke":
                    {
                        var g = svc.Inspect(S(s["id"]));
                        var by = S(s["by"]);
                        var scope = s["scope"];
                        var auth = by == "admin" ? new D { ["admin"] = true } : by == "noauth" ? new D()
                            : new D { ["sig"] = Sig.SignBody(K3.GrantRevokeDomain, K3.GrantRevokeMessage(g["id"], S(scope)), Sec(by)) };
                        r = new D { ["revoked"] = svc.Revoke(S(s["id"]), scope, auth).Cast<object?>().ToList() };
                        break;
                    }
                    case "needs": r = svc.RequestNeeds(S(s["id"]), s["needs"]); break;
                    case "approve":
                    {
                        var needId = S(s["needId"]);
                        var nid = svc.NeedGrantId(needId);
                        var g = svc.Inspect(nid);
                        var sig = Sig.SignBody(K3.NeedApproveDomain, K3.NeedApproveMessage(new D { ["id"] = needId, ["grant_id"] = nid }, g["rev"], s["approved"]), Sec(S(s["by"])));
                        var (grant, created) = svc.ApproveNeeds(needId, s["approved"], sig, Get(s, "stepUp") as string);
                        r = new D { ["grant"] = grant, ["created"] = created };
                        break;
                    }
                    case "deny": svc.DenyNeeds(S(s["needId"])); r = null; break;
                    case "http": r = HttpJson(handler(HttpReq(s))); break;
                    default: throw new InvalidOperationException("bad op");
                }
                outp.Add(r);
            }
            catch (Exception e) { outp.Add(Err(e)); }
        }
        return new D
        {
            ["steps"] = outp, ["events"] = events,
            ["grants"] = store.List().OrderBy(g => S(g["id"]), StringComparer.Ordinal).Cast<object?>().ToList(),
        };
    }

    [Fact] public void GrantScenarioFn() => Base.Check(M, "grantScenario", a => GrantScenario((D)a[0]!));

    // ---- leases ----
    static D Strip(D x) { var o = new D(x); o.Remove("reason"); return o; } // the reference now prints the registry's message too: it is compared

    static D AcceptJson(LeaseAccept a) => a.Ok ? new D { ["ok"] = true, ["replaced"] = a.Replaced, ["seq"] = N(a.Seq) } : a.Reason != null ? new D { ["ok"] = false, ["code"] = a.Code, ["reason"] = a.Reason } : new D { ["ok"] = false, ["code"] = a.Code };

    static D DecisionJson(LeaseDecision d)
    {
        var o = new D { ["decision"] = d.Decision };
        if (d.Code != null) o["code"] = d.Code;
        if (d.LeaseId != null) o["lease_id"] = d.LeaseId;
        if (d.ExpiresAt != null) o["expires_at"] = N(d.ExpiresAt.Value);
        return o;
    }

    static object? LeaseScenario(D spec)
    {
        var pol = Get(spec, "policy") as D ?? new D();
        var policy = new LeasePolicy(new List<string> { Pub("auth") }, Has(pol, "minApprovals") ? Base.Long(pol["minApprovals"]) : 1,
            Has(pol, "eligibleApprovers") ? Strs(pol["eligibleApprovers"]) : null, true, Has(pol, "maxTtlCeiling") ? Base.Long(pol["maxTtlCeiling"]) : null);
        var reg = new LeaseRegistry(policy, new MemoryAtomicKv(), new LeaseRegistryOptions(Has(spec, "shards") ? (int)Base.Long(spec["shards"]) : 4, () => T0));
        var handler = LeaseHttp.Handler(reg, req => Caller(req.Context), () => T0);
        var outp = new L();
        foreach (var raw in (L)spec["steps"]!)
        {
            var s = (D)Resolve(raw)!;
            try
            {
                object? r;
                switch (S(s["op"]))
                {
                    case "accept": r = AcceptJson(reg.Accept(s["lease"], Has(s, "chain") ? Strs(s["chain"]) : new List<string>())); break;
                    case "revoke":
                    {
                        var v = reg.Revoke(s["rev"]);
                        r = v.Ok ? new D { ["ok"] = true, ["revoked"] = N(v.Revoked) } : new D { ["ok"] = false, ["code"] = v.Code };
                        break;
                    }
                    case "get": r = reg.Get(S(s["id"])); break;
                    case "history":
                        r = reg.History(S(s["id"])).Select(h => (object?)new D { ["seq"] = N(h.Seq), ["renewed_at"] = N(h.RenewedAt), ["expires_at"] = N(h.ExpiresAt), ["justification_digest"] = h.JustificationDigest }).ToList();
                        break;
                    case "shardRevs": r = reg.ShardRevocations((int)Base.Long(s["i"])).Cast<object?>().ToList(); break;
                    case "renew":
                    {
                        Func<D, bool>? veto = Has(s, "vetoSeq") ? c => Base.Long(c["seq"]) >= Base.Long(s["vetoSeq"]) : null;
                        r = Leases.RenewLease(Key(Has(s, "label") ? S(s["label"]) : "auth"), reg, S(s["id"]), Get(s, "now"), Get(s, "increment"), S(s["just"]),
                            Has(s, "approvers") ? ((L)s["approvers"]!).ToList() : null, veto, Has(s, "chain") ? Strs(s["chain"]) : null);
                        break;
                    }
                    case "check": r = DecisionJson(Lease.Check(s["lease"], reg, Get(s, "now"))); break;
                    case "http":
                    {
                        var res = handler(HttpReq(s));
                        r = new D { ["status"] = N(res.Status), ["body"] = res.Body is D bd ? Strip(bd) : res.Body };
                        break;
                    }
                    default: throw new InvalidOperationException("bad op");
                }
                outp.Add(r);
            }
            catch (Exception e) { outp.Add(Err(e)); }
        }
        return outp;
    }

    [Fact] public void LeaseScenarioFn() => Base.Check(M, "leaseScenario", a => LeaseScenario((D)a[0]!));

    // ---- blueprints ----
    static object? BlueprintScenario(D spec)
    {
        var reg = new BlueprintRegistry(new List<string> { Pub("op") }, new MemoryBlueprintStore());
        var adm = new Blueprints.AdmissionRegistry();
        var revoked = new L();
        var fresh = new FreshAtIssuer(Key("iss"), "scope", new D
        {
            ["revocation_epoch"] = N(0), ["ledger_tree_size"] = N(0), ["budget_version"] = N(0), ["policy_revision"] = N(0), ["policy_digest"] = "pd",
        });
        var outp = new L();
        foreach (var raw in (L)spec["steps"]!)
        {
            var s = (D)Resolve(raw)!;
            try
            {
                object? r;
                switch (S(s["op"]))
                {
                    case "accept":
                    {
                        var v = reg.Accept(s["bp"]);
                        r = v.Ok ? new D { ["ok"] = true, ["replaced"] = v.Replaced } : new D { ["ok"] = false, ["code"] = v.Code };
                        break;
                    }
                    case "epoch": r = N(reg.Epoch()); break;
                    case "kill":
                        r = Blueprints.GroupKill(Key(Has(s, "label") ? S(s["label"]) : "op"), reg, S(s["key"]), s["now"], Get(s, "reason") as string,
                            Get(s, "revoker") is true ? i => revoked.Add(i) : null,
                            Get(s, "fresh") is true ? epoch => fresh.Advance(new D { ["revocation_epoch"] = N(epoch) }, Base.Long(s["now"])) : null);
                        break;
                    case "revoked": r = new L(revoked); break;
                    case "admit": adm.Admit(S(s["instance"]), reg.Get(S(s["key"]))!, Base.Long(s["until"])); r = true; break;
                    case "admitRevoke": r = adm.Revoke(S(s["instance"]), S(s["key"])); break;
                    case "admitCheck": r = adm.Checker(Base.Long(s["now"]))(S(s["instance"]), reg.Get(S(s["key"]))!); break;
                    default: throw new InvalidOperationException("bad op");
                }
                outp.Add(r);
            }
            catch (Exception e) { outp.Add(Err(e)); }
        }
        return outp;
    }

    [Fact] public void BlueprintScenarioFn() => Base.Check(M, "blueprintScenario", a => BlueprintScenario((D)a[0]!));

    [Fact]
    public void AdmitWithEvidence() => Base.Check(M, "admitWithEvidence", a =>
    {
        var e = a[1];
        return Blueprints.AdmitWithEvidence((D)a[0]!, () =>
        {
            if (e is D d && d.TryGetValue("$throw", out var t) && t is true) throw new EvidenceException("TypeError", "boom");
            return e;
        });
    });

    [Fact]
    public void EveryFn() { Base.Covers(M, new[]
    {
        "signLease", "signLeaseUnsafeOverCap", "signLeaseRevocation", "signBlueprint", "signBreakGlass", "signBreakGlassReview", "signerOf", "signBody", "verifyBody",
        "signBundle", "assembleBundle", "maskRecord", "logScenario", "replayScenario", "mergeFreshAt", "gateDecision", "freshScenario", "shadowScenario", "listScenario",
        "windowAcc", "grantScenario", "leaseScenario", "blueprintScenario", "admitWithEvidence",
    }); Assert.Equal(2767, Base.Total(M)); }
}
