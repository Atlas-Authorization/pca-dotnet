using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.FrostReplay;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of networked FROST signing (test-data/ref-frost-net.json.gz, 634 cases): the allow token, the signer proof of possession and enrollment, the equivocation guard, the wire decoders, the signer
/// service and the coordinator as scenarios (the reference's randomness is fed through the injected seam, hostile transports are scripted), the durable nonce store contract, the group-algorithm registry, the hybrid
/// co-sign and the ML-DSA-65 quorum. A reference throw requires a refusal; a typed error compares class and fields. Every fn has a handler and the totals are asserted.</summary>
public class RefFrostNetTests
{
    const string M = "ref-frost-net";

    static Func<byte[]>? Src(Rng? r) { if (r == null) return null; return r.Next; }

    static byte[] B(object? o) => o as byte[] ?? throw new ArgumentException("bytes expected");

    // ---- stores ----
    sealed class FailStore(string method) : FrostMemoryNonceStore
    {
        static void Down() => throw new InvalidOperationException("store down");
        public override void Create(string s, FrostNonceRecord r) { if (method == "create") Down(); base.Create(s, r); }
        public override FrostNonceRecord? Load(string s) { if (method == "load") Down(); return base.Load(s); }
        public override void Spend(string s) { if (method == "spend") Down(); base.Spend(s); }
        public override void Drop(string s) { if (method == "drop") Down(); base.Drop(s); }
        public override bool IsSpent(string s) { if (method == "isSpent") Down(); return base.IsSpent(s); }
    }

    static IFrostNonceStore? MkStore(string? kind) => kind switch
    {
        null or "none" => null,
        "memory" => new FrostMemoryNonceStore(),
        "invalid-no-spend" => throw new ArgumentException("GuardianSignerService: nonceStore.spend must be a function"), // the interface cannot lack a method
        _ when kind.StartsWith("fail-", StringComparison.Ordinal) => new FailStore(kind[5..]),
        _ => throw new ArgumentException("store " + kind),
    };

    /// <summary>A store with exactly one defect (or none), for the contract check.</summary>
    sealed class BrokenStore(string kind) : IFrostNonceStore
    {
        readonly Dictionary<string, FrostNonceRecord> _live = new();
        readonly HashSet<string> _spent = new();
        public void Create(string id, FrostNonceRecord r)
        {
            if (kind != "create-overwrites" && _live.ContainsKey(id)) throw new InvalidOperationException("exists");
            if (kind != "create-over-spent" && _spent.Contains(id)) throw new InvalidOperationException("spent");
            _live[id] = kind == "create-aliases-input" ? r : r.Copy();
        }
        public FrostNonceRecord? Load(string id) => !_live.TryGetValue(id, out var r) ? null : kind == "load-aliases" ? r : r.Copy();
        public void Spend(string id)
        {
            if (!_live.ContainsKey(id))
            {
                if (kind == "spend-unknown-ok" || (kind == "spend-twice-ok" && _spent.Contains(id))) return;
                throw new InvalidOperationException("not live");
            }
            _live.Remove(id);
            _spent.Add(id);
        }
        public void Drop(string id) { _live.Remove(id); if (kind == "drop-marks-spent") _spent.Add(id); }
        public bool IsSpent(string id) => kind == "unknown-reports-spent" || _spent.Contains(id);
        public IFrostNonceStore Reopen()
        {
            if (kind == "spent-forgotten-on-restart") _spent.Clear();
            if (kind == "live-lost-on-restart") _live.Clear();
            return this;
        }
    }

    static object? Contract(L a)
    {
        var kind = (string)((D)a[0]!)["store"]!;
        try
        {
            if (kind == "memory") FrostNonceStores.AssertContract(() => new FrostMemoryNonceStore());
            else
            {
                var st = new BrokenStore(kind["broken:".Length..]);
                FrostNonceStores.AssertContract(() => st, s => ((BrokenStore)s).Reopen());
            }
            return null;
        }
        catch (InvalidOperationException e) when (e.Message.StartsWith("nonce-store contract: ", StringComparison.Ordinal)) { return new D { ["$throws"] = e.Message }; }
    }

    static FrostNonceRecord Rec(D r) => new()
    {
        Hiding = B(r["hiding"]), Binding = B(r["binding"]), HidingCommitment = B(r["hidingCommitment"]), BindingCommitment = B(r["bindingCommitment"]), CreatedAt = Lng(r["createdAt"]),
    };

    static D RecOut(FrostNonceRecord r) => new() { ["hiding"] = r.Hiding, ["binding"] = r.Binding, ["hidingCommitment"] = r.HidingCommitment, ["bindingCommitment"] = r.BindingCommitment, ["createdAt"] = r.CreatedAt };

    static object? NonceStore(L a)
    {
        var s = new FrostMemoryNonceStore();
        var res = new L();
        foreach (var o in (L)a[0]!)
        {
            var op = (D)o!;
            var sid = op.GetValueOrDefault("sid") as string; // a non-string id is unknown to every method and refused by create
            try
            {
                switch ((string)op["op"]!)
                {
                    case "create":
                    {
                        var r = Rec((D)op["rec"]!);
                        s.Create(sid ?? "", r);
                        if (op.GetValueOrDefault("mutateInputAfter") is true) { Array.Fill(r.Hiding, (byte)0xee); Array.Fill(r.HidingCommitment, (byte)0xee); }
                        res.Add(new D { ["ok"] = true });
                        break;
                    }
                    case "load":
                    {
                        var r = sid == null ? null : s.Load(sid);
                        res.Add(new D { ["value"] = r == null ? null : RecOut(r) });
                        break;
                    }
                    case "spend": s.Spend(sid ?? ""); res.Add(new D { ["ok"] = true }); break;
                    case "drop": if (sid != null) s.Drop(sid); res.Add(new D { ["ok"] = true }); break;
                    case "isSpent": res.Add(new D { ["value"] = sid != null && s.IsSpent(sid) }); break;
                    default: throw new ArgumentException("bad op");
                }
            }
            catch (Exception e) { res.Add(ErrOut(e)); }
        }
        return res;
    }

    // ---- guard and decoders ----
    static object? Guard(L a)
    {
        var g = new EquivocationGuard();
        var res = new L();
        foreach (var o in (L)a[0]!)
        {
            var op = (D)o!;
            try
            {
                switch ((string)op["op"]!)
                {
                    case "observe": g.Observe(op.GetValueOrDefault("session_id"), op.GetValueOrDefault("round"), op.GetValueOrDefault("identifier"), op.GetValueOrDefault("message")); break;
                    case "forget": g.Forget((string)op["session_id"]!); break;
                    default: throw new ArgumentException("bad op");
                }
                res.Add(new D { ["ok"] = true });
            }
            catch (Exception e) { res.Add(ErrOut(e)); }
        }
        return res;
    }

    static D CommitmentOut(Frost.FrostCommitment c) => new() { ["identifier"] = c.Identifier, ["hiding"] = c.Hiding, ["binding"] = c.Binding };
    static D ShareOut(Frost.VerificationShare v) => new() { ["identifier"] = v.Identifier, ["publicKey"] = v.PublicKey };

    // ---- allow token and PoP ----
    static object? Issue(L a, Rng? rng)
    {
        var o = (D)a[1]!;
        var opts = new IssueAllowOpts
        {
            Message = o.GetValueOrDefault("message") as byte[], FrostActionDigest = o.GetValueOrDefault("frostActionDigest") as string, GroupPublicKey = o.GetValueOrDefault("groupPublicKey") as byte[],
            Nonce = o.GetValueOrDefault("nonce") as string, NotBefore = o.GetValueOrDefault("notBefore"), ExpiresAt = o.GetValueOrDefault("expiresAt"),
        };
        return FrostNet.IssueAllowToken(B(a[0]), opts, Src(rng));
    }

    static object? Verify(L a)
    {
        var e = (D)a[1]!;
        return FrostNet.VerifyAllowToken(a[0], e.GetValueOrDefault("policyAuthorityPublicKey") as byte[], e.GetValueOrDefault("groupPublicKey") as byte[], e.GetValueOrDefault("message") as byte[], e.GetValueOrDefault("now"));
    }

    static object? Pop(L a, Rng? rng)
    {
        var o = (D)a[2]!;
        return FrostNet.CreateSignerPoP(Lng(a[0]), a[1] as byte[], o.GetValueOrDefault("groupPublicKey") as byte[], o.GetValueOrDefault("nonce") as byte[], Src(rng));
    }

    // ---- signer service ----
    static object? SignerServiceRun(L a, Rng? rng)
    {
        var cfg = (D)a[0]!;
        long clock = cfg.GetValueOrDefault("clock") is { } cv ? Lng(cv) : 1_000_000;
        IFrostNonceStore? store = null;
        GuardianSignerService? svc = null;
        GuardianSignerService Mk() => new(new GuardianSignerOptions
        {
            Identifier = Dbl(cfg.GetValueOrDefault("identifier")), Share = cfg.GetValueOrDefault("share") as byte[], GroupPublicKey = cfg.GetValueOrDefault("groupPublicKey") as byte[],
            Threshold = Dbl(cfg.GetValueOrDefault("threshold")), PolicyAuthorityPublicKey = cfg.GetValueOrDefault("policyAuthorityPublicKey") as byte[],
            SessionTtlMs = DblOpt(cfg.GetValueOrDefault("sessionTtlMs")), Now = () => clock, NonceStore = store, Random = Src(rng),
        });
        var res = new D { ["ctor"] = null, ["steps"] = new L() };
        var steps = (L)res["steps"]!;
        try
        {
            store = MkStore(cfg.GetValueOrDefault("store") as string);
            svc = Mk();
            res["ctor"] = new D { ["verificationShare"] = svc.VerificationShare, ["pop"] = svc.ProofOfPossession, ["enrollment"] = svc.Enrollment() };
        }
        catch (Exception e) { res["ctor"] = ErrOut(e); return res; }
        foreach (var so in (L)a[1]!)
        {
            var st = (D)so!;
            try
            {
                switch ((string)st["op"]!)
                {
                    case "round1": steps.Add(svc.Round1(st.GetValueOrDefault("req"))); break;
                    case "round2": steps.Add(svc.Round2(st.GetValueOrDefault("req"))); break;
                    case "clock": clock += Lng(st["ms"]); steps.Add(new D { ["clock"] = clock }); break;
                    case "restart": svc = Mk(); steps.Add(new D { ["restarted"] = true, ["pop"] = svc.ProofOfPossession }); break;
                    case "storeLoad": steps.Add(new D { ["live"] = store!.Load((string)st["sid"]!) != null }); break;
                    case "storeIsSpent": steps.Add(new D { ["spent"] = store!.IsSpent((string)st["sid"]!) }); break;
                    default: throw new ArgumentException("bad step");
                }
            }
            catch (Exception e) { steps.Add(ErrOut(e)); }
        }
        return res;
    }

    // ---- coordinator ----
    /// <summary>A transport over a real service (or canned responses) that can delay, throw "unreachable" and rewrite the responses it returns, per the case's script.</summary>
    sealed class Scripted(long id, GuardianSignerService? svc, D s) : ISignerTransport
    {
        int _r1, _r2;
        public long Identifier => id;
        public Task<D> Round1Async(D req) => Respond(1, req);
        public Task<D> Round2Async(D req) => Respond(2, req);

        async Task<D> Respond(int round, D req)
        {
            var key = round == 1 ? "r1" : "r2";
            var n = round == 1 ? _r1++ : _r2++;
            if (s.GetValueOrDefault("delay") is D dl && dl.GetValueOrDefault(key) is { } ms && Dbl(ms) != 0) await Task.Delay((int)Dbl(ms));
            if (s.GetValueOrDefault("throws") is D th && th.GetValueOrDefault(key) is true) throw new InvalidOperationException("unreachable");
            D resp;
            if (s.GetValueOrDefault("canned") is D cn)
            {
                var list = (L)cn[round == 1 ? "round1" : "round2"]!;
                var c = n < list.Count ? list[n] : null;
                if (c is null or "throw") throw new InvalidOperationException("unreachable");
                resp = (D)c;
            }
            else resp = round == 1 ? svc!.Round1(req) : svc!.Round2(req);
            return ApplyEdits(resp, s.GetValueOrDefault("edits") as L, round);
        }
    }

    static D ApplyEdits(D resp, L? edits, int round)
    {
        var r = (D)Base.Deep(resp)!;
        foreach (var eo in edits ?? new L())
        {
            var e = (D)eo!;
            if (Lng(e["round"]) != round) continue;
            var path = ((L)e["path"]!).Select(k => (string)k!).ToList();
            object? cur = r;
            foreach (var k in path.Take(path.Count - 1)) cur = (cur as D)?.GetValueOrDefault(k);
            if (cur is not D parent) continue;
            var last = path[^1];
            switch ((string)e["op"]!)
            {
                case "set": parent[last] = e["value"]; break;
                case "delete": parent.Remove(last); break;
                case "flip": parent[last] = Flip((string)parent[last]!); break;
            }
        }
        return r;
    }

    static object? CoordinatorRun(L a)
    {
        var cfg = (D)a[0]!;
        var transports = new List<ISignerTransport>();
        foreach (var so in (L)cfg["signers"]!)
        {
            var s = (D)so!;
            var id = Lng(s["identifier"]);
            GuardianSignerService? svc = null;
            if (s.GetValueOrDefault("canned") == null)
            {
                var rr = new Rng(((L)s["rng"]!).Select(x => (byte[])x!));
                svc = new GuardianSignerService(new GuardianSignerOptions
                {
                    Identifier = id, Share = s["share"] as byte[], GroupPublicKey = s["groupPublicKey"] as byte[], Threshold = Dbl(s["threshold"]), PolicyAuthorityPublicKey = s["policyAuthorityPublicKey"] as byte[],
                    SessionTtlMs = DblOpt(s.GetValueOrDefault("sessionTtlMs")), Now = () => 1_000_000, NonceStore = MkStore(s.GetValueOrDefault("store") as string), Random = rr.Next,
                });
            }
            transports.Add(new Scripted(id, svc, s));
        }
        var sids = new Queue<string>(((L?)cfg.GetValueOrDefault("sessionIds") ?? new L()).Select(x => (string)x!));
        var res = new D { ["calls"] = new L() };
        var calls = (L)res["calls"]!;
        NetworkCoordinator coord;
        try
        {
            coord = new NetworkCoordinator(new NetworkCoordinatorOptions
            {
                GroupPublicKey = cfg["groupPublicKey"] as byte[], Threshold = Dbl(cfg["threshold"]), Signers = transports,
                VerificationShares = cfg.GetValueOrDefault("verificationShares") is L vs ? vs.Select(v => new Frost.VerificationShare(Lng(((D)v!)["identifier"]), B(((D)v!)["publicKey"]))).ToList() : null,
                Enroll = cfg.GetValueOrDefault("enroll"), TimeoutMs = DblOpt(cfg.GetValueOrDefault("timeoutMs")),
                NewSessionId = () => sids.Count > 0 ? sids.Dequeue() : throw new InvalidOperationException("no more scripted session ids"),
            });
        }
        catch (Exception e) { res["ctor"] = ErrOut(e); return res; }
        foreach (var co in (L)cfg["calls"]!)
        {
            var c = (D)co!;
            try
            {
                var ids = (c.GetValueOrDefault("signerIds") as L)?.Select(Lng).ToList();
                var r = coord.SignAsync(c.GetValueOrDefault("message") as byte[], c.GetValueOrDefault("allow"), ids, DblOpt(c.GetValueOrDefault("timeoutMs"))).GetAwaiter().GetResult();
                calls.Add(new D { ["signature"] = r.Signature, ["sessionId"] = r.SessionId, ["signers"] = r.Signers });
            }
            catch (Exception e) { calls.Add(ErrOut(e)); }
        }
        return res;
    }

    // ---- post-quantum ----
    static object? SignHybrid(L a)
    {
        var o = (D)a[3]!;
        var quorum = ((L)a[1]!).Select(p => new Frost.FrostParticipantShare(Lng(((D)p!)["identifier"]), B(((D)p!)["share"]), B(((D)p!)["publicKey"]))).ToList();
        var opts = new FrostPq.HybridCosignOpts
        {
            GroupAlg = o.GetValueOrDefault("groupAlg") as string, Threshold = o.GetValueOrDefault("threshold") is { } t ? (int)Lng(t) : null,
            GuardianMlDsa = o.GetValueOrDefault("guardianMlDsaSeed") is byte[] seed ? PqSuites.MlDsa65Keygen(seed) : null,
        };
        var gpk = B(a[0]);
        var msg = B(a[2]);
        var r = FrostPq.SignHybridFrostCosign(gpk, quorum, msg, opts);
        var sig = Pca.B64uDecode(r["sig"])!;
        r.Remove("sig");
        r["sigVerifies"] = Pca.VerifyEd25519Strict(gpk, msg, sig);
        r["sigLength"] = sig.Length;
        return r;
    }

    static List<PqKeyPair> Keys(object? seeds) => ((L)seeds!).Select(s => PqSuites.MlDsa65Keygen(B(s))).ToList();

    static Dictionary<string, Func<L, Rng?, object?>> Fns => new()
    {
        ["constants"] = (_, _) => new D
        {
            ["ALLOW_TOKEN_TYP"] = FrostNet.AllowTokenTyp, ["SIGNER_POP_DST"] = FrostNet.SignerPopDst, ["MAX_FROST_SIGNING_SET"] = FrostNet.MaxFrostSigningSet, ["DEFAULT_FROST_GROUP_ALG"] = FrostPq.DefaultFrostGroupAlg,
            ["PQ_QUORUM_VERSION"] = FrostPq.PqQuorumVersion, ["PQ_QUORUM_ALG"] = FrostPq.PqQuorumAlg, ["MAX_PQ_QUORUM_ENTRIES"] = FrostPq.MaxPqQuorumEntries,
        },
        ["frostActionDigest"] = (a, _) => FrostNet.FrostActionDigest((a[0] as byte[])!),
        ["issueAllowToken"] = (a, r) => Issue(a, r),
        ["verifyAllowToken"] = (a, _) => Verify(a),
        ["createSignerPoP"] = (a, r) => Pop(a, r),
        ["verifySignerPoP"] = (a, _) => FrostNet.VerifySignerPoP(a[0], (a[1] as D)?.GetValueOrDefault("groupPublicKey") as byte[]),
        ["enrollVerificationShares"] = (a, _) => FrostNet.EnrollVerificationShares(a[0], ((D)a[1]!).GetValueOrDefault("groupPublicKey") as byte[]).Select(ShareOut).ToList(),
        ["equivocationGuard"] = (a, _) => Guard(a),
        ["decodeCommitment"] = (a, _) => CommitmentOut(FrostNet.DecodeCommitment(a[0])),
        ["decodeCommitments"] = (a, _) => FrostNet.DecodeCommitments(a[0]).Select(CommitmentOut).ToList(),
        ["decodeVerificationShares"] = (a, _) => FrostNet.DecodeVerificationShares(a[0]).Select(ShareOut).ToList(),
        ["signerService"] = (a, r) => SignerServiceRun(a, r),
        ["coordinator"] = (a, _) => CoordinatorRun(a),
        ["nonceStore"] = (a, _) => NonceStore(a),
        ["assertNonceStoreContract"] = (a, _) => Contract(a),
        ["resolveFrostGroupAlg"] = (a, _) => FrostPq.ResolveFrostGroupAlg(a.Count > 0 ? a[0] : null, a.Count > 0),
        ["frostSignerSetDigest"] = (a, _) => FrostPq.FrostSignerSetDigest(a[0]),
        ["frostCosignRepresentative"] = (a, _) => FrostPq.FrostCosignRepresentative(a[0], (a[1] as byte[])!, a[2], a[3] as string),
        ["verifyHybridFrostCosign"] = (a, _) => FrostPq.VerifyHybridFrostCosign(a[0], B(a[1]), a[2], a[3], a[4]),
        ["signHybridFrostCosign"] = (a, _) => SignHybrid(a),
        ["pqQuorumRepresentative"] = (a, _) => FrostPq.PqQuorumRepresentative((a[0] as byte[])!),
        ["signPqQuorum"] = (a, _) => FrostPq.SignPqQuorum(B(a[0]), Keys(a[1]), a[2] == null ? null : (int)Lng(a[2])),
        ["normalizePqQuorumPool"] = (a, _) => FrostPq.NormalizePqQuorumPool((L)a[0]!),
        ["verifyPqQuorum"] = (a, _) => FrostPq.VerifyPqQuorum(a[0], B(a[1]), ((L)a[2]!).Select(x => (string)x!), a[3]),
    };

    static void Fn(string fn, int min) => FrostReplay.Replay(M, fn, Fns[fn], min);

    [Fact] public void Constants() => Fn("constants", 1);
    [Fact] public void AllowToken() { foreach (var (f, n) in new[] { ("frostActionDigest", 7), ("issueAllowToken", 25), ("verifyAllowToken", 58) }) Fn(f, n); }
    [Fact] public void ProofOfPossession() { foreach (var (f, n) in new[] { ("createSignerPoP", 24), ("verifySignerPoP", 36), ("enrollVerificationShares", 23) }) Fn(f, n); }
    [Fact] public void EquivocationAndDecoders() { foreach (var (f, n) in new[] { ("equivocationGuard", 27), ("decodeCommitment", 22), ("decodeCommitments", 10), ("decodeVerificationShares", 16) }) Fn(f, n); }
    [Fact] public void SignerService() => Fn("signerService", 95);
    [Fact] public void Coordinator() => Fn("coordinator", 86);
    [Fact] public void NonceStores() { foreach (var (f, n) in new[] { ("nonceStore", 16), ("assertNonceStoreContract", 11) }) Fn(f, n); }
    [Fact] public void GroupAlgorithms() { foreach (var (f, n) in new[] { ("resolveFrostGroupAlg", 16), ("frostSignerSetDigest", 17), ("frostCosignRepresentative", 13) }) Fn(f, n); }
    [Fact] public void HybridCosign() { foreach (var (f, n) in new[] { ("verifyHybridFrostCosign", 60), ("signHybridFrostCosign", 18) }) Fn(f, n); }
    [Fact] public void PqQuorum() { foreach (var (f, n) in new[] { ("pqQuorumRepresentative", 4), ("signPqQuorum", 7), ("normalizePqQuorumPool", 6), ("verifyPqQuorum", 36) }) Fn(f, n); }

    [Fact]
    public void Covers()
    {
        Base.Covers(M, Fns.Keys);
        Assert.Equal(634, Base.Total(M));
        Assert.Equal(Fns.Count, Base.Cases(M).Select(c => (string)c["fn"]!).Distinct().Count());
    }
}
