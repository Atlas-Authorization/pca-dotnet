using System.Globalization;
using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.FrostReplay;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replay of the FROST distributed key generation and its channel (test-data/ref-frost-dkg.json.gz, 439 cases, plus the 286 cases that carry derived secrets, which CI generates into ref-frost-dkg-gen.json.gz and
/// which the replay requires there): the rounds, complaints, rebuttals and blame, the qualified set, the echo agreement, finalize, the whole simulated ceremony, the wire codec and its body decoders, the inbox, the in-memory
/// network, the framing and one party run over a scripted channel with the reference's randomness fed through the injected seam. A reference throw requires a refusal; a channel error compares code and peer.</summary>
public class RefFrostDkgTests
{
    const string M = "ref-frost-dkg";
    const int MainTotal = 439, FullTotal = 725;

    static Func<byte[]>? Src(Rng? r) { if (r == null) return null; return r.Next; }
    static byte[] B(object? o) => o as byte[] ?? throw new ArgumentException("bytes expected");
    static void Extra(Exception e, D o)
    {
        if (e is not DkgChannelError c) return;
        o["class"] = "DkgChannelError"; o["code"] = c.Code; o["peer"] = c.Peer;
    }

    static DkgState StateOf(D spec) =>
        FrostDkg.Round1(Lng(spec["id"]), (int)Lng(spec["t"]), (int)Lng(spec["n"]), spec["sessionId"] as byte[], ((L)spec["coefficients"]!).Select(x => B(x)).ToList(), spec["popNonce"] as byte[]).State;

    static D Bodies(Dictionary<long, object?> m) => m.ToDictionary(kv => kv.Key.ToString(CultureInfo.InvariantCulture), kv => kv.Value);

    // ---- rounds ----
    static object? Round1(L a, Rng? r)
    {
        var o = (D)a[4]!;
        var coeffs = o.GetValueOrDefault("coefficients") is L cl ? cl.Select(x => B(x)).ToList() : null;
        return new D { ["package"] = FrostDkg.Round1(Lng(a[0]), (int)Lng(a[1]), (int)Lng(a[2]), a[3] as byte[], coeffs, o.GetValueOrDefault("popNonce") as byte[], Src(r)).Package };
    }

    static object? Complaint(L a)
    {
        var o = (D)a[0]!;
        return FrostDkg.FileComplaint(Lng(o["accused"]), Lng(o["accuser"]), o.GetValueOrDefault("receivedShare") as byte[], o.GetValueOrDefault("shareSig") as string, o.GetValueOrDefault("sessionId") as byte[]);
    }

    static object? Simulate(L a, Rng? r)
    {
        var o = (D)a[2]!;
        var opts = new DkgSimulateOpts
        {
            Identifiers = (o.GetValueOrDefault("identifiers") as L)?.Select(x => Lng(x)).ToList(),
            CoefficientsByParticipant = (o.GetValueOrDefault("coefficientsByParticipant") as L)?.Select(l => (IReadOnlyList<byte[]>?)((L)l!).Select(x => B(x)).ToList()).ToList(),
            SessionId = o.GetValueOrDefault("sessionId") as byte[],
            Cheaters = (o.GetValueOrDefault("cheaters") as L)?.Select(x => Lng(x)).ToList(),
            EquivocateEchoFor = o.GetValueOrDefault("equivocateEchoFor") is { } e ? Lng(e) : null,
            Random = Src(r),
        };
        return FrostDkg.Simulate(Lng(a[0]), Lng(a[1]), opts);
    }

    // ---- inbox and network ----
    static object? Inbox(L a)
    {
        var s = (D)a[0]!;
        var ib = new DkgInbox(B(s["sessionId"]), ((L)s["peers"]!).Select(x => Lng(x)).ToList());
        var res = new L();
        foreach (var o in (L)s["ops"]!)
        {
            var op = (D)o!;
            try
            {
                switch ((string)op["op"]!)
                {
                    case "accept": ib.Accept(Lng(op["sender"]), B(op["bytes"])); res.Add(new D { ["ok"] = true }); break;
                    case "fail": ib.Fail(Lng(op["peer"]), new DkgChannelError((string)op["code"]!, null, (string)op["message"]!)); res.Add(new D { ["ok"] = true }); break;
                    case "peerGone": ib.PeerGone(Lng(op["peer"])); res.Add(new D { ["ok"] = true }); break;
                    case "close": ib.Close(); res.Add(new D { ["ok"] = true }); break;
                    case "collect":
                    {
                        var m = ib.Collect((string)op["kind"]!, ((L)op["from"]!).Select(x => Lng(x)).ToList(), Dbl(op["timeoutMs"])).GetAwaiter().GetResult();
                        res.Add(new D { ["ok"] = true, ["bodies"] = Bodies(m) });
                        break;
                    }
                    default: throw new ArgumentException("bad op");
                }
            }
            catch (Exception e) { res.Add(ErrOut(e, Extra)); }
        }
        return res;
    }

    static object? Network(L a)
    {
        var s = (D)a[0]!;
        var sid = B(s["sessionId"]);
        Func<FrostDkgChannel.MemoryDelivery, byte[]?>? icpt = null;
        if (s.GetValueOrDefault("intercept") is D m)
            icpt = d =>
            {
                var hit = (!m.ContainsKey("kind") || (m["kind"] is string k && k == d.Kind)) && (!m.ContainsKey("from") || Lng(m["from"]) == d.From) && (!m.ContainsKey("to") || Lng(m["to"]) == d.To);
                if (!hit) return d.Bytes;
                return (string)m["action"]! switch { "drop" => null, "replace" => B(m["bytes"]), _ => d.Bytes };
            };
        var net = FrostDkgChannel.CreateMemoryNetwork(((L)s["ids"]!).Select(x => Lng(x)).ToList(), sid, icpt);
        var res = new L
        {
            new D { ["channels"] = net.Channels.ToDictionary(kv => kv.Key.ToString(CultureInfo.InvariantCulture), kv => (object?)new D { ["self"] = kv.Value.Self, ["peers"] = kv.Value.Peers.ToList() }) },
        };
        foreach (var o in (L)s["ops"]!)
        {
            var op = (D)o!;
            try
            {
                var ch = op.TryGetValue("at", out var at) ? net.Channels[Lng(at)] : null;
                switch ((string)op["op"]!)
                {
                    case "broadcast": net.Channels[Lng(op["from"])].Broadcast((string)op["kind"]!, op["body"]).GetAwaiter().GetResult(); res.Add(new D { ["ok"] = true }); break;
                    case "send": net.Channels[Lng(op["from"])].Send(Lng(op["to"]), (string)op["kind"]!, op["body"]).GetAwaiter().GetResult(); res.Add(new D { ["ok"] = true }); break;
                    case "deliver": net.Deliver(Lng(op["from"]), Lng(op["to"]), B(op["bytes"])); res.Add(new D { ["ok"] = true }); break;
                    case "collect":
                        res.Add(new D { ["ok"] = true, ["bodies"] = Bodies(ch!.Collect((string)op["kind"]!, ((L)op["fromIds"]!).Select(x => Lng(x)).ToList(), Dbl(op["timeoutMs"])).GetAwaiter().GetResult()) });
                        break;
                    case "close": ch!.Close().GetAwaiter().GetResult(); res.Add(new D { ["ok"] = true }); break;
                    default: throw new ArgumentException("bad op");
                }
            }
            catch (Exception e) { res.Add(ErrOut(e, Extra)); }
        }
        return res;
    }

    static object? FrameDecode(L a)
    {
        var d = new FrostDkgChannel.FrameDecoder();
        foreach (var c in (L)((D)a[0]!)["chunks"]!) d.Feed(B(c));
        return new D { ["accepted"] = d.Accepted, ["error"] = d.Error, ["buffered"] = d.Buffered };
    }

    // ---- one party over a scripted channel ----
    static readonly string[] Phases = ["round1", "share", "complaints", "rebuttals", "echo"];

    /// <summary>A channel that records everything the party sends and delivers the scripted inbound messages, in list order, before each collect of their phase or a later one.</summary>
    sealed class Scripted(long self, IReadOnlyList<long> peers, byte[] sid, DkgInbox inbox, List<(long From, string Kind, byte[] Bytes)> pending, L outbound) : IDkgChannel
    {
        public long Self => self;
        public IReadOnlyList<long> Peers => peers;
        public Task Broadcast(string kind, object? body)
        {
            outbound.Add(new D { ["op"] = "broadcast", ["kind"] = kind, ["bytes"] = FrostDkgChannel.EncodeMessage(sid, kind, body) });
            return Task.CompletedTask;
        }
        public Task Send(long to, string kind, object? body)
        {
            if (!peers.Contains(to)) throw new DkgChannelError("identity", to, "not a connected peer");
            outbound.Add(new D { ["op"] = "send", ["kind"] = kind, ["to"] = to, ["bytes"] = FrostDkgChannel.EncodeMessage(sid, kind, body) });
            return Task.CompletedTask;
        }
        public Task<Dictionary<long, object?>> Collect(string kind, IReadOnlyList<long> from, double timeoutMs)
        {
            var lim = Array.IndexOf(Phases, kind);
            var keep = new List<(long From, string Kind, byte[] Bytes)>();
            foreach (var m in pending)
                if (Array.IndexOf(Phases, m.Kind) <= lim) inbox.Accept(m.From, m.Bytes); else keep.Add(m);
            pending.Clear();
            pending.AddRange(keep);
            return inbox.Collect(kind, from, timeoutMs);
        }
        public Task Close() { inbox.Close(); return Task.CompletedTask; }
    }

    static object? Party(L a, Rng? rng)
    {
        var spec = (D)a[0]!;
        var sid = B(spec["sessionId"]);
        var self = Lng(spec["self"]);
        var participants = ((L)spec["participants"]!).Select(x => Dbl(x)).ToList();
        var peers = spec.GetValueOrDefault("peers") is L pl ? pl.Select(x => (long)Dbl(x)).ToList() : participants.Where(p => p != self).OrderBy(p => p).Select(p => (long)p).ToList();
        var inbox = new DkgInbox(sid, peers);
        var pending = ((spec.GetValueOrDefault("inbound") as L) ?? new L()).Select(m => (Lng(((D)m!)["from"]), (string)((D)m)["kind"]!, B(((D)m)["bytes"]))).ToList();
        var outbound = new L();
        foreach (var g in (spec.GetValueOrDefault("gone") as L) ?? new L()) inbox.PeerGone(Lng(g));
        var ch = new Scripted(self, peers, sid, inbox, pending, outbound);
        try
        {
            var r = FrostDkgChannel.RunAsync(ch, new FrostDkgChannel.RunOpts { T = Dbl(spec["t"]), Participants = participants, SessionId = sid, TimeoutMs = Dbl(spec["timeoutMs"]), Random = Src(rng) }).GetAwaiter().GetResult();
            return new D { ["outbound"] = outbound, ["result"] = new D { ["qualified"] = r["qualified"], ["complaints"] = r["complaints"], ["keyPackage"] = r["keyPackage"] } };
        }
        catch (Exception e) { return new D { ["outbound"] = outbound, ["error"] = ErrOut(e, Extra) }; }
    }

    static Dictionary<string, Func<L, Rng?, object?>> Fns => new()
    {
        ["constants"] = (_, _) => new D
        {
            ["DKG_WIRE_VERSION"] = FrostDkgChannel.WireVersion, ["DKG_MAX_MESSAGE_BYTES"] = FrostDkgChannel.MaxMessageBytes, ["DKG_MAX_PARTICIPANTS"] = FrostDkgChannel.MaxParticipants,
            ["DKG_MESSAGE_KINDS"] = FrostDkgChannel.MessageKinds.ToList(),
        },
        ["dkgRound1"] = (a, r) => Round1(a, r),
        ["dkgVerifyRound1"] = (a, _) => FrostDkg.VerifyRound1(a[0], a[1], a[2] as byte[]),
        ["dkgSignShare"] = (a, _) => FrostDkg.SignShare(StateOf((D)a[0]!), Lng(a[1]), a[2] as byte[] ?? throw new ArgumentException("bytes expected")),
        ["dkgRound2"] = (a, _) => FrostDkg.Round2(StateOf((D)a[0]!), a[1]),
        ["dkgVerifyShare"] = (a, _) => FrostDkg.VerifyShare(a[0], a[1], Lng(a[2]), a[3] as byte[]),
        ["dkgFileComplaint"] = (a, _) => Complaint(a),
        ["dkgVerifyComplaint"] = (a, _) => FrostDkg.VerifyComplaint(a[0], a[1]),
        ["dkgRebut"] = (a, _) => FrostDkg.Rebut(Lng(a[0]), a[1], StateOf((D)a[2]!)),
        ["dkgResolveBlame"] = (a, _) => FrostDkg.ResolveBlame(a[0], a[1], a[2]),
        ["dkgQualifiedSet"] = (a, _) => FrostDkg.QualifiedSet(a[0], a[1], a[2], a.Count > 3 ? a[3] : null),
        ["dkgTranscriptDigest"] = (a, _) => { var o = (D)a[0]!; return FrostDkg.TranscriptDigest(o["round1Packages"], o["complaints"], o["qualified"], o["sessionId"] as byte[]); },
        ["dkgEcho"] = (a, _) => { var o = (D)a[0]!; return FrostDkg.Echo(o["identifier"], o["round1Packages"], o["complaints"], o["qualified"], o["sessionId"] as byte[]); },
        ["dkgCheckEchoes"] = (a, _) => FrostDkg.CheckEchoes(a[0], a[1], a[2] as byte[]),
        ["dkgFinalize"] = (a, _) => FrostDkg.Finalize(Lng(a[0]), StateOf((D)a[1]!), a[2], a[3], a[4], a[5]),
        ["frostDkgSimulate"] = (a, r) => Simulate(a, r),
        ["encodeDkgMessage"] = (a, _) => FrostDkgChannel.EncodeMessage(B(a[0]), a[1], a[2]),
        ["decodeDkgMessage"] = (a, _) => FrostDkgChannel.DecodeMessage(a[0], a[1] as byte[]),
        ["decodeDkgRound1Package"] = (a, _) => FrostDkgChannel.DecodeRound1Package(a[0], a[1]),
        ["decodeDkgShareMessage"] = (a, _) => FrostDkgChannel.DecodeShareMessage(a[0]),
        ["decodeDkgComplaints"] = (a, _) => FrostDkgChannel.DecodeComplaints(a[0]),
        ["decodeDkgRebuttals"] = (a, _) => FrostDkgChannel.DecodeRebuttals(a[0]),
        ["decodeDkgEcho"] = (a, _) => FrostDkgChannel.DecodeEcho(a[0]),
        ["dkgInbox"] = (a, _) => Inbox(a),
        ["memoryNetwork"] = (a, _) => Network(a),
        ["tlsFrameEncode"] = (a, _) => FrostDkgChannel.EncodeFrame(B(a[0])),
        ["tlsFrameDecode"] = (a, _) => FrameDecode(a),
        ["runDkgOverChannel"] = (a, r) => Party(a, r),
    };

    /// <summary>The replay of one fn: the committed cases are always there, the secret-bearing ones (generated by CI) when the generated file is.</summary>
    static void Fn(string fn, int main, int full = 0) =>
        FrostReplay.Replay(M, fn, Fns[fn], Base.Cases(M).Count > MainTotal && full > 0 ? full : main, Extra);

    [Fact] public void Constants() => Fn("constants", 1);
    [Fact] public void RoundOne() { foreach (var (f, n) in new[] { ("dkgRound1", 56), ("dkgVerifyRound1", 36), ("dkgSignShare", 20) }) Fn(f, n); }
    [Fact] public void RoundTwoAndShares() { foreach (var (f, n, g) in new[] { ("dkgRound2", 5, 18), ("dkgVerifyShare", 3, 29) }) Fn(f, n, g); }
    [Fact] public void ComplaintsAndBlame() { foreach (var (f, n, g) in new[] { ("dkgFileComplaint", 2, 24), ("dkgVerifyComplaint", 3, 17), ("dkgRebut", 0, 10), ("dkgResolveBlame", 1, 19), ("dkgQualifiedSet", 13, 23) }) Fn(f, n, g); }
    [Fact] public void EchoAgreement() { foreach (var (f, n, g) in new[] { ("dkgTranscriptDigest", 10, 13), ("dkgEcho", 4, 5), ("dkgCheckEchoes", 18, 18) }) Fn(f, n, g); }
    [Fact] public void FinalizeAndSimulate() { foreach (var (f, n, g) in new[] { ("dkgFinalize", 1, 39), ("frostDkgSimulate", 13, 31) }) Fn(f, n, g); }
    [Fact] public void WireCodec() { foreach (var (f, n, g) in new[] { ("encodeDkgMessage", 18, 21), ("decodeDkgMessage", 56, 56), ("decodeDkgRound1Package", 32, 32), ("decodeDkgShareMessage", 27, 27), ("decodeDkgComplaints", 25, 25), ("decodeDkgRebuttals", 9, 9), ("decodeDkgEcho", 13, 13) }) Fn(f, n, g); }
    [Fact] public void InboxAndNetwork() { foreach (var (f, n) in new[] { ("dkgInbox", 24), ("memoryNetwork", 11) }) Fn(f, n); }
    [Fact] public void Framing() { foreach (var (f, n) in new[] { ("tlsFrameEncode", 5), ("tlsFrameDecode", 17) }) Fn(f, n); }
    [Fact] public void PartyRuns() => Fn("runDkgOverChannel", 16, 126);

    /// <summary>The secret-bearing half is generated in CI (gen-secret-corpus.sh frost-dkg:frost-dkg); with it present the totals must be the full corpus.</summary>
    [Fact]
    public void SecretCorpusIsPresent()
    {
        Base.RequireGenCorpus(M);
        if (Base.Cases(M).Count > MainTotal) Assert.Equal(FullTotal, Base.Cases(M).Count);
    }

    [Fact]
    public void Covers()
    {
        Base.Covers(M, Fns.Keys);
        Assert.Equal(MainTotal, Base.Total(M));
        Assert.Equal(Fns.Count - (Base.Cases(M).Count > MainTotal ? 0 : 1), Base.Cases(M).Select(c => (string)c["fn"]!).Distinct().Count());
    }
}
