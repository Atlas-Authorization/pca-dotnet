// The authenticated-channel interface of the FROST DKG and what the protocol can enforce on top of it. The DKG module produces and verifies the protocol messages but assumes an authenticated broadcast and
// private authenticated point-to-point links; this module states that assumption as an interface and enforces the rest:
//  - the CHANNEL supplies the sender's identity (for a TLS channel, the pinned certificate), never the message: every driver check compares the authenticated sender with the identifier inside the message;
//  - a message names one session; a second message of the same kind from the same sender is refused (identical: duplicate, different: equivocation) and the refusal is sticky for that peer;
//  - every message is size-capped before parsing, parsed with the strict JSON profile and shape-checked with exact member sets; nothing malformed is repaired;
//  - a message missing at the timeout aborts the run (fail closed); nothing is finalized on a partial view; transcript equivocation is caught by the echo round the driver always runs.
// What the channel must provide (the interface cannot check it): confidentiality and integrity of every message, and that Collect reports a message under the identity of the party that really sent it.
// Wire values are the JSON tree.
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>Every channel and driver refusal. <see cref="Peer"/> is the authenticated party the refusal is about, when known.</summary>
public sealed class DkgChannelError(string code, long? peer, string message)
    : Exception($"dkg channel ({code}{(peer == null ? "" : $", peer {peer}")}): {message}")
{
    /// <summary>One of timeout, identity, wrong-session, duplicate, equivocation, malformed, oversize, closed, protocol, disqualified.</summary>
    public string Code { get; } = code;
    public long? Peer { get; } = peer;
    /// <summary>The message without the "dkg channel (...): " prefix.</summary>
    public string Detail { get; } = message;
}

/// <summary>One participant's end of the authenticated channel.</summary>
public interface IDkgChannel
{
    long Self { get; }
    /// <summary>Every other participant this channel is connected to, ascending.</summary>
    IReadOnlyList<long> Peers { get; }
    /// <summary>Authenticated broadcast of the body to every peer.</summary>
    Task Broadcast(string kind, object? body);
    /// <summary>Private, authenticated delivery of the body to one peer.</summary>
    Task Send(long to, string kind, object? body);
    /// <summary>Wait for exactly one message of the kind from each of <paramref name="from"/> and return the bodies keyed by the AUTHENTICATED sender (ascending). Throws <see cref="DkgChannelError"/> on timeout,
    /// a duplicate or divergent second message, a malformed, oversize or wrong-session message from any of them, or a closed channel.</summary>
    Task<Dictionary<long, object?>> Collect(string kind, IReadOnlyList<long> from, double timeoutMs);
    Task Close();
}

public static class FrostDkgChannel
{
    public const int WireVersion = 1, MaxMessageBytes = 256 * 1024, MaxParticipants = 256;
    public static readonly IReadOnlyList<string> MessageKinds = ["round1", "share", "complaints", "rebuttals", "echo"];

    // ---- wire envelope ----

    /// <summary>Encode one wire message: <c>JSON.stringify({v, sid, kind, body})</c> (the kind is not checked on encode; the body keeps its member order).</summary>
    public static byte[] EncodeMessage(byte[] sessionId, object? kind, object? body)
    {
        var bytes = Encoding.UTF8.GetBytes(JsJson.Stringify(new D { ["v"] = WireVersion, ["sid"] = Pca.B64u(sessionId), ["kind"] = kind, ["body"] = body }));
        if (bytes.Length > MaxMessageBytes) throw new DkgChannelError("oversize", null, $"message of {bytes.Length} bytes exceeds the cap");
        return bytes;
    }

    /// <summary>Strictly decode one wire message for the session: {kind, body}. A typed <see cref="DkgChannelError"/> on every deviation.</summary>
    public static D DecodeMessage(object? bytes, byte[]? sessionId)
    {
        if (bytes is not byte[] b) throw new DkgChannelError("malformed", null, "message is not bytes");
        if (b.Length > MaxMessageBytes) throw new DkgChannelError("oversize", null, $"message of {b.Length} bytes exceeds the cap");
        object? msg;
        try { msg = Pca.ParseStrict(new UTF8Encoding(false, true).GetString(b)); }
        catch (Exception) { throw new DkgChannelError("malformed", null, "message is not strict JSON"); }
        var o = AsRecord(msg, ["v", "sid", "kind", "body"], "envelope");
        if (!(o["v"] is Num v && v.Raw == "1")) throw new DkgChannelError("malformed", null, "unsupported wire version");
        if (o["kind"] is not string kind || !MessageKinds.Contains(kind)) throw new DkgChannelError("malformed", null, "unknown message kind");
        if (!(o["sid"] is string sid && sid == Pca.B64u(sessionId!))) throw new DkgChannelError("wrong-session", null, "message names another session");
        return new D { ["kind"] = kind, ["body"] = o["body"] };
    }

    static D AsRecord(object? x, string[] keys, string what)
    {
        if (x is not D d) throw new DkgChannelError("malformed", null, $"{what} is not an object");
        if (d.Count != keys.Length || !keys.All(d.ContainsKey)) throw new DkgChannelError("malformed", null, $"{what} has unexpected or missing members");
        return d;
    }

    static object PosInt(object? x, string what) =>
        x is Num && IntentJs.IsSafeInteger(x) && IntentJs.NumOf(x)!.Value > 0 ? x : throw new DkgChannelError("malformed", null, $"{what} is not a positive integer");

    static string B64Field(object? x, string what, int? len = null) =>
        Pca.B64uDecode(x, len) != null ? (string)x! : throw new DkgChannelError("malformed", null, $"{what} is not canonical base64url");

    // ---- message-body decoders ----

    /// <summary>Decode a round-1 package body; <paramref name="t"/> is the threshold it must commit to.</summary>
    public static D DecodeRound1Package(object? x, object? t)
    {
        var o = AsRecord(x, ["identifier", "sessionId", "coefficientCommitments", "proofOfKnowledge"], "round-1 package");
        var pok = AsRecord(o["proofOfKnowledge"], ["R", "mu"], "proof of knowledge");
        if (!(o["coefficientCommitments"] is L cc && t is not string && IntentJs.NumOf(t) is double td && cc.Count == td))
            throw new DkgChannelError("malformed", null, $"round-1 package must commit to exactly t={JsJson.ToJsString(t)} coefficients");
        return new D
        {
            ["identifier"] = PosInt(o["identifier"], "identifier"), ["sessionId"] = B64Field(o["sessionId"], "sessionId"),
            ["coefficientCommitments"] = cc.Select(c => (object?)B64Field(c, "coefficient commitment", 32)).ToList(),
            ["proofOfKnowledge"] = new D { ["R"] = B64Field(pok["R"], "PoP R", 32), ["mu"] = B64Field(pok["mu"], "PoP mu", 32) },
        };
    }

    /// <summary>Decode a private share body into the wire form (<c>share</c> as bytes).</summary>
    public static D DecodeShareMessage(object? x)
    {
        var o = AsRecord(x, ["from", "to", "sessionId", "share", "sig"], "share message");
        return new D
        {
            ["from"] = PosInt(o["from"], "from"), ["to"] = PosInt(o["to"], "to"), ["sessionId"] = B64Field(o["sessionId"], "sessionId"),
            ["share"] = Pca.B64uDecode(B64Field(o["share"], "share", 32)), ["sig"] = B64Field(o["sig"], "share signature", 64),
        };
    }

    static D ComplaintOf(object? x)
    {
        var o = AsRecord(x, ["accused", "accuser", "sessionId", "revealedShare", "shareSig"], "complaint");
        return new D
        {
            ["accused"] = PosInt(o["accused"], "accused"), ["accuser"] = PosInt(o["accuser"], "accuser"), ["sessionId"] = B64Field(o["sessionId"], "sessionId"),
            ["revealedShare"] = B64Field(o["revealedShare"], "revealed share", 32), ["shareSig"] = B64Field(o["shareSig"], "share signature", 64),
        };
    }

    static D RebuttalOf(object? x)
    {
        var o = AsRecord(x, ["accused", "accuser", "sessionId", "presentedShare", "shareSig"], "rebuttal");
        return new D
        {
            ["accused"] = PosInt(o["accused"], "accused"), ["accuser"] = PosInt(o["accuser"], "accuser"), ["sessionId"] = B64Field(o["sessionId"], "sessionId"),
            ["presentedShare"] = B64Field(o["presentedShare"], "presented share", 32), ["shareSig"] = B64Field(o["shareSig"], "share signature", 64),
        };
    }

    static L ListOf(object? x, string key, Func<object?, D> one)
    {
        var o = AsRecord(x, [key], key);
        if (o[key] is not L l || l.Count > MaxParticipants) throw new DkgChannelError("malformed", null, $"{key} is not a bounded list");
        return l.Select(v => (object?)one(v)).ToList();
    }

    /// <summary>Decode a complaints body (<c>{complaints: [...]}</c>, possibly empty).</summary>
    public static L DecodeComplaints(object? x) => ListOf(x, "complaints", ComplaintOf);
    /// <summary>Decode a rebuttals body (<c>{rebuttals: [...]}</c>, possibly empty).</summary>
    public static L DecodeRebuttals(object? x) => ListOf(x, "rebuttals", RebuttalOf);

    /// <summary>Decode an echo body.</summary>
    public static D DecodeEcho(object? x)
    {
        var o = AsRecord(x, ["identifier", "sessionId", "transcriptDigest"], "echo");
        return new D { ["identifier"] = PosInt(o["identifier"], "identifier"), ["sessionId"] = B64Field(o["sessionId"], "sessionId"), ["transcriptDigest"] = B64Field(o["transcriptDigest"], "transcript digest", 32) };
    }

    // ---- the in-memory reference channel ----

    /// <summary>A delivery the in-memory network is about to make: the interceptor returns the bytes to deliver, or null to drop it.</summary>
    public sealed record MemoryDelivery(long From, long To, string Kind, byte[] Bytes);

    sealed class MemoryChannel(long self, IReadOnlyList<long> peers, Func<long, string, object?, byte[]?> route, DkgInbox inbox) : IDkgChannel
    {
        public long Self => self;
        public IReadOnlyList<long> Peers => peers;
        public Task Broadcast(string kind, object? body)
        {
            foreach (var p in peers) route(p, kind, body);
            return Task.CompletedTask;
        }
        public Task Send(long to, string kind, object? body)
        {
            if (!peers.Contains(to)) return Task.FromException(new DkgChannelError("identity", to, "not a connected peer"));
            route(to, kind, body);
            return Task.CompletedTask;
        }
        public Task<Dictionary<long, object?>> Collect(string kind, IReadOnlyList<long> from, double timeoutMs) => inbox.Collect(kind, from, timeoutMs);
        public Task Close() { inbox.Close(); return Task.CompletedTask; }
    }

    /// <summary>The in-process reference network: <c>Channels</c> by participant and <c>Deliver</c> (the adversary hook: deliver raw bytes to a participant as if sent by another). <c>intercept</c> sees every delivery and
    /// returns the bytes to deliver, or null to drop it, so tests model a network or a corrupted peer without any private API.</summary>
    public sealed class MemoryNetwork(Dictionary<long, IDkgChannel> channels, Action<long, long, byte[]> deliver)
    {
        public Dictionary<long, IDkgChannel> Channels => channels;
        public void Deliver(long from, long to, byte[] bytes) => deliver(from, to, bytes);
    }

    public static MemoryNetwork CreateMemoryNetwork(IEnumerable<long> ids, byte[] sessionId, Func<MemoryDelivery, byte[]?>? intercept = null)
    {
        var sorted = ids.OrderBy(x => x).ToList();
        var inboxes = new Dictionary<long, DkgInbox>();
        foreach (var id in sorted) inboxes[id] = new DkgInbox(sessionId, sorted.Where(p => p != id).ToList());
        void Deliver(long from, long to, byte[] bytes) { if (inboxes.TryGetValue(to, out var ib)) ib.Accept(from, bytes); }
        var channels = new Dictionary<long, IDkgChannel>();
        foreach (var self in sorted)
        {
            var peers = sorted.Where(p => p != self).ToList();
            byte[]? Route(long to, string kind, object? body)
            {
                var bytes = EncodeMessage(sessionId, kind, body);
                var outp = intercept != null ? intercept(new MemoryDelivery(self, to, kind, bytes)) : bytes;
                if (outp != null) Deliver(self, to, outp);
                return outp;
            }
            channels[self] = new MemoryChannel(self, peers, Route, inboxes[self]);
        }
        return new MemoryNetwork(channels, Deliver);
    }

    // ---- the driver ----

    /// <summary>The options of <see cref="RunAsync"/>. Numbers are JavaScript numbers (doubles), so a fraction is refused by the validation as in the reference.</summary>
    public sealed class RunOpts
    {
        public double T;
        /// <summary>Every participant including this one.</summary>
        public IReadOnlyList<double> Participants = [];
        /// <summary>The ceremony id, identical for all participants and unique per run.</summary>
        public byte[] SessionId = [];
        /// <summary>The per-phase wait for the other parties; a missing message after this aborts the run (default 30 s).</summary>
        public double? TimeoutMs;
        /// <summary>Fixed polynomial coefficients (tests).</summary>
        public IReadOnlyList<byte[]>? Coefficients;
        public Func<byte[]>? Random;
    }

    static T Bind<T>(long peer, Func<T> f)
    {
        try { return f(); }
        catch (DkgChannelError e) { throw new DkgChannelError(e.Code, peer, e.Detail); }
    }

    static bool Same(object? a, object? b) => IntentJs.JsonEquals(a, b);

    /// <summary>Run ONE participant's whole DKG over the channel: round 1, proof-of-possession checks, round 2 with signed shares, share verification, complaints, rebuttals, the qualified set, the echo round and finalize.
    /// Returns {keyPackage, qualified, complaints}; throws <see cref="DkgChannelError"/> on any channel or protocol violation (nothing partial is returned).</summary>
    public static async Task<D> RunAsync(IDkgChannel ch, RunOpts opts)
    {
        long self = ch.Self;
        var ids = opts.Participants.OrderBy(x => x).ToList();
        if (ids.Count > MaxParticipants || ids.Select((i, k) => !(i == Math.Floor(i) && i > 0 && i <= 9007199254740991.0) || (k > 0 && ids[k - 1] == i)).Any(b => b))
            throw new DkgChannelError("protocol", null, "participants must be distinct positive integers within the cap");
        if (!ids.Contains(self)) throw new DkgChannelError("protocol", null, "this participant is not in the participant list");
        if (!(opts.T == Math.Floor(opts.T) && opts.T >= 1 && opts.T <= ids.Count)) throw new DkgChannelError("protocol", null, "need 1 <= t <= n");
        var t = (int)opts.T;
        var others = ids.Where(i => i != self).Select(i => (long)i).ToList();
        if (ch.Peers.Count != others.Count || !others.Select((o, k) => ch.Peers[k] == o).All(b => b))
            throw new DkgChannelError("protocol", null, "the channel peers are not exactly the other participants");
        var sid = opts.SessionId;
        var sidB64 = Pca.B64u(sid);
        var tmo = opts.TimeoutMs ?? 30_000;
        var n = ids.Count;

        // round 1: broadcast, collect, bind each package to its authenticated sender
        var r1 = FrostDkg.Round1(self, t, n, sid, opts.Coefficients, null, opts.Random);
        await ch.Broadcast("round1", r1.Package).ConfigureAwait(false);
        var pkgs = new L { r1.Package };
        foreach (var (from, body) in await ch.Collect("round1", others, tmo).ConfigureAwait(false))
        {
            var p = Bind(from, () => DecodeRound1Package(body, t));
            if (!Same(p["identifier"], from)) throw new DkgChannelError("identity", from, $"package claims identifier {JsJson.ToJsString(p["identifier"])}");
            if (!Same(p["sessionId"], sidB64)) throw new DkgChannelError("wrong-session", from, "package names another session");
            pkgs.Add(p);
        }
        var byId = pkgs.ToDictionary(p => IntentJs.Lng(((D)p!)["identifier"]), p => (D)p!);
        // a package whose proof of possession fails is dropped by the qualified set; it gets and gives no shares
        var pok = pkgs.Where(p => FrostDkg.VerifyRound1(((D)p!)["identifier"], p, sid)).ToList();
        var okPeers = others.Where(o => pok.Any(p => Same(((D)p!)["identifier"], o))).ToList();

        // round 2: signed shares out (private), signed shares in
        foreach (var s in FrostDkg.Round2(r1.State, pok))
            await ch.Send(IntentJs.Lng(s["to"]), "share", new D { ["from"] = s["from"], ["to"] = s["to"], ["sessionId"] = s["sessionId"], ["share"] = Pca.B64u((byte[])s["share"]!), ["sig"] = s["sig"] }).ConfigureAwait(false);
        var inbox = new L();
        var mine = new L();
        foreach (var (from, body) in await ch.Collect("share", okPeers, tmo).ConfigureAwait(false))
        {
            var m = Bind(from, () => DecodeShareMessage(body));
            if (!Same(m["from"], from)) throw new DkgChannelError("identity", from, $"share claims sender {JsJson.ToJsString(m["from"])}");
            if (!Same(m["to"], self)) throw new DkgChannelError("identity", from, $"share is addressed to {JsJson.ToJsString(m["to"])}");
            if (!Same(m["sessionId"], sidB64)) throw new DkgChannelError("wrong-session", from, "share names another session");
            var received = new D { ["from"] = from, ["sessionId"] = m["sessionId"], ["share"] = m["share"], ["sig"] = m["sig"] };
            var sender = byId[from];
            if (FrostDkg.VerifyShare(received, sender, self, sid)) { inbox.Add(received); continue; }
            var c = FrostDkg.FileComplaint(from, self, (byte[])m["share"]!, (string)m["sig"]!, sid);
            // only a share the sender really signed is attributable blame; anything else aborts the run instead of accusing
            if (FrostDkg.VerifyComplaint(c, pkgs)["justified"] is not true) throw new DkgChannelError("protocol", from, "share failed verification and is not admissible blame");
            mine.Add(c);
        }

        // complaints (broadcast, possibly empty), then rebuttals by the accused
        await ch.Broadcast("complaints", new D { ["complaints"] = mine }).ConfigureAwait(false);
        var complaints = new L(mine);
        foreach (var (from, body) in await ch.Collect("complaints", others, tmo).ConfigureAwait(false))
        {
            var list = Bind(from, () => DecodeComplaints(body));
            var pairs = new HashSet<string>();
            foreach (var co in list)
            {
                var c = (D)co!;
                if (!Same(c["accuser"], from)) throw new DkgChannelError("identity", from, $"complaint filed as {JsJson.ToJsString(c["accuser"])}");
                if (!Same(c["sessionId"], sidB64)) throw new DkgChannelError("wrong-session", from, "complaint names another session");
                if (Same(c["accused"], from) || !ids.Any(i => Same(c["accused"], i))) throw new DkgChannelError("protocol", from, "complaint names an invalid accused");
                if (!pairs.Add(JsJson.ToJsString(c["accused"]))) throw new DkgChannelError("duplicate", from, "two complaints against one accused");
                complaints.Add(c);
            }
        }
        var rebuttals = complaints.Where(c => Same(((D)c!)["accused"], self)).Select(c => (object?)FrostDkg.Rebut(self, c, r1.State)).ToList();
        await ch.Broadcast("rebuttals", new D { ["rebuttals"] = rebuttals }).ConfigureAwait(false);
        var allRebuttals = new L(rebuttals);
        foreach (var (from, body) in await ch.Collect("rebuttals", others, tmo).ConfigureAwait(false))
            foreach (var ro in Bind(from, () => DecodeRebuttals(body)))
            {
                var r = (D)ro!;
                if (!Same(r["accused"], from)) throw new DkgChannelError("identity", from, $"rebuttal made as {JsJson.ToJsString(r["accused"])}");
                if (!Same(r["sessionId"], sidB64)) throw new DkgChannelError("wrong-session", from, "rebuttal names another session");
                allRebuttals.Add(r);
            }

        var qualified = FrostDkg.QualifiedSet(ids.Select(i => (object?)i).ToList(), complaints, pkgs, allRebuttals);
        if (!qualified.Contains(self)) throw new DkgChannelError("disqualified", self, "this participant was disqualified by the blame round");
        if (qualified.Count < t) throw new DkgChannelError("protocol", null, "fewer than t participants remain qualified");
        var qualifiedL = qualified.Cast<object?>().ToList();

        // echo round: every qualified party must have seen the identical transcript
        var echo = FrostDkg.Echo(self, pkgs, complaints, qualifiedL, sid);
        await ch.Broadcast("echo", echo).ConfigureAwait(false);
        var echoes = new L { echo };
        foreach (var (from, body) in await ch.Collect("echo", qualified.Where(q => q != self).ToList(), tmo).ConfigureAwait(false))
        {
            var e = Bind(from, () => DecodeEcho(body));
            if (!Same(e["identifier"], from)) throw new DkgChannelError("identity", from, $"echo claims identifier {JsJson.ToJsString(e["identifier"])}");
            echoes.Add(e);
        }
        var agreement = FrostDkg.CheckEchoes(qualifiedL, echoes, sid);
        if (agreement["agreed"] is not true) throw new DkgChannelError("equivocation", null, (string)agreement["reason"]!);

        var keyPackage = FrostDkg.Finalize(self, r1.State, inbox, pkgs, qualifiedL, new D { ["echoes"] = echoes, ["complaints"] = complaints });
        return new D { ["keyPackage"] = keyPackage, ["qualified"] = qualifiedL, ["complaints"] = complaints };
    }

    // ---- framing (the reference mutual-TLS channel reads length-prefixed frames off each authenticated link) ----

    /// <summary>One frame: a 4-byte big-endian length followed by the payload.</summary>
    public static byte[] EncodeFrame(byte[] payload)
    {
        var f = new byte[4 + payload.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(f, (uint)payload.Length);
        payload.CopyTo(f, 4);
        return f;
    }

    /// <summary>The receive side of the framing: bytes in, whole frames out. A frame whose length exceeds <see cref="MaxMessageBytes"/> is refused before any allocation (the link is then dead:
    /// <see cref="Error"/> is "oversize" and later input is ignored).</summary>
    public sealed class FrameDecoder
    {
        byte[] _buf = [];
        public List<byte[]> Accepted { get; } = [];
        public string? Error { get; private set; }
        public int Buffered => _buf.Length;

        public void Feed(byte[] chunk)
        {
            if (Error != null) return;
            _buf = [.. _buf, .. chunk];
            for (; ; )
            {
                if (_buf.Length < 4) break;
                var len = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(_buf);
                if (len > MaxMessageBytes) { Error = "oversize"; break; }
                if (_buf.Length < 4 + len) break;
                Accepted.Add(_buf[4..(4 + (int)len)]);
                _buf = _buf[(4 + (int)len)..];
            }
        }
    }
}

/// <summary>Receive side shared by channel implementations: holds at most one message per (kind, authenticated sender), records a sticky error per peer and implements Collect. A channel calls
/// <see cref="Accept"/> with the AUTHENTICATED sender.</summary>
public sealed class DkgInbox
{
    readonly Dictionary<string, (string Digest, object? Body)> _seen = new(StringComparer.Ordinal);
    readonly Dictionary<long, DkgChannelError> _errors = [];
    readonly List<TaskCompletionSource> _waiters = [];
    readonly HashSet<long> _gone = [];
    readonly object _lock = new();
    bool _closed;

    public byte[] SessionId { get; }
    public IReadOnlyList<long> Peers { get; }

    public DkgInbox(byte[] sessionId, IReadOnlyList<long> peers)
    {
        SessionId = sessionId;
        Peers = peers;
    }

    void Wake()
    {
        List<TaskCompletionSource> ws;
        lock (_lock) { ws = [.. _waiters]; _waiters.Clear(); }
        foreach (var w in ws) w.TrySetResult();
    }

    /// <summary>Record a peer failure (the first one wins).</summary>
    public void Fail(long peer, DkgChannelError err)
    {
        lock (_lock)
            if (!_errors.ContainsKey(peer)) _errors[peer] = new DkgChannelError(err.Code, peer, Regex.Replace(err.Message, @"^dkg channel \([^)]*\): ", ""));
        Wake();
    }

    /// <summary>Accept one wire message from the authenticated sender. Never throws; a bad message becomes a sticky peer error.</summary>
    public void Accept(long sender, byte[] bytes)
    {
        if (!Peers.Contains(sender)) return; // not a participant: nothing to attribute to
        try
        {
            var m = FrostDkgChannel.DecodeMessage(bytes, SessionId);
            var kind = (string)m["kind"]!;
            var key = $"{kind}\0{sender}";
            var digest = Pca.B64u(bytes);
            lock (_lock)
            {
                if (_seen.TryGetValue(key, out var prev)) throw new DkgChannelError(prev.Digest == digest ? "duplicate" : "equivocation", sender, $"second {kind} message");
                _seen[key] = (digest, m["body"]);
            }
            Wake();
        }
        catch (Exception e) { Fail(sender, e as DkgChannelError ?? new DkgChannelError("malformed", sender, "undecodable message")); }
    }

    /// <summary>The link to <paramref name="peer"/> ended. Soft: it only matters if a message that peer owed is still missing.</summary>
    public void PeerGone(long peer)
    {
        lock (_lock) _gone.Add(peer);
        Wake();
    }

    public void Close()
    {
        lock (_lock) _closed = true;
        Wake();
    }

    public async Task<Dictionary<long, object?>> Collect(string kind, IReadOnlyList<long> from, double timeoutMs)
    {
        var want = from.OrderBy(x => x).ToList();
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        for (; ; )
        {
            TaskCompletionSource waiter;
            double left;
            lock (_lock)
            {
                foreach (var id in want) if (_errors.TryGetValue(id, out var e)) throw e;
                var outp = new Dictionary<long, object?>();
                foreach (var id in want) if (_seen.TryGetValue($"{kind}\0{id}", out var m)) outp[id] = m.Body;
                if (outp.Count == want.Count) return outp;
                if (_closed) throw new DkgChannelError("closed", null, "channel closed before all messages arrived");
                var gone = want.Where(id => !outp.ContainsKey(id) && _gone.Contains(id)).Select(id => (long?)id).FirstOrDefault();
                if (gone != null) throw new DkgChannelError("closed", gone, $"link ended before its {kind} message arrived");
                left = (deadline - DateTime.UtcNow).TotalMilliseconds;
                if (left <= 0)
                {
                    var missing = want.Where(id => !outp.ContainsKey(id)).ToList();
                    throw new DkgChannelError("timeout", missing[0], $"no {kind} message from {string.Join(",", missing)}");
                }
                waiter = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _waiters.Add(waiter);
            }
            await Task.WhenAny(waiter.Task, Task.Delay(TimeSpan.FromMilliseconds(left))).ConfigureAwait(false);
            lock (_lock) _waiters.Remove(waiter);
        }
    }
}
