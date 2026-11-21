// The SSF 1.0 stream management API a transmitter serves to its receivers (framework-free: a request in, a response out): configuration create /
// read / update / replace / delete, stream status, add / remove subject and the verification trigger. A receiver only ever sees and changes its own
// streams; transmitter-supplied members (stream_id, iss, aud, events_supported, events_delivered, min_verification_interval) cannot be rewritten.
// Requests are JSON values (hostile shapes included): a malformed request is answered 400 / 404 / 405, an unexpected failure 500, never a crash.
using System.Globalization;
using J = AtlasPca.Jose.Jose;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Signals;

/// <summary>One managed stream. <see cref="Config"/> is the JSON stream configuration the receiver sees.</summary>
public sealed class StreamRecord
{
    public string Receiver { get; set; } = "";
    public D Config { get; set; } = new();
    public List<string>? EventsRequested { get; set; }
    public string Status { get; set; } = "enabled";
    public string? StatusReason { get; set; }
    public Dictionary<string, bool> Subjects { get; set; } = new();
    public double? LastVerification { get; set; }

    internal static object? Deep(object? v) => v switch
    {
        D d => d.ToDictionary(e => e.Key, e => Deep(e.Value)),
        L l => l.Select(Deep).ToList(),
        _ => v,
    };

    public StreamRecord Clone() => new()
    {
        Receiver = Receiver,
        Config = (D)Deep(Config)!,
        EventsRequested = EventsRequested?.ToList(),
        Status = Status,
        StatusReason = StatusReason,
        Subjects = new(Subjects),
        LastVerification = LastVerification,
    };

    /// <summary>The record as a JSON object (what a store serialises).</summary>
    public D ToJson()
    {
        var o = new D { ["receiver"] = Receiver, ["config"] = Deep(Config) };
        if (EventsRequested != null) o["events_requested"] = EventsRequested.Select(x => (object?)x).ToList();
        o["status"] = Status;
        if (StatusReason != null) o["status_reason"] = StatusReason;
        o["subjects"] = Subjects.ToDictionary(e => e.Key, e => (object?)e.Value);
        if (LastVerification != null) o["lastVerification"] = new Num(Signals.JsNum(LastVerification.Value));
        return o;
    }
}

/// <summary>Where streams live. Records are copied on the way in and out.</summary>
public interface IStreamStore
{
    StreamRecord? Get(string id);
    void Put(string id, StreamRecord r);
    void Delete(string id);
    List<(string Id, StreamRecord Record)> ListByReceiver(string receiver);
}

public sealed class MemoryStreamStore : IStreamStore
{
    readonly object _gate = new();
    readonly List<(string Id, StreamRecord R)> _m = new();

    public StreamRecord? Get(string id) { lock (_gate) return _m.FirstOrDefault(e => e.Id == id).R?.Clone(); }

    public void Put(string id, StreamRecord r)
    {
        lock (_gate)
        {
            var i = _m.FindIndex(e => e.Id == id);
            if (i >= 0) _m[i] = (id, r.Clone()); else _m.Add((id, r.Clone()));
        }
    }

    public void Delete(string id) { lock (_gate) _m.RemoveAll(e => e.Id == id); }

    public List<(string Id, StreamRecord Record)> ListByReceiver(string receiver)
    {
        lock (_gate) return _m.Where(e => e.R.Receiver == receiver).Select(e => (e.Id, e.R.Clone())).ToList();
    }
}

/// <summary>The authenticated receiver: its id and the audience its SETs are addressed to (a string or a list of strings).</summary>
public sealed record Receiver(string Id, object Aud);

public sealed class SsfManageOptions
{
    public required IStreamStore Store { get; init; }
    public required string Issuer { get; init; }
    public required IReadOnlyList<string> EventsSupported { get; init; }
    /// <summary>Default: push and poll.</summary>
    public IReadOnlyList<string>? DeliveryMethods { get; init; }
    public required Func<string, string> PollEndpoint { get; init; }
    public required object SigningKey { get; init; }
    public required Action<StreamRecord, string> Deliver { get; init; }
    /// <summary>Default 1.</summary>
    public double? MaxStreamsPerReceiver { get; init; }
    /// <summary>Default 10000.</summary>
    public double? MaxSubjectsPerStream { get; init; }
    public required Func<double> Now { get; init; }
    public Func<string>? NewId { get; init; }
}

public sealed record SsfResponse(int Status, object? Body = null);

public static class SsfManage
{
    static readonly string[] Endpoints = { "configuration", "status", "add_subject", "remove_subject", "verification" };
    static readonly string[] ReceiverSupplied = { "events_requested", "delivery", "description" };
    static readonly string[] TransmitterSupplied = { "stream_id", "iss", "aud", "events_supported", "events_delivered", "min_verification_interval" };

    static SsfResponse Bad(string m) => new(400, new D { ["error"] = "invalid_request", ["description"] = m });
    static SsfResponse NotFound() => new(404, new D { ["error"] = "not_found" });
    static SsfResponse NotAllowed() => new(405, new D { ["error"] = "method_not_allowed" });

    /// <summary>Object.keys order: array-index keys ascending first, then the rest in insertion order.</summary>
    internal static List<string> JsKeys(IEnumerable<string> keys)
    {
        var ks = keys.ToList();
        static bool Idx(string k) => k.Length is > 0 and <= 10 && k.All(char.IsAsciiDigit) && (k == "0" || k[0] != '0') && ulong.Parse(k, CultureInfo.InvariantCulture) < 4294967295UL;
        return ks.Where(Idx).OrderBy(k => ulong.Parse(k, CultureInfo.InvariantCulture)).Concat(ks.Where(k => !Idx(k))).ToList();
    }

    /// <summary>The SSF 1.0 section 7.1 transmitter metadata document.</summary>
    public static D TransmitterMetadata(string issuer, IReadOnlyList<string>? deliveryMethods, string baseUrl, string? jwksUri = null)
    {
        var o = new D { ["spec_version"] = "1_0", ["issuer"] = issuer };
        if (!string.IsNullOrEmpty(jwksUri)) o["jwks_uri"] = jwksUri;
        o["delivery_methods_supported"] = (deliveryMethods ?? new[] { SsfStream.DeliveryPush, SsfStream.DeliveryPoll }).Select(x => (object?)x).ToList();
        o["configuration_endpoint"] = $"{baseUrl}/ssf/configuration";
        o["status_endpoint"] = $"{baseUrl}/ssf/status";
        o["add_subject_endpoint"] = $"{baseUrl}/ssf/add_subject";
        o["remove_subject_endpoint"] = $"{baseUrl}/ssf/remove_subject";
        o["verification_endpoint"] = $"{baseUrl}/ssf/verification";
        o["default_subjects"] = "NONE";
        return o;
    }

    /// <summary>A canonical key for a Subject Identifier (members sorted by name), or null when it is not an object with a non-empty format.</summary>
    static string? SubjectKey(object? s)
    {
        if (s is not D d || d.GetValueOrDefault("format") is not string f || f.Length == 0) return null;
        try
        {
            var sorted = d.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
            var o = new D();
            foreach (var k in JsKeys(sorted)) o[k] = d[k];
            return J.Stringify(o);
        }
        catch (Exception) { return null; }
    }

    /// <summary>Build the management handler: a request (a JSON object {method, path, query?, body?}) in, a response out. <paramref name="authenticate"/>
    /// returns the calling receiver or null (401).</summary>
    public static Func<object?, SsfResponse> Handler(SsfManageOptions o, Func<object?, Receiver?> authenticate)
    {
        var methods = o.DeliveryMethods ?? new[] { SsfStream.DeliveryPush, SsfStream.DeliveryPoll };
        var newId = o.NewId ?? (() => Pca.B64u(System.Security.Cryptography.RandomNumberGenerator.GetBytes(12)));
        double maxStreams = o.MaxStreamsPerReceiver ?? 1;

        StreamRecord? Own(Receiver rcv, object? id)
        {
            if (id is not string s) return null;
            var r = o.Store.Get(s);
            return r != null && r.Receiver == rcv.Id ? r : null;
        }

        List<string> Delivered(List<string>? requested) => requested == null ? o.EventsSupported.ToList() : o.EventsSupported.Where(requested.Contains).ToList();

        static bool EventsRequestedOk(object? v) => v is L { Count: > 0 } l && l.All(e => e is string { Length: > 0 });
        static List<string> Strings(object? v) => ((L)v!).Select(x => (string)x!).ToList();

        (bool Ok, D? Delivery, string? Why) DeliveryFor(string id, bool present, object? d)
        {
            if (!present)
            {
                if (!methods.Contains(SsfStream.DeliveryPoll)) return (false, null, "delivery is required: this transmitter does not support poll");
                return (true, new D { ["method"] = SsfStream.DeliveryPoll, ["endpoint_url"] = o.PollEndpoint(id) }, null);
            }
            if (d is not D dd || dd.GetValueOrDefault("method") is not string method || !methods.Contains(method)) return (false, null, "delivery.method is not supported by this transmitter");
            if (method == SsfStream.DeliveryPoll) return (true, new D { ["method"] = SsfStream.DeliveryPoll, ["endpoint_url"] = o.PollEndpoint(id) }, null); // transmitter-set; a receiver value is ignored
            if (dd.GetValueOrDefault("endpoint_url") is not string url || !SsfStream.IsHttpsUrl(url)) return (false, null, "push delivery needs an https endpoint_url");
            return (true, new D { ["method"] = SsfStream.DeliveryPush, ["endpoint_url"] = url }, null);
        }

        D Build(string id, Receiver rcv, List<string>? requested, D delivery, string? description)
        {
            var c = new D
            {
                ["stream_id"] = id,
                ["iss"] = o.Issuer,
                ["aud"] = rcv.Aud,
                ["events_supported"] = o.EventsSupported.Select(x => (object?)x).ToList(),
                ["events_delivered"] = Delivered(requested).Select(x => (object?)x).ToList(),
                ["delivery"] = delivery,
            };
            if (description != null) c["description"] = description.Length > 256 ? description[..256] : description;
            return c;
        }

        SsfResponse Route(object? req, Receiver rcv)
        {
            var r = req as D;
            var seg = (r?.GetValueOrDefault("path") as string ?? throw new InvalidOperationException("req.path.split is not a function")).Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault() ?? "";
            var q = r!.GetValueOrDefault("query") as D ?? new D();
            var b = r.GetValueOrDefault("body") as D;
            var m = (r.GetValueOrDefault("method") as string ?? throw new InvalidOperationException("req.method.toUpperCase is not a function")).ToUpperInvariant();
            if (!Endpoints.Contains(seg)) return NotFound();
            q.TryGetValue("stream_id", out var qid);
            var qHas = q.ContainsKey("stream_id");

            if (seg == "configuration")
            {
                if (m == "POST") // 8.1.1.1
                {
                    if (b == null) return Bad("a JSON object body is required");
                    foreach (var k in JsKeys(b.Keys)) if (!ReceiverSupplied.Contains(k)) return Bad($"'{k}' is not a receiver-supplied member");
                    if (b.ContainsKey("events_requested") && !EventsRequestedOk(b["events_requested"])) return Bad("events_requested must be a non-empty array of event type URIs");
                    if (b.ContainsKey("description") && b["description"] is not string) return Bad("description must be a string");
                    if (o.Store.ListByReceiver(rcv.Id).Count >= maxStreams) return new(409, new D { ["error"] = "conflict", ["description"] = "this receiver already has the maximum number of streams" });
                    var id = newId();
                    var d = DeliveryFor(id, b.ContainsKey("delivery"), b.GetValueOrDefault("delivery"));
                    if (!d.Ok) return Bad(d.Why!);
                    var requested = b.ContainsKey("events_requested") ? Strings(b["events_requested"]) : null;
                    if (Delivered(requested).Count == 0) return Bad("none of events_requested is supported by this transmitter");
                    var config = Build(id, rcv, requested, d.Delivery!, b.GetValueOrDefault("description") as string);
                    var problems = SsfStream.ValidateStreamConfig(config);
                    if (problems.Count > 0) return Bad(string.Join("; ", problems));
                    o.Store.Put(id, new StreamRecord { Receiver = rcv.Id, Config = config, EventsRequested = requested, Status = "enabled" });
                    return new(201, config);
                }
                if (m == "GET") // 8.1.1.2
                {
                    if (!qHas) return new(200, o.Store.ListByReceiver(rcv.Id).Select(e => (object?)e.Record.Config).ToList());
                    var s = Own(rcv, qid);
                    return s != null ? new(200, s.Config) : NotFound();
                }
                if (m is "PATCH" or "PUT") // 8.1.1.3 / 8.1.1.4
                {
                    if (b == null) return Bad("a JSON object body is required");
                    var s = Own(rcv, b.GetValueOrDefault("stream_id"));
                    if (b.GetValueOrDefault("stream_id") is not string) return Bad("stream_id is required");
                    if (s == null) return NotFound();
                    foreach (var k in JsKeys(b.Keys)) if (!ReceiverSupplied.Contains(k) && !TransmitterSupplied.Contains(k)) return Bad($"unknown member '{k}'");
                    foreach (var k in TransmitterSupplied)
                    {
                        if (!b.ContainsKey(k)) continue;
                        if (!s.Config.TryGetValue(k, out var expected) || J.Stringify(b[k]) != J.Stringify(expected)) return Bad($"'{k}' is transmitter-supplied and does not match");
                    }
                    if (b.ContainsKey("events_requested") && !EventsRequestedOk(b["events_requested"])) return Bad("events_requested must be a non-empty array of event type URIs");
                    if (b.ContainsKey("description") && b["description"] is not string) return Bad("description must be a string");
                    var delivery = (D)s.Config["delivery"]!;
                    if (b.ContainsKey("delivery") || m == "PUT") // PUT: a missing delivery is a deleted one, i.e. the default
                    {
                        var d = DeliveryFor((string)s.Config["stream_id"]!, b.ContainsKey("delivery"), b.GetValueOrDefault("delivery"));
                        if (!d.Ok) return Bad(d.Why!);
                        if ((string)d.Delivery!["method"]! != (string)delivery["method"]!) return Bad("delivery.method cannot be changed: create a new stream");
                        delivery = d.Delivery!;
                    }
                    var requested = m == "PUT" ? (b.ContainsKey("events_requested") ? Strings(b["events_requested"]) : null)
                        : b.ContainsKey("events_requested") ? Strings(b["events_requested"]) : s.EventsRequested;
                    var description = m == "PUT" ? b.GetValueOrDefault("description") as string
                        : b.ContainsKey("description") ? (string)b["description"]! : s.Config.GetValueOrDefault("description") as string;
                    if (Delivered(requested).Count == 0) return Bad("none of events_requested is supported by this transmitter");
                    var next = Build((string)s.Config["stream_id"]!, rcv, requested, delivery, description);
                    if (s.Config.TryGetValue("min_verification_interval", out var mvi)) next["min_verification_interval"] = mvi;
                    s.Config = next;
                    s.EventsRequested = requested;
                    o.Store.Put((string)next["stream_id"]!, s);
                    return new(200, next);
                }
                if (m == "DELETE") // 8.1.1.5
                {
                    var s = Own(rcv, qid);
                    if (s == null) return NotFound();
                    o.Store.Delete((string)qid!);
                    return new(204);
                }
                return NotAllowed();
            }

            if (seg == "status") // 8.1.2
            {
                D StatusBody(StreamRecord s, object? id)
                {
                    var body = new D { ["stream_id"] = id, ["status"] = s.Status };
                    if (s.StatusReason != null) body["reason"] = s.StatusReason;
                    return body;
                }
                if (m == "GET")
                {
                    var s = Own(rcv, qid);
                    if (s == null) return !qHas ? Bad("stream_id is required") : NotFound();
                    return new(200, StatusBody(s, qid));
                }
                if (m == "POST")
                {
                    if (b == null || b.GetValueOrDefault("stream_id") is not string sid) return Bad("stream_id is required");
                    if (b.GetValueOrDefault("status") is not string status || !SsfStream.StreamStatuses.Contains(status)) return Bad("status must be 'enabled', 'paused' or 'disabled'");
                    if (b.ContainsKey("reason") && b["reason"] is not string) return Bad("reason must be a string");
                    var s = Own(rcv, sid);
                    if (s == null) return NotFound();
                    s.Status = status;
                    s.StatusReason = b.ContainsKey("reason") ? (string)b["reason"]! : null;
                    o.Store.Put(sid, s);
                    return new(200, StatusBody(s, sid));
                }
                return NotAllowed();
            }

            if (seg is "add_subject" or "remove_subject") // 8.1.3
            {
                if (m != "POST") return NotAllowed();
                if (b == null || b.GetValueOrDefault("stream_id") is not string sid) return Bad("stream_id is required");
                var key = SubjectKey(b.GetValueOrDefault("subject"));
                if (key == null) return Bad("subject must be a Subject Identifier object with a format");
                if (b.ContainsKey("verified") && b["verified"] is not bool) return Bad("verified must be a boolean");
                var s = Own(rcv, sid);
                if (s == null) return NotFound();
                if (seg == "add_subject")
                {
                    if (!s.Subjects.ContainsKey(key) && s.Subjects.Count >= (o.MaxSubjectsPerStream ?? 10_000)) return new(429, new D { ["error"] = "too_many_requests", ["description"] = "subject limit reached" });
                    s.Subjects[key] = b.ContainsKey("verified") && b["verified"] is bool v ? v : true; // SSF: SHOULD assume verified when omitted
                    o.Store.Put(sid, s);
                    return new(200);
                }
                s.Subjects.Remove(key); // an unknown subject is silently ignored (204)
                o.Store.Put(sid, s);
                return new(204);
            }

            // verification
            if (m != "POST") return NotAllowed();
            if (b == null) return Bad("a JSON object body is required");
            {
                var s = Own(rcv, b.GetValueOrDefault("stream_id"));
                if (s == null) return b.GetValueOrDefault("stream_id") is string ? NotFound() : Bad("stream_id is required");
                if (s.Status == "disabled") return Bad("the stream is disabled");
                var view = new Dictionary<string, StreamEntry> { [(string)s.Config["stream_id"]!] = new StreamEntry { Config = s.Config, LastVerification = s.LastVerification } };
                var vreq = new D { ["stream_id"] = b["stream_id"] };
                if (b.ContainsKey("state")) vreq["state"] = b["state"];
                var outc = SsfStream.HandleVerificationRequest(view, vreq, o.Now(), o.SigningKey);
                if (outc.Status != 204) return new(outc.Status, new D { ["error"] = outc.Status == 429 ? "too_many_requests" : "invalid_request", ["description"] = outc.Error });
                s.LastVerification = o.Now();
                o.Store.Put((string)s.Config["stream_id"]!, s);
                o.Deliver(s, outc.Set!);
                return new(204);
            }
        }

        return req =>
        {
            try
            {
                var rcv = authenticate(req);
                if (rcv == null) return new(401, new D { ["error"] = "unauthenticated" });
                return Route(req, rcv);
            }
            catch (Exception) { return new(500, new D { ["error"] = "server_error" }); }
        };
    }
}
