// K5 read-side authorization: what an agent may SEE, proven, and where it may go next. A principal signs a READ GRANT (per verb, resource
// prefix and purpose a mask mode per data class, per-class caps, per-sink label rules); RedactRead applies it to one response (every field
// is shown, masked or dropped; tighten-only), and CheckSink denies / escalates a write whose sink the grant does not allow the read labels
// to reach. Pure and total: anything malformed, unsigned, unknown or out of scope DENIES. Integers only. Port of
// packages/pca/src/readside.ts; replays packages/pca/conformance/readside-vectors.json. Inputs are parsed JSON values (Pca.ParseJson).
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using S = AtlasPca.K5Strict;

namespace AtlasPca;

/// <summary>View values are string | bool | Num (shown) or string | long (masked).</summary>
public sealed record ReadResult(string Decision, string? Code, JD View, JD Fields, List<string> Labels, Dictionary<string, long> Counts)
{
    public JD ToJson() => new()
    {
        ["decision"] = Decision,
        ["code"] = Code,
        ["view"] = View,
        ["fields"] = Fields,
        ["labels"] = Labels.Select(l => (object?)l).ToList(),
        ["counts"] = Counts.ToDictionary(e => e.Key, e => (object?)e.Value),
    };
}

/// <param name="Grant">the signed read grant {body, sig} (parsed JSON)</param>
/// <param name="Principal">the pinned principal key</param>
/// <param name="Now">anything other than an unsigned safe integer Num denies <c>bad_request</c> (never skips the time window)</param>
/// <param name="Schema">{fields: path -> class, required: [path]}</param>
/// <param name="Record">flat field -> scalar</param>
/// <param name="Tighten">class -> a STRICTER mode; a weaker one is ignored</param>
/// <param name="Salt">a per-read secret of at least 16 characters</param>
/// <param name="Counts">reads already charged per class in the current window</param>
public sealed record ReadInput(object? Grant, object? Principal, object? Now, object? Verb, object? Resource, object? Purpose, object? Schema, object? Record, object? Tighten, object? Salt, object? Counts);

public sealed record SinkInput(object? Grant, object? Principal, object? RsSigner, object? Now, object? Sink, object? Receipts);

public sealed record SinkResult(string Decision, string? Code, List<string> Labels)
{
    public JD ToJson() => new() { ["decision"] = Decision, ["code"] = Code, ["labels"] = Labels.Select(l => (object?)l).ToList() };
}

/// <summary>Either <see cref="Labels"/> (ok) or <see cref="Code"/> + <see cref="At"/>.</summary>
public sealed record ChainLabels(List<string>? Labels, string? Code, int At);

public static class ReadSide
{
    public const string GrantDomain = "atlas-pca/read-grant/v1\0";
    public const string ReceiptDomain = "atlas-pca/read-receipt/v1\0";
    const string RgRef = "atlas-pca/read-grant-ref/v1";
    const string RrRef = "atlas-pca/read-receipt-ref/v1";
    const string Rh = "atlas-pca/read-hash/v1";
    const string Rt = "atlas-pca/read-token/v1";
    const string Rv = "atlas-pca/read-value/v1";
    const int SaltMin = 16;

    static readonly Regex ModeRe = new(@"\A(show|last4|hash|token|drop|bucket:[1-9][0-9]{0,8})\z", RegexOptions.None);
    static readonly string[] EntryKeys = { "verb", "resource_prefix", "purposes", "modes", "default_mode" };
    static readonly string[] GrantKeys = { "v", "id", "principal", "issued_at", "expires_at", "reads", "caps", "sinks" };
    static readonly string[] RcptKeys = { "v", "grant", "verb", "resource", "purpose", "seq", "prev", "fields", "labels", "issued_at", "signer", "sig" };
    static readonly string[] RcptBodyKeys = { "v", "grant", "verb", "resource", "purpose", "seq", "prev", "fields", "labels", "issued_at", "signer" };

    static bool IsMode(object? x) => S.Rx(x, ModeRe);
    static int Rank(string m) => (m.StartsWith("bucket:", StringComparison.Ordinal) ? "bucket" : m) switch { "show" => 0, "last4" => 1, "bucket" => 2, "token" => 3, "hash" => 4, _ => 5 };

    sealed class Entry { public string Verb = "", Prefix = "", Default = ""; public List<string> Purposes = new(); public Dictionary<string, string> Modes = new(); }
    sealed class Grant
    {
        public JD Raw = new();
        public string Principal = "";
        public long IssuedAt, ExpiresAt;
        public List<Entry> Reads = new();
        public Dictionary<string, long> Caps = new();
        public Dictionary<string, (List<string> Allow, List<string> Escalate)> Sinks = new();
    }

    static bool ValidEntry(object? eo) =>
        eo is JD e && S.OnlyKeys(e, EntryKeys) && S.IsStr(e["verb"], 128) && S.IsStr(e["resource_prefix"], 512) && S.SortedUnique(e["purposes"], S.IdRe, 16) && ((List<object?>)e["purposes"]!).Count > 0 &&
        e["modes"] is JD m && m.Count <= 32 && m.All(x => S.LabelRe.IsMatch(x.Key) && IsMode(x.Value)) && IsMode(e["default_mode"]);

    /// <summary>Shape of a read grant body (no signature).</summary>
    public static bool ValidReadGrantBody(object? bo)
    {
        if (bo is not JD b || !S.OnlyKeys(b, GrantKeys) || !(S.TryInt(b["v"], out var v) && v == 1)) return false;
        if (!S.Rx(b["id"], S.IdRe) || !S.IsB32(b["principal"]) || !S.IsUint(b["issued_at"]) || !S.IsUint(b["expires_at"])) return false;
        if (b["reads"] is not List<object?> reads || reads.Count == 0 || reads.Count > 32 || !reads.All(ValidEntry)) return false;
        if (b["caps"] is not JD caps || caps.Count > 32 || !caps.All(e => S.LabelRe.IsMatch(e.Key) && S.IsUint(e.Value))) return false;
        if (b["sinks"] is not JD s || s.Count > 16) return false;
        return s.All(e => S.IdRe.IsMatch(e.Key) && e.Value is JD r && S.OnlyKeys(r, "allow", "escalate") && S.SortedUnique(r["allow"], S.LabelRe, 16) && S.SortedUnique(r["escalate"], S.LabelRe, 16) &&
            !S.Strs(r["allow"]).Any(S.Strs(r["escalate"]).Contains));
    }

    static Grant ParseGrant(JD b)
    {
        var g = new Grant
        {
            Raw = b, Principal = (string)b["principal"]!, IssuedAt = S.U(b["issued_at"]), ExpiresAt = S.U(b["expires_at"]),
            Caps = ((JD)b["caps"]!).ToDictionary(e => e.Key, e => S.U(e.Value)),
        };
        foreach (var eo in (List<object?>)b["reads"]!)
        {
            var e = (JD)eo!;
            g.Reads.Add(new Entry
            {
                Verb = (string)e["verb"]!, Prefix = (string)e["resource_prefix"]!, Purposes = S.Strs(e["purposes"]), Default = (string)e["default_mode"]!,
                Modes = ((JD)e["modes"]!).ToDictionary(x => x.Key, x => (string)x.Value!),
            });
        }
        foreach (var (k, vo) in (JD)b["sinks"]!)
        {
            var r = (JD)vo!;
            g.Sinks[k] = (S.Strs(r["allow"]), S.Strs(r["escalate"]));
        }
        return g;
    }

    public static string ReadGrantDigest(JD body) => Pca.HashCanonical(new JD { ["d"] = RgRef, ["g"] = body });
    public static string ReadReceiptRef(JD receipt) => Pca.HashCanonical(new JD { ["d"] = RrRef, ["r"] = receipt });

    static ReadResult Out(string decision, string? code, Dictionary<string, long>? counts = null) => new(decision, code, new JD(), new JD(), new List<string>(), counts ?? new Dictionary<string, long>());
    static List<string> Sorted(IEnumerable<string> xs) { var l = xs.Distinct().ToList(); l.Sort(string.CompareOrdinal); return l; }
    static bool Bmp(string s) => s.EnumerateRunes().All(r => r.Value < 0x10000);

    // The principal and the clock are checked FIRST: a missing or malformed `now` must deny, never skip the time window.
    static (Grant? G, string? Code) GradeGrant(object? g, object? principal, object? now)
    {
        if (!S.IsB32(principal) || !S.IsUint(now)) return (null, "bad_request");
        var n = S.U(now);
        if (g is not JD sg || !S.OnlyKeys(sg, "body", "sig") || !ValidReadGrantBody(sg["body"])) return (null, "bad_grant");
        var body = ParseGrant((JD)sg["body"]!);
        if (body.Principal != (string)principal! || !S.VerifyBody(GrantDomain, body.Raw, principal, sg["sig"])) return (null, "bad_signature");
        if (n < body.IssuedAt) return (null, "not_yet");
        if (n >= body.ExpiresAt) return (null, "expired");
        return (body, null);
    }

    /// <summary>Apply a read grant to one response. Never throws (a failure is deny <c>bad_request</c>).</summary>
    public static ReadResult RedactRead(ReadInput inp)
    {
        try
        {
            var (g, gcode) = GradeGrant(inp.Grant, inp.Principal, inp.Now);
            if (g == null) return Out("deny", gcode);
            if (!S.IsB32(inp.Principal) || !S.IsUint(inp.Now) || !S.IsStr(inp.Verb, 128) || !S.IsStr(inp.Resource, 512) || !S.Rx(inp.Purpose, S.IdRe) || inp.Salt is not string salt || salt.Length < SaltMin) return Out("deny", "bad_request");
            var verb = (string)inp.Verb!;
            var resource = (string)inp.Resource!;
            var purpose = (string)inp.Purpose!;
            if (inp.Schema is not JD sc || sc.GetValueOrDefault("fields") is not JD sfields || !sfields.All(e => S.NameRe.IsMatch(e.Key) && S.Rx(e.Value, S.LabelRe)) ||
                sc.GetValueOrDefault("required") is not List<object?> required || !required.All(p => p is string ps && sfields.ContainsKey(ps))) return Out("deny", "bad_request");
            if (!S.IsScalarMap(inp.Record) || inp.Tighten is not JD tighten || !tighten.All(e => S.LabelRe.IsMatch(e.Key) && IsMode(e.Value))) return Out("deny", "bad_request");
            if (inp.Counts is not JD countsIn || !countsIn.All(e => S.LabelRe.IsMatch(e.Key) && S.IsUint(e.Value))) return Out("deny", "bad_request");
            var record = (JD)inp.Record!;
            var inCounts = countsIn.ToDictionary(e => e.Key, e => S.U(e.Value));
            var entry = g.Reads.FirstOrDefault(e => e.Verb == verb && resource.StartsWith(e.Prefix, StringComparison.Ordinal) && e.Purposes.Contains(purpose));
            if (entry == null) return Out("deny", "no_read_scope", inCounts);
            var fields = new JD();
            var view = new JD();
            var used = new Dictionary<string, long>();
            foreach (var path in Sorted(record.Keys))
            {
                var v = record[path];
                var cls = sfields.TryGetValue(path, out var co) ? (string?)co : null;
                // a field the schema does not classify is never shown
                var vd = Pca.HashCanonical(new JD { ["d"] = Rv, ["salt"] = salt, ["p"] = path, ["v"] = v });
                if (cls == null)
                {
                    fields[path] = new JD { ["class"] = "unclassified", ["action"] = "dropped", ["kind"] = null, ["vd"] = vd };
                    continue;
                }
                var mode = entry.Modes.TryGetValue(cls, out var mm) ? mm : entry.Default;
                if (tighten.TryGetValue(cls, out var to) && Rank((string)to!) > Rank(mode)) mode = (string)to!;
                object? shown = null;
                var action = "masked";
                string? kind = mode.StartsWith("bucket:", StringComparison.Ordinal) ? "bucket" : mode;
                if (mode == "show")
                {
                    shown = v;
                    action = "shown";
                    kind = null;
                }
                else if (mode == "last4")
                {
                    if (v is string s && Bmp(s))
                    {
                        var runes = s.EnumerateRunes().ToList();
                        if (runes.Count > 4) shown = "****" + string.Concat(runes.Skip(runes.Count - 4).Select(r => r.ToString()));
                    }
                }
                else if (mode.StartsWith("bucket:", StringComparison.Ordinal))
                {
                    var n = long.Parse(mode.Substring(7), System.Globalization.CultureInfo.InvariantCulture);
                    if (S.TryInt(v, out var iv) && iv >= 0) shown = iv - (iv % n);
                }
                else if (mode == "hash")
                {
                    shown = Pca.HashCanonical(new JD { ["d"] = Rh, ["salt"] = salt, ["c"] = cls, ["v"] = v });
                }
                else if (mode == "token")
                {
                    shown = "tok_" + Pca.HashCanonical(new JD { ["d"] = Rt, ["salt"] = salt, ["c"] = cls, ["v"] = v }).Substring(0, 22);
                }
                if (shown == null)
                {
                    fields[path] = new JD { ["class"] = cls, ["action"] = "dropped", ["kind"] = null, ["vd"] = vd };
                    continue;
                }
                fields[path] = new JD { ["class"] = cls, ["action"] = action, ["kind"] = kind, ["vd"] = vd };
                view[path] = shown;
                used[cls] = used.GetValueOrDefault(cls) + 1;
            }
            var counts = new Dictionary<string, long>(inCounts);
            foreach (var (c, n) in used)
            {
                counts[c] = counts.GetValueOrDefault(c) + n;
                if (g.Caps.TryGetValue(c, out var cap) && counts[c] > cap) return Out("deny", "read_cap", inCounts);
            }
            if (required.Any(p => !view.ContainsKey((string)p!))) return Out("escalate", "required_dropped", inCounts);
            var labels = Sorted(fields.Values.Select(f => (JD)f!).Where(f => (string)f["action"]! != "dropped").Select(f => (string)f["class"]!));
            return new ReadResult("allow", null, view, fields, labels, counts);
        }
        catch (Exception) { return Out("deny", "bad_request"); }
    }

    sealed class RRec { public JD Raw = new(); public string Grant = "", Signer = ""; public long Seq, IssuedAt; public string? Prev; public object? Sig; public List<(string Class, string Action)> Fields = new(); public List<string> Labels = new(); }

    static RRec? ValidReadReceipt(object? ro)
    {
        if (ro is not JD r || !S.OnlyKeys(r, RcptKeys) || !(S.TryInt(r["v"], out var v) && v == 1)) return null;
        if (!S.IsB32(r["grant"]) || !S.IsStr(r["verb"], 128) || !S.IsStr(r["resource"], 512) || !S.Rx(r["purpose"], S.IdRe) || !S.IsUint(r["seq"]) || !(r["prev"] == null || S.IsB32(r["prev"])) || (S.U(r["seq"]) == 0) != (r["prev"] == null)) return null;
        if (!S.IsUint(r["issued_at"]) || !S.IsB32(r["signer"]) || r["sig"] is not string || !S.SortedUnique(r["labels"], S.LabelRe, 32) || r["fields"] is not JD fs || fs.Count > 64) return null;
        var fields = new List<(string, string)>();
        foreach (var (k, fo) in fs)
        {
            if (!S.NameRe.IsMatch(k) || fo is not JD f || !S.OnlyKeys(f, "class", "action", "kind", "vd") || f["class"] is not string cls || !(cls == "unclassified" || S.LabelRe.IsMatch(cls)) ||
                !(f["action"] is "shown" or "masked" or "dropped") || !(f["kind"] == null || f["kind"] is string) || !S.IsB32(f["vd"])) return null;
            fields.Add((cls, (string)f["action"]!));
        }
        return new RRec { Raw = r, Grant = (string)r["grant"]!, Signer = (string)r["signer"]!, Seq = S.U(r["seq"]), IssuedAt = S.U(r["issued_at"]), Prev = r["prev"] as string, Sig = r["sig"], Fields = fields, Labels = S.Strs(r["labels"]) };
    }

    /// <summary>The labels carried by a verified, unbroken chain of read receipts, or an error code.</summary>
    public static ChainLabels ReadChainLabels(object? receipts, string rsSigner, string grantDigest, long now)
    {
        if (receipts is not List<object?> list) return new(null, "bad_receipt", 0);
        var all = new HashSet<string>();
        RRec? prev = null;
        for (var i = 0; i < list.Count; i++)
        {
            var r = ValidReadReceipt(list[i]);
            if (r == null || r.Signer != rsSigner || r.Grant != grantDigest || r.Seq != i || r.IssuedAt > now) return new(null, "bad_receipt", i);
            if ((prev == null ? r.Prev != null : r.Prev != ReadReceiptRef(prev.Raw)) || !S.VerifyBody(ReceiptDomain, S.Pick(r.Raw, RcptBodyKeys), rsSigner, r.Sig)) return new(null, "bad_receipt", i);
            // the receipt's labels must be exactly the classes of its non-dropped fields: an understated label list would launder data
            var want = Sorted(r.Fields.Where(f => f.Action != "dropped").Select(f => f.Class));
            if (!want.SequenceEqual(r.Labels)) return new(null, "bad_receipt", i);
            foreach (var l in r.Labels) all.Add(l);
            prev = r;
        }
        return new(Sorted(all), null, -1);
    }

    /// <summary>May data read under these receipts reach the sink? Deny on any label the grant does not allow; escalate on an "ask" label.</summary>
    public static SinkResult CheckSink(SinkInput inp)
    {
        SinkResult No(string code) => new("deny", code, new List<string>());
        try
        {
            var (g, gcode) = GradeGrant(inp.Grant, inp.Principal, inp.Now);
            if (g == null) return No(gcode!);
            if (!S.IsB32(inp.RsSigner) || inp.Sink is not string sink) return No("bad_request");
            if (!g.Sinks.TryGetValue(sink, out var rule)) return No("unknown_sink");
            var c = ReadChainLabels(inp.Receipts, (string)inp.RsSigner!, ReadGrantDigest(g.Raw), S.U(inp.Now));
            if (c.Labels == null) return No(c.Code!);
            if (c.Labels.Any(l => !rule.Allow.Contains(l) && !rule.Escalate.Contains(l))) return new("deny", "label_flow", c.Labels);
            if (c.Labels.Any(rule.Escalate.Contains)) return new("escalate", "label_escalate", c.Labels);
            return new("allow", null, c.Labels);
        }
        catch (Exception) { return No("bad_request"); }
    }
}
