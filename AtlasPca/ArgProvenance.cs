// PROVENANCE BY DEFAULT (check provenance_flow): an agent cannot be steered by injected content into choosing who, where or how
// much. Port of packages/pca/src/arg-provenance.ts (decideArgProvenance, createProvenanceRecorder, principalDirectProvenance);
// replays packages/pca/conformance/arg-provenance-vectors.json. Named ArgProvenance so it never collides with the Intent Layer v2
// rule 17 check `provenance` (ParamProvenance) or the K9 build-provenance gate (ProvenanceGate).
//
// A MEDIATOR (the agent harness, a gateway, an MCP client: whatever sees bytes enter the model's context and holds a key the model
// cannot reach) appends one signed receipt per context segment to a per-session hash chain: the principal's message (`principal`),
// a tool result (`tool`), a retrieved document (`retrieval`), a fetched page (`web`), and finally the chosen action (`action`, bound
// to the exact operation digest). The verifier re-derives every label from that chain; nothing the agent writes can lower a label.
// A sensitive action whose choice or any sink argument does not derive from the principal is `escalate`; a forged chain is `deny`.
// Every function here is pure and total; malformed input fails closed.
using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>A pinned mediator key: <c>{mediator, kid, pk, pq_pk?}</c> (the verifier's own, or one the principal's grant envelope names).</summary>
public sealed record ProvMediatorPin(string Mediator, string Kid, string Pk, string? PqPk = null)
{
    public JD ToJson()
    {
        var d = new JD { ["mediator"] = Mediator, ["kid"] = Kid, ["pk"] = Pk };
        if (PqPk != null) d["pq_pk"] = PqPk;
        return d;
    }
}

/// <summary>Untrusted content THIS server saw reach the agent's context (raise only): origin <c>tool</c>, <c>retrieval</c> or <c>web</c>.</summary>
public sealed record ProvObservation(string Origin, string Source)
{
    public JD ToJson() => new() { ["origin"] = Origin, ["source"] = Source };
}

/// <summary>The input of <see cref="ArgProvenance.Decide"/>, as JSON values (so a malformed input is representable and fails closed).</summary>
public sealed class ArgProvenanceInput
{
    /// <summary>The presented bundle; null = none (unlabelled).</summary>
    public object? Bundle { get; init; }
    /// <summary><c>{verb, resource, params}</c>.</summary>
    public object? Operation { get; init; }
    /// <summary>The list of pins (<see cref="ProvMediatorPin.ToJson"/>).</summary>
    public object? Mediators { get; init; }
    /// <summary>The action facts <c>{effects?, traits?, params?}</c>; null = unknown action (sensitive).</summary>
    public object? Action { get; init; }
    /// <summary>The principal authorized this exact operation (a node of an executable, principal-authorized plan).</summary>
    public bool PrincipalPlan { get; init; }
    /// <summary>The principal committed to this step (an admitted workflow step): the CHOICE is trusted, the values are not.</summary>
    public bool PrincipalControl { get; init; }
    /// <summary>The list of observations <c>{origin, source}</c>; null = none.</summary>
    public object? Observed { get; init; }
}

/// <summary>The decision: <c>pass</c>, <c>escalate</c> (the principal must confirm) or <c>deny</c> (forged or malformed provenance).
/// <see cref="Labels"/> holds every top-level parameter's label; <see cref="Tainted"/> the sink parameters above their floor;
/// <see cref="Path"/> where the untrusted content came from (<c>origin:source</c>, plus <c>unlabelled</c> without a verified chain).</summary>
public sealed record ArgProvenanceDecision(string Outcome, string? Code, string? Reason, bool Sensitive, bool Verified, string Control,
    IReadOnlyDictionary<string, string> Labels, IReadOnlyList<string> Tainted, IReadOnlyList<string> Path)
{
    /// <summary>The wire shape the conformance vectors compare (<c>code</c> / <c>reason</c> only when present).</summary>
    public JD ToJson()
    {
        var d = new JD { ["outcome"] = Outcome };
        if (Code != null) d["code"] = Code;
        if (Reason != null) d["reason"] = Reason;
        d["sensitive"] = Sensitive;
        d["verified"] = Verified;
        d["control"] = Control;
        var l = new JD();
        foreach (var (k, v) in Labels) l[k] = v;
        d["labels"] = l;
        d["tainted"] = Tainted.Select(x => (object?)x).ToList();
        d["path"] = Path.Select(x => (object?)x).ToList();
        return d;
    }
}

/// <summary>Configuration of the <c>provenance_flow</c> gate in <see cref="Pca.Authorize"/> (ALWAYS ON; this only configures it).</summary>
public sealed class ArgProvenanceOptions
{
    /// <summary>Pinned mediator keys (the agent harness, gateway or MCP client that labels context segments). The grant envelope may add more.</summary>
    public IReadOnlyList<ProvMediatorPin>? Mediators { get; init; }
    /// <summary>The facts of the action about to run, from YOUR action definitions: <c>{effects?, traits?, params?: {name: floor}}</c>.
    /// Null for an operation = unknown action: every argument is a sink and the choice must derive from the principal. An exception fails closed.</summary>
    public Func<Operation, Dictionary<string, object?>?>? Actions { get; init; }
    /// <summary>Untrusted content THIS server saw reach the agent's context in the session (<c>(pcactn, operation, session) -&gt; observations</c>;
    /// raise only). An exception fails closed.</summary>
    public Func<Dictionary<string, object?>, Operation, string?, IReadOnlyList<ProvObservation>?>? Observed { get; init; }
}

public static class ArgProvenance
{
    public const string ReceiptDomain = "atlas-pca/prov-receipt/v1\0";
    public const string ReceiptRefDomain = "atlas-pca/prov-receipt-ref/v1";
    public const string ActionDomain = "atlas-pca/prov-action/v1";
    /// <summary>Request header carrying a bundle (base64url of its JSON). The JSON body member is <see cref="BodyMember"/>.</summary>
    public const string Header = "PCA-Provenance";
    public const string BodyMember = "pca_provenance";
    public const int MaxReceipts = 256;
    /// <summary>Largest principal message a bundle may carry (UTF-8 bytes).</summary>
    public const int MaxContentBytes = 65_536;
    /// <summary>Leaves examined per parameter; a larger value is not examined and keeps the context label.</summary>
    public const int MaxLeaves = 4096;
    const int MaxDepth = 32;

    public static readonly IReadOnlyList<string> Origins = new[] { "principal", "tool", "retrieval", "web", "action" };
    /// <summary>The label lattice: trusted &lt; first_party &lt; tool &lt; web &lt; agent.</summary>
    public static readonly IReadOnlyList<string> Levels = new[] { "trusted", "first_party", "tool", "web", "agent" };
    static readonly string[] Floors = { "first_party", "tool", "agent" };
    /// <summary>Traits a read-only action may carry and still be non-sensitive.</summary>
    public static readonly IReadOnlyList<string> ReadSafeTraits = new[] { "pca.financial_data_read", "pca.pii_access", "pca.regulated_data" };
    static readonly Regex ContentKeyRe = new(@"^(0|[1-9][0-9]{0,8})\z", RegexOptions.CultureInvariant);

    static int Rank(string level) => Levels.ToList().IndexOf(level);
    static string Join(string a, string b) => Rank(a) >= Rank(b) ? a : b;
    /// <summary>The level of a segment origin (<c>action</c> contributes nothing: it is the model's own output).</summary>
    static string OriginLevel(string origin) => origin switch { "principal" => "trusted", "tool" => "tool", "retrieval" => "tool", "web" => "web", _ => "agent" };
    static bool IsOne(object? v) => IntentJs.IsInt(v) && IntentJs.NumOf(v) == 1.0;

    // ------------------------------------------------------------------------------------------------------------ wire

    /// <summary>The digest an <c>action</c> receipt binds: the exact operation (verb, resource, params).</summary>
    public static string ActionDigest(string verb, string resource, object? parameters) =>
        Pca.HashCanonical(new JD { ["d"] = ActionDomain, ["verb"] = verb, ["resource"] = resource, ["params"] = parameters });

    static string ActionDigest(JD op) => Pca.HashCanonical(new JD { ["d"] = ActionDomain, ["verb"] = op["verb"], ["resource"] = op["resource"], ["params"] = op["params"] });

    /// <summary>Content address of a receipt (signature included).</summary>
    public static string ReceiptRef(JD receipt) => IntentArtifacts.ArtifactRef(ReceiptRefDomain, "r", receipt);

    /// <summary>Is <paramref name="k"/> a well-formed pin <c>{mediator (1..256 bytes), kid (1..64), pk (b64u 32 bytes), pq_pk? (non-empty)}</c>?</summary>
    public static bool IsMediatorPin(object? k) =>
        k is JD d && IntentArtifacts.ClosedMembers(d, new[] { "mediator", "kid", "pk" }, new[] { "pq_pk" }, "pin") == null
        && IntentArtifacts.IsBoundedString(d["mediator"], 256) && IntentArtifacts.IsBoundedString(d["kid"], 64) && IntentArtifacts.IsDigest(d["pk"]) && IntentArtifacts.PinPqOk(d);

    /// <summary>Wire validation of one receipt. Null = well-formed.</summary>
    public static string? ReceiptWireError(object? receipt)
    {
        if (receipt is not JD r) return "a receipt must be an object";
        var m = IntentArtifacts.ClosedMembers(r, new[] { "v", "kind", "mediator", "kid", "session", "seq", "prev", "origin", "source", "content_digest", "issued_at", "sig" }, IntentArtifacts.SuiteMembers, "receipt");
        if (m != null) return m;
        if (!IsOne(r["v"]) || !Equals(r["kind"], "pca-prov")) return "a receipt must be {v: 1, kind: \"pca-prov\"}";
        if (!IntentArtifacts.IsBoundedString(r["mediator"], 256)) return "'mediator' must be a non-empty string (<= 256 bytes)";
        if (!IntentArtifacts.IsBoundedString(r["kid"], 64)) return "'kid' must be a non-empty string (<= 64 bytes)";
        if (!IntentArtifacts.IsDigest(r["session"])) return "'session' must be canonical base64url (32 bytes)";
        if (!IntentJs.IsNonNeg(r["seq"])) return "'seq' must be a non-negative safe integer";
        if (r["prev"] != null && !IntentArtifacts.IsDigest(r["prev"])) return "'prev' must be null or canonical base64url (32 bytes)";
        if (r["origin"] is not string o || !Origins.Contains(o)) return $"'origin' must be one of {string.Join(", ", Origins)}";
        if (!IntentArtifacts.IsBoundedString(r["source"], 256)) return "'source' must be a non-empty string (<= 256 bytes)";
        if (!IntentArtifacts.IsDigest(r["content_digest"])) return "'content_digest' must be canonical base64url (32 bytes)";
        if (!IntentJs.IsNonNeg(r["issued_at"])) return "'issued_at' must be a non-negative safe integer";
        if (r["sig"] is not string) return "'sig' must be a string";
        return IntentArtifacts.ArtifactSuiteError(r);
    }

    /// <summary>Validate action facts <c>{effects?, traits?, params?}</c>. Null = well-formed.</summary>
    public static string? ActionInfoError(object? action)
    {
        if (action is not JD a) return "action info must be an object";
        var m = IntentArtifacts.ClosedMembers(a, Array.Empty<string>(), new[] { "effects", "traits", "params" }, "action info");
        if (m != null) return m;
        foreach (var k in new[] { "effects", "traits" })
        {
            if (!a.ContainsKey(k)) continue;
            if (!(a[k] is JL l && l.Count <= 64 && l.All(x => IntentArtifacts.IsBoundedString(x, 128)))) return $"action info '{k}' must be a list of strings";
        }
        if (a.ContainsKey("params"))
        {
            if (a["params"] is not JD ps) return "action info 'params' must be an object";
            foreach (var k in IntentJs.JsKeys(ps.Keys))
                if (!IntentArtifacts.IsBoundedString(k, 128) || !(ps[k] is string f && Floors.Contains(f))) return $"action info param '{k}' must map to first_party | tool | agent";
        }
        return null;
    }

    /// <summary>Is an action with these facts non-sensitive (it only reads)? Null (unknown facts) is sensitive.</summary>
    public static bool IsReadOnlyAction(object? action)
    {
        if (action is not JD a || IntentJs.Get(a, "effects") is not JL effects || effects.Count == 0) return false;
        if (!effects.All(e => e is "read")) return false;
        var traits = IntentJs.Get(a, "traits");
        if (traits == null) return true;
        return traits is JL tl && tl.All(t => t is string s && ReadSafeTraits.Contains(s));
    }

    /// <summary>The grant envelope member <c>provenance</c>: closed <c>{mode?: "enforce" | "insecure_off", mediators?: pin[] (&lt;= 16)}</c>. Null = well-formed.
    /// <c>insecure_off</c> is the documented DANGEROUS opt-out: injected content can then steer the grant's sensitive actions.</summary>
    public static string? EnvelopeError(object? p)
    {
        if (p is not JD d) return "provenance must be an object";
        var m = IntentArtifacts.ClosedMembers(d, Array.Empty<string>(), new[] { "mode", "mediators" }, "provenance");
        if (m != null) return m;
        if (d.ContainsKey("mode") && !(d["mode"] is "enforce" or "insecure_off")) return "provenance.mode must be 'enforce' or 'insecure_off'";
        if (d.ContainsKey("mediators") && !(d["mediators"] is JL l && l.Count <= 16 && l.All(IsMediatorPin))) return "provenance.mediators must be at most 16 {mediator, kid, pk, pq_pk?}";
        return null;
    }

    // ------------------------------------------------------------------------------------------------------------ tokens

    /// <summary>Word characters for token boundaries: ASCII letters, digits, <c>_</c>, and every non-ASCII UTF-16 code unit (fail closed: fewer matches).</summary>
    static bool IsWord(char c) => (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c >= '\u0080';

    /// <summary>Does <paramref name="needle"/> occur in <paramref name="text"/> as a whole token? An occurrence counts when the code unit
    /// before it is not a word character (or the needle starts with a non-word character), and likewise after it. Exact, case-sensitive,
    /// on UTF-16 code units (the native string unit, so no conversion is needed); no normalization. An empty needle never occurs.</summary>
    public static bool OccursAsToken(string? text, string? needle)
    {
        if (text == null || string.IsNullOrEmpty(needle)) return false;
        bool headWord = IsWord(needle[0]), tailWord = IsWord(needle[^1]);
        for (int i = text.IndexOf(needle, StringComparison.Ordinal); i >= 0; i = text.IndexOf(needle, i + 1, StringComparison.Ordinal))
        {
            bool okB = !headWord || i == 0 || !IsWord(text[i - 1]);
            int end = i + needle.Length;
            bool okA = !tailWord || end == text.Length || !IsWord(text[end]);
            if (okB && okA) return true;
        }
        return false;
    }

    /// <summary>The text of every leaf of a value (strings as is, other scalars in strict canonical form, object keys included, in JSON
    /// member order); null when too large (more than 4096 leaves, deeper than 32) or not canonical.</summary>
    public static List<string>? Leaves(object? v)
    {
        var outp = new List<string>();
        bool Walk(object? x, int depth)
        {
            if (depth > MaxDepth || outp.Count > MaxLeaves) return false;
            switch (x)
            {
                case string s: outp.Add(s); break;
                case JL l:
                    foreach (var y in l) if (!Walk(y, depth + 1)) return false;
                    break;
                case JD d:
                    foreach (var k in IntentJs.JsKeys(d.Keys))
                    {
                        outp.Add(k);
                        if (!Walk(d[k], depth + 1)) return false;
                    }
                    break;
                default:
                    // a number as JSON.parse reads it, in strict canonical form; -0, NaN and out-of-profile values have none
                    try { outp.Add(Pca.Canonicalize(IntentJs.Normalize(x))); }
                    catch (Exception) { return false; }
                    break;
            }
            return outp.Count <= MaxLeaves;
        }
        return Walk(v, 0) ? outp : null;
    }

    // ------------------------------------------------------------------------------------------------------------ decision

    static List<string> SortU(IEnumerable<string> xs) => IntentJs.SortedUtf8(xs.Distinct(StringComparer.Ordinal));

    static bool OperationOk(object? op) =>
        op is JD o && IntentArtifacts.IsBoundedString(IntentJs.Get(o, "verb"), 256) && IntentJs.Get(o, "resource") is string && IntentJs.Get(o, "params") is JD;

    static bool ObservationOk(object? o) =>
        o is JD d && IntentJs.Get(d, "origin") is "tool" or "retrieval" or "web" && IntentArtifacts.IsBoundedString(IntentJs.Get(d, "source"), 256);

    sealed record Chain(bool Verified, string Context, List<string> Path, List<string> PrincipalTexts, string? Code = null, string? Reason = null);

    static Chain Bad(string code, string reason) => new(false, "agent", new(), new(), code, reason);

    /// <summary>Verify a bundle against the pins and the operation. A result with a code is a deny.</summary>
    static Chain VerifyChain(object? bundle, JD op, List<JD> pins)
    {
        var unverified = new Chain(false, "agent", new() { "unlabelled" }, new());
        if (bundle == null) return unverified;
        if (bundle is not JD b) return Bad("malformed_bundle", "the bundle must be an object");
        var m = IntentArtifacts.ClosedMembers(b, new[] { "v", "kind", "receipts" }, new[] { "contents" }, "bundle");
        if (m != null) return Bad("malformed_bundle", m);
        if (!IsOne(b["v"]) || !Equals(b["kind"], "pca-provenance")) return Bad("malformed_bundle", "the bundle must be {v: 1, kind: \"pca-provenance\"}");
        if (b["receipts"] is not JL rs || rs.Count == 0 || rs.Count > MaxReceipts) return Bad("malformed_bundle", $"the bundle must hold 1..{MaxReceipts} receipts");
        for (int i = 0; i < rs.Count; i++)
        {
            var e = ReceiptWireError(rs[i]);
            if (e != null) return Bad("malformed_bundle", $"receipt {i}: {e}");
        }
        var contentsV = b.ContainsKey("contents") ? b["contents"] : new JD();
        if (contentsV is not JD contents) return Bad("malformed_bundle", "'contents' must be an object");
        var receipts = rs.Cast<JD>().ToList();
        var first = receipts[0];
        for (int i = 0; i < receipts.Count; i++)
        {
            var r = receipts[i];
            if (IntentJs.NumOf(r["seq"]) != i) return Bad("broken_chain", $"receipt {i} has seq {IntentJs.Lng(r["seq"]).ToString(CultureInfo.InvariantCulture)}");
            if (!Equals(r["session"], first["session"]) || !Equals(r["mediator"], first["mediator"]) || !Equals(r["kid"], first["kid"]))
                return Bad("broken_chain", $"receipt {i} belongs to another session or mediator");
            if (i == 0 ? r["prev"] != null : !Equals(r["prev"], ReceiptRef(receipts[i - 1]))) return Bad("broken_chain", $"receipt {i} does not link to its predecessor");
            if (i > 0 && IntentJs.NumOf(r["issued_at"]) < IntentJs.NumOf(receipts[i - 1]["issued_at"])) return Bad("broken_chain", $"receipt {i} is older than its predecessor");
        }
        var last = receipts[^1];
        if (!Equals(last["origin"], "action") || !Equals(last["source"], op["verb"]) || !Equals(last["content_digest"], ActionDigest(op)))
            return Bad("unbound_action", "the last receipt is not the action receipt of this operation");
        var principalTexts = new List<string>();
        foreach (var k in IntentJs.JsKeys(contents.Keys))
        {
            var r = ContentKeyRe.IsMatch(k) && int.Parse(k, CultureInfo.InvariantCulture) < receipts.Count ? receipts[int.Parse(k, CultureInfo.InvariantCulture)] : null;
            if (r == null || !Equals(r["origin"], "principal")) return Bad("malformed_bundle", $"contents '{k}' does not name a principal receipt");
            if (contents[k] is not string text || IntentJs.U8Len(text) > MaxContentBytes) return Bad("malformed_bundle", $"contents '{k}' must be a string of at most {MaxContentBytes} bytes");
            string d;
            try { d = Pca.HashCanonical(text); }
            catch (Exception) { return Bad("content_mismatch", $"contents '{k}' is not canonical text"); }
            if (!Equals(d, r["content_digest"])) return Bad("content_mismatch", $"contents '{k}' does not hash to its receipt");
            principalTexts.Add(text);
        }
        var pin = pins.FirstOrDefault(p => Equals(p["mediator"], first["mediator"]) && Equals(p["kid"], first["kid"]));
        // a chain from a mediator this verifier does not pin vouches for nothing: every value stays at the top (escalate, never allow)
        if (pin == null) return unverified;
        for (int i = 0; i < receipts.Count; i++)
            if (!IntentArtifacts.VerifyArtifactSig(ReceiptDomain, receipts[i], pin["pk"], IntentJs.Get(pin, "pq_pk")))
                return Bad("bad_signature", $"receipt {i} does not verify under the pinned mediator key");
        var before = receipts.Take(receipts.Count - 1).Where(r => !Equals(r["origin"], "action")).ToList();
        var context = before.Count == 0 ? "agent" : "trusted";
        var path = new List<string>();
        foreach (var r in before)
        {
            var origin = (string)r["origin"]!;
            context = Join(context, OriginLevel(origin));
            if (origin != "principal") path.Add($"{origin}:{(string)r["source"]!}");
        }
        if (before.Count == 0) path.Add("unlabelled");
        return new Chain(true, context, SortU(path), principalTexts);
    }

    /// <summary>The provenance decision for one operation. Steps, first failure wins:
    /// 0. inputs (pins, operation, action facts, observations) well-formed, else deny (malformed_config / malformed_operation / malformed_action);
    /// 1. the bundle when present: wire, chain (contiguous seq, prev links, one session and mediator, non-decreasing issued_at), the last
    ///    receipt is the action receipt of this operation, every principal content hashes to its receipt, every signature verifies under the
    ///    pinned (mediator, kid): a failure is deny; an unpinned mediator is ignored (unverified). context = join of the non-action segments
    ///    before the action (agent when none or unverified);
    /// 2. observations join into context (raise only); 3. control = trusted with a principal plan or principal control, else context;
    /// 4. each top-level parameter: trusted under a principal plan; else the join over its leaves (a leaf is trusted when the context is
    ///    trusted or it occurs as a token in a verified principal content, else context); no leaves = trusted; too large = context;
    /// 5. floors: the action facts' params[p], else first_party when sensitive and agent otherwise; above the floor = tainted;
    /// 6. a sensitive action whose control is not trusted, or any tainted parameter, is escalate; otherwise pass. Never throws.</summary>
    public static ArgProvenanceDecision Decide(ArgProvenanceInput? input)
    {
        bool sensitive = true, verified = false;
        string control = "agent";
        IReadOnlyDictionary<string, string> labels = new Dictionary<string, string>();
        IReadOnlyList<string> tainted = Array.Empty<string>(), path = Array.Empty<string>();
        ArgProvenanceDecision Deny(string code, string reason) => new("deny", code, reason, sensitive, verified, control, labels, tainted, path);
        try
        {
            if (input == null) return Deny("malformed_config", "input must be an object");
            if (input.Mediators is not JL pinList || !pinList.All(IsMediatorPin)) return Deny("malformed_config", "mediator pins must be a list of {mediator, kid, pk, pq_pk?}");
            if (!OperationOk(input.Operation)) return Deny("malformed_operation", "the operation needs a verb, a resource and a params object");
            var op = (JD)input.Operation!;
            if (input.Action != null)
            {
                var e = ActionInfoError(input.Action);
                if (e != null) return Deny("malformed_action", e);
            }
            var obs = input.Observed ?? new JL();
            if (obs is not JL obsList || !obsList.All(ObservationOk)) return Deny("malformed_config", "observations must be a list of {origin, source}");
            sensitive = !IsReadOnlyAction(input.Action);
            var ch = VerifyChain(input.Bundle, op, pinList.Cast<JD>().ToList());
            if (ch.Code != null) return Deny(ch.Code, ch.Reason!);
            verified = ch.Verified;
            var context = ch.Context;
            var p = new List<string>(ch.Path);
            foreach (JD o in obsList)
            {
                context = Join(context, OriginLevel((string)o["origin"]!));
                p.Add($"{(string)o["origin"]!}:{(string)o["source"]!}");
            }
            path = SortU(p);
            bool plan = input.PrincipalPlan;
            control = plan || input.PrincipalControl ? "trusted" : context;
            var prms = (JD)op["params"]!;
            var lab = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var name in SortU(prms.Keys))
            {
                if (plan) { lab[name] = "trusted"; continue; }
                var leaves = Leaves(prms[name]);
                if (leaves == null) { lab[name] = context; continue; }
                var l = "trusted";
                // a leaf the principal typed verbatim is the principal's choice whatever else the context held
                foreach (var leaf in leaves) l = Join(l, context == "trusted" || ch.PrincipalTexts.Any(t => OccursAsToken(t, leaf)) ? "trusted" : context);
                lab[name] = l;
            }
            labels = lab;
            var floors = IntentJs.Get(input.Action, "params") as JD ?? new JD();
            var t = new List<string>();
            foreach (var (name, label) in lab)
            {
                var f = floors.TryGetValue(name, out var fv) && fv is string fs ? fs : sensitive ? "first_party" : "agent";
                if (Rank(label) > Rank(f)) t.Add(name);
            }
            tainted = SortU(t);
            // no segment origin maps to first_party, so a control label is trusted or untrusted
            bool badControl = sensitive && control != "trusted";
            if (!badControl && tainted.Count == 0) return new("pass", null, null, sensitive, verified, control, labels, tainted, path);
            var where = path.Count > 0 ? $" [{string.Join(", ", path)}]" : "";
            var code = badControl && tainted.Count > 0 ? "untrusted_control_and_args" : badControl ? "untrusted_control" : "untrusted_args";
            var parts = new List<string>();
            if (badControl) parts.Add($"the choice of {(string)op["verb"]!} derives from untrusted content");
            if (tainted.Count > 0) parts.Add($"{string.Join(", ", tainted)} {(tainted.Count == 1 ? "derives" : "derive")} from untrusted content");
            return new("escalate", code, $"{string.Join("; ", parts)}{where}: the principal must confirm (prompt-injection path)", sensitive, verified, control, labels, tainted, path);
        }
        catch (Exception e) { return Deny("malformed_config", "evaluation error (fail closed): " + e.GetType().Name); }
    }

    // ------------------------------------------------------------------------------------------------------------ request side

    /// <summary>The bundle a request presents: header <c>PCA-Provenance</c> (strict base64url of the JSON, strict parse), else the member
    /// <c>pca_provenance</c> of a JSON body (an unparsable body presents no bundle). A header that does not decode or parse is
    /// <c>Unreadable</c> (the gate then denies). Never throws.</summary>
    public static (object? Bundle, bool Unreadable) ReadBundle(string? header, string? body)
    {
        if (!string.IsNullOrEmpty(header))
        {
            var text = Pca.DecodePcaHeader(header);
            if (text == null) return (null, true);
            try { return (Pca.ParseStrict(text), false); }
            catch (Exception) { return (null, true); }
        }
        if (string.IsNullOrWhiteSpace(body)) return (null, false);
        try { return (Pca.ParseStrict(body) is JD env ? IntentJs.Get(env, BodyMember) : null, false); }
        catch (Exception) { return (null, false); }
    }

    /// <summary>The session id a bundle names (receipt 0), for <see cref="ArgProvenanceOptions.Observed"/>; null when none.</summary>
    public static string? BundleSession(object? bundle) =>
        IntentJs.Get(bundle, "receipts") is JL rs && rs.Count > 0 && IntentJs.Get(rs[0], "session") is string s ? s : null;

    /// <summary>The bundle for an operation that came straight from the principal (the application's own UI acting on the user's explicit
    /// input, no model in between): one principal segment holding the operation, then the action. Under a pinned recorder key the
    /// operation's choice and values are trusted.</summary>
    public static JD PrincipalDirect(ProvenanceRecorder recorder, string verb, string resource, object? parameters)
    {
        var prms = Pca.OperationParamsTree(parameters ?? new JD()) ?? throw new ArgumentException("PrincipalDirect: params must be a JSON object");
        recorder.Principal(Pca.Canonicalize(new JD { ["verb"] = verb, ["resource"] = resource, ["params"] = prms }));
        return recorder.ForAction(verb, resource, prms);
    }
}

/// <summary>
/// The mediator side (the client half): one recorder per agent session. It must run where the bytes enter the model's context (the
/// harness that builds the prompt, a gateway, an MCP client), with a key the model cannot reach. Each call appends one signed receipt;
/// <see cref="ForAction"/> records the chosen action and returns the bundle to present with it (header <c>PCA-Provenance</c> or body
/// member <c>pca_provenance</c>). The verifier pins <see cref="Pin"/> (or the principal names it in the grant envelope).
/// </summary>
public sealed class ProvenanceRecorder
{
    readonly string _mediator, _kid;
    readonly SuiteKey _signer;
    readonly Func<long> _now;
    readonly List<JD> _chain = new();
    readonly JD _contents = new();
    readonly object _lock = new();

    /// <summary>The b64u 32-byte session id.</summary>
    public string Session { get; }
    /// <summary>The pin a verifier (or the principal's grant envelope) must carry for this recorder.</summary>
    public ProvMediatorPin Pin { get; }

    /// <param name="mediator">Mediator name (1..256 UTF-8 bytes).</param>
    /// <param name="kid">Key id (1..64 bytes).</param>
    /// <param name="signer">The mediator key (an Ed25519 identity, optionally a PQ / hybrid suite). Generated when null (then pin <see cref="Pin"/>).</param>
    /// <param name="session">b64u of 32 bytes (random when null).</param>
    /// <param name="now">Epoch ms clock (default: the wall clock).</param>
    public ProvenanceRecorder(string mediator, string kid, SuiteKey? signer = null, string? session = null, Func<long>? now = null)
    {
        if (!IntentArtifacts.IsBoundedString(mediator, 256) || !IntentArtifacts.IsBoundedString(kid, 64))
            throw new ArgumentException("ProvenanceRecorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required");
        _signer = signer ?? SuiteKey.Ed25519(EdKey.Generate());
        if (_signer.Ed == null) throw new ArgumentException("ProvenanceRecorder: the mediator key needs an Ed25519 identity");
        Session = session ?? Pca.B64u(RandomNumberGenerator.GetBytes(32));
        if (!IntentArtifacts.IsDigest(Session)) throw new ArgumentException("ProvenanceRecorder: session must be canonical base64url of 32 bytes");
        _mediator = mediator;
        _kid = kid;
        _now = now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        Pin = new ProvMediatorPin(mediator, kid, _signer.Ed.Id, _signer.PqPk);
    }

    static string Clip(string s) => IntentJs.U8Len(s) <= 256 ? (s.Length > 0 ? s : "-") : Clip(s.Substring(0, Math.Max(1, s.Length / 2)));

    static string TextOf(object? c)
    {
        if (c is string s) return s;
        try { return Pca.JsonText(c); }
        catch (Exception) { return c?.ToString() ?? "null"; }
    }

    JD Append(string origin, string source, string digest)
    {
        var prev = _chain.Count > 0 ? _chain[^1] : null;
        long issued = Math.Max(prev != null ? IntentJs.Lng(prev["issued_at"]) : 0L, _now());
        var body = new JD
        {
            ["v"] = 1L, ["kind"] = "pca-prov", ["mediator"] = _mediator, ["kid"] = _kid, ["session"] = Session, ["seq"] = (long)_chain.Count,
            ["prev"] = prev == null ? null : ArgProvenance.ReceiptRef(prev), ["origin"] = origin, ["source"] = Clip(source), ["content_digest"] = digest, ["issued_at"] = issued,
        };
        var r = Issue.SignArtifact(ArgProvenance.ReceiptDomain, body, _signer);
        _chain.Add(r);
        return new JD(r);
    }

    JD Segment(string origin, string source, object? content)
    {
        lock (_lock)
        {
            var text = TextOf(content);
            var r = Append(origin, source, Pca.HashCanonical(text));
            if (origin == "principal" && IntentJs.U8Len(text) <= ArgProvenance.MaxContentBytes) _contents[IntentJs.Lng(r["seq"]).ToString(CultureInfo.InvariantCulture)] = text;
            return r;
        }
    }

    /// <summary>The principal's own message (TRUSTED).</summary>
    public JD Principal(string text) => Segment("principal", "user", text);
    /// <summary>A tool result (UNTRUSTED). Non-string output is recorded as its canonical JSON text.</summary>
    public JD Tool(string name, object? output) => Segment("tool", name, output);
    /// <summary>A retrieved document (UNTRUSTED).</summary>
    public JD Retrieval(string source, object? content) => Segment("retrieval", source, content);
    /// <summary>A fetched web page or HTTP response (UNTRUSTED).</summary>
    public JD Web(string url, object? content) => Segment("web", url, content);

    /// <summary>Record the chosen action and return the bundle <c>{v: 1, kind: "pca-provenance", receipts, contents?}</c> to present with it.
    /// <paramref name="parameters"/> are read as the verifier reads the operation's params (null = {}). Throws when the session already
    /// holds 256 receipts (start a new session with the principal's message) or the params are not a JSON object.</summary>
    public JD ForAction(string verb, string resource, object? parameters)
    {
        lock (_lock)
        {
            if (_chain.Count >= ArgProvenance.MaxReceipts)
                throw new InvalidOperationException($"provenance: the session holds {ArgProvenance.MaxReceipts} receipts; start a new session with the principal's message");
            var prms = Pca.OperationParamsTree(parameters ?? new JD()) ?? throw new ArgumentException("ForAction: params must be a JSON object");
            Append("action", verb, ArgProvenance.ActionDigest(verb, resource, prms));
            var b = new JD { ["v"] = 1L, ["kind"] = "pca-provenance", ["receipts"] = _chain.Select(x => (object?)new JD(x)).ToList() };
            if (_contents.Count > 0) b["contents"] = new JD(_contents);
            return b;
        }
    }

    /// <summary>Every receipt so far (copies).</summary>
    public IReadOnlyList<JD> Receipts()
    {
        lock (_lock) return _chain.Select(x => new JD(x)).ToList();
    }

    /// <summary>The <c>PCA-Provenance</c> header value of a bundle: unpadded base64url of its canonical JSON.</summary>
    public static string HeaderValue(JD bundle) => Pca.B64u(System.Text.Encoding.UTF8.GetBytes(Pca.Canonicalize(bundle)));
}
