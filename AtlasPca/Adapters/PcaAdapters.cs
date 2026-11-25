// Framework adapters, agent side: the framework-agnostic primitives every concrete AI-stack adapter is built from. Wrap a tool so each
// call produces a PCActn, attach it to the outbound request, record what enters the model's context (the principal's message is
// TRUSTED; tool results are UNTRUSTED) in the agent's provenance recorder, and fast-fail locally on an obvious deny.
//
// HONESTY: Guard is NOT the authorization. It builds a proof-carrying action, offers the agent's local non-authoritative dry run as a
// fast client-side reject, and hands the encoded PCActn to the caller's dispatch so the RESOURCE SERVER verifies and decides. A guard
// that is bypassed changes nothing: an action without a valid PCActn fails server-side.
using System.Runtime.CompilerServices;
using System.Text;
using AtlasPca.InteropJs;
using AtlasPca.Js;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Adapters;

/// <summary>Thrown by <see cref="PcaAdapters.Guard"/> when the agent's local dry run rejects a call before dispatch.</summary>
public sealed class PcaDenied(string reason, string verb, string resource) : Exception($"PCA denied {verb} on {resource}: {reason}")
{
    public string Reason { get; } = reason;
    public string Verb { get; } = verb;
    public string Resource { get; } = resource;
}

/// <summary>Thrown by <see cref="PcaAdapters.DecodePcaHeader"/> for a <c>PCA-Action</c> value that is not strict unpadded base64url of UTF-8 text.</summary>
public sealed class PcaHeaderError(string message) : Exception(message)
{
    public string Code { get; } = "invalid_pca_header";
}

/// <summary>What a guarded dispatch receives so it can carry the proof to the resource server.</summary>
/// <param name="PCActn">The signed action.</param>
/// <param name="Encoded">Its canonical JSON.</param>
/// <param name="Headers">Ready-to-send HTTP headers: <c>PCA-Action</c>, and <c>PCA-Provenance</c> when the bundle fits a header.</param>
/// <param name="Provenance">The provenance bundle of this action (send it as body member <c>pca_provenance</c> when it is not in <paramref name="Headers"/>).</param>
public sealed record PcaCall(D PCActn, string Encoded, IReadOnlyDictionary<string, string> Headers, D? Provenance);

/// <summary>A context segment a chat message adds: Origin is <c>principal</c> or <c>tool</c>.</summary>
public sealed record MessageSegment(string Origin, string Source, object? Content);

/// <summary>A framework-agnostic tool call: name and JSON-object arguments (OpenAI, Anthropic and LangChain all reduce to this).</summary>
public sealed record AgentToolCall(string Name, D Arguments);

/// <summary>How a framework tool is guarded: verb, resource derived from the call params, optional audience, and whether a failing local dry run refuses before dispatch (default true).</summary>
public sealed class GuardSpec
{
    public required string Verb { get; init; }
    public required Func<D, string> Resource { get; init; }
    public string? Aud { get; init; }
    public bool FailFast { get; init; } = true;
}

public static class PcaAdapters
{
    /// <summary>The header a resource server reads the PCActn from.</summary>
    public const string PcaHeader = "PCA-Action";
    /// <summary>The provenance header name.</summary>
    public const string ProvHeader = ArgProvenance.Header;
    /// <summary>Largest bundle carried as a header (base64url characters); a larger one goes in the request body as <c>pca_provenance</c>.</summary>
    public const int ProvHeaderMax = 8192;

    /// <summary><c>PCA-Provenance: base64url(canonical JSON)</c> for a bundle that fits <see cref="ProvHeaderMax"/>; empty otherwise (send it in the body).</summary>
    public static Dictionary<string, string> ProvenanceHeaders(object? bundle)
    {
        var h = new Dictionary<string, string>();
        if (bundle == null) return h;
        var v = Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(bundle)));
        if (v.Length <= ProvHeaderMax) h[ProvHeader] = v;
        return h;
    }

    /// <summary>Headers carrying an encoded PCActn (<c>PCA-Action</c>, base64url of its JSON) and its provenance bundle when it fits a header.</summary>
    public static Dictionary<string, string> PcaHeaders(string encoded, object? provenance = null)
    {
        var h = new Dictionary<string, string> { [PcaHeader] = Pca.B64u(Encoding.UTF8.GetBytes(encoded)) };
        foreach (var kv in ProvenanceHeaders(provenance)) h[kv.Key] = kv.Value;
        return h;
    }

    /// <summary>Reverse <see cref="PcaHeaders"/>: a <c>PCA-Action</c> value to the encoded PCActn JSON text, strictly (nothing is normalized). Throws <see cref="PcaHeaderError"/>.</summary>
    public static string DecodePcaHeader(string? value)
    {
        if (string.IsNullOrEmpty(value)) throw new PcaHeaderError("PCA-Action header is empty");
        if (Pca.B64uDecode(value) == null) throw new PcaHeaderError("PCA-Action header is not strict unpadded base64url");
        return Pca.DecodePcaHeader(value) ?? throw new PcaHeaderError("PCA-Action header does not decode to UTF-8 text");
    }

    /// <summary>Record the principal's own message in the agent's provenance chain (TRUSTED). Adapters call it for every user turn.</summary>
    public static void RecordPrincipal(AgentHandle? agent, string text) => agent?.Provenance.Principal(text);

    /// <summary>Record a tool result entering the model's context (UNTRUSTED). Adapters call it for every tool result they hand back.</summary>
    public static void RecordToolResult(AgentHandle? agent, string tool, object? output) => agent?.Provenance.Tool(tool, output);

    static readonly HashSet<string> PrincipalRoles = new() { "user", "human" };
    static readonly HashSet<string> ModelRoles = new() { "assistant", "ai", "model", "system", "developer" };

    // a JSON object (or array: no named members) read as a JavaScript property bag; absent and null both read as null (as `??` does)
    static object? Prop(object? o, string k) => o is D d && d.TryGetValue(k, out var v) ? v : null;
    static bool IsObj(object? o) => o is D || o is L;
    static string RoleOf(object? m) => Prop(m, "role") is string r ? r : Prop(m, "type") is string t ? t : "";

    // String(x.toolName ?? x.name ?? ... ?? 'tool')
    static string ToolName(object? x, object? msg)
    {
        foreach (var v in new[] { Prop(x, "toolName"), Prop(x, "name"), Prop(x, "tool_use_id"), Prop(x, "toolCallId"), Prop(x, "tool_call_id"), Prop(msg, "name"), Prop(msg, "tool_call_id") })
            if (v != null) return JsX.Str(v);
        return "tool";
    }

    /// <summary>The context segments a chat message adds, by the conversation's own roles: a user / human turn is the PRINCIPAL (its text,
    /// and its other parts); a <c>tool_result</c> / <c>tool-result</c> / <c>function_call_output</c> part inside any turn, a tool / function
    /// turn, and a turn of an unknown role are UNTRUSTED tool output; assistant / system / developer turns add nothing.</summary>
    public static List<MessageSegment> MessageSegments(object? m)
    {
        var res = new List<MessageSegment>();
        if (!IsObj(m)) return res;
        var role = RoleOf(m).ToLowerInvariant();
        if (ModelRoles.Contains(role)) return res;
        var content = Prop(m, "content");
        if (!PrincipalRoles.Contains(role)) { res.Add(new MessageSegment("tool", ToolName(m, m), content ?? m)); return res; }
        if (content is not L parts) { res.Add(new MessageSegment("principal", "user", content ?? "")); return res; }
        var text = new List<string>();
        foreach (var part in parts)
        {
            if (!IsObj(part)) { text.Add(JsX.Str(part)); continue; }
            var t = Prop(part, "type") is string ts ? ts : "";
            if (t is "tool_result" or "tool-result" or "function_call_output")
                res.Add(new MessageSegment("tool", ToolName(part, m), Prop(part, "content") ?? Prop(part, "result") ?? Prop(part, "output") ?? part));
            else if (Prop(part, "text") is string s) text.Add(s);
            else res.Add(new MessageSegment("principal", "user", part));
        }
        if (text.Count > 0) res.Insert(0, new MessageSegment("principal", "user", string.Join("\n", text)));
        return res;
    }

    sealed class Seen { public int N; }
    static readonly ConditionalWeakTable<ProvenanceRecorder, Seen> SeenMessages = new();

    /// <summary>Record a conversation's new messages in the agent's provenance chain (call it with the whole message list before each model
    /// turn; messages already recorded are skipped, a shorter list starts over). The framework adapters call it for you.</summary>
    public static void RecordMessages(AgentHandle? target, IReadOnlyList<object?>? messages) => RecordMessages(target?.Provenance, messages);

    /// <inheritdoc cref="RecordMessages(AgentHandle?, IReadOnlyList{object?}?)"/>
    public static void RecordMessages(ProvenanceRecorder? rec, IReadOnlyList<object?>? messages)
    {
        if (rec == null || messages == null) return;
        var seen = SeenMessages.GetOrCreateValue(rec);
        lock (seen)
        {
            var start = messages.Count < seen.N ? 0 : seen.N;
            for (int i = start; i < messages.Count; i++)
                foreach (var seg in MessageSegments(messages[i]))
                {
                    if (seg.Origin == "principal") rec.Principal(seg.Content as string ?? JsJson.Stringify(seg.Content));
                    else rec.Tool(seg.Source, seg.Content);
                }
            seen.N = messages.Count;
        }
    }

    /// <summary>Record what the principal asked for: a string is the principal's message; a message list (or <c>{messages}</c>) is recorded
    /// with <see cref="RecordMessages(ProvenanceRecorder?, IReadOnlyList{object?}?)"/>; an object's <c>input</c> / <c>prompt</c> / <c>query</c> /
    /// <c>question</c> / <c>message</c> / <c>text</c> string (or message list) is the principal's message. Anything else records nothing
    /// (the gate then keeps the context at <c>agent</c>: fail closed).</summary>
    public static void RecordInput(AgentHandle? target, object? input) => RecordInput(target?.Provenance, input);

    /// <inheritdoc cref="RecordInput(AgentHandle?, object?)"/>
    public static void RecordInput(ProvenanceRecorder? rec, object? input)
    {
        if (rec == null) return;
        if (input is string s) rec.Principal(s);
        else if (input is L l) RecordMessages(rec, l);
        else if (input is D o)
        {
            if (o.GetValueOrDefault("messages") is L ms) RecordMessages(rec, ms);
            foreach (var k in new[] { "input", "prompt", "query", "question", "message", "text" })
            {
                var v = o.GetValueOrDefault(k);
                if (v is string vs) rec.Principal(vs);
                else if (v is L vl) RecordMessages(rec, vl);
            }
        }
    }

    /// <summary>Wrap a framework entry point so its argument, the principal's request, is recorded before it runs.</summary>
    public static Func<TArg, TResult> WithPrincipalInput<TArg, TResult>(AgentHandle? target, Func<TArg, TResult> fn) =>
        arg => { RecordInput(target, arg); return fn(arg); };

    /// <summary>A provenance bundle from wherever a framework carried it: the bundle object itself, its JSON text, or a <c>PCA-Provenance</c>
    /// header value (base64url JSON). Null for anything else (the gate then treats the call as unlabelled: fail closed).</summary>
    public static object? ProvenanceFrom(object? v)
    {
        if (v == null) return null;
        if (IsObj(v)) return v;
        if (v is not string s || s.Length == 0) return null;
        try { return Pca.ParseStrict(s); }
        catch (Exception)
        {
            try { return Pca.DecodePcaHeader(s) is { } t ? Pca.ParseStrict(t) : null; }
            catch (Exception) { return null; }
        }
    }

    static PcaCall CallOf(ActResult r) => new(r.PCActn, r.Encoded, PcaHeaders(r.Encoded, r.Provenance), r.Provenance);

    /// <summary>Wrap a tool <c>run(params, pca)</c> so every invocation first builds a PCActn via <c>agent.Act</c>, optionally fast-fails on
    /// the local dry run (<see cref="PcaDenied"/>), then dispatches with the proof attached; what the tool returned is recorded as untrusted
    /// tool output. The returned function takes the params and optional per-call counter / issue time.</summary>
    public static Func<D, ActOptions?, Task<R>> Guard<R>(AgentHandle agent, GuardSpec spec, Func<D, PcaCall, Task<R>> run) =>
        async (prms, opts) =>
        {
            var resource = spec.Resource(prms);
            var r = agent.Act(spec.Verb, resource, prms, new ActOptions { Aud = spec.Aud, Counter = opts?.Counter, Now = opts?.Now });
            if (spec.FailFast && !r.DryRun.Allowed) throw new PcaDenied(r.DryRun.Reason ?? "denied", spec.Verb, resource);
            var output = await run(prms, CallOf(r)).ConfigureAwait(false);
            RecordToolResult(agent, spec.Verb, output); // what the tool returned enters the model's context: untrusted from here on
            return output;
        };

    /// <summary>Bridge a single framework tool call into a PCActn using a name to (verb, resource) mapping. Null when the mapping declines
    /// the call (an unmapped tool): the caller must then refuse to run it. The tool's result is not seen here; record it with
    /// <see cref="RecordToolResult"/>.</summary>
    public static PcaCall? BridgeToolCall(AgentHandle agent, AgentToolCall call, Func<AgentToolCall, (string Verb, string Resource)?> map, ActOptions? opts = null)
    {
        if (map(call) is not { } m) return null;
        return CallOf(agent.Act(m.Verb, m.Resource, call.Arguments, new ActOptions { Aud = opts?.Aud, Counter = opts?.Counter, Now = opts?.Now }));
    }
}
