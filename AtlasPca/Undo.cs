// UNDO WINDOWS (0.5), the pure layer: reversible actions execute at once and the principal gets a veto window in which they can
// undo them. Port of packages/pca/src/undo.ts (the language-neutral part); replays packages/pca/conformance/undo-vectors.json.
// Here: the compensation digest, the signed one-click undo token, the signed hash-chained audit receipts, the record state machine
// and the window clamp. Admission, the durable ledger, compensation and notification belong to the undo coordinator (the TypeScript
// coordinator or the hosted ledger); Authorize only takes its admission through AuthorizeInput.Undo.
//
//     open --veto (now <= window_end)--> vetoed --compensated--> compensated
//       |                                  |  \--compensation_failed--> compensation_failed --retry--> vetoed
//       |                                  |                                   \--compensated--> compensated
//       +--finalize (now > window_end)--> finalized
//       +--abort (the effect never ran)--> finalized
//
// Values are the parsed JSON tree (Dictionary<string, object?>, List<object?>, Num, string, bool, null). Every check is total.
using System.Globalization;
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The compensating action of an admission (what an undo runs).</summary>
public sealed record UndoCompensationRef(string Verb, string Resource);

/// <summary>What an undo coordinator returns when it admitted an escalated action under a veto window. The coordinator returns it
/// ONLY after the window's record is durably opened (the TypeScript coordinator or the hosted ledger).</summary>
public sealed record UndoAdmission(string Id, long WindowEnd, UndoCompensationRef Compensation);

/// <summary>The result of <see cref="UndoWindows.Transition"/>: <c>applied</c> (the next <see cref="Record"/>, version bumped, and the
/// receipt <see cref="Event"/> / <see cref="Note"/> the store layer signs), <c>replayed</c> (nothing to write) or <c>refused</c> (<see cref="Code"/>).</summary>
public sealed record UndoTransitionResult(string Outcome, string? Code = null, string? Reason = null, Dictionary<string, object?>? Record = null, string? Event = null, string? Note = null);

public static class UndoWindows
{
    public const string TokenDomain = "atlas-pca/undo-token/v1\0";
    public const string ReceiptDomain = "atlas-pca/undo-receipt/v1\0";
    public const string CompensationDomain = "atlas-pca/undo-compensation/v1";
    public const string ReceiptRefDomain = "atlas-pca/undo-receipt-ref/v1";
    public const string TokenRefDomain = "atlas-pca/undo-token-ref/v1";
    public const string TokenKind = "pca-undo-token";
    public const string ReceiptKind = "pca-undo-receipt";
    /// <summary>The realistic floor of a veto window: a human must be able to react.</summary>
    public const long MinWindowMs = 30_000;
    public const long DefaultWindowMs = 900_000;
    public const long MaxWindowMs = 86_400_000;
    public static readonly IReadOnlyList<string> States = new[] { "open", "vetoed", "compensated", "compensation_failed", "finalized" };
    public static readonly IReadOnlyList<string> Events = new[] { "opened", "vetoed", "compensated", "compensation_failed", "finalized", "aborted", "retried", "effect" };
    public static readonly IReadOnlyList<string> VetoVias = new[] { "token", "operator", "fraud_proof", "revocation" };
    static readonly string[] TokenMembers = { "v", "kind", "record", "aud", "principal", "compensation_digest", "render_digest", "exp", "signer", "sig" };
    const int IdMax = 256;

    /// <summary>A record id: a string of 1..256 UTF-16 code units without control characters (U+0000..U+001F).</summary>
    public static bool IdOk(object? s) => s is string x && x.Length > 0 && x.Length <= IdMax && !x.Any(c => c < ' ');
    static bool IsOne(object? v) => IntentJs.IsInt(v) && IntentJs.NumOf(v) == 1.0;
    static bool NumEq(object? a, object? b) => IntentJs.NumOf(a) is double x && IntentJs.NumOf(b) is double y && x == y;
    static byte[] DomainBytes(string domain, object? body) => IntentJs.Message(domain, body);
    static JD Without(JD o, string k) { var c = new JD(o); c.Remove(k); return c; }

    // ------------------------------------------------------------------------------------------------------------ digests

    /// <summary><c>hashCanonical({d, verb, resource, params, undo_of, def_digest, target_param?})</c> (target_param only when present).</summary>
    public static string CompensationDigest(Dictionary<string, object?> c)
    {
        var b = new JD
        {
            ["d"] = CompensationDomain, ["verb"] = IntentJs.Get(c, "verb"), ["resource"] = IntentJs.Get(c, "resource"), ["params"] = IntentJs.Get(c, "params"),
            ["undo_of"] = IntentJs.Get(c, "undo_of"), ["def_digest"] = IntentJs.Get(c, "def_digest"),
        };
        if (c.ContainsKey("target_param")) b["target_param"] = c["target_param"];
        return Pca.HashCanonical(b);
    }

    // ------------------------------------------------------------------------------------------------------------ the one-click undo token

    /// <summary>Sign the token for a record <c>{id, aud, principal, compensation_digest, render_digest?, window_end}</c> under the undo service
    /// key (a 32-byte Ed25519 seed): bound to the record, the compensation, the render ('' when none) and the window end (<c>exp</c>).</summary>
    public static JD SignToken(Dictionary<string, object?> record, byte[] seed)
    {
        if (seed is not { Length: 32 }) throw new ArgumentException("signer_missing: the undo service key must be a 32-byte Ed25519 secret");
        var key = EdKey.FromSeed(seed);
        var body = new JD
        {
            ["v"] = 1L, ["kind"] = TokenKind, ["record"] = IntentJs.Get(record, "id"), ["aud"] = IntentJs.Get(record, "aud"), ["principal"] = IntentJs.Get(record, "principal"),
            ["compensation_digest"] = IntentJs.Get(record, "compensation_digest"), ["render_digest"] = IntentJs.Get(record, "render_digest") ?? "",
            ["exp"] = IntentJs.Get(record, "window_end"), ["signer"] = key.Id,
        };
        var t = Issue.NormJ(body);
        t["sig"] = Pca.B64u(key.Sign(DomainBytes(TokenDomain, t)));
        return t;
    }

    /// <summary>The first check a token fails, in order: <c>malformed</c> (not exactly the 10 members, v, kind, record id, string members,
    /// safe-integer exp, canonical 64-byte sig), <c>signer</c> (not the pinned undo service key), <c>signature</c>, <c>record</c>,
    /// <c>binding</c> (aud, principal, compensation, render, exp vs window_end), <c>expired</c> (<paramref name="now"/> not a safe integer, or
    /// after exp: valid THROUGH exp inclusive); <c>ok</c> when none. Never throws.</summary>
    public static string TokenCheck(object? token, string expectedSigner, Dictionary<string, object?> record, object? now)
    {
        try
        {
            if (token is not JD t) return "malformed";
            if (t.Count != TokenMembers.Length || !TokenMembers.All(t.ContainsKey)) return "malformed";
            if (!IsOne(t["v"]) || !Equals(t["kind"], TokenKind) || !IdOk(t["record"]) || t["aud"] is not string || t["principal"] is not string
                || t["compensation_digest"] is not string || t["render_digest"] is not string || !IntentJs.IsInt(t["exp"]) || t["signer"] is not string
                || Pca.B64uDecode(t["sig"], 64) == null) return "malformed";
            if (!Equals(t["signer"], expectedSigner)) return "signer";
            if (!IntentJs.VerifyEd(expectedSigner, DomainBytes(TokenDomain, Without(t, "sig")), t["sig"])) return "signature";
            if (!Equals(t["record"], IntentJs.Get(record, "id"))) return "record";
            if (!Equals(t["aud"], IntentJs.Get(record, "aud")) || !Equals(t["principal"], IntentJs.Get(record, "principal"))
                || !Equals(t["compensation_digest"], IntentJs.Get(record, "compensation_digest")) || !Equals(t["render_digest"], IntentJs.Get(record, "render_digest") ?? "")
                || !NumEq(t["exp"], IntentJs.Get(record, "window_end"))) return "binding";
            if (!IntentJs.IsInt(now) || IntentJs.NumOf(now) > IntentJs.NumOf(t["exp"])) return "expired";
            return "ok";
        }
        catch (Exception) { return "malformed"; }
    }

    /// <summary>The token as a URL-safe string (base64url of its strict-canonical JSON) for a one-click link.</summary>
    public static string EncodeToken(Dictionary<string, object?> token) => Pca.B64u(Encoding.UTF8.GetBytes(Pca.Canonicalize(token)));

    /// <summary>Inverse of <see cref="EncodeToken"/>: a non-empty string of at most 4096 characters, strict base64url, well-formed UTF-8,
    /// a JSON object; null for anything else. Never throws.</summary>
    public static JD? DecodeToken(object? s)
    {
        try
        {
            if (s is not string str || str.Length == 0 || str.Length > 4096) return null;
            var b = Pca.B64uDecode(str);
            if (b == null) return null;
            var text = new UTF8Encoding(false, true).GetString(b);
            return Pca.ParseJson(text) as JD;
        }
        catch (Exception) { return null; }
    }

    /// <summary><c>hashCanonical({d: "atlas-pca/undo-token-ref/v1", t})</c>.</summary>
    public static string TokenDigest(Dictionary<string, object?> token) => Pca.HashCanonical(new JD { ["d"] = TokenRefDomain, ["t"] = token });

    // ------------------------------------------------------------------------------------------------------------ receipts

    /// <summary><c>hashCanonical({d: "atlas-pca/undo-receipt-ref/v1", r})</c> (the receipt WITH its signature).</summary>
    public static string ReceiptDigest(Dictionary<string, object?> receipt) => Pca.HashCanonical(new JD { ["d"] = ReceiptRefDomain, ["r"] = receipt });

    /// <summary>Sign a receipt body <c>{record, event, state, at, compensation_digest, prev, note}</c> under the undo service key.</summary>
    public static JD SignReceipt(Dictionary<string, object?> body, byte[] seed)
    {
        if (seed is not { Length: 32 }) throw new ArgumentException("signer_missing: the undo service key must be a 32-byte Ed25519 secret");
        var key = EdKey.FromSeed(seed);
        var b = new JD
        {
            ["v"] = 1L, ["kind"] = ReceiptKind, ["record"] = IntentJs.Get(body, "record"), ["event"] = IntentJs.Get(body, "event"), ["state"] = IntentJs.Get(body, "state"),
            ["at"] = IntentJs.Get(body, "at"), ["compensation_digest"] = IntentJs.Get(body, "compensation_digest"), ["prev"] = IntentJs.Get(body, "prev"),
            ["note"] = IntentJs.Get(body, "note"), ["signer"] = key.Id,
        };
        var r = Issue.NormJ(b);
        r["sig"] = Pca.B64u(key.Sign(DomainBytes(ReceiptDomain, r)));
        return r;
    }

    /// <summary>True iff <paramref name="receipt"/> has exactly the 11 members, a known event and state, a valid record id, a safe-integer
    /// <c>at</c>, string digests and note, <c>signer == expectedSigner</c>, a canonical 64-byte sig, and the Ed25519 signature verifies over
    /// exactly its content. Never throws.</summary>
    public static bool VerifyReceipt(object? receipt, string expectedSigner)
    {
        try
        {
            if (receipt is not JD x) return false;
            if (!IsOne(IntentJs.Get(x, "v")) || !Equals(IntentJs.Get(x, "kind"), ReceiptKind) || !IdOk(IntentJs.Get(x, "record"))
                || !(IntentJs.Get(x, "event") is string ev && Events.Contains(ev)) || !(IntentJs.Get(x, "state") is string st && States.Contains(st))
                || !IntentJs.IsInt(IntentJs.Get(x, "at")) || IntentJs.Get(x, "compensation_digest") is not string || IntentJs.Get(x, "prev") is not string
                || IntentJs.Get(x, "note") is not string || !Equals(IntentJs.Get(x, "signer"), expectedSigner) || Pca.B64uDecode(IntentJs.Get(x, "sig"), 64) == null) return false;
            if (x.Count != 11) return false;
            return IntentJs.VerifyEd(expectedSigner, DomainBytes(ReceiptDomain, Without(x, "sig")), x["sig"]);
        }
        catch (Exception) { return false; }
    }

    /// <summary>Verify a record's receipt chain (<paramref name="record"/>: <c>{id, compensation_digest, state, receipts}</c>): null iff every
    /// receipt verifies, names this record and its compensation, links <c>prev</c> to the previous one ('' for the first), the first is
    /// <c>opened</c>, <c>at</c> never goes back, and the last state is the record's state; else the reason. Never throws.</summary>
    public static string? ReceiptChainError(Dictionary<string, object?> record, string expectedSigner)
    {
        try
        {
            if (IntentJs.Get(record, "receipts") is not JL rs || rs.Count == 0) return "no receipts";
            var prev = "";
            double at = double.NegativeInfinity;
            for (int i = 0; i < rs.Count; i++)
            {
                if (!VerifyReceipt(rs[i], expectedSigner)) return $"receipt {i} does not verify";
                var r = (JD)rs[i]!;
                if (!Equals(r["record"], IntentJs.Get(record, "id")) || !Equals(r["compensation_digest"], IntentJs.Get(record, "compensation_digest"))) return $"receipt {i} is for another record";
                if (!Equals(r["prev"], prev)) return $"receipt {i} does not link to the previous one";
                if (i == 0 && !Equals(r["event"], "opened")) return "the first receipt is not opened";
                var t = IntentJs.NumOf(r["at"])!.Value;
                if (t < at) return $"receipt {i} goes back in time";
                prev = ReceiptDigest(r);
                at = t;
            }
            return Equals(((JD)rs[^1]!)["state"], IntentJs.Get(record, "state")) ? null : "the last receipt does not state the record state";
        }
        catch (Exception) { return "malformed receipt chain (fail closed)"; }
    }

    /// <summary>Append the signed receipt of an applied transition (linked to the previous one) to a copy of <paramref name="record"/>.</summary>
    public static JD WithReceipt(Dictionary<string, object?> record, string ev, string note, long at, byte[] seed)
    {
        var receipts = IntentJs.Get(record, "receipts") as JL ?? new JL();
        var last = receipts.Count > 0 ? (JD)receipts[^1]! : null;
        var receipt = SignReceipt(new JD
        {
            ["record"] = IntentJs.Get(record, "id"), ["event"] = ev, ["state"] = IntentJs.Get(record, "state"), ["at"] = at,
            ["compensation_digest"] = IntentJs.Get(record, "compensation_digest"), ["prev"] = last == null ? "" : ReceiptDigest(last), ["note"] = note,
        }, seed);
        return new JD(record) { ["receipts"] = new JL(receipts) { receipt } };
    }

    // ------------------------------------------------------------------------------------------------------------ the pure transitions

    static UndoTransitionResult Refused(string code, string reason) => new("refused", code, reason);
    // JavaScript String(x) for the JSON values an event can carry
    static string Text(object? ev, string k) => !IntentJs.Own(ev, k) ? "undefined" : IntentJs.Get(ev, k) switch
    {
        string s => s, null => "null", bool b => b ? "true" : "false", Num n => n.Raw, JD => "[object Object]",
        JL l => string.Join(",", l.Select(e => e == null ? "" : Text(new JD { ["x"] = e }, "x"))),
        var o => Convert.ToString(o, CultureInfo.InvariantCulture) ?? "",
    };
    static string Clip(string s, int n) => s.Length <= n ? s : s.Substring(0, n);

    /// <summary>The state machine, pure: <paramref name="record"/> is not modified; an applied transition returns the next record (version
    /// bumped, receipt NOT yet appended: the store layer signs and links it with <see cref="WithReceipt"/>). <paramref name="ev"/> is
    /// <c>{kind: veto (veto {at, via, by}) | finalize | abort (reason) | effect (result?) | compensated (result?) | compensation_failed (reason) | retry}</c>.
    /// <paramref name="now"/> is the trusted server clock. Total; never throws.</summary>
    public static UndoTransitionResult Transition(object? record, object? ev, object? now)
    {
        try
        {
            if (record is not JD rec || !(IntentJs.Get(rec, "state") is string state && States.Contains(state)) || !IntentJs.IsInt(IntentJs.Get(rec, "window_end")) || !IntentJs.IsInt(IntentJs.Get(rec, "ver")))
                return Refused("invalid", "malformed record");
            if (!IntentJs.IsInt(now)) return Refused("invalid", "now must be a safe integer");
            double n = IntentJs.NumOf(now)!.Value, end = IntentJs.NumOf(rec["window_end"])!.Value;
            long nowL = IntentJs.Lng(now);
            var windowEnd = IntentJs.Lng(rec["window_end"]).ToString(CultureInfo.InvariantCulture);
            UndoTransitionResult Next(JD patch, string evName, string note = "")
            {
                var next = (JD)IntentJs.Normalize(rec)!;
                foreach (var (pk, pv) in patch) next[pk] = pv;
                next["ver"] = IntentJs.OfLong(IntentJs.Lng(rec["ver"]) + 1);
                return new("applied", Record: next, Event: evName, Note: note);
            }
            var replayed = new UndoTransitionResult("replayed", Record: rec);
            bool effectPresent = rec.ContainsKey("effect");
            switch (IntentJs.Get(ev, "kind"))
            {
                case "veto":
                    {
                        var v = IntentJs.Get(ev, "veto");
                        if (v is not JD vd || !IntentJs.IsInt(IntentJs.Get(vd, "at")) || !(IntentJs.Get(vd, "via") is string via && VetoVias.Contains(via))
                            || !(IntentJs.Get(vd, "by") is string by && by.Length > 0)) return Refused("invalid", "malformed veto");
                        if (state is "vetoed" or "compensated" or "compensation_failed") return replayed;
                        if (state == "finalized") return Refused("finalized", "the window is closed and the action is final");
                        if (n > end) return Refused("window_closed", $"the veto window closed at {windowEnd}");
                        return Next(new JD { ["state"] = "vetoed", ["veto"] = IntentJs.Normalize(vd) }, "vetoed", via);
                    }
                case "finalize":
                    if (state == "finalized") return replayed;
                    if (state != "open") return Refused("vetoed", $"a {state} record is not finalized");
                    if (n <= end) return Refused("window_open", $"the veto window is open until {windowEnd}");
                    return Next(new JD { ["state"] = "finalized", ["outcome"] = new JD { ["at"] = IntentJs.OfLong(nowL), ["status"] = "finalized" } }, "finalized");
                case "abort":
                    {
                        if (state == "finalized" && IntentJs.Get(IntentJs.Get(rec, "outcome"), "status") is "aborted") return replayed;
                        if (state is not ("open" or "vetoed")) return Refused("finalized", $"a {state} record cannot be aborted");
                        if (effectPresent) return Refused("effect_recorded", "the effect ran: it can only be compensated or finalized");
                        var reason = Text(ev, "reason");
                        return Next(new JD { ["state"] = "finalized", ["outcome"] = new JD { ["at"] = IntentJs.OfLong(nowL), ["status"] = "aborted", ["reason"] = Clip(reason, 512) } }, "aborted", Clip(reason, 128));
                    }
                case "effect":
                    {
                        if (effectPresent) return replayed;
                        if (state is not ("open" or "vetoed")) return Refused("finalized", $"a {state} record takes no effect report");
                        var eff = new JD { ["at"] = IntentJs.OfLong(nowL) };
                        if (IntentJs.Own(ev, "result")) eff["result"] = IntentJs.Normalize(IntentJs.Get(ev, "result"));
                        return Next(new JD { ["effect"] = eff }, "effect");
                    }
                case "compensated":
                    {
                        if (state == "compensated") return replayed;
                        if (state is not ("vetoed" or "compensation_failed")) return Refused("not_vetoed", $"a {state} record is not being compensated");
                        var outcome = new JD { ["at"] = IntentJs.OfLong(nowL), ["status"] = "compensated" };
                        if (IntentJs.Own(ev, "result")) outcome["result"] = IntentJs.Normalize(IntentJs.Get(ev, "result"));
                        return Next(new JD { ["state"] = "compensated", ["outcome"] = outcome }, "compensated");
                    }
                case "compensation_failed":
                    {
                        if (state == "compensation_failed") return replayed;
                        if (state != "vetoed") return Refused("not_vetoed", $"a {state} record is not being compensated");
                        var reason = Text(ev, "reason");
                        return Next(new JD { ["state"] = "compensation_failed", ["outcome"] = new JD { ["at"] = IntentJs.OfLong(nowL), ["status"] = "compensation_failed", ["reason"] = Clip(reason, 512) } }, "compensation_failed", Clip(reason, 128));
                    }
                case "retry":
                    if (state != "compensation_failed") return Refused("not_failed", $"a {state} record is not retried");
                    // a record without a safe-integer attempt counter cannot be retried. The TypeScript reference applies the retry with a NaN
                    // attempt (serialized as null); refusing is the deliberate fail-closed divergence (no vector covers it).
                    if (!IntentJs.IsInt(IntentJs.Get(rec, "attempt"))) return Refused("invalid", "malformed record");
                    return Next(new JD { ["state"] = "vetoed", ["attempt"] = IntentJs.OfLong(IntentJs.Lng(rec["attempt"]) + 1) }, "retried");
                default:
                    return Refused("invalid", "unknown event");
            }
        }
        catch (Exception) { return Refused("invalid", "evaluation error (fail closed)"); }
    }

    // ------------------------------------------------------------------------------------------------------------ window and obligation

    /// <summary>Clamp a requested window into [max(30 000, minMs), min(maxMs, 86 400 000)] (a host maximum below the minimum is the minimum);
    /// an absent or non-finite request takes <paramref name="defaultMs"/> (900 000 when null). Floored to an integer.</summary>
    public static long ResolveWindow(object? requestedMs, double? minMs = null, double? maxMs = null, double? defaultMs = null)
    {
        double min = Math.Max(MinWindowMs, minMs ?? MinWindowMs);
        double max = Math.Max(min, Math.Min(maxMs ?? MaxWindowMs, MaxWindowMs));
        double want = IntentJs.NumOf(requestedMs) is double r && double.IsFinite(r) ? r : (defaultMs ?? DefaultWindowMs);
        return (long)Math.Floor(Math.Min(max, Math.Max(min, want)));
    }

    /// <summary>The <c>undo_window</c> obligation an allow under a veto window carries: <c>{kind, params: {id, window_end}, due: window_end}</c>.</summary>
    public static JD Obligation(UndoAdmission admission) => new()
    {
        ["kind"] = "undo_window",
        ["params"] = new JD { ["id"] = admission.Id, ["window_end"] = IntentJs.OfLong(admission.WindowEnd) },
        ["due"] = IntentJs.OfLong(admission.WindowEnd),
    };
}
