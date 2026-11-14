using System.Security.Cryptography;
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>Signed per-action safety evidence of the prohibition plane: evidence that admitting ONE action preserves every invariant, re-derivable offline, and its signed, bound form
/// (the signature covers an id that commits to the signer and to the evidence, constitution, action and state digests, so it cannot be lifted onto another action, constitution or state).
/// Properties are read with JavaScript semantics (a missing or mistyped member is absent) and nothing here throws on a malformed record.</summary>
public static class SafetyEvidence
{
    public const long Version = 1;
    public const string SigDomain = "atlas-pca/safety-evidence/v1\0";
    public const string ConstitutionSigDomain = "atlas-pca/constitution/v1\0";
    const string Unhashable = "<unhashable>";

    static string Safe(Func<string> f) { try { return f(); } catch (Exception) { return Unhashable; } }
    static byte[] DomainMessage(string domain, string id) => Encoding.UTF8.GetBytes(domain).Concat(SHA256.HashData(Encoding.UTF8.GetBytes(id))).ToArray();
    static object? Get(object? o, string k) => o is JD d ? d.GetValueOrDefault(k) : null;

    /// <summary>The content id of a constitution body (without <c>id</c> and <c>sig</c>).</summary>
    public static string ConstitutionId(JD c) { var b = new JD(c); b.Remove("id"); b.Remove("sig"); return Pca.HashCanonical(b); }

    /// <summary>The principal signs a constitution: <c>{...body, id, sig}</c>, <c>sig</c> over the domain and <c>sha256(id)</c>. A malformed
    /// constitution is refused (authoring-time guard).</summary>
    public static JD SignConstitution(JD c, EdKey principal)
    {
        var n = Issue.NormJ(c);
        var problems = Prohibitions.ValidateConstitution(n);
        if (problems.Count > 0) throw new ArgumentException("signConstitution: " + string.Join("; ", problems));
        var id = ConstitutionId(n);
        var o = new JD(n); // an id or sig already there is overwritten
        o["id"] = id;
        o["sig"] = Pca.B64u(principal.Sign(DomainMessage(ConstitutionSigDomain, id)));
        return o;
    }

    /// <summary>Well formed, the id matches the content, signed by <paramref name="expectedPrincipal"/> (or the embedded one). Never throws.</summary>
    public static (bool Ok, string? Reason) VerifyConstitution(object? sc, string? expectedPrincipal = null) => VerifyConstitution(sc, expectedPrincipal != null, expectedPrincipal);

    /// <summary>The same with the pin given as any JSON value: a pinned value that is not a string (a number, null) matches no principal, so it refuses.</summary>
    internal static (bool Ok, string? Reason) VerifyConstitution(object? sc, bool pinned, object? expectedPrincipal)
    {
        try
        {
            var problems = Prohibitions.ValidateConstitution(sc);
            if (problems.Count > 0) return (false, problems[0]);
            var m = (JD)sc!;
            if (pinned && !Equals(m["principal"], expectedPrincipal)) return (false, "principal mismatch");
            if (m.GetValueOrDefault("id") is not string id || id != ConstitutionId(m)) return (false, "id does not match content");
            if (m.GetValueOrDefault("sig") is not string sig || !Pca.VerifyEdInternal((string)m["principal"]!, DomainMessage(ConstitutionSigDomain, id), sig)) return (false, "bad signature");
            return (true, null);
        }
        catch (Exception) { return (false, "verification error (fail closed)"); }
    }

    /// <summary>Builds the evidence a verifier re-checks. Anything that cannot be digested makes it <c>ok: false</c> with the structural id in <c>violated</c>. Never throws.</summary>
    public static JD Prove(object? action, JD? constitution, JD? state)
    {
        var r = Prohibitions.Check(action as Dictionary<string, object?>, constitution, state);
        var cid = Safe(() => ConstitutionId(constitution!));
        var adg = Safe(() => Pca.HashCanonical(action));
        var sdg = Safe(() => Prohibitions.StateDigest(state!));
        var extra = new List<string>();
        if (cid == Unhashable) extra.Add("<constitution>");
        if (adg == Unhashable) extra.Add("<action>");
        if (sdg == Unhashable) extra.Add("<state>");
        var rows = r.Evaluated.Select(e =>
        {
            var row = new JD { ["id"] = e.Id, ["kind"] = e.Kind, ["result"] = e.Result };
            if (e.Reason != null) row["reason"] = e.ReasonValue ?? e.Reason;
            return (object?)row;
        }).ToList();
        var violated = r.Violated.Concat(extra.Where(x => !r.Violated.Contains(x))).Select(v => (object?)v).ToList();
        return new JD
        {
            ["v"] = Version, ["constitution"] = cid, ["action_digest"] = adg, ["state_digest"] = sdg,
            ["now"] = state != null && IntentJs.NumOf(state.GetValueOrDefault("now")) is double n && double.IsFinite(n) ? state["now"] : 0L,
            ["evaluated"] = rows, ["ok"] = r.Ok && extra.Count == 0, ["violated"] = violated,
        };
    }

    /// <summary>Offline re-check: recompute the monitor and require the evidence to match EXACTLY, covering every invariant; forged "all clear" evidence is rejected. Never throws.</summary>
    public static (bool Ok, string? Reason) Verify(object? evidence, object? action, JD? constitution, JD? state)
    {
        try
        {
            if (evidence is not JD ev || !(IntentJs.NumOf(ev.GetValueOrDefault("v")) == Version)) return (false, "unsupported evidence version");
            var fresh = Prove(action, constitution, state);
            if (!Equals(fresh["constitution"], ev.GetValueOrDefault("constitution"))) return (false, "constitution mismatch");
            if (!Equals(fresh["action_digest"], ev.GetValueOrDefault("action_digest"))) return (false, "action digest mismatch");
            if (!Equals(fresh["state_digest"], ev.GetValueOrDefault("state_digest"))) return (false, "state digest mismatch");
            if (Pca.HashCanonical(fresh) != Pca.HashCanonical(ev)) return (false, "evidence does not reproduce");
            if (!(bool)fresh["ok"]!) return (false, "prohibition violated: " + string.Join(",", ((JL)fresh["violated"]!).Select(x => (string)x!)));
            return (true, null);
        }
        catch (Exception) { return (false, "verification error (fail closed)"); }
    }

    /// <summary>True when the constitution, the action and the state can all be digested (nothing is then <c>&lt;unhashable&gt;</c> in the evidence).</summary>
    internal static bool Attestable(object? action, object? constitution, JD? state) =>
        Safe(() => ConstitutionId((JD)constitution!)) != Unhashable && Safe(() => Pca.HashCanonical(action)) != Unhashable && Safe(() => Prohibitions.StateDigest(state!)) != Unhashable;

    /// <summary>The binding id: commits to the signer, the evidence digest and the three bound digests. Throws when evidence lacks a bound member (nothing to commit to).</summary>
    public static string BindingId(JD evidence, string signer)
    {
        foreach (var k in new[] { "constitution", "action_digest", "state_digest" })
            if (!evidence.ContainsKey(k)) throw new InvalidOperationException("canonicalize: unsupported type undefined");
        return BindingIdOf(evidence, signer);
    }

    static string BindingIdOf(JD evidence, string signer) => Pca.HashCanonical(new JD
    {
        ["d"] = SigDomain, ["signer"] = signer, ["evidence"] = Pca.HashCanonical(evidence), ["constitution"] = evidence.GetValueOrDefault("constitution"),
        ["action_digest"] = evidence.GetValueOrDefault("action_digest"), ["state_digest"] = evidence.GetValueOrDefault("state_digest"),
    });

    /// <summary>Signs evidence (Ed25519, domain separated); evidence whose action, constitution or state could not be digested is refused (nothing to bind).</summary>
    public static JD Sign(JD evidence, EdKey signer) => Sign(evidence, signer, signer.Id);

    /// <summary>The reference shape: <paramref name="signerPublic"/> is the id the binding commits to and the record names (it must be a non-empty string; it need not be the key's own).</summary>
    public static JD Sign(object? evidence, EdKey signer, object? signerPublic)
    {
        if (evidence is not JD ev || !(IntentJs.NumOf(ev.GetValueOrDefault("v")) == Version)) throw new ArgumentException("signSafetyEvidence: unsupported evidence");
        foreach (var k in new[] { "constitution", "action_digest", "state_digest" })
            if (ev.GetValueOrDefault(k) is not string { Length: > 0 } s || s == Unhashable) throw new ArgumentException("signSafetyEvidence: unbound evidence");
        if (signerPublic is not string { Length: > 0 } pub) throw new ArgumentException("signSafetyEvidence: signer missing");
        var id = BindingId(ev, pub);
        return new JD { ["evidence"] = ev, ["signer"] = pub, ["id"] = id, ["sig"] = Pca.B64u(signer.Sign(DomainMessage(SigDomain, id))) };
    }

    /// <summary>Verifies signed evidence offline against what the verifier already knows (<paramref name="expected"/>: <c>signer</c> (pinned key or list), <c>action</c> or <c>actionDigest</c>,
    /// <c>constitution</c> or <c>constitutionId</c>, <c>principal</c>, <c>state</c> or <c>stateDigest</c>, <c>requireOk</c>). Checks, in order: expectations present, signer pinned, binding id,
    /// signature, bindings to the expected action, constitution (which must itself be well formed) and state, internal consistency, full recomputation when all three are supplied.</summary>
    public static (bool Ok, string? Reason) VerifySigned(object? signed, object? expected)
    {
        (bool, string?) No(string r) => (false, r);
        try
        {
            if (signed is not JD sg || sg.GetValueOrDefault("evidence") is not JD ev || expected is not JD ex) return No("malformed input");
            if (!(IntentJs.NumOf(ev.GetValueOrDefault("v")) == Version)) return No("unsupported evidence version");
            var signersRaw = ex.GetValueOrDefault("signer");
            var signers = signersRaw is JL sl ? sl : new JL { signersRaw };
            if (signers.Count == 0 || signers.Any(s => s is not string { Length: > 0 })) return No("no pinned signer");
            if (sg.GetValueOrDefault("signer") is not string signer || !signers.Contains(signer)) return No("signer not trusted");
            bool has(string k) => ex.ContainsKey(k); // JS: present means not undefined (a JSON null counts)
            if (!has("action") && !has("actionDigest")) return No("unbound: action not specified");
            if (!has("constitution") && !has("constitutionId")) return No("unbound: constitution not specified");
            if (!has("state") && !has("stateDigest")) return No("unbound: state not specified");
            if (sg.GetValueOrDefault("id") is not string id || id != BindingId(ev, signer)) return No("binding id mismatch");
            if (sg.GetValueOrDefault("sig") is not string sig || !Pca.VerifyEdInternal(signer, DomainMessage(SigDomain, id), sig)) return No("bad signature");

            var wantAction = has("action") ? Pca.HashCanonical(ex["action"]) : ex["actionDigest"] as string;
            if (has("action") && has("actionDigest") && !Equals(ex["actionDigest"], wantAction)) return No("expected action and digest disagree");
            if (!Equals(ev.GetValueOrDefault("action_digest"), wantAction)) return No("action digest mismatch (evidence bound to another action)");

            if (has("principal"))
            {
                if (ex.GetValueOrDefault("constitution") is not JD sc || sc.GetValueOrDefault("sig") is not string) return No("principal pin requires a signed constitution");
                var vc = VerifyConstitution(sc, true, ex["principal"]);
                if (!vc.Ok) return No("constitution not authentic: " + vc.Reason);
            }
            var wantConst = has("constitution") ? ex["constitution"] is JD cd ? ConstitutionId(cd) : throw new InvalidOperationException("constitution is not an object") : ex["constitutionId"] as string;
            if (has("constitution") && has("constitutionId") && !Equals(ex["constitutionId"], wantConst)) return No("expected constitution and id disagree");
            if (!Equals(ev.GetValueOrDefault("constitution"), wantConst)) return No("constitution mismatch (evidence bound to another constitution)");
            // a malformed expected constitution never verifies: an invariant without a string id would otherwise "cover" an id-less row
            if (has("constitution"))
            {
                var cp = Prohibitions.ValidateConstitution(ex["constitution"]);
                if (cp.Count > 0) return No("constitution malformed: " + cp[0]);
            }
            var wantState = has("state") ? Prohibitions.StateDigest((JD)ex["state"]!) : ex["stateDigest"] as string;
            if (has("state") && has("stateDigest") && !Equals(ex["stateDigest"], wantState)) return No("expected state and digest disagree");
            if (!Equals(ev.GetValueOrDefault("state_digest"), wantState)) return No("state digest mismatch (evidence bound to another state)");

            if (ev.GetValueOrDefault("evaluated") is not JL rows || ev.GetValueOrDefault("violated") is not JL violated) return No("malformed evidence");
            if (rows.Any(r => r is JD rd && rd.ContainsKey("id") && rd["id"] is not string)) return No("malformed evidence");
            var badRows = rows.Where(r => !Equals(Get(r, "result"), "pass")).Select(r => Get(r, "id")).ToList();
            var claimedOk = ev.GetValueOrDefault("ok") is true;
            if (ev.GetValueOrDefault("ok") is not bool || claimedOk != (badRows.Count == 0 && violated.Count == 0)) return No("evidence verdict inconsistent with rows");

            if (has("action") && has("constitution") && has("state"))
            {
                var full = Verify(ev, ex["action"], (JD)ex["constitution"]!, (JD)ex["state"]!);
                if (!full.Ok && claimedOk) return No(full.Reason ?? "evidence does not reproduce");
                if (!full.Ok && !claimedOk && full.Reason != null && !full.Reason.StartsWith("prohibition violated", StringComparison.Ordinal)) return No(full.Reason);
            }
            else if (claimedOk && has("constitution"))
            {
                var ids = ((JL)((JD)ex["constitution"]!)["invariants"]!).Select(i => Get(i, "id")).ToList();
                if (rows.Count != ids.Count || rows.Where((r, i) => !Equals(Get(r, "id"), ids[i])).Any()) return No("evidence does not cover every invariant");
            }
            if (!(ex.ContainsKey("requireOk") && ex["requireOk"] is false) && !claimedOk) return No("prohibition violated: " + string.Join(",", violated.Select(v => v == null ? "" : Prohibitions.JsString(v))));
            return (true, null);
        }
        catch (Exception) { return No("verification error (fail closed)"); }
    }

}
