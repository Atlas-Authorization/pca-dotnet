// The approval half of natural-language policy authoring of the reference (nl.ts): the model's completion is parsed strictly and grounded in the catalog (IntentCompilers.NlPrompt / ParseNlPolicy), the draft is
// content-addressed and bound to the instruction, the model and the prompt, a reviewer signs it, and only a verified unexpired approval compiles into an agent. The model is an injected completion function: no model
// dependency is added. Drafts, approvals and results are the JSON tree in the reference's member names.
using System.Security.Cryptography;
using System.Text;
using AtlasPca.IntentPkg;
using AtlasPca.Js;
using AtlasPca.Research;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static class NlApproval
{
    public const string DomainV1 = "atlas-pca/nl-approval/v1\0";
    public const string DomainV2 = "atlas-pca/nl-approval/v2\0";
    public const int MaxOutputBytes = 16_384;
    public const double MaxApprovalTtlMs = 24 * 3_600_000;
    const double DefaultApprovalTtlMs = 3_600_000;

    /// <summary>The published constants of the module.</summary>
    public static D Constants() => new()
    {
        ["NL_APPROVAL_DOMAIN"] = DomainV1, ["NL_APPROVAL_DOMAIN_V2"] = DomainV2, ["MAX_NL_OUTPUT_BYTES"] = IntentJs.OfLong(MaxOutputBytes), ["MAX_NL_APPROVAL_TTL_MS"] = IntentJs.OfLong((long)MaxApprovalTtlMs),
    };

    static string HashLenient(object? v) => Pca.B64u(SHA256.HashData(Encoding.UTF8.GetBytes(JsCanon.Lenient(v) ?? throw new InvalidOperationException("canonicalize: non-finite number"))));

    /// <summary>The digest of the catalog an instruction was grounded in: sha256 over the lenient canonical rows <c>[verb, reversibility, amountField | null]</c> sorted by verb (not the catalog digest of the catalog module).</summary>
    public static string CatalogDigest(Catalog catalog)
    {
        var rows = catalog.All().Select(s => (object?)new L { s.Verb, s.Reversibility, s.AmountField is { } af ? af : null }).ToList();
        rows.Sort((a, b) => string.CompareOrdinal((string)((L)a!)[0]!, (string)((L)b!)[0]!));
        return HashLenient(new D { ["v"] = IntentJs.OfLong(1), ["rows"] = rows });
    }

    /// <summary>What a draft is bound to: <c>{instruction_digest, model, prompt_digest}</c>.</summary>
    public static D DraftBinding(string instruction, Catalog catalog, string? model = null) => new()
    {
        ["instruction_digest"] = HashLenient(new D { ["d"] = "atlas-pca/nl-instruction/v1", ["text"] = instruction }), ["model"] = model,
        ["prompt_digest"] = HashLenient(new D { ["d"] = "atlas-pca/nl-prompt/v1", ["text"] = IntentCompilers.NlPrompt(instruction, catalog) }),
    };

    static D SortedPermissions(object? permissions)
    {
        var p = permissions as D ?? throw new InvalidOperationException("permissions is not an object");
        var perms = new D();
        var keys = p.Keys.ToList();
        keys.Sort(string.CompareOrdinal);
        foreach (var c in keys)
        {
            var list = (p[c] as L ?? (p[c] is string chars ? chars.EnumerateRunes().Select(r => (object?)r.ToString()).ToList() : throw new InvalidOperationException("permissions value is not iterable"))).Select(x => JsJson.ToJsString(x)).ToList();
            list.Sort(string.CompareOrdinal);
            perms[c] = list.Cast<object?>().ToList();
        }
        return perms;
    }

    /// <summary>The v2 draft digest: permissions (connectors and actions sorted), limits, the catalog digest and the binding.</summary>
    public static string DraftDigestV2(object? permissions, object? limits, string catalogDigest, D binding) => HashLenient(new D
    {
        ["v"] = IntentJs.OfLong(2), ["permissions"] = SortedPermissions(permissions), ["limits"] = limits, ["catalog_digest"] = catalogDigest, ["instruction_digest"] = binding.GetValueOrDefault("instruction_digest"),
        ["model"] = binding.GetValueOrDefault("model"), ["prompt_digest"] = binding.GetValueOrDefault("prompt_digest"),
    });

    /// <summary>The v1 (legacy) draft digest, without a binding.</summary>
    public static string DraftDigest(object? permissions, object? limits, string catalogDigest) => HashLenient(new D
    {
        ["v"] = IntentJs.OfLong(1), ["permissions"] = SortedPermissions(permissions), ["limits"] = limits, ["catalog_digest"] = catalogDigest,
    });

    static L LintsOf(D permissions, D limits, Catalog catalog)
    {
        if (permissions.Count == 0) return new L();
        var lim = limits.ToDictionary(e => e.Key, e => (string)e.Value!);
        return PolicySim.LintPolicy(Facade.CompilePolicy(new PolicyOptions { Permissions = permissions, Limits = lim, Catalog = catalog, Now = 0 }), catalog);
    }

    /// <summary>The model's draft of an instruction: <c>{permissions, limits, unknownVerbs, droppedLimits, raw, lints}</c>. The completion is asked once with the grounding prompt; a throwing completion throws.</summary>
    public static D PolicyFromNL(string instruction, Func<string, string> complete, Catalog? catalog = null)
    {
        var cat = catalog ?? Catalog.Default;
        var raw = complete(IntentCompilers.NlPrompt(instruction, cat));
        var parsed = IntentCompilers.ParseNlPolicy(raw, cat);
        var lints = LintsOf((D)parsed["permissions"]!, (D)parsed["limits"]!, cat);
        return new D(parsed) { ["raw"] = raw, ["lints"] = lints };
    }

    /// <summary>The reviewable draft of an instruction: <c>{status: "draft", instruction, permissions, limits, catalog_digest, binding, digest, unknownVerbs, droppedLimits, lints, analyzerOk}</c>. A completion over
    /// 16384 UTF-8 bytes, or one that throws, throws.</summary>
    public static D DraftPolicyFromNL(string instruction, Func<string, string> complete, Catalog? catalog = null, string? model = null)
    {
        var cat = catalog ?? Catalog.Default;
        var raw = complete(IntentCompilers.NlPrompt(instruction, cat));
        if (Encoding.UTF8.GetByteCount(raw) > MaxOutputBytes) throw new InvalidOperationException($"draftPolicyFromNL: model output exceeds {MaxOutputBytes} bytes or is not a string");
        var p = IntentCompilers.ParseNlPolicy(raw, cat);
        var permissions = (D)p["permissions"]!;
        var lints = LintsOf(permissions, (D)p["limits"]!, cat);
        var cd = CatalogDigest(cat);
        var binding = DraftBinding(instruction, cat, model);
        return new D
        {
            ["status"] = "draft", ["instruction"] = instruction, ["permissions"] = permissions, ["limits"] = p["limits"], ["catalog_digest"] = cd, ["binding"] = binding,
            ["digest"] = DraftDigestV2(permissions, p["limits"], cd, binding), ["unknownVerbs"] = p["unknownVerbs"], ["droppedLimits"] = p["droppedLimits"], ["lints"] = lints,
            ["analyzerOk"] = permissions.Count > 0 && !lints.Any(l => ((D)l!)["level"] is "error"),
        };
    }

    static byte[] ApprovalMessage(D a)
    {
        var body = new D
        {
            ["v"] = a.GetValueOrDefault("v"), ["digest"] = a.GetValueOrDefault("digest"), ["catalog_digest"] = a.GetValueOrDefault("catalog_digest"), ["reviewer"] = a.GetValueOrDefault("reviewer"),
            ["approved_at"] = a.GetValueOrDefault("approved_at"), ["expires_at"] = a.GetValueOrDefault("expires_at"),
        };
        return [.. Encoding.UTF8.GetBytes(IntentJs.NumOf(a.GetValueOrDefault("v")) == 2 ? DomainV2 : DomainV1), .. Encoding.UTF8.GetBytes(JsCanon.Lenient(body) ?? throw new InvalidOperationException("canonicalize: non-finite number"))];
    }

    /// <summary>A reviewer's v2 approval of a draft: <c>{v: 2, digest, catalog_digest, reviewer, approved_at, expires_at, sig}</c>. The draft must have passed the static analyzer and proposed no unknown verb;
    /// <paramref name="ttlMs"/> defaults to one hour and may not exceed 24 hours. Throws otherwise.</summary>
    public static D ApproveDraft(D draft, byte[] reviewerSecret, double? now = null, double? ttlMs = null)
    {
        if (!AttestationSoft.Truthy(draft.GetValueOrDefault("analyzerOk"))) throw new InvalidOperationException("approveDraft: the draft did not pass the static analyzer");
        if (draft.GetValueOrDefault("unknownVerbs") is null) throw new InvalidOperationException("Cannot read properties of undefined (reading 'length')");
        if (draft.GetValueOrDefault("unknownVerbs") is L { Count: > 0 }) throw new InvalidOperationException("approveDraft: the draft proposed verbs that are not in the catalog");
        double n = now ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), ttl = ttlMs ?? DefaultApprovalTtlMs;
        if (!double.IsFinite(n) || !double.IsFinite(ttl) || ttl <= 0 || ttl > MaxApprovalTtlMs) throw new InvalidOperationException("approveDraft: invalid time or ttl");
        using var key = EdKey.FromSeed(reviewerSecret);
        var body = new D { ["v"] = IntentJs.OfLong(2), ["digest"] = draft.GetValueOrDefault("digest"), ["catalog_digest"] = draft.GetValueOrDefault("catalog_digest"), ["reviewer"] = key.Id, ["approved_at"] = Facade.JsNumber(n), ["expires_at"] = Facade.JsNumber(n + ttl) };
        return new D(body) { ["sig"] = Pca.B64u(key.Sign(ApprovalMessage(body))) };
    }

    /// <summary>The v1 (legacy) approval of a draft: its digest has no binding (see <see cref="ApproveDraft"/> for the checks).</summary>
    public static D ApproveDraftLegacyV1(D draft, byte[] reviewerSecret, double? now = null, double? ttlMs = null)
    {
        var v2 = ApproveDraft(draft, reviewerSecret, now, ttlMs);
        var body = new D
        {
            ["v"] = IntentJs.OfLong(1), ["digest"] = DraftDigest(draft.GetValueOrDefault("permissions"), draft.GetValueOrDefault("limits"), (string)draft["catalog_digest"]!), ["catalog_digest"] = draft["catalog_digest"],
            ["reviewer"] = v2["reviewer"], ["approved_at"] = v2["approved_at"], ["expires_at"] = v2["expires_at"],
        };
        using var key = EdKey.FromSeed(reviewerSecret);
        return new D(body) { ["sig"] = Pca.B64u(key.Sign(ApprovalMessage(body))) };
    }

    static D Fail(string reason) => new() { ["ok"] = false, ["reason"] = reason };

    static bool IsInt(object? n) => IntentJs.IsSafeInteger(n) && !IntentJs.IsNegZero(IntentJs.NumOf(n)!.Value);

    /// <summary>Load the policy of a draft only under a verified, unexpired approval of a pinned reviewer: <c>{ok: true, permissions, limits, reviewer, instruction, legacy_unbound_instruction}</c> or
    /// <c>{ok: false, reason}</c> with the rejection code (no_reviewers_pinned, not_a_draft, catalog_mismatch, tampered_draft, unknown_verbs, empty_permissions, analyzer_error, malformed_approval,
    /// digest_mismatch, reviewer_not_pinned, ttl_too_long, not_yet_valid, expired, bad_signature). <paramref name="reviewers"/> are the pinned reviewer keys; a v1 approval loads with
    /// <c>legacy_unbound_instruction: true</c>. Never throws.</summary>
    public static D LoadApprovedPolicy(object? draftO, object? approvalO, object? reviewers, Catalog? catalog = null, double? now = null)
    {
        try
        {
            var cat = catalog ?? Catalog.Default;
            double n = now ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (reviewers is not L { Count: > 0 } pinned) return Fail("no_reviewers_pinned");
            if (draftO is not D draft || draft.GetValueOrDefault("status") is not "draft" || draft.GetValueOrDefault("permissions") is not D permissions || draft.GetValueOrDefault("limits") is not (D or L)) return Fail("not_a_draft");
            object? limitsAny = draft.GetValueOrDefault("limits"); // typeof object: an array passes the shape check and fails the digest
            var cd = CatalogDigest(cat);
            if (!Equals(draft.GetValueOrDefault("catalog_digest"), cd)) return Fail("catalog_mismatch");
            if (draft.GetValueOrDefault("instruction") is not string instruction) return Fail("not_a_draft");
            bool legacyDraft = !draft.ContainsKey("binding");
            D? bindingD = null;
            if (!legacyDraft && (bindingD = draft["binding"] as D) == null) return Fail("not_a_draft");
            if (legacyDraft)
            {
                if (DraftDigest(permissions, limitsAny, cd) != draft.GetValueOrDefault("digest") as string) return Fail("tampered_draft");
            }
            else
            {
                var binding = DraftBinding(instruction, cat, bindingD!.GetValueOrDefault("model") as string);
                if (!Equals(bindingD.GetValueOrDefault("instruction_digest"), binding["instruction_digest"]) || !Equals(bindingD.GetValueOrDefault("prompt_digest"), binding["prompt_digest"]) || !Equals(bindingD.GetValueOrDefault("model"), binding["model"]))
                    return Fail("tampered_draft");
                if (DraftDigestV2(permissions, limitsAny, cd, binding) != draft.GetValueOrDefault("digest") as string) return Fail("tampered_draft");
            }
            if (limitsAny is not D limits) return Fail("malformed_approval");
            foreach (var (c, acts) in permissions)
                if (acts is not L al || al.Any(a => a is not string s || cat.Get(c + "." + s) == null)) return Fail("unknown_verbs");
            if (draft.GetValueOrDefault("unknownVerbs") is L { Count: > 0 }) return Fail("unknown_verbs");
            if (permissions.Count == 0) return Fail("empty_permissions");
            if (LintsOf(permissions, limits, cat).Any(l => ((D)l!)["level"] is "error")) return Fail("analyzer_error");
            if (approvalO is not D a || !(IntentJs.NumOf(a.GetValueOrDefault("v")) is 1 or 2) || a.GetValueOrDefault("sig") is not string sig || a.GetValueOrDefault("reviewer") is not string reviewer
                || a.GetValueOrDefault("digest") is not string digest || a.GetValueOrDefault("catalog_digest") is not string acd || !IsInt(a.GetValueOrDefault("approved_at")) || !IsInt(a.GetValueOrDefault("expires_at")))
                return Fail("malformed_approval");
            bool legacy = IntentJs.NumOf(a["v"]) == 1;
            if (legacyDraft && !legacy) return Fail("digest_mismatch");
            if (digest != (legacy ? DraftDigest(permissions, limits, cd) : draft.GetValueOrDefault("digest") as string) || acd != cd) return Fail("digest_mismatch");
            if (!pinned.Any(r => r is string rs && rs == reviewer)) return Fail("reviewer_not_pinned");
            double at = IntentJs.NumOf(a["approved_at"])!.Value, ex = IntentJs.NumOf(a["expires_at"])!.Value;
            if (ex - at <= 0 || ex - at > MaxApprovalTtlMs) return Fail("ttl_too_long");
            if (!(at <= n)) return Fail("not_yet_valid");
            if (!(n < ex)) return Fail("expired");
            if (!IntentJs.VerifyEd(reviewer, ApprovalMessage(a), sig)) return Fail("bad_signature");
            return new D { ["ok"] = true, ["permissions"] = permissions, ["limits"] = limits, ["reviewer"] = reviewer, ["instruction"] = instruction, ["legacy_unbound_instruction"] = legacy };
        }
        catch (Exception) { return Fail("malformed_approval"); }
    }

    /// <summary>An agent under an approved draft: the policy loads only as <see cref="LoadApprovedPolicy"/> allows (else this throws <c>agentFromApprovedNL: &lt;code&gt;</c>), and a v2 approval binds the agent's goal
    /// to the approved instruction (<c>goal_mismatch</c>). <paramref name="principal"/> signs the grant; the agent is minted with the loaded permissions and limits at <paramref name="now"/>.</summary>
    public static (AgentHandle Agent, string Reviewer, bool LegacyUnboundInstruction) AgentFromApprovedNL(D draft, D approval, object? reviewers, SuiteKey principal, string goal, Catalog? catalog = null, string? aud = null,
        SuiteKey? holder = null, double? now = null)
    {
        var loaded = LoadApprovedPolicy(draft, approval, reviewers, catalog, now);
        if (loaded["ok"] is not true) throw new InvalidOperationException($"agentFromApprovedNL: {loaded["reason"]}");
        bool legacy = loaded["legacy_unbound_instruction"] is true;
        if (!legacy && goal != (string)loaded["instruction"]!) throw new InvalidOperationException("agentFromApprovedNL: goal_mismatch");
        var a = Agent.FromPrincipal(new AgentOptions
        {
            Principal = principal, Goal = goal, Permissions = (D)loaded["permissions"]!, Limits = ((D)loaded["limits"]!).ToDictionary(e => e.Key, e => (string)e.Value!), Catalog = catalog, Aud = aud, Holder = holder,
            Now = now is double nn ? (long)nn : null,
        });
        return (a, (string)loaded["reviewer"]!, legacy);
    }
}
