// The public constants and small pure helpers of the TypeScript core that this SDK carried only as private or inline literals, under the TS
// names in PascalCase: wire field sets, domains, limits, hash-suite agility and a few predicates. Where the SDK already exposes the same
// value under its own class (UndoWindows, PolicyClasses, Escalation, RevocationFreshness, PcaGrant, ReadSide) this file points at it, so there
// is one source of truth and a test (PcaConstantsTests) pins the literals.
using System.Security.Cryptography;
using System.Text;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>Public constants of the core packages.</summary>
public static partial class PcaConstants
{
    // ---- wire (wire.ts, pcactn.ts, replay.ts) ----
    public const int PcactnWireVersion = 2;
    public static IReadOnlyList<string> PcactnRequiredFields { get; } = new[]
    {
        "ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim", "aud", "iat", "exp", "sig",
    };
    public static IReadOnlyList<string> PcactnOptionalFields { get; } = new[]
    {
        "nonce", "caution", "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding", "threshold", "zk_compliance", "bond_ref",
        "alg", "pq_pk", "pq_sig",
    };
    /// <summary>Default PCActn lifetime (20 minutes; covers the 15-minute step-up window).</summary>
    public const long PcactnDefaultTtlMs = 20 * 60_000;
    public const long DefaultFreshnessEpochMs = 60_000;
    /// <summary>Minimum nonce retention: the longest action lifetime plus twice the allowed clock skew.</summary>
    public const long ReplayMinRetentionMs = Pca.MaxLifetimeMs + 2 * Pca.MaxSkewMs;
    /// <summary>The largest JSON document the strict parser reads (1 MiB).</summary>
    public const int MaxJsonBytes = 1 << 20;

    // ---- merkle (merkle.ts) ----
    public const string DefaultReversibilityClass = "reversible";
    public static string EmptyParamsDigest => Pca.ParamsDigest(null);

    // ---- caveat language (caveat-lang.ts) ----
    public const string CaveatNeedsDischarge = "needs_discharge", CaveatSealed = "sealed", CaveatMaxUses = "max_uses", CaveatDerive = "derive", CaveatSpiffeBound = "spiffe_bound";
    public const long K1MaxLifetimeMs = 86_400_000;

    // ---- verdict model roots (decision.ts) ----
    public static IReadOnlyList<string> ModelEnvRoots { get; } = new[] { "class", "prov", "judge", "detect" };

    // ---- chain compaction (chain-compact.ts) ----
    public const string ChainHopDomain = "atlas-pca/chain-hop/v1";
    public const long ChainMemoMaxTtlMs = 3_600_000;
    public const int ChainMemoDefaultMaxEntries = 10_000;

    // ---- detector receipts (detector-receipt.ts) ----
    public const string DetectorReceiptDomain = "atlas-pca/detector-receipt/v1\0";
    public const string DetectorReceiptRefDomain = "atlas-pca/detector-receipt-ref/v1";
    public static IReadOnlyList<string> DetectorVerdicts { get; } = new[] { "suspicious", "no_finding" };
    public const int MaxDetectorReceipts = 32;

    // ---- escalation (escalation.ts) ----
    public const string EscalationPolicyDomain = "atlas-pca/escalation-policy/v1";
    public const string EscalationActionDomain = "atlas-pca/escalation-action/v1";
    public const string EscalationHistoryDomain = "atlas-pca/escalation-history/v1";
    public const long EscalationMaxLifetimeMs = 86_400_000;

    // ---- forbid certificate, fresh-at, read side, workflow (forbid-certificate.ts, fresh-at.ts, readside.ts, workflow.ts) ----
    public const int ForbidCertVersion = 1;
    public const string ForbidCertKind = "forbid-wins";
    public const string FreshAtRefDomain = "atlas-pca/fresh-at-ref/v1";
    public const string ReadGrantDomain = "atlas-pca/read-grant/v1\0";
    public const string ReadReceiptDomain = "atlas-pca/read-receipt/v1\0";
    public const string WfReceiptDomain = "atlas-pca/wf-receipt/v1\0";
    public static IReadOnlyDictionary<string, int> WorkflowLimits { get; } =
        new Dictionary<string, int> { ["steps"] = 64, ["edges"] = 256, ["deps"] = 16, ["labels"] = 16, ["fields"] = 32, ["cost"] = 8, ["id"] = 64 };

    // ---- approvals (approval-render.ts) ----
    public const string ApprovalRenderDomain = "atlas-pca/approval-render/v1";
    public const string ApprovalChallengeDomain = "atlas-pca/approval-challenge/v1\0";
    public const string ApprovalRenderKind = "pca-approval-render";
    public const int MaxRenderFields = 64;

    // ---- argument provenance (arg-provenance.ts) ----
    public const string ProvReceiptDomain = "atlas-pca/prov-receipt/v1\0";
    public const string ProvReceiptRefDomain = "atlas-pca/prov-receipt-ref/v1";
    public const string ProvActionDomain = "atlas-pca/prov-action/v1";
    public const int MaxProvReceipts = 256;
    public const int MaxProvContentBytes = 65_536;
    public const int MaxProvLeaves = 4096;
    public static IReadOnlyList<string> ProvOrigins { get; } = new[] { "principal", "tool", "retrieval", "web", "action" };

    // ---- authorization details / need / templates ----
    public const string PcaGrantDomain = "atlas-pca/pca-grant-chain/v1";
    public const int PcaGrantMaxDetails = 16;
    public const int PcaGrantMaxChainLen = 16;
    public const string PcaNeedParam = "pca_need";
    public const string PcaNeedDomain = "atlas-pca/need/v1";
    public const int PcaNeedMaxEncoded = 2048;
    public const string TemplateKind = "pca-policy-template";
    public const string TightenKind = "pca-template-tighten";
    public const int MaxSlots = 32;
    public const int MaxSlotString = 256;
    public const int MaxSlotSet = 64;
    public static int MaxPolicyClasses => PolicyClasses.Classes.Length;

    // ---- regex budget (regex-budget.ts, regex-cache.ts) ----
    public const int RegexRequestScale = 4;
    public const int RegexCacheMaxEntries = 512;

    // ---- revocation (revocation.ts) ----
    public const long RevocationEpochRefreshMs = 60_000;
    public const long RevocationEpochValidityMs = 5 * 60_000;
    public const long RevocationIrreversibleMaxAgeMs = 2 * RevocationEpochRefreshMs;

    // ---- threshold (threshold.ts) ----
    public const string AgentLeafShareBindingVersion = "2.1";
}

/// <summary>Hash-suite agility (hash.ts): sha256 is the default and the only suite of the existing corpus; sha384 is an optional stronger-margin
/// variant that is never selected implicitly. Anything unknown must fail closed at the caller.</summary>
public static class HashSuites
{
    public const string DefaultHashSuite = "sha256";
    public static IReadOnlyDictionary<string, int> HashLen { get; } = new Dictionary<string, int> { ["sha256"] = 32, ["sha384"] = 48 };

    public static bool IsHashSuite(object? s) => s is "sha256" or "sha384";

    /// <summary>Hash raw bytes under <paramref name="suite"/> (sha256 by default, byte-identical to a bare SHA-256). Throws on an unknown suite.</summary>
    public static byte[] HashWithSuite(byte[] bytes, string suite = DefaultHashSuite) => suite switch
    {
        "sha256" => SHA256.HashData(bytes),
        "sha384" => SHA384.HashData(bytes),
        _ => throw new ArgumentOutOfRangeException(nameof(suite), $"unknown hash suite '{suite}'"),
    };

    /// <summary>base64url(H(strict canonical form of value)) under <paramref name="suite"/>.</summary>
    public static string HashCanonical(object? value, string suite = DefaultHashSuite) => Pca.B64u(HashWithSuite(Encoding.UTF8.GetBytes(Pca.Canonicalize(value)), suite));

    /// <summary>Encoded (unpadded base64url) length of <paramref name="n"/> bytes.</summary>
    public static int B64uLen(int n) => (n * 4 + 2) / 3;

    /// <summary>True iff <paramref name="s"/> is canonical base64url (optionally of an exact decoded byte length).</summary>
    public static bool IsCanonicalB64u(object? s, int? len = null) => Pca.B64uDecode(s, len) != null;

    /// <summary>STRICT base64url decode (alphabet only, no padding, canonical trailing bits, optional exact decoded length); null on any deviation. Never throws.</summary>
    public static byte[]? DecodeB64uStrict(object? s, int? len = null) => Pca.B64uDecode(s, len);

    /// <summary>The LENIENT canonical bytes: server-only digests that are never recomputed by another verifier (exponent forms and long floats allowed).
    /// Never feed a protocol digest. Null when the value has no lenient form.</summary>
    public static byte[]? CanonicalBytesLenient(object? value) => JsCanon.Lenient(value) is { } s ? Encoding.UTF8.GetBytes(s) : null;

    /// <summary>base64url(sha256(lenient canonical form)); server-only digests. Null when the value has no lenient form.</summary>
    public static string? HashCanonicalLenient(object? value) => CanonicalBytesLenient(value) is { } b ? Pca.B64u(SHA256.HashData(b)) : null;

    /// <summary>Encode a signature as unpadded base64url (a wire <c>sig</c>).</summary>
    public static string EncodeSig(byte[] sig) => Pca.B64u(sig);

    /// <summary>Decode a wire signature; throws <see cref="ArgumentException"/> on anything that is not canonical base64url.</summary>
    public static byte[] DecodeSig(string s) => Pca.B64uDecode(s) ?? throw new ArgumentException("decodeSig: not canonical base64url");
}

/// <summary>Small public predicates and builders of the core.</summary>
public static partial class PcaHelpers
{
    /// <summary>Meet (greatest lower bound) over a list of decisions; <c>allow</c> for the empty list.</summary>
    public static string MeetAll(IEnumerable<string?> decisions) => decisions.Aggregate(PcaDecision.Allow, (acc, d) => PcaDecision.Meet(acc, d));

    /// <summary>A predicate-condition group (<c>all_of</c> / <c>any_of</c> / <c>not</c>).</summary>
    public static bool IsGroupCondition(object? c) => c is JD d && (d.ContainsKey("all_of") || d.ContainsKey("any_of") || d.ContainsKey("not"));

    /// <summary>A leaf predicate condition: a plain object that is not a group and names a string <c>field</c>.</summary>
    public static bool IsLeafCondition(object? c) => c is JD d && !IsGroupCondition(d) && d.GetValueOrDefault("field") is string;

    /// <summary>A well-formed <c>budget_alloc</c> caveat: a finite non-negative <c>limit</c>.</summary>
    public static bool IsBudgetAllocCaveat(object? cv) =>
        cv is JD d && d.GetValueOrDefault("type") as string == "budget_alloc" && d.GetValueOrDefault("limit") is Num n
        && double.TryParse(n.Raw, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var lim) && double.IsFinite(lim) && lim >= 0; // typeof number, finite, >= 0 (no strict-profile limits)

    /// <summary>Open a goal commitment with the revealed (goal, salt).</summary>
    public static bool VerifyGoalCommit(string commit, string goal, string salt) => Issue.GoalCommit(goal, salt) == commit;

    /// <summary>The Merkle leaf of a plan node (<c>{id, verb, resource, params_digest?, reversibility_class?, pre?, post?}</c>).</summary>
    public static JD PlanNodeLeaf(JD node) =>
        Pca.PlanLeaf(node.GetValueOrDefault("id"), node, Pca.ConditionsDigest(node.GetValueOrDefault("pre"), node.GetValueOrDefault("post")))
        ?? throw new ArgumentException("planNodeLeaf: missing node id");

    /// <summary>The first <paramref name="n"/> UTF-16 units of <paramref name="s"/>, one fewer when the cut would split a surrogate pair.</summary>
    public static string ClipUnits(string s, int n)
    {
        var k = s.Length > n && n > 0 && char.IsHighSurrogate(s[n - 1]) && char.IsLowSurrogate(s[n]) ? n - 1 : n;
        return s[..Math.Max(0, Math.Min(k, s.Length))];
    }

    /// <summary>Validate a decoded <c>pca_need</c>: null when well formed, else the typed code (bad_shape, unknown_member, bad_version, bad_kind, bad_field).</summary>
    public static string? ValidatePcaNeed(object? need) => A2a.NeedError(need);

    /// <summary>Decode a <c>pca_need</c> value; never throws. Exactly one of the tuple members is set.</summary>
    public static (JD? Need, string? Code) DecodePcaNeed(object? value) => A2a.DecodeNeed(value);

    /// <summary>The content address an approval flow cites for a need.</summary>
    public static string PcaNeedDigest(JD need) => A2a.NeedDigest(need);
}
