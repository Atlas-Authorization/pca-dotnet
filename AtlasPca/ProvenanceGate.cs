// Build provenance as a K1 discharge (track K9): a port of packages/pca/src/provenance-gate.ts. The RFC 9162 inclusion check,
// the policy gates over the facts the cryptographic Sigstore check established (refusal codes, check order and reason strings
// are normative, shared through conformance/provenance-vectors.json), and the needs_discharge caveat a grant uses to ask an
// `artifact` verifier for the claims. Provenance can only remove authority.
// Values are the parsed JSON tree (Dictionary<string, object?>, List<object?>, Num, string, bool, null). Total: malformed input
// is false or a refusal code, never an exception.
using System.Security.Cryptography;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary><c>{ok: true, level, claims}</c> (claims in the reference's order) or <c>{ok: false, code}</c>.</summary>
public sealed record ProvenanceGateResult(bool Ok, long Level = 0, Dictionary<string, object?>? Claims = null, string? Code = null);

/// <summary>Options of <see cref="ProvenanceGate.ProvenanceCaveat"/>; null members take the reference default
/// (id <c>provenance</c>, require_runtime true, bind <c>action</c>, ttl 300 000 ms).</summary>
public sealed record ProvenanceCaveatOptions(
    string Issuer,
    long MinLevel,
    string? Id = null,
    string? SourceRepo = null,
    IReadOnlyList<string>? BuilderIds = null,
    string? OidcIssuer = null,
    bool? RequireRuntime = null,
    string? Bind = null,
    long? TtlMs = null);

public static class ProvenanceGate
{
    public const string SlsaProvenanceV1 = "https://slsa.dev/provenance/v1";
    public const string IntotoStatementV1 = "https://in-toto.io/Statement/v1";

    const long MaxSafe = 9_007_199_254_740_991;

    // ---- RFC 9162 inclusion ----

    /// <summary>RFC 9162 section 2.1.1: the hash of a leaf, SHA-256(0x00 || data).</summary>
    public static byte[] Rfc9162LeafHash(byte[] data)
    {
        var m = new byte[data.Length + 1];
        data.CopyTo(m, 1);
        return SHA256.HashData(m);
    }

    static byte[] NodeHash(byte[] l, byte[] r)
    {
        var m = new byte[65];
        m[0] = 1;
        l.CopyTo(m, 1);
        r.CopyTo(m, 33);
        return SHA256.HashData(m);
    }

    /// <summary>RFC 9162 section 2.1.3.2: verify an inclusion proof of <paramref name="leafHash"/> at <paramref name="index"/> in a
    /// tree of <paramref name="size"/> leaves with root <paramref name="root"/>. <paramref name="proof"/> runs from the leaf level
    /// up, without the leaf and the root. Index and size are non-negative safe integers (64-bit arithmetic). False on any
    /// malformed input.</summary>
    public static bool VerifyRfc9162Inclusion(byte[] leafHash, long index, long size, IReadOnlyList<byte[]> proof, byte[] root)
    {
        try
        {
            if (!(index >= 0 && size >= 1 && size <= MaxSafe && index < size)) return false;
            if (leafHash is not { Length: 32 } || root is not { Length: 32 }) return false;
            if (proof == null || proof.Count > 64 || proof.Any(p => p is not { Length: 32 })) return false;
            long fn = index, sn = size - 1;
            var r = leafHash;
            foreach (var p in proof)
            {
                if (sn == 0) return false;
                if ((fn & 1) == 1 || fn == sn)
                {
                    r = NodeHash(p, r);
                    if ((fn & 1) == 0)
                    {
                        while ((fn & 1) == 0 && fn != 0)
                        {
                            fn >>= 1;
                            sn >>= 1;
                        }
                    }
                }
                else r = NodeHash(r, p);
                fn >>= 1;
                sn >>= 1;
            }
            return sn == 0 && r.AsSpan().SequenceEqual(root);
        }
        catch (Exception) { return false; }
    }

    // ---- facts and policy ----

    /// <summary>A non-empty string of at most 2048 UTF-8 bytes.</summary>
    static bool Str(object? v) => IntentArtifacts.IsBoundedString(v, 2048);
    static string? Closed(JD o, string[] required, string[] optional, string where = "object") => IntentArtifacts.ClosedMembers(o, required, optional, where);
    static bool LowerHex(object? v, int n) => v is string s && s.Length == n && s.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    static bool IsLevel(object? v) => IntentJs.IsInt(v) && IntentJs.Lng(v) is >= 1 and <= 3;

    static bool SubjectError(object? s)
    {
        if (s is not JD d || Closed(d, new[] { "alg", "digest" }, Array.Empty<string>()) != null) return true;
        var n = d["alg"] switch { "sha256" => 64, "sha512" => 128, _ => -1 };
        return n < 0 || !LowerHex(d["digest"], n);
    }

    /// <summary>Null when well-formed (closed members, bounded strings), else the reference's reason.</summary>
    public static string? ProvenanceFactsError(object? fo)
    {
        if (fo is not JD f) return "facts must be an object";
        var e = Closed(f,
            new[] { "v", "predicate_type", "build_type", "builder_id", "subjects", "identity", "oidc_issuer", "integrated_time", "rekor_log_index" },
            new[] { "source_repo", "source_ref", "source_digest", "provenance_source" }, "facts");
        if (e != null) return e;
        if (!(IntentJs.IsInt(f["v"]) && IntentJs.Lng(f["v"]) == 1)) return "facts.v must be 1";
        foreach (var k in new[] { "predicate_type", "build_type", "builder_id", "identity", "oidc_issuer" }) if (!Str(f[k])) return $"facts.{k} must be a non-empty string";
        foreach (var k in new[] { "source_repo", "source_ref", "source_digest" }) if (f.ContainsKey(k) && !Str(f[k])) return $"facts.{k} must be a non-empty string";
        if (!(f["subjects"] is JL subs && subs.Count is >= 1 and <= 64 && !subs.Any(SubjectError))) return "facts.subjects must be 1..64 {alg, digest}";
        if (!IntentJs.IsNonNeg(f["integrated_time"])) return "facts.integrated_time must be a non-negative integer";
        if (!IntentJs.IsNonNeg(f["rekor_log_index"])) return "facts.rekor_log_index must be a non-negative integer";
        if (f.TryGetValue("provenance_source", out var po))
        {
            if (po is not JD p || Closed(p, new[] { "uri" }, new[] { "git_commit" }) != null || !Str(p["uri"]) || (p.TryGetValue("git_commit", out var gc) && !Str(gc)))
                return "facts.provenance_source is malformed";
        }
        return null;
    }

    /// <summary>Null when well-formed, else the reference's reason.</summary>
    public static string? ProvenancePolicyError(object? po)
    {
        if (po is not JD p) return "policy must be an object";
        var e = Closed(p, new[] { "roots", "min_level" }, new[] { "source_repo", "source_ref", "source_ref_prefix", "build_types", "max_age_s", "require_runtime" }, "policy");
        if (e != null) return e;
        if (!(p["roots"] is JL roots && roots.Count is >= 1 and <= 32)) return "policy.roots must hold 1..32 pairs";
        foreach (var ro in roots)
        {
            if (ro is not JD r || Closed(r, new[] { "oidc_issuer", "builder_id", "level" }, new[] { "identity", "identity_prefix" }) != null) return "policy root is malformed";
            if (!Str(r["oidc_issuer"]) || !Str(r["builder_id"])) return "policy root needs oidc_issuer and builder_id";
            if (r.ContainsKey("identity") == r.ContainsKey("identity_prefix")) return "policy root needs exactly one of identity and identity_prefix";
            if (r.TryGetValue("identity", out var id) && !Str(id)) return "policy root identity is malformed";
            // a prefix must at least name a scheme and a host (length in UTF-16 code units, as the reference counts it)
            if (r.TryGetValue("identity_prefix", out var pre) && !(Str(pre) && ((string)pre!).Length >= 10)) return "policy root identity_prefix must be at least 10 characters";
            if (!IsLevel(r["level"])) return "policy root level must be 1, 2 or 3";
        }
        if (!IsLevel(p["min_level"])) return "policy.min_level must be 1, 2 or 3";
        if (p.TryGetValue("source_repo", out var sr) && !Str(sr)) return "policy.source_repo is malformed";
        if (p.ContainsKey("source_ref") && p.ContainsKey("source_ref_prefix")) return "policy takes source_ref or source_ref_prefix, not both";
        if (p.TryGetValue("source_ref", out var sf) && !Str(sf)) return "policy.source_ref is malformed";
        if (p.TryGetValue("source_ref_prefix", out var sp) && !Str(sp)) return "policy.source_ref_prefix is malformed";
        if (p.TryGetValue("build_types", out var bt) && !(bt is JL b && b.Count is >= 1 and <= 16 && b.All(Str))) return "policy.build_types must hold 1..16 strings";
        if (p.TryGetValue("max_age_s", out var ma) && !(IntentJs.IsInt(ma) && IntentJs.Lng(ma) >= 1)) return "policy.max_age_s must be a positive integer";
        if (p.TryGetValue("require_runtime", out var rr) && rr is not bool) return "policy.require_runtime must be a boolean";
        return null;
    }

    // ---- the gate ----

    static ProvenanceGateResult No(string code) => new(false, Code: code);

    /// <summary>The provenance gates in the reference order over <c>{facts, policy, runtime?, now}</c>: policy, facts, clock, runtime
    /// digest, predicate type, time, a pinned signer-builder pair (the highest matching level), the level floor, the provenance's
    /// own source against the certificate's, the source repository and ref pins, the build type, then the subject. An absent
    /// member is absent; a JSON null is present (and malformed). Total.</summary>
    public static ProvenanceGateResult Gate(object? input)
    {
        try
        {
            if (input is not JD inp) return No("malformed_facts");
            if (ProvenancePolicyError(inp.GetValueOrDefault("policy")) != null) return No("malformed_policy");
            if (ProvenanceFactsError(inp.GetValueOrDefault("facts")) != null) return No("malformed_facts");
            var nowO = inp.GetValueOrDefault("now");
            if (!IntentJs.IsNonNeg(nowO)) return No("malformed_facts");
            long now = IntentJs.Lng(nowO);
            var f = (JD)inp["facts"]!;
            var p = (JD)inp["policy"]!;
            var hasRuntime = inp.TryGetValue("runtime", out var rt);
            if (hasRuntime && SubjectError(rt)) return No("malformed_runtime");
            if (f["predicate_type"] as string != SlsaProvenanceV1) return No("predicate_type");
            long it = IntentJs.Lng(f["integrated_time"]);
            if (it > now) return No("future");
            if (p.TryGetValue("max_age_s", out var ma) && now - it > IntentJs.Lng(ma)) return No("stale");
            var identity = (string)f["identity"]!;
            long level = 0;
            foreach (var ro in (JL)p["roots"]!)
            {
                var r = (JD)ro!;
                if ((string)r["oidc_issuer"]! != (string)f["oidc_issuer"]! || (string)r["builder_id"]! != (string)f["builder_id"]!) continue;
                if (r.TryGetValue("identity", out var id) ? (string)id! != identity : !identity.StartsWith((string)r["identity_prefix"]!, StringComparison.Ordinal)) continue;
                level = Math.Max(level, IntentJs.Lng(r["level"]));
            }
            if (level == 0) return No("no_root");
            if (level < IntentJs.Lng(p["min_level"])) return No("level");
            string? F(string k) => f.GetValueOrDefault(k) as string;
            if (f.TryGetValue("provenance_source", out var pso))
            {
                var ps = (JD)pso!;
                if (ps.GetValueOrDefault("git_commit") is string gc && F("source_digest") is string sd && gc != sd) return No("source_mismatch");
                if (F("source_repo") is string repo)
                {
                    var uri = (string)ps["uri"]!;
                    var b = "git+" + repo;
                    if (!(uri == b || uri.StartsWith(b + "@", StringComparison.Ordinal))) return No("source_mismatch");
                }
            }
            if (p.GetValueOrDefault("source_repo") is string pr && F("source_repo") != pr) return No("source_repo");
            if (p.GetValueOrDefault("source_ref") is string pf && F("source_ref") != pf) return No("source_ref");
            if (p.GetValueOrDefault("source_ref_prefix") is string pp && !(F("source_ref") is string fr && fr.StartsWith(pp, StringComparison.Ordinal))) return No("source_ref");
            if (p.GetValueOrDefault("build_types") is JL bts && !bts.Any(x => (string)x! == F("build_type"))) return No("build_type");
            var subjects = (JL)f["subjects"]!;
            JD subject;
            var bound = false;
            if (hasRuntime)
            {
                var r = (JD)rt!;
                var hit = subjects.Cast<JD>().FirstOrDefault(s => (string)s["alg"]! == (string)r["alg"]! && (string)s["digest"]! == (string)r["digest"]!);
                if (hit == null) return No("runtime_mismatch");
                subject = hit;
                bound = true;
            }
            else
            {
                if (p.GetValueOrDefault("require_runtime") is true) return No("runtime_required");
                if (subjects.Count != 1) return No("subject_ambiguous");
                subject = (JD)subjects[0]!;
            }
            var claims = new JD
            {
                ["subject_alg"] = subject["alg"],
                ["subject_digest"] = subject["digest"],
                ["slsa_level"] = level,
            };
            foreach (var k in new[] { "builder_id", "build_type", "oidc_issuer", "identity", "source_repo", "source_ref", "source_digest" })
                if (f.TryGetValue(k, out var v)) claims[k] = v;
            claims["rekor_log_index"] = IntentJs.Lng(f["rekor_log_index"]);
            claims["runtime_bound"] = bound;
            if (claims.Values.Any(v => v is string s && IntentJs.U8Len(s) > 256)) return No("claim_too_long");
            return new ProvenanceGateResult(true, level, claims);
        }
        catch (Exception) { return No("malformed_facts"); }
    }

    // ---- caveat ----

    static JD Req(string claim, string op, object? value) => new() { ["claim"] = claim, ["op"] = op, ["value"] = value };

    /// <summary>A <c>needs_discharge</c> caveat that asks the pinned <c>artifact</c> verifier for provenance claims.</summary>
    public static JD ProvenanceCaveat(ProvenanceCaveatOptions o)
    {
        var require = new JL { Req("slsa_level", "gte", o.MinLevel) };
        if (o.SourceRepo != null) require.Add(Req("source_repo", "eq", o.SourceRepo));
        if (o.BuilderIds != null) require.Add(Req("builder_id", "in", o.BuilderIds.Cast<object?>().ToList()));
        if (o.OidcIssuer != null) require.Add(Req("oidc_issuer", "eq", o.OidcIssuer));
        if (o.RequireRuntime != false) require.Add(Req("runtime_bound", "eq", true));
        return new JD
        {
            ["type"] = CaveatLang.NeedsDischarge,
            ["id"] = o.Id ?? "provenance",
            ["issuer"] = o.Issuer,
            ["issuer_class"] = "artifact",
            ["bind"] = o.Bind ?? "action",
            ["ttl_ms"] = o.TtlMs ?? 300_000L,
            ["require"] = require,
        };
    }
}
