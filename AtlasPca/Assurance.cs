// Assurance labels (T8, B7). A check's status ("pass", "fail", "not-enforced", "unsupported") says WHETHER it held; the assurance report
// says WHAT a pass rests on: software or hardware attestation, a SNARK proof or an attested-VM statement, a post-quantum or an Ed25519
// signature, independent multisig shares or a FROST (preview) aggregate. It also names the features this verifier does not implement
// ("unsupported": a bond reference), which are reported and never count as a pass.
//
// Labels come from the VERIFIER'S configuration, never from the presented evidence: a hook or verifier carries its label (it implements
// IAssuranceLabeled, or is labelled with AssuranceLabels.Set); an unlabelled one is "unknown" and satisfies no requirement. A
// requirement (AssuranceRequirement) turns the report into a gate: when the evidence is weaker, missing, failed, unlabelled, preview,
// degraded or unsupported, the `assurance` check fails and the request is denied. Mirrors the reference assurance module;
// assurance-vectors.json pins the report and every reason.
using System.Runtime.CompilerServices;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>What a hook, hardware verifier or SNARK backend declares about itself.</summary>
/// <param name="Level">The level, system or scheme: attestation <c>software</c> &lt; <c>hardware</c> &lt; <c>multi_root</c>; zk <c>groth16</c>, <c>policyvm_snark</c>, <c>stark</c>, <c>zkvm</c>, <c>attested_vm</c>, <c>attested_vm_hw</c>; threshold <c>multisig</c>, <c>frost</c>, <c>frost_dkg</c>, <c>mpc</c>.</param>
/// <param name="Vendor">The vendor or root id, for example <c>amd-sev-snp</c>.</param>
/// <param name="Preview">Preview (not production) crypto: FROST, DKG, MPC.</param>
/// <param name="Ceremony"><c>single-party</c> or <c>multi-party</c>: how a SNARK verifying key was set up.</param>
public sealed record AssuranceLabel(string Level, string? Vendor = null, bool Preview = false, string? Ceremony = null);

/// <summary>Implemented by a verifier, hook or backend that declares its assurance label.</summary>
public interface IAssuranceLabeled
{
    AssuranceLabel Assurance { get; }
}

/// <summary>Attaches an <see cref="AssuranceLabel"/> to any reference object (a hook delegate, a hardware verifier, a SNARK backend).</summary>
public static class AssuranceLabels
{
    static readonly ConditionalWeakTable<object, AssuranceLabel> Table = new();

    /// <summary>Labels <paramref name="target"/> so a requirement can be met by it. The library's own constructors label what they build; label a custom one. Returns <paramref name="target"/>.</summary>
    public static T Set<T>(T target, AssuranceLabel label) where T : class
    {
        if (target is null) throw new ArgumentNullException(nameof(target));
        Table.AddOrUpdate(target, label);
        return target;
    }

    /// <summary>The label of <paramref name="target"/>: an explicit <see cref="Set"/> wins over <see cref="IAssuranceLabeled"/>; null when it has none.</summary>
    public static AssuranceLabel? Of(object? target)
    {
        if (target is null) return null;
        if (Table.TryGetValue(target, out var l)) return l;
        return target is IAssuranceLabeled lab ? lab.Assurance : null;
    }
}

/// <summary>One check in the assurance report.</summary>
public sealed record CheckAssurance(string Outcome)
{
    /// <summary>Present only on a pass that rests on labelled evidence.</summary>
    public string? Level { get; init; }
    public string? Vendor { get; init; }
    public bool Preview { get; init; }
    public string? Ceremony { get; init; }
    /// <summary>The signature suites involved (leaf, or root + hops).</summary>
    public IReadOnlyList<string>? Suites { get; init; }
    /// <summary>The threshold the hook enforced.</summary>
    public double? T { get; init; }
    /// <summary>Why the outcome is unsupported, or why a passing check is degraded.</summary>
    public string? Reason { get; init; }
    /// <summary>A passing check that rests on a compatibility mode; any high-assurance requirement refuses it.</summary>
    public bool Degraded { get; init; }

    /// <summary>The member names of the reference report.</summary>
    public Dictionary<string, object?> ToJson()
    {
        var m = new D { ["outcome"] = Outcome };
        if (Level != null) m["level"] = Level;
        if (Vendor != null) m["vendor"] = Vendor;
        if (Preview) m["preview"] = true;
        if (Ceremony != null) m["ceremony"] = Ceremony;
        if (Suites != null) m["suites"] = Suites.Select(s => (object?)s).ToList();
        if (T is double t) m["t"] = new Num(JsCanon.NumberString(t));
        if (Reason != null) m["reason"] = Reason;
        if (Degraded) m["degraded"] = true;
        return m;
    }
}

/// <summary>The per-check report, in the order the checks were decided.</summary>
public sealed class AssuranceReport
{
    readonly List<string> _names = new();
    readonly Dictionary<string, CheckAssurance> _by = new(StringComparer.Ordinal);

    public IReadOnlyList<string> Names => _names;

    public CheckAssurance? Get(string name) => _by.GetValueOrDefault(name);

    /// <summary>Adds or replaces an entry (a replaced entry keeps its position).</summary>
    public void Set(string name, CheckAssurance entry)
    {
        if (!_by.ContainsKey(name)) _names.Add(name);
        _by[name] = entry;
    }

    public Dictionary<string, object?> ToJson()
    {
        var m = new D();
        foreach (var n in _names) m[n] = _by[n].ToJson();
        return m;
    }

    /// <summary>Reads a report from parsed JSON (members in text order).</summary>
    public static AssuranceReport FromJson(object? json)
    {
        var r = new AssuranceReport();
        if (json is not D m) return r;
        foreach (var (name, v) in m)
        {
            var e = v as D ?? new D();
            r.Set(name, new CheckAssurance(e.GetValueOrDefault("outcome") as string ?? "")
            {
                Level = e.GetValueOrDefault("level") as string, Vendor = e.GetValueOrDefault("vendor") as string,
                Preview = e.GetValueOrDefault("preview") is true, Ceremony = e.GetValueOrDefault("ceremony") as string,
                Suites = e.GetValueOrDefault("suites") is L l ? l.Select(x => x as string ?? "").ToList() : null,
                T = IntentJs.NumOf(e.GetValueOrDefault("t")), Reason = e.GetValueOrDefault("reason") as string,
                Degraded = e.GetValueOrDefault("degraded") is true,
            });
        }
        return r;
    }
}

/// <summary>The verifier's hooks whose labels the report reads (null: no such hook; a hook with no label is "unknown").</summary>
public sealed record AssuranceHooks(object? Attestation = null, object? Zk = null, object? Threshold = null, object? Revocation = null);

/// <summary>What the report is built from: the checks (in order), the presented PCActn, the verifier's hooks and its PQ policy.</summary>
public sealed class AssuranceSources
{
    public IReadOnlyList<KeyValuePair<string, string>> Checks { get; set; } = Array.Empty<KeyValuePair<string, string>>();
    public Dictionary<string, object?>? Pcactn { get; set; }
    public AssuranceHooks Hooks { get; set; } = new();
    /// <summary>The attestation verifier actually used; it wins over <c>Hooks.Attestation</c>.</summary>
    public object? AttestationHook { get; set; }
    /// <summary>The <c>t</c> the threshold hook reported.</summary>
    public double? ThresholdT { get; set; }
    /// <summary>Reports a post-quantum signature whose key is not bound to a verifier-side source as <c>unbound_pq</c>.</summary>
    public bool AllowUnboundPq { get; set; }
    /// <summary>Passing checks that rest on a compatibility mode: check name to why.</summary>
    public IReadOnlyDictionary<string, string>? Degraded { get; set; }
}

/// <summary>One root of a multi-root attestation policy: its verifier (labelled or not) and whether it is required.</summary>
public sealed record AttestationRoot(object? Verifier, bool Required = false);

/// <summary>A high-assurance policy. Every listed dimension must be met by a PASSING check; otherwise the <c>assurance</c> check fails.</summary>
/// <param name="Attestation">The minimum attestation level: <c>software</c> &lt; <c>hardware</c> &lt; <c>multi_root</c>.</param>
/// <param name="Zk"><c>attested_vm</c> accepts any enforced statement; <c>attested_vm_hardware</c> a statement whose prover key is bound to hardware evidence (or any real proof); <c>proof</c> a cryptographic proof; <c>snark</c> only Groth16 / Policy-VM SNARK.</param>
/// <param name="Signature"><c>pq</c>: the leaf signature and every capability in the chain use a hybrid or pure post-quantum suite.</param>
/// <param name="Threshold">The accepted threshold schemes; null: not required.</param>
/// <param name="AllowPreview">Accept passing preview evidence (FROST, DKG, MPC) outside an explicit <paramref name="Threshold"/> list.</param>
public sealed record AssuranceRequirement(string? Attestation = null, string? Zk = null, string? Signature = null, IReadOnlyList<string>? Threshold = null, bool AllowPreview = false)
{
    /// <summary>From a parsed JSON object (<c>attestation</c>, <c>zk</c>, <c>signature</c>, <c>threshold</c>, <c>allowPreview</c>).</summary>
    public static AssuranceRequirement FromJson(object? json)
    {
        var m = json as D ?? new D();
        return new AssuranceRequirement(m.GetValueOrDefault("attestation") as string, m.GetValueOrDefault("zk") as string, m.GetValueOrDefault("signature") as string,
            m.GetValueOrDefault("threshold") is L l ? l.Select(x => x as string ?? "").ToList() : null, m.GetValueOrDefault("allowPreview") is true);
    }
}

public static class Assurance
{
    static readonly Dictionary<string, int> AttRank = new() { ["unknown"] = 0, ["software"] = 1, ["hardware"] = 2, ["multi_root"] = 3 };
    static readonly Dictionary<string, int> ZkRank = new()
        { ["unknown"] = 0, ["attested_vm"] = 1, ["attested_vm_hw"] = 1, ["stark"] = 2, ["zkvm"] = 2, ["groth16"] = 3, ["policyvm_snark"] = 3 };
    static readonly Dictionary<string, int> ZkNeed = new() { ["attested_vm"] = 1, ["attested_vm_hardware"] = 1, ["proof"] = 2, ["snark"] = 3 };

    static bool IsPreviewScheme(string s) => s is "frost" or "frost_dkg" or "mpc";

    static int Rank(Dictionary<string, int> table, string? level, int missing) => table.TryGetValue(level ?? "unknown", out var r) ? r : missing;

    /// <summary>Classifies one signature suite (absent or null = Ed25519): <c>ed25519</c>, <c>hybrid</c>, <c>pq</c>, or <c>unknown</c> for an unregistered suite.</summary>
    public static string SignatureLevel(object? alg)
    {
        if (alg is null) return "ed25519";
        if (alg is not string s) return "unknown";
        if (s == "ed25519") return "ed25519";
        if (!Pq.RegisteredSuites.Contains(s)) return "unknown";
        return s.StartsWith("hybrid-", StringComparison.Ordinal) ? "hybrid" : "pq";
    }

    /// <summary>The weakest level in a chain: any unknown suite, then any Ed25519-only signer, then any hybrid, else pure PQ.</summary>
    static string Weakest(IReadOnlyList<string> levels)
    {
        foreach (var l in new[] { "unknown", "ed25519", "hybrid" }) if (levels.Contains(l)) return l;
        return levels.Count > 0 ? "pq" : "unknown";
    }

    /// <summary>The attestation level an N-of-M multi-root policy guarantees: the fewest hardware roots any accepted subset can contain (all
    /// required roots, filled up to <paramref name="threshold"/> with the weakest optional ones). Two or more is <c>multi_root</c>, one is
    /// <c>hardware</c>, none is the weakest level among the roots that could make up the quorum.</summary>
    public static string MultiRootLevel(IReadOnlyList<AttestationRoot> roots, int threshold)
    {
        int RankOf(AttestationRoot r) => Rank(AttRank, AssuranceLabels.Of(r.Verifier)?.Level, 0); // an unlabelled or unrecognised level ranks 0
        var req = roots.Where(r => r.Required).ToList();
        var opt = roots.Where(r => !r.Required).OrderBy(RankOf).ToList(); // stable, weakest first
        var chosen = req.Concat(opt.Take(Math.Max(0, threshold - req.Count))).ToList();
        int hw = chosen.Count(r => RankOf(r) >= AttRank["hardware"]);
        if (hw >= 2) return "multi_root";
        if (hw == 1) return "hardware";
        // the minimum of nothing is +Infinity: an empty quorum is "software"
        return chosen.Count == 0 || chosen.Min(RankOf) >= AttRank["software"] ? "software" : "unknown";
    }

    static string AlgText(object? alg) => IntentRevocation.JsText(alg, true);

    /// <summary>Builds the per-check assurance report (pure; never throws on odd input).</summary>
    public static AssuranceReport BuildReport(AssuranceSources src)
    {
        var report = new AssuranceReport();
        var p = src.Pcactn;
        foreach (var (name, status) in src.Checks)
        {
            var e = new CheckAssurance(status);
            if (status == "unsupported") e = e with { Reason = name + " is not implemented by this verifier" };
            if (status == "pass")
            {
                object? hook = name switch
                {
                    "attestation" => src.AttestationHook ?? src.Hooks.Attestation,
                    "zk_compliance" => src.Hooks.Zk,
                    "threshold" => src.Hooks.Threshold,
                    "revocation" => src.Hooks.Revocation,
                    _ => null,
                };
                var label = AssuranceLabels.Of(hook);
                if (name is "attestation" or "zk_compliance" || (name == "threshold" && hook != null))
                {
                    var level = string.IsNullOrEmpty(label?.Level) ? "unknown" : label!.Level;
                    e = e with { Level = level, Vendor = label?.Vendor };
                    if (name == "zk_compliance" && label?.Ceremony != null) e = e with { Ceremony = label.Ceremony };
                    if (label?.Preview == true || (name == "threshold" && IsPreviewScheme(level))) e = e with { Preview = true };
                    if (name == "threshold" && src.ThresholdT is double t) e = e with { T = t };
                }
                else if (label != null)
                {
                    e = e with { Level = label.Level, Vendor = label.Vendor, Preview = label.Preview };
                }
                if (name == "leaf_signature" && p != null)
                {
                    var alg = p.GetValueOrDefault("alg") ?? "ed25519";
                    e = e with { Suites = new[] { AlgText(alg) }, Level = src.AllowUnboundPq && !(alg is string a0 && a0 == "ed25519") ? "unbound_pq" : SignatureLevel(alg) };
                }
                if (name == "cap_chain" && p != null && p.GetValueOrDefault("cap_chain") is L chain)
                {
                    var algs = chain.Select(c => (c as D)?.GetValueOrDefault("alg") ?? "ed25519").ToList();
                    bool unbound = algs.Any(a => !(a is string s && s == "ed25519"));
                    e = e with { Suites = algs.Select(AlgText).ToList(), Level = src.AllowUnboundPq && unbound ? "unbound_pq" : Weakest(algs.Select(SignatureLevel).ToList()) };
                }
            }
            report.Set(name, e);
        }
        if (src.Degraded != null)
            foreach (var (name, why) in src.Degraded)
                if (report.Get(name) is { Outcome: "pass" } c) report.Set(name, c with { Degraded = true, Reason = why });
        // Features this verifier does not implement: reported, never a pass.
        if (p != null && p.ContainsKey("bond_ref"))
            report.Set("bond", new CheckAssurance("unsupported") { Reason = "bond verification is not implemented by this verifier" });
        return report;
    }

    /// <summary>Checks a report against a requirement. Returns the reason of the first unmet dimension (prefixed <c>assurance: </c>), or null when
    /// every listed dimension is met. Missing, failed, not-enforced, unlabelled, weaker, preview, degraded and unsupported evidence never meet a requirement.</summary>
    public static string? Unmet(AssuranceReport report, AssuranceRequirement req)
    {
        foreach (var name in report.Names)
        {
            var e = report.Get(name)!;
            if (e.Outcome == "unsupported")
                return $"assurance: unsupported: {name} ({(string.IsNullOrEmpty(e.Reason) ? "not implemented" : e.Reason)}); a high-assurance policy never accepts it";
        }
        foreach (var name in report.Names)
        {
            var e = report.Get(name)!;
            if (e.Outcome == "pass" && e.Degraded)
                return $"assurance: {name} rests on a degraded compatibility mode ({(string.IsNullOrEmpty(e.Reason) ? "degraded" : e.Reason)}); a high-assurance policy never accepts it";
        }
        (CheckAssurance? Entry, string? Why) Need(string name, string what)
        {
            var e = report.Get(name);
            if (e == null) return (null, $"assurance: {what} required but there is no {name} evidence");
            if (e.Outcome != "pass") return (null, $"assurance: {what} required but the {name} check is {e.Outcome}");
            return (e, null);
        }
        static string OrUnknown(string? s) => string.IsNullOrEmpty(s) ? "unknown" : s;

        if (req.Attestation != null)
        {
            var (e, why) = Need("attestation", req.Attestation + " attestation");
            if (why != null) return why;
            if (Rank(AttRank, e!.Level, 0) < (AttRank.TryGetValue(req.Attestation, out var want) ? want : 99))
                return $"assurance: {req.Attestation} attestation required but the evidence is {OrUnknown(e.Level)}";
        }
        if (req.Zk != null)
        {
            var (e, why) = Need("zk_compliance", $"zk compliance ({req.Zk})");
            if (why != null) return why;
            if (req.Zk == "attested_vm_hardware" && (e!.Level is "attested_vm" or "unknown" or null or ""))
                return $"assurance: zk compliance ({req.Zk}) required but the prover key is not bound to hardware evidence";
            if (Rank(ZkRank, e!.Level, 0) < (ZkNeed.TryGetValue(req.Zk, out var floor) ? floor : 99))
                return $"assurance: zk compliance ({req.Zk}) required but the evidence is {OrUnknown(e.Level)}";
        }
        if (req.Signature == "pq")
        {
            foreach (var name in new[] { "leaf_signature", "cap_chain" })
            {
                var (e, why) = Need(name, "post-quantum signatures");
                if (why != null) return why;
                if (e!.Level is not ("pq" or "hybrid")) return $"assurance: post-quantum signatures required but {name} is {OrUnknown(e.Level)}";
            }
        }
        if (req.Threshold != null)
        {
            var list = string.Join(" | ", req.Threshold);
            var (e, why) = Need("threshold", $"threshold ({list})");
            if (why != null) return why;
            if (e!.Level == null) return $"assurance: threshold ({list}) required but no threshold verifier enforced it";
            if (!req.Threshold.Contains(e.Level)) return $"assurance: threshold ({list}) required but the scheme is {e.Level}";
        }
        if (!req.AllowPreview)
        {
            foreach (var name in report.Names)
            {
                var e = report.Get(name)!;
                if (e.Outcome != "pass" || !e.Preview) continue;
                if (name == "threshold" && req.Threshold != null && req.Threshold.Contains(e.Level ?? "")) continue;
                return $"assurance: {name} rests on preview crypto ({OrUnknown(e.Level)}); set allowPreview or list the scheme to accept it";
            }
        }
        return null;
    }
}
