using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

// Assurance labels and the high-assurance gate (T8, B7): replays assurance-vectors.json (signature_level, report, requirement, multi_root)
// with reports and reasons compared exactly. Labels come from the verifier configuration (a labelled hook object), never from the
// presented evidence. A missing vector file FAILS.
public class AssuranceVectorTests
{
    static List<D> Rows(string table, int expected)
    {
        var doc = Load("assurance-vectors.json");
        Assert.True(doc.ContainsKey(table), $"{table}: missing table");
        var rows = L(doc[table]).Cast<D>().ToList();
        Assert.True(rows.Count == expected, $"{table}: {rows.Count} rows, this runner pins {expected}");
        return rows;
    }

    /// <summary>null = no hook; the string "unlabelled" = a hook with no label; an object = a hook carrying that label.</summary>
    static object? Hook(object? v) => v switch
    {
        null => null,
        string => new object(),
        D m => AssuranceLabels.Set(new object(), new AssuranceLabel(
            (string)m["level"]!, m.GetValueOrDefault("vendor") as string, m.GetValueOrDefault("awaiting_audit") is true, m.GetValueOrDefault("ceremony") as string)),
        _ => null,
    };

    [Fact]
    public void SignatureLevelVectors()
    {
        foreach (var v in Rows("signature_level", 14))
            Assert.True(Assurance.SignatureLevel(v["alg"]) == (string)v["level"]!, $"{Pca.Canonicalize(v["alg"])}");
    }

    [Fact]
    public void ReportVectors()
    {
        foreach (var v in Rows("report", 37))
        {
            var src = new AssuranceSources { Pcactn = v.GetValueOrDefault("pcactn") as D };
            var checks = D(v["checks"]);
            src.Checks = checks.Select(kv => new KeyValuePair<string, string>(kv.Key, (string)kv.Value!)).ToList();
            if (v.GetValueOrDefault("hooks") is D h)
                src.Hooks = new AssuranceHooks(Hook(h.GetValueOrDefault("attestation")), Hook(h.GetValueOrDefault("zk")), Hook(h.GetValueOrDefault("threshold")), Hook(h.GetValueOrDefault("revocation")));
            src.AttestationHook = Hook(v.GetValueOrDefault("attestation_hook"));
            src.ThresholdT = v.TryGetValue("threshold_t", out var t) ? IntentJs.NumOf(t) : null; // a non-number is no t
            src.AllowUnboundPq = v.GetValueOrDefault("allow_unbound_pq") is true;
            if (v.GetValueOrDefault("degraded") is D d) src.Degraded = d.ToDictionary(kv => kv.Key, kv => (string)kv.Value!);
            var got = Pca.Canonicalize(Assurance.BuildReport(src).ToJson());
            var want = Pca.Canonicalize(v["report"]);
            Assert.True(got == want, $"{v["name"]}:\n got  {got}\n want {want}");
        }
    }

    [Fact]
    public void RequirementVectors()
    {
        foreach (var v in Rows("requirement", 47))
        {
            var got = Assurance.Unmet(AssuranceReport.FromJson(v["report"]), AssuranceRequirement.FromJson(v["require"]));
            Assert.True(got == v["unmet"] as string, $"{v["name"]}:\n got  {got}\n want {v["unmet"]}");
        }
    }

    [Fact]
    public void MultiRootVectors()
    {
        foreach (var v in Rows("multi_root", 10))
        {
            var roots = L(v["roots"]).Cast<D>().Select(r => new AttestationRoot(Hook(new D { ["level"] = r["level"] }), r.GetValueOrDefault("required") is true)).ToList();
            Assert.True(Assurance.MultiRootLevel(roots, (int)N(v["threshold"])) == (string)v["level"]!, $"{v["name"]}");
        }
    }

    // A label comes from the verifier's configuration: an unlabelled hook, a hook of another level, and presented evidence can never meet a requirement.
    [Fact]
    public void LabelsNeverComeFromEvidence()
    {
        var hw = AssuranceLabels.Set(new object(), new AssuranceLabel("hardware", "v"));
        AssuranceReport Rep(object? hook) => Assurance.BuildReport(new AssuranceSources
        {
            Checks = new[] { new KeyValuePair<string, string>("attestation", "pass") }, Hooks = new AssuranceHooks(Attestation: hook),
        });
        Assert.Null(Assurance.Unmet(Rep(hw), new AssuranceRequirement(Attestation: "hardware")));
        Assert.NotNull(Assurance.Unmet(Rep(hw), new AssuranceRequirement(Attestation: "multi_root")));
        Assert.Equal("assurance: software attestation required but the evidence is unknown", Assurance.Unmet(Rep(new object()), new AssuranceRequirement(Attestation: "software")));
        Assert.Equal("assurance: software attestation required but there is no attestation evidence", Assurance.Unmet(new AssuranceReport(), new AssuranceRequirement(Attestation: "software")));
        Assert.Equal("assurance: unknown attestation requirement \"bogus\" (fail closed)", Assurance.Unmet(new AssuranceReport(), new AssuranceRequirement(Attestation: "bogus"))); // an unknown required level can never be met
    }

    [Fact]
    public void AVendorVerifierIsHardwareEvidenceOfItsVendor()
    {
        var label = AssuranceLabels.Of(AttestationVerifiers.FromConfig("amd-sev-snp", (D)Pca.ParseJson("{\"family\":\"milan\",\"binding\":\"report-data\",\"policy\":{\"measurements\":[\"aa\"]}}")!));
        Assert.Equal(new AssuranceLabel("hardware", "amd-sev-snp"), label);
    }

    [Fact]
    public void AnUnknownRequirementKeyOrValueIsRefusedWithTheSharedTexts()
    {
        var r = new AssuranceReport();
        string? Why(string json) => Assurance.Unmet(r, AssuranceRequirement.FromJson(Pca.ParseJson(json)));
        Assert.Equal("assurance: unknown requirement atestation (fail closed)", Why("{\"atestation\":\"hardware\"}"));
        Assert.Equal("assurance: unknown zk requirement \"groth16\" (fail closed)", Why("{\"zk\":\"groth16\"}"));
        Assert.Equal("assurance: unknown signature requirement \"PQ\" (fail closed)", Why("{\"signature\":\"PQ\"}"));
        Assert.Equal("assurance: unknown signature requirement null (fail closed)", Why("{\"signature\":null}"));
        Assert.Equal("assurance: unknown attestation requirement \"tpm\" (fail closed)", Why("{\"attestation\":\"tpm\"}"));
        Assert.Equal("assurance: unknown threshold requirement \"multisig\" (fail closed)", Why("{\"threshold\":\"multisig\"}"));
        Assert.Equal("assurance: unknown threshold requirement [\"multisig\",\"bls\"] (fail closed)", Why("{\"threshold\":[\"multisig\",\"bls\"]}"));
        // one valid scheme beside an invalid one is still refused, with the original (not the coerced) text
        Assert.Equal("assurance: unknown threshold requirement [\"multisig\",7] (fail closed)", Why("{\"threshold\":[\"multisig\",7]}"));
        // a value that cannot be serialised is shown as null
        Assert.Equal("assurance: unknown zk requirement null (fail closed)", Assurance.Unmet(r, AssuranceRequirement.FromJson(new D { ["zk"] = new object() })));
        Assert.Null(Why("{\"allowAwaitingAudit\":\"yes\"}"));
        // the first refusal wins: an unknown key before any bad value, then attestation, zk, signature, threshold in that order
        Assert.Equal("assurance: unknown requirement b (fail closed)", Why("{\"attestation\":\"x\",\"b\":1}"));
        Assert.Equal("assurance: unknown attestation requirement 7 (fail closed)", Why("{\"threshold\":\"x\",\"signature\":\"x\",\"zk\":\"x\",\"attestation\":7}"));
        Assert.Equal("assurance: unknown zk requirement null (fail closed)", Why("{\"threshold\":\"x\",\"signature\":\"x\",\"zk\":null}"));
        Assert.Equal("assurance: unknown signature requirement \"x\" (fail closed)", Why("{\"threshold\":\"x\",\"signature\":\"x\"}"));
        Assert.Equal("assurance: unknown threshold requirement [7] (fail closed)", Why("{\"threshold\":[7]}"));
        Assert.Equal("assurance: unknown threshold requirement null (fail closed)", Why("{\"threshold\":null}"));
        foreach (var ok in new[] { "{\"attestation\":\"software\"}", "{\"attestation\":\"hardware\"}", "{\"attestation\":\"multi_root\"}", "{\"zk\":\"snark\"}", "{\"signature\":\"pq\"}", "{\"threshold\":[\"frost_dkg\",\"mpc\"]}" })
            Assert.False((Why(ok) ?? "").StartsWith("assurance: unknown", System.StringComparison.Ordinal), ok);
        // a requirement built in code is refused the same way
        Assert.Equal("assurance: unknown zk requirement \"x\" (fail closed)", Assurance.Unmet(r, new AssuranceRequirement(Zk: "x")));
        Assert.Equal("assurance: unknown signature requirement \"x\" (fail closed)", Assurance.Unmet(r, new AssuranceRequirement(Signature: "x")));
        Assert.Equal("assurance: unknown threshold requirement [\"multisig\",\"bls\"] (fail closed)", Assurance.Unmet(r, new AssuranceRequirement(Threshold: new[] { "multisig", "bls" })));
    }
}
