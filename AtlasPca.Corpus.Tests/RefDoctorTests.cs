using AtlasPca.Doctor;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;
using P = AtlasPca.Doctor.PcaDoctor;

namespace AtlasPca.Corpus.Tests;

/// <summary>Replays the pca-doctor oracle: the fake fetch / clock / library tables are named inputs replayed identically here. The replay-store checks need an
/// adapter and the conformance kit (covered by the store-conformance oracle).</summary>
public class RefDoctorTests
{
    const string M = "ref-doctor";
    const string Url1 = "https://api.example.com";

    static D AsD(object? o) => (D)o!;
    static L AsL(object? o) => (L)o!;

    /// <summary>The fake fetch + clock: each call pops the next response of its URL (the last repeats), advances the clock by rtt before answering.</summary>
    sealed class Env
    {
        public long T;
        readonly D _responses;
        readonly Dictionary<string, int> _idx = new();
        public DoctorFetch Fetch;
        public Env(object? spec)
        {
            T = Base.Long(AsD(spec)["now"]);
            _responses = AsD(AsD(spec)["responses"]);
            Fetch = (method, url, headers, timeoutMs) =>
            {
                if (!_responses.TryGetValue(url, out var lst) || lst == null) throw new InvalidOperationException("no route " + url);
                var rs = AsL(lst);
                int i = _idx.GetValueOrDefault(url, 0);
                _idx[url] = i + 1;
                var r = AsD(rs[Math.Min(i, rs.Count - 1)]);
                if (r.GetValueOrDefault("rtt") != null) T += Base.Long(r["rtt"]);
                if (r.GetValueOrDefault("throw") != null) throw new InvalidOperationException((string)r["throw"]!);
                return new DoctorResponse(200, n => n == "date" ? r.GetValueOrDefault("date") as string : n == "ratelimit-remaining" ? r.GetValueOrDefault("rl") as string : null);
            };
        }
        public long Now() => T;
    }

    static DoctorDecision Dec(bool allowed, params string[] reasons) => new(allowed, reasons);

    /// <summary>The named fake library: behaviours enforce | ignore-max | ignore-unknown | deny-all | throws | nonarray-reasons | allow-all.</summary>
    static Func<string?, LoadedPca> Loader(object? specO)
    {
        var spec = AsD(specO);
        return dir =>
        {
            if (spec.GetValueOrDefault("throws") != null) throw new InvalidOperationException((string)spec["throws"]!);
            var behavior = (string)spec["behavior"]!;
            DoctorProbe p = (cav, amount) =>
            {
                if (behavior == "throws") throw new InvalidOperationException("boom");
                if (behavior == "allow-all") return Dec(true);
                if (behavior == "deny-all") return Dec(false, "denied", "7");
                if (behavior == "nonarray-reasons") return Dec(false);
                if ((string)cav["type"]! == "max_spend")
                {
                    if (behavior == "ignore-max") return Dec(true);
                    return amount <= IntentJs.NumOf(cav["usd"])!.Value ? Dec(true) : Dec(false, "over max_spend");
                }
                return behavior == "ignore-unknown" ? Dec(true) : Dec(false, "unknown caveat type");
            };
            return new LoadedPca((string)spec["version"]!, (string)spec["path"]!, p);
        };
    }

    static List<CheckResult> Results(object? o) => AsL(o).Select(x => CheckResult.FromJson(AsD(x))).ToList();
    static Dictionary<string, string> StrEnv(object? o) => AsD(o).ToDictionary(e => e.Key, e => (string)e.Value!);
    static List<string> Strs(object? o) => AsL(o).Select(x => (string)x!).ToList();
    static object? Out(List<CheckResult> rs) => rs.Select(r => (object?)r.ToJson()).ToList();

    [Fact]
    public void Consts() => Base.Check(M, "consts", _ => new D
    {
        ["USAGE"] = P.Usage,
        ["CHECK_GROUPS"] = P.CheckGroups,
        ["DEFAULT_REQUIRED"] = P.DefaultRequired,
        ["ROOT_CAVEAT_MIN_VERSION"] = P.RootCaveatMinVersion,
        ["DEFAULT_REFERENCE_URL"] = P.DefaultReferenceUrl,
        ["SUITES_REMEDIATION"] = P.SuitesRemediation,
        ["PQ_REMEDIATION"] = P.PqRemediation,
        ["CLOCK_REMEDIATION"] = P.ClockRemediation,
        ["PROXY_REMEDIATION"] = P.ProxyRemediation,
        ["ATOMICITY_REMEDIATION"] = P.AtomicityRemediation,
        ["DURABILITY_REMEDIATION"] = P.DurabilityRemediation,
        ["CAVEAT_REMEDIATION"] = P.CaveatRemediation,
    });

    [Fact] public void ScrubText() => Base.Check(M, "scrubText", a => P.ScrubText(a[0]));
    [Fact] public void ScrubDeep() => Base.Check(M, "scrubDeep", a => P.ScrubDeep(a[0]));
    [Fact] public void CheckAllowedSuites() => Base.Check(M, "checkAllowedSuites", a => P.CheckAllowedSuites(AsD(a[0])).ToJson());
    [Fact] public void CheckPqBinding() => Base.Check(M, "checkPqBinding", a => P.CheckPqBinding(AsD(a[0])).ToJson());
    [Fact] public void CheckProxyConfig() => Base.Check(M, "checkProxyConfig", a => P.CheckProxyConfig(AsD(a[0])).ToJson());
    [Fact] public void TestNetIp() => Base.Check(M, "testNetIp", a => P.TestNetIp(P.Mulberry32(Base.Long(a[0]))));
    [Fact] public void ForgedHeaders() => Base.Check(M, "forgedHeaders", a => P.ForgedHeaders(P.Mulberry32(Base.Long(a[0]))));
    [Fact] public void CheckClock() => Base.Check(M, "checkClock", a => { var e = new Env(a[1]); return P.CheckClock(AsD(a[0]), e.Fetch, e.Now).ToJson(); });
    [Fact] public void ReadDate() => Base.Check(M, "readDate", a => { var e = new Env(a[1]); return P.ReadDate(Url1, e.Fetch, e.Now, 1000).ToJson(); });
    [Fact] public void CheckProxyProbe() => Base.Check(M, "checkProxyProbe", a => { var e = new Env(a[1]); return P.CheckProxyProbe(AsD(a[0]), e.Fetch, P.Mulberry32(7)).ToJson(); });
    [Fact] public void CompareVersion() => Base.Check(M, "compareVersion", a => P.CompareVersion((string)a[0]!, (string)a[1]!));
    [Fact] public void CheckRootCaveats() => Base.Check(M, "checkRootCaveats", a => P.CheckRootCaveats(AsD(a[0]), Loader(a[1])).ToJson());
    [Fact] public void CheckEnforcement() => Base.Check(M, "checkEnforcement", a => P.CheckEnforcement(AsD(a[0])).ToJson());
    [Fact] public void ConfigProblems() => Base.Check(M, "configProblems", a => P.ConfigProblems(AsD(a[0])));
    [Fact] public void VerdictOf() => Base.Check(M, "verdictOf", a => P.VerdictOf(Results(a[0]), a.Count > 1 && a[1] is true));
    [Fact] public void FormatResults() => Base.Check(M, "formatResults", a => P.FormatResults(Results(a[0]), a[1] as string, a.Count > 2 && a[2] is true));
    [Fact] public void ConfigFromEnv() => Base.Check(M, "configFromEnv", a => P.Json(P.ConfigFromEnv(StrEnv(a[0]))));
    [Fact] public void MergeConfig() => Base.Check(M, "mergeConfig", a => P.Json(P.MergeConfig(a.Select(AsD).ToList())));
    [Fact] public void ParseDoctorArgs() => Base.Check(M, "parseDoctorArgs", a => P.Json(P.ParseDoctorArgs(Strs(a[0]))));

    [Fact]
    public void MainCli() => Base.Check(M, "main", a =>
    {
        var o = new L();
        var er = new L();
        int code = P.Main(Strs(a[0]), StrEnv(a[1]), s => o.Add(s), s => er.Add(s));
        return new D { ["code"] = (long)code, ["out"] = o, ["err"] = er };
    });

    [Fact]
    public void RunDoctor() => Base.Check(M, "runDoctor", a =>
    {
        var e = new Env(a[2]);
        var d = new DoctorDeps { Fetch = e.Fetch, Now = e.Now, LoadPca = Loader(a[3]) };
        return Out(P.RunDoctor(AsD(a[0]), a[1] == null ? null : Strs(a[1]), d));
    });

    [Fact]
    public void AllFnsCovered() { Base.Covers(M, new[]
    {
        "consts", "scrubText", "scrubDeep", "checkAllowedSuites", "checkPqBinding", "checkProxyConfig", "testNetIp", "forgedHeaders", "checkClock", "readDate", "checkProxyProbe",
        "compareVersion", "checkRootCaveats", "checkEnforcement", "configProblems", "verdictOf", "formatResults", "configFromEnv", "mergeConfig", "parseDoctorArgs", "main", "runDoctor",
    }); Assert.Equal(1597, Base.Total(M)); }
}
