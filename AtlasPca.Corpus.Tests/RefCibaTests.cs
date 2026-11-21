using AtlasPca.Ciba;
using AtlasPca.Gnap;
using Cb = AtlasPca.Ciba.Ciba;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the CIBA on-ramp oracles (test-data/ref-ciba.json.gz and ref-ciba-java.json.gz, TS reference @atlasauth/pca-ciba): the
/// canonical action, binding message and auth request, gating, the cosign budget effect, and the in-memory and durable brokers as scripted scenarios.</summary>
public class RefCibaTests
{
    const string M = "ref-ciba";
    const string MJ = "ref-ciba-java";
    const long T0 = 1_800_000_000_000L;

    // the corpus replays run without libatlasada (the dedicated Ada workflow runs them on it); the built-in host approximation is opted into here only
    static RefCibaTests() { if (!AdaIdna.Loaded) AdaIdna.AllowFallback = true; }

    static D? Opt(L a, int i) => a.Count > i ? (a[i] as D ?? (a[i] == null ? null : new D())) : null; // a non-object option bag has no members

    // ---- pure functions (both corpora) ----

    [Fact]
    public void CibaActionFromStepUp()
    {
        Base.Check(M, "cibaActionFromStepUp", a => Cb.CibaActionFromStepUp((D)a[0]!));
        Base.Check(MJ, "cibaActionFromStepUp", a => Cb.CibaActionFromStepUp((D)a[0]!));
    }

    [Fact]
    public void ToCibaAuthRequest()
    {
        Func<L, object?> run = a =>
        {
            if (a.Count > 1 && a[1] == null) throw new ArgumentException("opts is null"); // the reference reads a member of null
            return Cb.ToCibaAuthRequest((D)a[0]!, Opt(a, 1));
        };
        Base.Check(M, "toCibaAuthRequest", run);
        Base.Check(MJ, "toCibaAuthRequest", run);
    }

    [Fact]
    public void AsciiForm()
    {
        Base.Check(M, "asciiForm", a => Cb.AsciiForm((string)a[0]!));
        Base.Check(MJ, "asciiForm", a => Cb.AsciiForm((string)a[0]!));
    }

    [Fact]
    public void RequiresCiba()
    {
        Base.Check(M, "requiresCiba", a => Cb.RequiresCiba(a[0]));
        Base.Check(MJ, "requiresCiba", a => Cb.RequiresCiba(a[0]));
    }

    [Fact]
    public void CibaDecisionToCosign()
    {
        Base.Check(M, "cibaDecisionToCosign", a => Cb.CibaDecisionToCosign(a[0], (D)a[1]!, (D)a[2]!, a[3], Opt(a, 4)));
        Base.Check(MJ, "cibaDecisionToCosign", a => Cb.CibaDecisionToCosign(a[0], (D)a[1]!, (D)a[2]!, a[3], Opt(a, 4)));
    }

    [Fact]
    public void DurableBrokerConfig() => Base.Check(MJ, "durableBrokerConfig", a =>
    {
        var c = (D)a[0]!;
        var o = new DurableBrokerOptions();
        if (c.GetValueOrDefault("noStore") is not true) o.Store = CibaApproval.CreateMemoryApprovalStore();
        if (c.ContainsKey("decisionTtlSec")) o.DecisionTtlSec = GnapJs.NumOf(c["decisionTtlSec"]);
        try { CibaApproval.CreateDurableCibaBroker(o); return "ok"; } catch (Exception) { return "throws"; }
    });

    // ---- lifecycles of the two brokers (ref-ciba) ----

    static readonly D SuLife = new()
    {
        ["id"] = "su1", ["verb"] = "stripe.payout", ["resource"] = "acct:1", ["params"] = new D { ["amount"] = new Num("80"), ["currency"] = "USD", ["payee"] = "bob" },
        ["tier"] = new Num("3"), ["reason"] = "r", ["goalCommit"] = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq", ["goal"] = "pay suppliers", ["lineage"] = new D(),
        ["r"] = new Num("0.5"), ["requestedAt"] = new Num("1"),
    };

    static object? Mask(object? v, string? id) => v switch
    {
        string s when id != null && s == id => "ID",
        L l => new L(l.Select(x => Mask(x, id))),
        D m => m.ToDictionary(e => e.Key, e => Mask(e.Value, id)),
        _ => v,
    };

    static object Lifecycle(string kind, L ops)
    {
        long t = 1_000_000;
        IApprovalBroker b = kind == "memory"
            ? CibaApproval.CreateCibaBroker(new BrokerOptions { Now = () => t, OnComplete = _ => { } })
            : CibaApproval.CreateDurableCibaBroker(new DurableBrokerOptions { Store = CibaApproval.CreateMemoryApprovalStore(), Now = () => t, DecisionTtlSec = 100 });
        string? id = null;
        var outp = new L();
        foreach (var oo in ops)
        {
            var op = (D)oo!;
            var name = (string)op["op"]!;
            if (name == "now") { t = IntentJs.Lng(op["t"]); outp.Add(null); continue; }
            try
            {
                object? v;
                switch (name)
                {
                    case "start":
                        {
                            var r = b.Start((D?)op.GetValueOrDefault("stepUp") ?? SuLife, (D?)op.GetValueOrDefault("opts"));
                            id = (string)r["auth_req_id"]!;
                            v = new D(r) { ["auth_req_id"] = "ID" };
                            break;
                        }
                    case "poll": v = b.Poll(id!); break;
                    case "token": v = b.Token(id!); break;
                    case "resolve": v = b.Resolve(id!, op.GetValueOrDefault("decision") as string, op.GetValueOrDefault("by") as string); break;
                    case "get": v = b.Get(id!); break;
                    case "unknown":
                        v = (string)op["fn"]! switch
                        {
                            "poll" => b.Poll("nope"),
                            "token" => b.Token("nope"),
                            "resolve" => b.Resolve("nope", "approve", "x"),
                            _ => b.Get("nope"),
                        };
                        break;
                    default: throw new InvalidOperationException("unknown op " + name);
                }
                outp.Add(new D { ["ok"] = true, ["value"] = Mask(Base.Json(v), id) });
            }
            catch (Exception) { outp.Add(new D { ["ok"] = false }); }
        }
        return outp;
    }

    [Fact] public void LifecycleOfBothBrokers() => Base.Check(M, "lifecycle", a => Lifecycle((string)a[0]!, (L)a[1]!));

    // ---- brokers as scripted scenarios (ref-ciba-java) ----

    static object? RedactIds(object? v, List<string> ids)
    {
        switch (v)
        {
            case string s:
                for (int i = 0; i < ids.Count; i++) s = s.Replace(ids[i], "<ID" + (i + 1) + ">", StringComparison.Ordinal);
                return s;
            case L l: return new L(l.Select(x => RedactIds(x, ids)));
            case D m: return m.ToDictionary(e => e.Key, e => RedactIds(e.Value, ids));
            default: return v;
        }
    }

    static object BrokerScenario(D s)
    {
        long[] clock = { T0 };
        var kind = (string)s["kind"]!;
        var opts = s.GetValueOrDefault("opts") as D ?? new D();
        var oc = opts.GetValueOrDefault("onComplete") as string;
        var completes = new L();
        Action<D>? onComplete = oc == null ? null : sess =>
        {
            completes.Add(sess);
            if (oc == "throws") throw new InvalidOperationException("notifier down");
        };
        IApprovalStore? store = null;
        AtlasPca.Ciba.IDurableKv? kv = null;
        IApprovalBroker broker;
        if (kind == "memory") broker = CibaApproval.CreateCibaBroker(new BrokerOptions { Now = () => clock[0], OnComplete = onComplete });
        else
        {
            if (kind == "durable-kv") { kv = CibaKv.CreateMemoryKv(); store = CibaKv.CreateKvApprovalStore(kv); } else store = CibaApproval.CreateMemoryApprovalStore();
            var o = new DurableBrokerOptions { Store = store, Now = () => clock[0], OnComplete = onComplete };
            if (opts.ContainsKey("decisionTtlSec")) o.DecisionTtlSec = GnapJs.NumOf(opts["decisionTtlSec"]);
            broker = CibaApproval.CreateDurableCibaBroker(o);
        }
        var ids = new List<string>();
        var trace = new L();
        foreach (var so in (L)s["steps"]!)
        {
            var st = (D)so!;
            var op = (string)st["op"]!;
            var entry = new D { ["op"] = op };
            try
            {
                object? value = null;
                string? id = null;
                if (st.GetValueOrDefault("id") is string x) id = x == "$id" ? ids[^1] : x.StartsWith("$id", StringComparison.Ordinal) ? ids[int.Parse(x[3..]) - 1] : x;
                switch (op)
                {
                    case "start":
                        {
                            var req = broker.Start((D)st["stepUp"]!, st.GetValueOrDefault("opts") as D);
                            var rid = (string)req["auth_req_id"]!;
                            if (!ids.Contains(rid)) ids.Add(rid);
                            value = req;
                            break;
                        }
                    case "poll": value = broker.Poll(id!); break;
                    case "token": value = broker.Token(id!); break;
                    case "resolve": value = broker.Resolve(id!, st.GetValueOrDefault("decision") as string ?? "\u0000invalid", st.GetValueOrDefault("by") as string); break;
                    case "get": value = broker.Get(id!); break;
                    case "advance": clock[0] += IntentJs.Lng(st["ms"]); value = clock[0]; break;
                    case "storeSet":
                        {
                            var key = ((string)st["key"]!).Replace("$id", ids.Count == 0 ? "" : ids[^1], StringComparison.Ordinal);
                            var cur = store!.Get(key);
                            value = store.Cas(key, cur?.Version ?? 0, st.GetValueOrDefault("value"));
                            break;
                        }
                    case "kvRaw":
                        {
                            var key = ((string)st["key"]!).Replace("$id", ids.Count == 0 ? "" : ids[^1], StringComparison.Ordinal);
                            value = kv!.PutIfEquals(key, kv.Get(key), (string)st["raw"]!);
                            break;
                        }
                    default: throw new InvalidOperationException("unknown step " + op);
                }
                entry["ok"] = true;
                entry["value"] = value;
            }
            catch (ApprovalStoreException e)
            {
                entry["ok"] = false;
                entry["msg"] = e.Message;
                entry["code"] = e.Code;
            }
            catch (Exception e)
            {
                entry["ok"] = false;
                entry["msg"] = e.Message;
            }
            if (completes.Count > 0) { entry["complete"] = new L(completes); completes.Clear(); }
            trace.Add(entry);
        }
        return RedactIds(Base.Json(trace), ids)!;
    }

    [Fact] public void BrokerScenarios() => Base.Check(MJ, "brokerScenario", a => BrokerScenario((D)a[0]!));

    // ---- the KV approval store ----

    static object KvScenario(D s)
    {
        var kv = CibaKv.CreateMemoryKv();
        var store = CibaKv.CreateKvApprovalStore(kv);
        var trace = new L();
        foreach (var so in (L)s["steps"]!)
        {
            var st = (D)so!;
            var op = (string)st["op"]!;
            var entry = new D { ["op"] = op };
            try
            {
                object? value;
                switch (op)
                {
                    case "get":
                        {
                            var v = store.Get((string)st["key"]!);
                            value = v == null ? null : new D { ["version"] = v.Version, ["value"] = v.Value };
                            break;
                        }
                    case "cas": value = store.Cas((string)st["key"]!, IntentJs.Lng(st["expected"]), st.GetValueOrDefault("value")); break;
                    case "kvSet": value = kv.PutIfEquals((string)st["key"]!, kv.Get((string)st["key"]!), (string)st["raw"]!); break;
                    case "kvGet": value = kv.Get((string)st["key"]!); break;
                    default: throw new InvalidOperationException("unknown step " + op);
                }
                entry["ok"] = true;
                entry["value"] = value;
            }
            catch (ApprovalStoreException e) { entry["ok"] = false; entry["code"] = e.Code; }
            catch (Exception) { entry["ok"] = false; entry["code"] = "other"; }
            trace.Add(entry);
        }
        return trace;
    }

    [Fact] public void KvStoreScenarios() => Base.Check(MJ, "kvScenario", a => KvScenario((D)a[0]!));

    // ---- the client ----

    static CibaClientConfig ConfigOf(D c)
    {
        var cfg = new CibaClientConfig
        {
            BackchannelAuthenticationEndpoint = (string?)c.GetValueOrDefault("backchannelAuthenticationEndpoint"),
            TokenEndpoint = (string?)c.GetValueOrDefault("tokenEndpoint"),
            ClientId = (string?)c.GetValueOrDefault("clientId"),
            ClientSecret = (string?)c.GetValueOrDefault("clientSecret"),
            AllowInsecureHttp = c.GetValueOrDefault("allowInsecureHttp") is true,
        };
        if (c.ContainsKey("timeoutMs")) cfg.TimeoutMs = GnapJs.NumOf(c["timeoutMs"]) ?? double.NaN;
        return cfg;
    }

    [Fact]
    public void CreateCibaClientConfig() => Base.Check(MJ, "createCibaClientConfig", a =>
    {
        var cfg = ConfigOf((D)a[0]!);
        cfg.Transport = (url, headers, body, timeoutMs) => new CibaResponse(200, "{}");
        CibaClient.CreateCibaClient(cfg);
        return true;
    });

    [Fact]
    public void VerifyPingCallback()
    {
        Func<L, object?> run = a =>
        {
            var inp = (D)a[0]!;
            return CibaClient.VerifyPingCallback(inp.GetValueOrDefault("authorization") as string, inp.GetValueOrDefault("body"), (D)a[1]!);
        };
        Base.Check(M, "verifyPingCallback", run);
        Base.Check(MJ, "verifyPingCallback", run);
    }

    static object? RedactToken(object? v, string nt) => nt.Length == 0 ? v : v switch
    {
        string s => s.Replace(nt, "<NTOKEN>", StringComparison.Ordinal),
        L l => new L(l.Select(x => RedactToken(x, nt))),
        D m => m.ToDictionary(e => e.Key, e => RedactToken(e.Value, nt)),
        _ => v,
    };

    static object ClientScenario(D s)
    {
        long[] clock = { T0 };
        var reqs = new L(); var sleeps = new L();
        var queue = new List<object?>((L)s["responses"]!);
        var cfg = ConfigOf((D)s["cfg"]!);
        cfg.Now = () => clock[0];
        cfg.Sleep = ms => { sleeps.Add(ms); clock[0] += ms; };
        cfg.Transport = (url, headers, body, timeoutMs) =>
        {
            reqs.Add(new D { ["url"] = url, ["method"] = "POST", ["headers"] = headers.ToDictionary(h => h.Key, h => (object?)h.Value), ["body"] = body });
            if (queue.Count == 0) throw new IOException("no scripted response");
            var resp = (D)queue[0]!;
            queue.RemoveAt(0);
            if (resp.GetValueOrDefault("fail") is true) throw new IOException("connection reset");
            var b = resp.GetValueOrDefault("body");
            return new CibaResponse((int)IntentJs.Lng(resp["status"]), b as string ?? GnapJs.Stringify(b));
        };
        var client = CibaClient.CreateCibaClient(cfg);
        CibaClient.Poller? poller = null;
        var trace = new L();
        var nt = "";
        foreach (var so in (L)s["steps"]!)
        {
            var st = (D)so!;
            var op = (string)st["op"]!;
            var entry = new D { ["op"] = op };
            try
            {
                object? value = null;
                switch (op)
                {
                    case "initiate":
                        {
                            var flow = client.Initiate((D)st["stepUp"]!, st.GetValueOrDefault("opts") as D);
                            poller = client.GetPoller(flow);
                            value = flow;
                            bool given = st.GetValueOrDefault("opts") is D od && od.ContainsKey("clientNotificationToken");
                            if (flow.GetValueOrDefault("clientNotificationToken") != null && !given) nt = (string)flow["clientNotificationToken"]!;
                            break;
                        }
                    case "poll": value = poller!.Poll(); break;
                    case "wait": value = poller!.Await(); break;
                    case "notify": poller!.NotifyPing(); break;
                    case "advance": clock[0] += IntentJs.Lng(st["ms"]); value = clock[0]; break;
                    case "interval": value = poller!.IntervalSec; break;
                    default: throw new InvalidOperationException("unknown step " + op);
                }
                entry["ok"] = true;
                entry["value"] = value;
            }
            catch (CibaProviderException e)
            {
                entry["ok"] = false;
                entry["error"] = e.Error;
                entry["status"] = e.Status;
                entry["retryable"] = e.Retryable;
                entry["errorDescription"] = e.ErrorDescription;
            }
            catch (Exception)
            {
                entry["ok"] = false;
                entry["other"] = true;
            }
            entry["requests"] = new L(reqs);
            reqs.Clear();
            entry["sleeps"] = new L(sleeps);
            sleeps.Clear();
            trace.Add(RedactToken(Base.Json(entry), nt));
        }
        return trace;
    }

    [Fact] public void ClientScenarios() => Base.Check(MJ, "clientScenario", a => ClientScenario((D)a[0]!));

    [Fact]
    public void NewClientNotificationTokenShape()
    {
        var t = CibaClient.NewClientNotificationToken();
        Assert.Matches(new System.Text.RegularExpressions.Regex(@"\A[A-Za-z0-9_-]{43}\z"), t);
        Assert.NotEqual(t, CibaClient.NewClientNotificationToken());
    }

    [Fact]
    public void EveryFnIsCovered()
    {
        Base.Covers(M, new[] { "cibaActionFromStepUp", "asciiForm", "requiresCiba", "toCibaAuthRequest", "cibaDecisionToCosign", "lifecycle", "verifyPingCallback" }); Assert.Equal(200, Base.Total(M));
        Base.Covers(MJ, new[] { "cibaActionFromStepUp", "asciiForm", "requiresCiba", "toCibaAuthRequest", "cibaDecisionToCosign", "brokerScenario", "durableBrokerConfig", "verifyPingCallback", "createCibaClientConfig", "clientScenario", "kvScenario" }); Assert.Equal(1129, Base.Total(MJ));
    }
}
