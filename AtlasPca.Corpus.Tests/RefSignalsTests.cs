using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using AtlasPca.Signals;
using Xunit;
using SignalsApi = AtlasPca.Signals.Signals;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the SSF / CAEP surface (SET build and verify, revocation state, replay store, receive path, standard revocations,
/// authorize() adapters, snapshot / restore, stream validation, health, verification, poll queue, management API) against the TypeScript reference
/// (test-data/ref-signals.json.gz). The reference mints SETs with a random jti and the wall clock, so a built SET is compared after decoding
/// (jti -> "&lt;uuid&gt;", a current iat -> "&lt;now&gt;") plus a signature check; the transmitter key is read back from the corpus arguments.</summary>
public class RefSignalsTests
{
    const string M = "ref-signals";

    /// <summary>The frozen clock the corpus generator ran under (its header's clockMs).</summary>
    static readonly double Clock = Base.ClockMs(M);

    // ---- the corpus' own keys / config (the oracle derives them from seeds the native side does not have) ----
    static D? _k1Priv, _k1Pub, _cfg;
    static D K1Priv => _k1Priv ??= (D)((D)Base.Args(Base.Of(M, "buildSETShape").First())[0]!)["keyJwk"]!;
    static D K1Pub => _k1Pub ??= (D)Base.Args(Base.Of(M, "verifySET").First())[1]!;
    static D Cfg => _cfg ??= (D)((D)((D)((D)Base.Args(Base.Of(M, "verificationScenario").First())[0]!)["streams"]!)["s1"]!)["config"]!;

    // ---- helpers ----
    static double Dbl(object? x) => x is Num n ? SignalsApi.V(n) : double.NaN;
    static double? DblOrNull(object? x) => x is Num n ? SignalsApi.V(n) : null;
    static Num N(double v) => new(SignalsApi.JsNum(v));
    static string? Code(Exception e) => e.GetType().GetProperty("Code")?.GetValue(e) as string;

    /// <summary>errOut of the oracle: an error marker, with the error's code unless it is a platform (ERR_ / N...) one.</summary>
    static D ErrOut(Exception e)
    {
        var o = new D { ["$err"] = true };
        if (Code(e) is string c && !c.StartsWith("ERR_", StringComparison.Ordinal) && !c.StartsWith('N')) o["code"] = c;
        return o;
    }

    static L Pairs(Dictionary<string, Num>? m) => m == null ? new L() : m.Select(e => (object?)new L { e.Key, e.Value }).ToList();

    static D StateJson(SetRevocationState st) => new() { ["grants"] = Pairs(st.RevokedGrants), ["agents"] = Pairs(st.KilledAgents), ["intents"] = st.RevokedIntentIds == null ? null : Pairs(st.RevokedIntentIds) };

    static D ParsedJson(ParsedSet p)
    {
        var o = new D { ["events"] = p.Events, ["iss"] = p.Iss, ["jti"] = p.Jti };
        if (p.Sub != null) o["sub"] = p.Sub;
        o["payload"] = p.Payload;
        return o;
    }

    static ParsedSet ParsedOf(object? p) => p is D d
        ? new ParsedSet { Events = d.GetValueOrDefault("events"), Iss = d.GetValueOrDefault("iss") as string, Jti = d.GetValueOrDefault("jti") as string, Payload = d.GetValueOrDefault("payload") }
        : throw new InvalidOperationException("Cannot read properties of null (reading 'events')");

    static readonly Regex Uuid = new("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", RegexOptions.CultureInvariant);

    /// <summary>The decoded SET with its volatile claims masked, and whether the transmitter key signed it.</summary>
    static D Shape(string set)
    {
        var parts = set.Split('.');
        var header = (D)FixtureJson.Parse(Encoding.UTF8.GetString(Pca.B64uDecode(parts[0])!))!;
        var payload = (D)FixtureJson.Parse(Encoding.UTF8.GetString(Pca.B64uDecode(parts[1])!))!;
        if (payload.GetValueOrDefault("iat") is Num iat && (Math.Abs(SignalsApi.V(iat) * 1000 - DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()) < 120_000 || Math.Abs(SignalsApi.V(iat) * 1000 - Clock) < 120_000)) payload["iat"] = "<now>";
        if (payload.GetValueOrDefault("jti") is string jti && Uuid.IsMatch(jti)) payload["jti"] = "<uuid>";
        var sigOk = Pca.VerifyEd25519Strict(Pca.B64uDecode(K1Priv["x"])!, Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), Pca.B64uDecode(parts[2])!);
        return new D { ["header"] = header, ["payload"] = payload, ["sigOk"] = sigOk };
    }

    static Func<D, object?>? Mapper(string name)
    {
        switch (name)
        {
            case "email": return x => x.GetValueOrDefault("format") is "email" && x.GetValueOrDefault("email") is string e ? e : null;
            case "throws": return _ => throw new InvalidOperationException("x");
            case "empty": return _ => "";
            case "num": return _ => 5;
            case "id": return x => x.GetValueOrDefault("id") as string;
            case "prefixed": return x => x.GetValueOrDefault("id") is string i ? $"agent:{i}" : null;
            default: throw new InvalidDataException("mapper " + name);
        }
    }

    static StandardRevocationOptions? StdOpts(object? sp)
    {
        if (sp is not D s) return null;
        var mapper = s.GetValueOrDefault("mapper") is string m && m != "default" ? Mapper(m) : null;
        return new StandardRevocationOptions { SubjectToAgent = mapper, FailOnUnmapped = s.GetValueOrDefault("fail") as bool? };
    }

    static Func<object?, object?, object?>? AgentOf(string? name)
    {
        if (name == null || name == "leaf") return null;
        if (name.StartsWith("const:", StringComparison.Ordinal)) return (_, _) => name[6..];
        switch (name)
        {
            case "throws": return (_, _) => throw new InvalidOperationException("x");
            case "empty": return (_, _) => "";
            case "num": return (_, _) => 5;
            case "grantId": return (_, g) => g is D gd ? gd.GetValueOrDefault("id") : null;
            default: throw new InvalidDataException("agentOf " + name);
        }
    }

    static VerifySetOptions VOpts(object? op) => op is not D o ? new() : new()
    {
        Issuer = o.GetValueOrDefault("issuer"),
        Audience = o.GetValueOrDefault("audience"),
        ClockTolerance = DblOrNull(o.GetValueOrDefault("clockTolerance")),
        CurrentDateMs = DblOrNull(o.GetValueOrDefault("currentDate")),
        Typ = o.GetValueOrDefault("typ") as string,
        RequireTyp = o.GetValueOrDefault("requireTyp") as bool?,
    };

    // ---------------------------------------------------------------- tests

    [Fact]
    public void Constants() => Base.Check(M, "constants", a => new D
    {
        ["SET_TYP"] = SignalsApi.SetTyp,
        ["SET_ALG"] = SignalsApi.SetAlg,
        ["EVENT_TYPES"] = new D
        {
            ["sessionRevoked"] = SignalsApi.EventTypes.SessionRevoked,
            ["credentialChange"] = SignalsApi.EventTypes.CredentialChange,
            ["grantRevoked"] = SignalsApi.EventTypes.GrantRevoked,
            ["killSwitch"] = SignalsApi.EventTypes.KillSwitch,
            ["intentRevoked"] = SignalsApi.EventTypes.IntentRevoked,
            ["verification"] = SignalsApi.EventTypes.Verification,
            ["riskLevelChange"] = SignalsApi.EventTypes.RiskLevelChange,
            ["assuranceLevelChange"] = SignalsApi.EventTypes.AssuranceLevelChange,
        },
        ["RISC_EVENT_TYPES"] = new D
        {
            ["sessionsRevoked"] = SignalsApi.RiscEventTypes.SessionsRevoked,
            ["accountDisabled"] = SignalsApi.RiscEventTypes.AccountDisabled,
            ["accountPurged"] = SignalsApi.RiscEventTypes.AccountPurged,
            ["credentialCompromise"] = SignalsApi.RiscEventTypes.CredentialCompromise,
        },
        ["SET_INMEMORY_MAX_ENTRIES"] = SignalsApi.SetInMemoryMaxEntries,
        ["DELIVERY_PUSH"] = SsfStream.DeliveryPush,
        ["DELIVERY_POLL"] = SsfStream.DeliveryPoll,
        ["STREAM_STATUSES"] = SsfStream.StreamStatuses.ToList(),
    });

    [Fact]
    public void VerifySet() => Base.Check(M, "verifySET", a =>
    {
        if (a.Count > 2 && a[2] == null) throw new ArgumentException("opts is null (a default applies only to undefined)");
        var r = SignalsApi.VerifySet(a[0], a[1], VOpts(a.Count > 2 ? a[2] : null));
        var o = new D { ["events"] = r.Events, ["iss"] = r.Iss, ["jti"] = r.Jti };
        if (r.Sub != null) o["sub"] = r.Sub;
        o["payload"] = r.Payload;
        return o;
    });

    [Fact]
    public void BuildSetShape() => Base.Check(M, "buildSETShape", a =>
    {
        var s = (D)a[0]!;
        if (s["events"] is not D events) throw new InvalidOperationException("buildSET: at least one event is required in the `events` map");
        return Shape(SignalsApi.BuildSet(events, (string)s["issuer"]!, s["audience"]!, s.GetValueOrDefault("subject") as string, s["keyJwk"]!));
    });

    [Fact]
    public void State() => Base.Check(M, "stateScenario", a =>
    {
        var spec = (D)a[0]!;
        var st = SignalsApi.CreateRevocationState();
        var outl = new L();
        foreach (var o in (L)spec["ops"]!)
        {
            var s = (D)o!;
            try
            {
                object? r;
                var target = s.GetValueOrDefault("badState") is true ? null : st;
                switch ((string)s["op"]!)
                {
                    case "apply": SignalsApi.ApplySet(st, ParsedOf(s["parsed"])); r = StateJson(st); break;
                    case "applyStd":
                        {
                            var plan = SignalsApi.ApplyStandardRevocations(target, ParsedOf(s["parsed"]), StdOpts(s.GetValueOrDefault("std")));
                            r = new D { ["plan"] = PlanJson(plan), ["state"] = StateJson(st) };
                            break;
                        }
                    case "plan": r = PlanJson(SignalsApi.PlanStandardRevocations(ParsedOf(s["parsed"]), StdOpts(s.GetValueOrDefault("std")))); break;
                    case "isRevoked": r = SignalsApi.IsRevoked(st, (string)s["grant"]!, s.GetValueOrDefault("agent") as string); break;
                    case "isIntentRevoked": r = SignalsApi.IsIntentRevoked(st, (string)s["id"]!); break;
                    case "stream":
                        {
                            if (s["sets"] is not L sets) throw new InvalidOperationException("parsedSets is not iterable");
                            var res = SignalsApi.StreamProcessor(sets.Select(ParsedOf).ToList(), s.GetValueOrDefault("useState") is true ? st : null);
                            r = StateJson(res);
                            break;
                        }
                    case "snapshot": r = SignalsApi.SnapshotRevocationState(target); break;
                    case "restore":
                        {
                            var snap = s.GetValueOrDefault("snapshot");
                            var res = s.GetValueOrDefault("fresh") is true ? SignalsApi.RestoreRevocationState(snap)
                                : s.GetValueOrDefault("nullInto") is true ? SignalsApi.RestoreRevocationState(snap, null)
                                : SignalsApi.RestoreRevocationState(snap, target);
                            r = StateJson(res);
                            break;
                        }
                    default: throw new InvalidOperationException("bad op");
                }
                outl.Add(JsonOf(r));
            }
            catch (Exception e) { outl.Add(ErrOut(e)); }
        }
        outl.Add(StateJson(st));
        return outl;
    });

    /// <summary>The oracle's <c>JSON.parse(JSON.stringify(v))</c> of every operation result: a negative zero comes back as 0 (the final state is not passed through it).</summary>
    static object? JsonOf(object? v) => v switch
    {
        Num n when IntentJs.NumOf(n) is double d && IntentJs.IsNegZero(d) => new Num("0"),
        double d when IntentJs.IsNegZero(d) => 0L,
        D m => m.ToDictionary(e => e.Key, e => JsonOf(e.Value)),
        L l => l.Select(JsonOf).ToList(),
        _ => v,
    };

    static D PlanJson(StandardRevocationPlan p) => new()
    {
        ["agents"] = p.Agents.Select(x => (object?)new L { x.Agent, x.Timestamp }).ToList(),
        ["unmapped"] = p.Unmapped.Select(x => (object?)x).ToList(),
    };

    sealed class FuncStore(Func<string, double, double, bool> f) : ISetReplayStore
    {
        public bool AddIfAbsent(string jti, double expiresAtSec, double nowSec) => f(jti, expiresAtSec, nowSec);
    }

    [Fact]
    public void ReplayStore()
    {
        Base.Check(M, "replayScenario", a =>
        {
            var spec = (D)a[0]!;
            var outl = new L();
            ISetReplayStore store;
            try { store = SignalsApi.CreateInMemorySetReplayStore((spec.GetValueOrDefault("opts") as D)?.GetValueOrDefault("maxEntries")); }
            catch (Exception e) { return new L { ErrOut(e) }; }
            foreach (var o in (L)spec["ops"]!)
            {
                var t = (L)o!;
                try { outl.Add(store.AddIfAbsent((string)t[0]!, Dbl(t[1]), Dbl(t[2]))); }
                catch (Exception) { outl.Add(new D { ["$err"] = true }); }
            }
            return outl;
        });
        Base.Check(M, "replayConformance", a =>
        {
            var spec = (D)a[0]!;
            var gate = new object();
            var seen = new HashSet<string>();
            Func<ISetReplayStore> make = (string)spec["store"]! switch
            {
                "alwaysTrue" => () => new FuncStore((_, _, _) => true),
                "alwaysFalse" => () => new FuncStore((_, _, _) => false),
                "noExpiry" => () => new FuncStore((j, _, _) => { lock (gate) return seen.Add(j); }),
                _ => () => SignalsApi.CreateInMemorySetReplayStore((spec.GetValueOrDefault("opts") as D)?.GetValueOrDefault("maxEntries")),
            };
            return SignalsApi.RunSetReplayStoreConformance(make);
        });
    }

    [Fact]
    public void Receive() => Base.Check(M, "receiveScenario", a =>
    {
        var spec = (D)a[0]!;
        var st = SignalsApi.CreateRevocationState();
        ISetReplayStore store = spec["store"] switch
        {
            "throws" => new FuncStore((_, _, _) => throw new InvalidOperationException("boom")),
            "false" => new FuncStore((_, _, _) => false),
            "mem1" => SignalsApi.CreateInMemorySetReplayStore(new Num("1")),
            _ => SignalsApi.CreateInMemorySetReplayStore(),
        };
        var outl = new L();
        foreach (var o in (L)spec["deliveries"]!)
        {
            var d = (D)o!;
            var op = d.GetValueOrDefault("opts") as D ?? new D();
            var opts = d.GetValueOrDefault("noOpts") is true ? null : new ReceiveSetOptions
            {
                Issuer = op.GetValueOrDefault("issuer"),
                Audience = op.GetValueOrDefault("audience"),
                ReplayStore = d.GetValueOrDefault("noStore") is true ? null : store,
                State = d.GetValueOrDefault("noState") is true ? null : st,
                MaxAgeSec = DblOrNull(op.GetValueOrDefault("maxAgeSec")),
                ClockSkewSec = DblOrNull(op.GetValueOrDefault("clockSkewSec")),
                NowSec = DblOrNull(op.GetValueOrDefault("nowSec")),
                MaxBytes = DblOrNull(op.GetValueOrDefault("maxBytes")),
                StandardRevocations = d.ContainsKey("std") ? StdOpts(d["std"]) ?? new StandardRevocationOptions() : null,
            };
            object? r;
            try
            {
                var key = d.ContainsKey("key") ? d["key"] : K1Pub;
                var res = SignalsApi.ReceiveSet(d["set"], key, opts);
                if (res.Ok) r = new D { ["ok"] = true, ["parsed"] = ParsedJson(res.Parsed!) };
                else r = new D { ["ok"] = false, ["code"] = res.Code, ["reason"] = res.Code == "verify_failed" && !res.Reason!.StartsWith("SET invalid:", StringComparison.Ordinal) ? "<jose>" : res.Reason };
            }
            catch (Exception) { r = new D { ["$err"] = true }; }
            outl.Add(r);
        }
        outl.Add(StateJson(st));
        return outl;
    });

    [Fact]
    public void Adapters() => Base.Check(M, "adapterScenario", a =>
    {
        var spec = (D)a[0]!;
        var agentOf = AgentOf(spec.GetValueOrDefault("agentOf") as string);
        Func<object?, object?, RevocationHookResult> hook;
        Func<object?, object?, bool> isRev;
        try
        {
            SetRevocationState? st = spec.ContainsKey("badState") ? null : SignalsApi.RestoreRevocationState(new D
            {
                ["v"] = new Num("1"),
                ["grants"] = spec.GetValueOrDefault("grants") ?? new L(),
                ["agents"] = spec.GetValueOrDefault("agents") ?? new L(),
                ["intents"] = new L(),
            });
            hook = SignalsApi.CreateRevocationHook(st, new RevocationAdapterOptions { AgentOf = agentOf });
            isRev = SignalsApi.CreateIsRevoked(st, new RevocationAdapterOptions { AgentOf = agentOf });
        }
        catch (Exception e) { return new L { ErrOut(e) }; }
        var outl = new L();
        foreach (var o in (L)spec["calls"]!)
        {
            var c = (D)o!;
            var pcactn = c.GetValueOrDefault("pcactn");
            var grant = c.GetValueOrDefault("grant");
            object? ha, hb;
            try
            {
                var h = hook(pcactn, grant);
                var d = new D { ["enforced"] = h.Enforced, ["ok"] = h.Ok };
                if (h.Reason != null) d["reason"] = h.Reason;
                ha = d;
            }
            catch (Exception) { ha = new D { ["$err"] = true }; }
            try { hb = isRev(grant, pcactn); }
            catch (Exception) { hb = new D { ["$err"] = true }; }
            outl.Add(new D { ["hook"] = ha, ["isRevoked"] = hb });
        }
        return outl;
    });

    [Fact]
    public void StreamConfig() => Base.Check(M, "validateStreamConfig", a => SsfStream.ValidateStreamConfig(a[0]));

    [Fact]
    public void Health() => Base.Check(M, "healthScenario", a =>
    {
        var spec = (D)a[0]!;
        var op = spec.GetValueOrDefault("opts") as D;
        var h = new SsfStream.StreamHealth(spec.GetValueOrDefault("config") as D ?? Cfg, op == null ? null : new StreamHealthOptions
        {
            VerifyTimeoutSec = DblOrNull(op.GetValueOrDefault("verifyTimeoutSec")),
            VerifiedWithinSec = DblOrNull(op.GetValueOrDefault("verifiedWithinSec")),
            FailAfter = DblOrNull(op.GetValueOrDefault("failAfter")),
            MaxPending = DblOrNull(op.GetValueOrDefault("maxPending")),
        });
        var issued = new List<string>();
        var outl = new L();
        foreach (var o in (L)spec["ops"]!)
        {
            var s = (D)o!;
            try
            {
                object? r = null;
                switch ((string)s["op"]!)
                {
                    case "status": h.SetStatus(s.GetValueOrDefault("v") as string); break;
                    case "event": h.RecordEvent(Dbl(s.GetValueOrDefault("now"))); break;
                    case "request":
                        if (h.RequestVerification(Dbl(s.GetValueOrDefault("now"))) is string st) { issued.Add(st); r = $"<state:{issued.Count - 1}>"; }
                        break;
                    case "ack":
                        {
                            object? state = s.ContainsKey("ref") ? (s["ref"] is Num rn && (int)SignalsApi.V(rn) is var ri && ri >= 0 && ri < issued.Count ? issued[ri] : null) : s.GetValueOrDefault("state");
                            r = h.AckVerification(state, Dbl(s.GetValueOrDefault("now")));
                            break;
                        }
                    case "report":
                        {
                            var rep = h.Report(Dbl(s.GetValueOrDefault("now")));
                            var d = new D { ["state"] = rep.State, ["status"] = rep.Status, ["reasons"] = rep.Reasons.Select(x => (object?)x).ToList(), ["pending_verifications"] = rep.PendingVerifications,
                                ["consecutive_verification_failures"] = rep.ConsecutiveVerificationFailures, ["rejected_verifications"] = rep.RejectedVerifications };
                            if (rep.LastEventAt != null) d["last_event_at"] = N(rep.LastEventAt.Value);
                            if (rep.LastVerifiedAt != null) d["last_verified_at"] = N(rep.LastVerifiedAt.Value);
                            r = d;
                            break;
                        }
                    case "fresh": r = h.RevocationFreshWithin(Dbl(s.GetValueOrDefault("max")), Dbl(s.GetValueOrDefault("now"))); break;
                    default: throw new InvalidOperationException("bad op");
                }
                outl.Add(r);
            }
            catch (Exception) { outl.Add(new D { ["$err"] = true }); }
        }
        return outl;
    });

    [Fact]
    public void Verification() => Base.Check(M, "verificationScenario", a =>
    {
        var spec = (D)a[0]!;
        var streams = new Dictionary<string, StreamEntry>();
        foreach (var (id, v) in (D)(spec.GetValueOrDefault("streams") ?? new D())!)
        {
            var sd = (D)v!;
            streams[id] = new StreamEntry { Config = sd.GetValueOrDefault("config") is D c ? (D)StreamRecord.Deep(c)! : null, LastVerification = DblOrNull(sd.GetValueOrDefault("lastVerification")) };
        }
        var outl = new L();
        foreach (var o in (L)spec["ops"]!)
        {
            var s = (D)o!;
            object? r;
            try
            {
                var res = SsfStream.HandleVerificationRequest(streams, s.GetValueOrDefault("req"), Dbl(s.GetValueOrDefault("now")), s.GetValueOrDefault("noKey") is true ? null : K1Priv);
                r = res.Status == 204 ? new D { ["status"] = 204, ["set"] = Shape(res.Set!) } : new D { ["status"] = res.Status, ["error"] = res.Error };
            }
            catch (Exception) { r = new D { ["$err"] = true }; }
            outl.Add(r);
        }
        outl.Add(streams.ToDictionary(e => e.Key, e => e.Value.LastVerification is double lv ? (object?)N(lv) : null));
        return outl;
    });

    [Fact]
    public void Poll() => Base.Check(M, "pollScenario", a =>
    {
        var spec = (D)a[0]!;
        var q = new SsfStream.PollQueue();
        var outl = new L();
        foreach (var o in (L)spec["ops"]!)
        {
            var s = (D)o!;
            try
            {
                object? r = null;
                if (s.GetValueOrDefault("enqueue") is L e) q.Enqueue((string)e[0]!, (string)e[1]!);
                else if (s.ContainsKey("depth")) r = q.Depth;
                else r = q.Poll(s.GetValueOrDefault("poll"));
                outl.Add(r);
            }
            catch (Exception) { outl.Add(new D { ["$err"] = true }); }
        }
        outl.Add(new D { ["depth"] = q.Depth, ["errors"] = q.Errors.Select(x => (object?)x).ToList() });
        return outl;
    });

    [Fact]
    public void PushAndCaep()
    {
        Base.Check(M, "pushResponse", a => SsfStream.PushResponse(a[0]));
        Base.Check(M, "caepSET", a =>
        {
            var s = (D)a[0]!;
            var ev = (D)s["event"]!;
            var set = (string)s["kind"]! == "risk"
                ? SsfStream.RiskLevelChangeSet((string)s["issuer"]!, s["audience"]!, s["keyJwk"]!, ev)
                : SsfStream.AssuranceLevelChangeSet((string)s["issuer"]!, s["audience"]!, s["keyJwk"]!, ev, s.GetValueOrDefault("order"));
            return Shape(set);
        });
        Base.Check(M, "transmitterMetadata", a =>
        {
            var o = (D)a[0]!;
            var dm = o.GetValueOrDefault("deliveryMethods") is L l ? l.Select(x => (string)x!).ToList() : null;
            return SsfManage.TransmitterMetadata((string)o["issuer"]!, dm, (string)a[1]!, a.Count > 2 ? a[2] as string : null);
        });
    }

    [Fact]
    public void Manage() => Base.Check(M, "manageScenario", a =>
    {
        var spec = (D)a[0]!;
        var store = new MemoryStreamStore();
        var delivered = new L();
        int ids = 0;
        double now = 0;
        object? rcvSpec = null;
        var so = spec.GetValueOrDefault("options") as D ?? new D();
        var h = SsfManage.Handler(new SsfManageOptions
        {
            Store = store,
            Issuer = "https://tx.example",
            EventsSupported = spec.GetValueOrDefault("eventsSupported") is L es ? es.Select(x => (string)x!).ToList()
                : new List<string> { SignalsApi.EventTypes.GrantRevoked, SignalsApi.EventTypes.KillSwitch, SignalsApi.EventTypes.SessionRevoked },
            DeliveryMethods = so.GetValueOrDefault("deliveryMethods") is L dm ? dm.Select(x => (string)x!).ToList() : null,
            PollEndpoint = id => $"https://tx.example/poll/{id}",
            SigningKey = K1Priv,
            Deliver = (stream, set) => delivered.Add(new D { ["stream"] = stream.ToJson(), ["set"] = Shape(set) }),
            MaxStreamsPerReceiver = DblOrNull(so.GetValueOrDefault("maxStreamsPerReceiver")),
            MaxSubjectsPerStream = DblOrNull(so.GetValueOrDefault("maxSubjectsPerStream")),
            Now = () => now,
            NewId = () => $"s{++ids}",
        }, _ =>
        {
            if (rcvSpec is "throws") throw new InvalidOperationException("auth");
            return rcvSpec is D r ? new Receiver((string)r["id"]!, r["aud"]!) : null;
        });
        var outl = new L();
        foreach (var o in (L)spec["steps"]!)
        {
            var st = (D)o!;
            now = st.TryGetValue("now", out var nv) && nv != null ? Dbl(nv) : 1000;
            rcvSpec = st.ContainsKey("rcv") ? st["rcv"] : new D { ["id"] = "rx1", ["aud"] = "rx" };
            object? r;
            try
            {
                var res = h(st.GetValueOrDefault("req"));
                var d = new D { ["status"] = res.Status };
                if (res.Body != null) d["body"] = res.Body;
                r = d;
            }
            catch (Exception) { r = new D { ["$err"] = true }; }
            outl.Add(r);
        }
        var dump = new D();
        foreach (var rid in spec.GetValueOrDefault("receivers") is L rl ? rl.Select(x => (string)x!) : new[] { "rx1", "rx2" })
            dump[rid] = store.ListByReceiver(rid).Select(e => (object?)new L { e.Id, e.Record.ToJson() }).ToList();
        outl.Add(new D { ["delivered"] = delivered, ["store"] = dump });
        return outl;
    });

    [Fact]
    public void AllFunctionsCovered() { Base.Covers(M, new[]
    {
        "constants", "verifySET", "buildSETShape", "stateScenario", "replayScenario", "replayConformance", "receiveScenario", "adapterScenario",
        "validateStreamConfig", "healthScenario", "verificationScenario", "pollScenario", "pushResponse", "caepSET", "transmitterMetadata", "manageScenario",
    }); Assert.Equal(2465, Base.Total(M)); }
}
