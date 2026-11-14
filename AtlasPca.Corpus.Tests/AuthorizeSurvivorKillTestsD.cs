using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using AtlasPca;
using Xunit;
using static AtlasPca.Corpus.Tests.Conf;
using JD = System.Collections.Generic.Dictionary<string, object?>;
using JL = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Survivors of Authorize.cs in the SQL pin / budget statements, the budget key, and the authorize pipeline from the Intent v2 provider
/// to the replay read: revocation, rollback pin, beacon, taint, forbid, contract, template, freshness gate, principal, passport, plan root,
/// reversibility, the policy context and the delegated caveats. Wording pinned to packages/pca/src/server/authorize.ts.</summary>
public class AuthorizeSurvivorKillTestsD
{
    // ================= SqlStateStore pins and budgets over a strict fake =================

    sealed class Db
    {
        public readonly string T;
        public readonly Dictionary<string, long> Pins = new(StringComparer.Ordinal);
        public readonly Dictionary<string, string> Budgets = new(StringComparer.Ordinal);
        public bool NullAsDbNull;
        public Db(string table) { T = table; }

        string SelPin => $"SELECT pin FROM {T}_pin WHERE key = @key";
        string InsPin => $"INSERT INTO {T}_pin (key, pin) VALUES (@key, @pin) ON CONFLICT(key) DO UPDATE SET pin = excluded.pin WHERE excluded.pin > {T}_pin.pin";
        string SelB => $"SELECT value FROM {T}_budget WHERE key = @key";
        string InsB => $"INSERT INTO {T}_budget (key, value) VALUES (@key, @v) ON CONFLICT(key) DO NOTHING";
        string UpdB => $"UPDATE {T}_budget SET value = @v WHERE key = @key AND value = @old";

        public int Exec(string sql, Cmd c)
        {
            if (sql == InsPin)
            {
                var k = c.Str("@key"); var n = c.Lng("@pin");
                if (Pins.TryGetValue(k, out var cur) && !(n > cur)) return 0;
                Pins[k] = n;
                return 1;
            }
            if (sql == InsB)
            {
                var k = c.Str("@key");
                if (Budgets.ContainsKey(k)) return 0;
                Budgets[k] = c.Str("@v");
                return 1;
            }
            if (sql == UpdB)
            {
                var k = c.Str("@key");
                if (!Budgets.TryGetValue(k, out var cur) || cur != c.Str("@old")) return 0;
                Budgets[k] = c.Str("@v");
                return 1;
            }
            throw new InvalidOperationException("unexpected SQL: " + sql);
        }

        public object? Scalar(string sql, Cmd c)
        {
            object? None() => NullAsDbNull ? DBNull.Value : null;
            if (sql == SelPin) return Pins.TryGetValue(c.Str("@key"), out var v) ? (object)v : None();
            if (sql == SelB) return Budgets.TryGetValue(c.Str("@key"), out var b) ? b : None();
            throw new InvalidOperationException("unexpected SQL: " + sql);
        }
    }

    sealed class Conn : DbConnection
    {
        readonly Db _db;
        ConnectionState _state = ConnectionState.Closed;
        public Conn(Db db) => _db = db;
        [AllowNull] public override string ConnectionString { get; set; } = "";
        public override string Database => "fake";
        public override string DataSource => "fake";
        public override string ServerVersion => "0";
        public override ConnectionState State => _state;
        public override void Open() => _state = ConnectionState.Open;
        public override void Close() => _state = ConnectionState.Closed;
        public override void ChangeDatabase(string databaseName) { }
        protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel) => throw new NotSupportedException();
        protected override DbCommand CreateDbCommand() => new Cmd(_db) { Connection = this };
    }

    sealed class Cmd : DbCommand
    {
        readonly Db _db;
        readonly Params _ps = new();
        public Cmd(Db db) => _db = db;
        [AllowNull] public override string CommandText { get; set; } = "";
        public override int CommandTimeout { get; set; }
        public override CommandType CommandType { get; set; }
        public override bool DesignTimeVisible { get; set; }
        public override UpdateRowSource UpdatedRowSource { get; set; }
        protected override DbConnection? DbConnection { get; set; }
        protected override DbParameterCollection DbParameterCollection => _ps;
        protected override DbTransaction? DbTransaction { get; set; }
        public override void Cancel() { }
        public override void Prepare() { }
        protected override DbParameter CreateDbParameter() => new Prm();
        protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior) => throw new NotSupportedException();
        public override int ExecuteNonQuery() => _db.Exec(CommandText, this);
        public override object? ExecuteScalar() => _db.Scalar(CommandText, this);

        object? Val(string name)
        {
            int i = _ps.IndexOf(name);
            if (i < 0) throw new InvalidOperationException("missing parameter " + name);
            return _ps[i].Value;
        }
        public long Lng(string name) => (long)Val(name)!;
        public string Str(string name) => (string)Val(name)!;
    }

    sealed class Prm : DbParameter
    {
        public override DbType DbType { get; set; }
        public override ParameterDirection Direction { get; set; }
        public override bool IsNullable { get; set; }
        [AllowNull] public override string ParameterName { get; set; } = "";
        public override int Size { get; set; }
        [AllowNull] public override string SourceColumn { get; set; } = "";
        public override bool SourceColumnNullMapping { get; set; }
        public override object? Value { get; set; }
        public override void ResetDbType() { }
    }

    sealed class Params : DbParameterCollection
    {
        readonly List<DbParameter> _l = new();
        public override int Count => _l.Count;
        public override object SyncRoot => _l;
        public override int Add(object value) { _l.Add((DbParameter)value); return _l.Count - 1; }
        public override void AddRange(Array values) { foreach (var v in values) Add(v!); }
        public override void Clear() => _l.Clear();
        public override bool Contains(object value) => _l.Contains((DbParameter)value);
        public override bool Contains(string value) => IndexOf(value) >= 0;
        public override void CopyTo(Array array, int index) => ((System.Collections.ICollection)_l).CopyTo(array, index);
        public override System.Collections.IEnumerator GetEnumerator() => _l.GetEnumerator();
        public override int IndexOf(object value) => _l.IndexOf((DbParameter)value);
        public override int IndexOf(string parameterName) => _l.FindIndex(p => p.ParameterName == parameterName);
        public override void Insert(int index, object value) => _l.Insert(index, (DbParameter)value);
        public override void Remove(object value) => _l.Remove((DbParameter)value);
        public override void RemoveAt(int index) => _l.RemoveAt(index);
        public override void RemoveAt(string parameterName) => _l.RemoveAt(IndexOf(parameterName));
        protected override DbParameter GetParameter(int index) => _l[index];
        protected override DbParameter GetParameter(string parameterName) => _l[IndexOf(parameterName)];
        protected override void SetParameter(int index, DbParameter value) => _l[index] = value;
        protected override void SetParameter(string parameterName, DbParameter value) => _l[IndexOf(parameterName)] = value;
    }

    static (SqlStateStore Store, Db Db) Sql()
    {
        var db = new Db("tbl");
        return (new SqlStateStore(() => new Conn(db), "tbl"), db);
    }

    const string PinMsg = "RaisePin needs a non-empty key and 0 <= value <= 2^53-1";

    [Fact]
    public void SqlPinReadsNullForAMissingRowAndTheStoredValueOtherwise()
    {
        foreach (var dbNull in new[] { false, true })
        {
            var (s, db) = Sql();
            db.NullAsDbNull = dbNull;
            Assert.Null(s.Pin("k"));
            Assert.Equal(5, s.RaisePin("k", 5));
            Assert.Equal(5L, s.Pin("k"));
            Assert.Equal(5L, db.Pins["k"]);
            Assert.Null(s.Pin("other"));
        }
    }

    [Fact]
    public void SqlRaisePinOnlyRaisesAndReturnsTheStoredValue()
    {
        var (s, db) = Sql();
        Assert.Equal(5, s.RaisePin("k", 5));
        Assert.Equal(5, s.RaisePin("k", 3)); // the statement does not lower; the read returns the stored value
        Assert.Equal(5L, db.Pins["k"]);
        Assert.Equal(5, s.RaisePin("k", 5));
        Assert.Equal(9, s.RaisePin("k", 9));
        Assert.Equal(9L, s.Pin("k"));
        Assert.Equal(0, s.RaisePin("zero", 0)); // 0 is a valid pin
        Assert.Equal(0L, s.Pin("zero"));
        Assert.Equal(Pca.MaxSafeInt, s.RaisePin("max", Pca.MaxSafeInt)); // 2^53-1 is the inclusive top
        Assert.Equal(Pca.MaxSafeInt, s.Pin("max"));
    }

    [Fact]
    public void SqlRaisePinRefusesEachOutOfRangeArgumentSeparately()
    {
        var (s, db) = Sql();
        Assert.Equal(PinMsg, Assert.Throws<ArgumentException>(() => s.RaisePin("", 1)).Message);
        Assert.Equal(PinMsg, Assert.Throws<ArgumentException>(() => s.RaisePin(null!, 1)).Message);
        Assert.Equal(PinMsg, Assert.Throws<ArgumentException>(() => s.RaisePin("k", -1)).Message);
        Assert.Equal(PinMsg, Assert.Throws<ArgumentException>(() => s.RaisePin("k", Pca.MaxSafeInt + 1)).Message);
        Assert.Empty(db.Pins); // nothing was written by a refused call
    }

    [Fact]
    public void SqlBudgetRoundTripsAndComparesAndSwapsOnTheStoredText()
    {
        var (s, db) = Sql();
        Assert.Null(s.Budget("k"));
        var b0 = new TrustBudget(0.5, 1, 100);
        Assert.True(s.BudgetCas("k", null, b0));
        Assert.Equal("0.5|1|100", db.Budgets["k"]);
        Assert.Equal(b0, s.Budget("k"));
        Assert.False(s.BudgetCas("k", null, new TrustBudget(9, 9, 9))); // an existing row is never replaced by an insert
        Assert.Equal(b0, s.Budget("k"));
        var b1 = new TrustBudget(0.25, 2, 200);
        Assert.False(s.BudgetCas("k", new TrustBudget(0.5, 1, 101), b1)); // the old text must match
        Assert.True(s.BudgetCas("k", b0, b1));
        Assert.False(s.BudgetCas("k", b0, new TrustBudget(7, 7, 7)));
        Assert.Equal(b1, s.Budget("k"));
        Assert.Equal("0.25|2|200", db.Budgets["k"]);
    }

    [Fact]
    public void SqlBudgetWithoutAsOfIsStoredAsNaNAndReadBackAsNull()
    {
        var (s, db) = Sql();
        var noAsOf = new TrustBudget(0.25, 2);
        Assert.True(s.BudgetCas("k", null, noAsOf));
        Assert.Equal("0.25|2|NaN", db.Budgets["k"]);
        var back = s.Budget("k")!;
        Assert.Null(back.AsOf);
        Assert.Equal(noAsOf, back);
        db.Budgets["bad"] = "1|2"; // a malformed row reads as no budget
        Assert.Null(s.Budget("bad"));
        db.NullAsDbNull = true;
        Assert.Null(s.Budget("missing"));
    }

    // ================= BudgetKeyOf =================

    static string BudgetKey(string? aud, JD grant, string grantRef, JD p) =>
        (string)typeof(Pca).GetMethod("BudgetKeyOf", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, new object?[] { aud, grant, grantRef, p })!;

    [Fact]
    public void TheBudgetKeyNamesAudienceGrantAndLeafHolder()
    {
        var p = new JD { ["cap_chain"] = new JL { new JD { ["holder"] = "h0" }, new JD { ["holder"] = "h1" } } };
        Assert.Equal("aud:a%20b:g1:h1:budget", BudgetKey("a b", new JD { ["id"] = "g1" }, "ref", p));
        Assert.Equal("aud::ref::budget", BudgetKey(null, new JD(), "ref", new JD())); // no audience, no id: the reference; no chain: no holder
        Assert.Equal("aud:x:g1::budget", BudgetKey("x", new JD { ["id"] = "g1" }, "ref", new JD { ["cap_chain"] = new JL() }));
        Assert.Equal("aud:x:ref::budget", BudgetKey("x", new JD { ["id"] = 5L }, "ref", new JD())); // a non-string id falls back to the reference
        Assert.Equal("aud:x:g1::budget", BudgetKey("x", new JD { ["id"] = "g1" }, "other", new JD { ["cap_chain"] = new JL { new JD { ["holder"] = 3L } } }));
    }

    // ================= pipeline harness =================

    const long Now = 1_800_000_000_000L;
    const string Aud = "ins_kill_d";
    static SuiteKey P => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x91, 32).ToArray()));
    static SuiteKey Me => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x92, 32).ToArray()));
    static SuiteKey Sub => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x93, 32).ToArray()));
    static SuiteKey Third => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x94, 32).ToArray()));

    static JD Amt() => new() { ["amount"] = 5L };

    static JD Env(JL? caveats = null, JL? predicates = null) => new()
    {
        ["predicates"] = predicates ?? new JL { new JD { ["verb"] = "*" } }, ["caveats"] = caveats ?? new JL(), ["risk_policy"] = Issue.DefaultRiskPolicy(),
    };

    static JD Grant(JL? caveats = null, JL? predicates = null) => Issue.MintGrant(P, Me.Id!, null, Env(caveats, predicates), "kill d").Grant;
    static Agent AgentOf(JD grant) => new(Me, Aud, grant, null, 0) { Clock = () => Now };
    static JD Act(JD grant, JD? slots = null) => AgentOf(grant).Act("pay", "inv/1", Amt(), slots);
    static JD Expires(long at) => new() { ["type"] = "expires", ["at"] = at };

    static AuthorizeInput Input(JD grant, IStateStore? store = null)
    {
        var g = Issue.NormJ(grant);
        return new AuthorizeInput
        {
            Operation = new Operation("pay", "inv/1", Amt()), Audience = Aud, ResolveGrant = id => id == (string)g["id"]! ? g : null,
            StateStore = store ?? new MemoryStateStore(), IsRevoked = (_, _) => false, Now = Now, Plan = "single-step", ServerRisk = ProvHarness.LowRisk,
        };
    }

    static AuthorizeResult Run(JD grant, Action<AuthorizeInput>? cfg = null, JD? pcactn = null, IStateStore? store = null)
    {
        var i = Input(grant, store);
        cfg?.Invoke(i);
        return Pca.Authorize(Issue.Encode(pcactn ?? Act(grant)), i.WithProv());
    }

    static string Gid(JD grant) => (string)grant["id"]!;

    /// <summary>A memory store that answers the pin / budget / last sides, with a switch that makes the pin read fail.</summary>
    sealed class Wrap : IStateStore, ILastStore, IPinStore, IBudgetStore
    {
        public readonly MemoryStateStore M = new();
        public bool ThrowPin, ThrowRaise;
        public ClaimResult? Claim(string key, long counter) => M.Claim(key, counter);
        public long? Last(string key) => M.Last(key);
        public long? Pin(string key) => ThrowPin ? throw new InvalidOperationException("down") : M.Pin(key);
        public long RaisePin(string key, long value) => ThrowRaise ? throw new InvalidOperationException("down") : M.RaisePin(key, value);
        public TrustBudget? Budget(string key) => M.Budget(key);
        public bool BudgetCas(string key, TrustBudget? old, TrustBudget @new) => M.BudgetCas(key, old, @new);
    }

    sealed class ClaimOnly : IStateStore
    {
        readonly MemoryStateStore _m = new();
        public ClaimResult? Claim(string key, long counter) => _m.Claim(key, counter);
    }

    [Fact]
    public void TheBaselineAllows()
    {
        var g = Grant();
        var r = Run(g);
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("pass", r.Checks["revocation"]);
        Assert.Equal("pass", r.Checks["operation"]);
        Assert.Equal("pass", r.Checks["delegated_caveats"]);
        Assert.Equal("pass", r.Checks["policy"]);
        Assert.Equal("not-enforced", r.Checks["taint_gate"]);
        Assert.Equal("not-enforced", r.Checks["beacon"]);
        Assert.False(r.Checks.ContainsKey("pq_pin"));
        Assert.False(r.Checks.ContainsKey("forbid"));
        Assert.False(r.Checks.ContainsKey("contract"));
        Assert.False(r.Checks.ContainsKey("template"));
        Assert.False(r.Checks.ContainsKey("principal"));
        Assert.False(r.Checks.ContainsKey("passport"));
        Assert.False(r.Checks.ContainsKey("freshness"));
        Assert.False(r.Checks.ContainsKey("reversibility"));
        Assert.False(r.Checks.ContainsKey("attestation"));
    }

    // ================= the Intent v2 provider: the async result wins over the sync one =================

    [Fact]
    public async Task AnAsyncProviderResultWinsOverTheSyncProvider()
    {
        var g = Grant();
        var i = Input(g);
        i.IntentV2ProviderAsync = _ => Task.FromResult<IntentV2Context?>(null);
        i.IntentV2Provider = _ => throw new InvalidOperationException("never asked");
        var r = await Pca.AuthorizeAsync(Issue.Encode(Act(g)), i.WithProv());
        Assert.True(r.Allow, r.Reason);
        var g2 = Grant();
        var j = Input(g2);
        j.IntentV2Provider = _ => throw new InvalidOperationException("down");
        var denied = await Pca.AuthorizeAsync(Issue.Encode(Act(g2)), j.WithProv());
        Assert.False(denied.Allow);
        Assert.Equal(403, denied.Status);
        Assert.Equal(new[] { "intent_v2: verifier state unavailable (fail closed)" }, denied.Reasons);
    }

    // ================= revocation (required) =================

    [Fact]
    public void RevocationPassesOnlyOnAnExplicitFalse()
    {
        var g = Grant();
        var revoked = Run(g, i => i.IsRevoked = (_, _) => true);
        Assert.False(revoked.Allow);
        Assert.Equal("fail", revoked.Checks["revocation"]);
        Assert.Contains("revocation: the grant is revoked", revoked.Reasons);
        var g2 = Grant();
        var unknown = Run(g2, i => i.IsRevoked = (_, _) => null);
        Assert.Equal("fail", unknown.Checks["revocation"]);
        Assert.Contains("revocation: the revocation check failed (fail closed)", unknown.Reasons);
        var g3 = Grant();
        var thrown = Run(g3, i => i.IsRevoked = (_, _) => throw new InvalidOperationException("down"));
        Assert.False(thrown.Allow);
        Assert.Contains("revocation: the revocation check failed (fail closed)", thrown.Reasons);
        Assert.DoesNotContain("revocation: the grant is revoked", thrown.Reasons);
    }

    // ================= freshness: the rollback pin floor and the pin raised on an allow =================

    static readonly byte[] GuardianSeed = Enumerable.Repeat((byte)0x99, 32).ToArray();

    static Dictionary<string, object?> Epoch(JD grant, long epoch) =>
        RevocationFreshness.SignEpoch(GuardianSeed, new RevocationEpochBody("inst", Gid(grant), epoch, 0, "root-x", Now - 1000, Now + 500_000));

    static void Staleness(AuthorizeInput i, JD grant, long epoch, double? lastAccepted = null)
    {
        var ep = Epoch(grant, epoch);
        i.RevocationStaleness = new RevocationStalenessPolicy(MaxRevocationAgeMs: 600_000);
        i.GuardianPublic = (string)ep["guardian"]!;
        i.RevocationIds = _ => new List<string>();
        i.RevocationState = (_, _) => new RevocationState(Epoch: ep, LastAcceptedEpoch: lastAccepted);
    }

    [Fact]
    public void AFreshEpochPassesAndRaisesTheStoredPinOnlyOnAnAllow()
    {
        var g = Grant();
        var w = new Wrap();
        var r = Run(g, i => Staleness(i, g, 7), FreshAct(g, 100), w);
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("pass", r.Checks["freshness"]);
        Assert.Equal(7L, w.M.Pin(Gid(g) + ":epoch"));
        var g2 = Grant();
        var w2 = new Wrap();
        var denied = Run(g2, i => { Staleness(i, g2, 7); i.IsRevoked = (_, _) => true; }, FreshAct(g2, 100), w2);
        Assert.False(denied.Allow);
        Assert.Null(w2.M.Pin(Gid(g2) + ":epoch")); // a denied action never raises the pin
    }

    [Fact]
    public void TheStoredPinIsTheFloorUnderTheHostsLastAcceptedEpoch()
    {
        var g = Grant();
        var w = new Wrap();
        w.M.RaisePin(Gid(g) + ":epoch", 10);
        var low = Run(g, i => Staleness(i, g, 7, 3), FreshAct(g, 100), w);
        Assert.False(low.Allow);
        Assert.Contains("freshness: revocation epoch 7 is older than the last accepted 10 (rollback)", low.Reasons);
        var g2 = Grant();
        var w2 = new Wrap();
        w2.M.RaisePin(Gid(g2) + ":epoch", 10);
        var high = Run(g2, i => Staleness(i, g2, 7, 20), FreshAct(g2, 100), w2);
        Assert.Contains("freshness: revocation epoch 7 is older than the last accepted 20 (rollback)", high.Reasons);
        var g3 = Grant();
        var w3 = new Wrap();
        w3.M.RaisePin(Gid(g3) + ":epoch", 10);
        var none = Run(g3, i => Staleness(i, g3, 7), FreshAct(g3, 100), w3); // no host value: the pin alone
        Assert.Contains("freshness: revocation epoch 7 is older than the last accepted 10 (rollback)", none.Reasons);
        var g4 = Grant();
        var w4 = new Wrap();
        w4.M.RaisePin(Gid(g4) + ":epoch", 7);
        Assert.True(Run(g4, i => Staleness(i, g4, 7), FreshAct(g4, 100), w4).Allow); // an equal epoch is not a rollback
    }

    [Fact]
    public void AFailingStateSourceAndAMissingStateAreRefused()
    {
        var g = Grant();
        var thrown = Run(g, i => { Staleness(i, g, 7); i.RevocationState = (_, _) => throw new InvalidOperationException("down"); }, store: new Wrap());
        Assert.False(thrown.Allow);
        Assert.Equal("fail", thrown.Checks["freshness"]);
        Assert.Contains("freshness: the revocation state source failed (fail closed)", thrown.Reasons);
        var g2 = Grant();
        var none = Run(g2, i => { Staleness(i, g2, 7); i.RevocationState = (_, _) => null; }, store: new Wrap());
        Assert.False(none.Allow);
        Assert.Equal("fail", none.Checks["freshness"]);
        Assert.StartsWith("freshness: ", none.Reasons.First(x => x.StartsWith("freshness: ")));
    }

    // ================= pq_pin =================

    [Fact]
    public void AClassicalGrantFromAPinnedIssuerIsRefusedAndFromAnotherIssuerPasses()
    {
        var g = Grant();
        var pinned = Run(g, i => i.PqPins = new Dictionary<string, string> { [P.Id!] = "pk" });
        Assert.False(pinned.Allow);
        Assert.Equal("fail", pinned.Checks["pq_pin"]);
        Assert.Contains("pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused", pinned.Reasons);
        var g2 = Grant();
        var other = Run(g2, i => i.PqPins = new Dictionary<string, string> { ["someone-else"] = "pk" });
        Assert.True(other.Allow, other.Reason);
        Assert.Equal("pass", other.Checks["pq_pin"]);
        var g3 = Grant();
        var empty = Run(g3, i => i.PqPins = new Dictionary<string, string>());
        Assert.Equal("pass", empty.Checks["pq_pin"]);
    }

    // ================= taint gate =================

    [Fact]
    public void TheTaintGatePassesUnderALooseMaximumAndFailsUnderAStrictOne()
    {
        var g = Grant();
        var ok = Run(g, i => i.EnforceTaint = new TaintGate(new TaintContext(new InMemoryTrustedInputRegistry()), 1));
        Assert.True(ok.Allow, ok.Reason);
        Assert.Equal("pass", ok.Checks["taint_gate"]);
        var g2 = Grant();
        var strict = Run(g2, i => i.EnforceTaint = new TaintGate(new TaintContext(new InMemoryTrustedInputRegistry()), 0));
        Assert.False(strict.Allow);
        Assert.Equal("fail", strict.Checks["taint_gate"]);
        Assert.Contains("taint_gate: information-flow taint 1 exceeds policy max 0", strict.Reasons);
    }

    // ================= beacon =================

    static SuiteKey BeaconIssuer => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x95, 32).ToArray()));
    static JD Beacon(JD grant, long seq) => Beacons.Mint(BeaconIssuer, Aud, seq, Now - 10_000, Gid(grant));
    static JD ActWithBeacon(JD grant, JD beacon) =>
        Act(grant, new JD { ["freshness"] = new JD { ["beacon_ref"] = Beacons.Ref(beacon), ["epoch"] = 0L, ["accumulator_witness"] = "" } });
    static Func<string, Dictionary<string, object?>, BeaconPresented?> Presents(JD beacon, long? last = null) =>
        (_, _) => new BeaconPresented(beacon, new[] { BeaconIssuer.Id! }, Aud, last);

    [Fact]
    public void ABeaconThatIsNotPresentOrWhoseCallbackFailsIsNotEnforced()
    {
        const string Denied = "beacon: required check is not-enforced (default-deny: not enforced by this resource server)"; // a configured beacon that yields nothing is required, not skipped
        var g = Grant();
        var nothing = Run(g, i => i.Beacon = (_, _) => null, store: new Wrap());
        Assert.False(nothing.Allow);
        Assert.Contains(Denied, nothing.Reasons);
        var g2 = Grant();
        var thrown = Run(g2, i => i.Beacon = (_, _) => throw new InvalidOperationException("down"), store: new Wrap());
        Assert.False(thrown.Allow);
        Assert.Contains(Denied, thrown.Reasons);
    }

    [Fact]
    public void TheHighestOfTheHostsAndTheStoresSequenceDecidesAReplay()
    {
        string Replay(long? hostLast, long? pin, long seq)
        {
            var g = Grant();
            var w = new Wrap();
            if (pin is long pn) w.M.RaisePin(Gid(g) + ":beacon", pn);
            var b = Beacon(g, seq);
            var r = Run(g, i => i.Beacon = Presents(b, hostLast), ActWithBeacon(g, b), w);
            Assert.False(r.Allow);
            Assert.Equal("fail", r.Checks["beacon"]);
            return r.Reasons.First(x => x.StartsWith("beacon: "));
        }
        Assert.Equal("beacon: beacon seq 5 is older than the last accepted 9 (replay)", Replay(3, 9, 5)); // pin above the host value
        Assert.Equal("beacon: beacon seq 15 is older than the last accepted 20 (replay)", Replay(20, 9, 15)); // host value above the pin
        Assert.Equal("beacon: beacon seq 5 is older than the last accepted 9 (replay)", Replay(null, 9, 5)); // the pin alone
        Assert.Equal("beacon: beacon seq 5 is older than the last accepted 9 (replay)", Replay(9, null, 5)); // the host value alone
    }

    [Fact]
    public void ASequenceEqualToTheLastAcceptedIsNotAReplayAndTheStoreRaisesItsPin()
    {
        var g = Grant();
        var w = new Wrap();
        w.M.RaisePin(Gid(g) + ":beacon", 7);
        var b = Beacon(g, 7);
        var r = Run(g, i => i.Beacon = Presents(b, 7), ActWithBeacon(g, b), w);
        Assert.True(r.Allow, r.Reason);
        Assert.Equal("pass", r.Checks["beacon"]);
        var g2 = Grant();
        var w2 = new Wrap();
        var b2 = Beacon(g2, 11);
        Assert.True(Run(g2, i => i.Beacon = Presents(b2), ActWithBeacon(g2, b2), w2).Allow);
        Assert.Equal(11L, w2.M.Pin(Gid(g2) + ":beacon")); // raised on the allow
    }

    [Fact]
    public void AStoreThatCannotAnswerItsPinAcceptsNoBeacon()
    {
        var g = Grant();
        var w = new Wrap { ThrowPin = true };
        var b = Beacon(g, 5);
        var r = Run(g, i => i.Beacon = Presents(b), ActWithBeacon(g, b), w);
        Assert.False(r.Allow);
        Assert.Contains("beacon: beacon seq 5 is older than the last accepted 9223372036854775807 (replay)", r.Reasons);
    }

    [Fact]
    public void ABeaconThePcactnDoesNotCommitOrThatFailsToVerifyIsRefused()
    {
        var g = Grant();
        var b = Beacon(g, 5);
        var unbound = Run(g, i => i.Beacon = Presents(b), store: new Wrap()); // the PCActn carries no beacon_ref
        Assert.False(unbound.Allow);
        Assert.Contains("beacon: PCActn freshness.beacon_ref does not bind the presented beacon", unbound.Reasons);
        var g2 = Grant();
        var expired = Beacons.Mint(BeaconIssuer, Aud, 1, Now - 400_000, Gid(g2));
        var rej = Run(g2, i => i.Beacon = Presents(expired), ActWithBeacon(g2, expired), new Wrap());
        Assert.Contains("beacon: expired", rej.Reasons);
        var g3 = Grant();
        var b3 = Beacon(g3, 5);
        var wrongPins = Run(g3, i => i.Beacon = (_, _) => new BeaconPresented(b3, new[] { P.Id! }, Aud), ActWithBeacon(g3, b3), new Wrap());
        Assert.Contains("beacon: issuer not pinned", wrongPins.Reasons);
    }

    // ================= forbid =================

    static JD Clause(string id, string kind, string verb = "pay") => new() { ["id"] = id, ["kind"] = kind, ["when"] = new JD { ["verb"] = verb } };

    [Fact]
    public void TheForbidContextCallbackOverridesTheEvaluatedContext()
    {
        var g = Grant();
        var plain = Run(g, i => i.Forbid = new ForbidOptions((_, _) => new JL { Clause("a", "permit") }));
        Assert.True(plain.Allow, plain.Reason);
        Assert.Equal("pass", plain.Checks["forbid"]);
        var g2 = Grant();
        var over = Run(g2, i => i.Forbid = new ForbidOptions((_, _) => new JL { Clause("a", "permit") },
            Context: _ => new JD { ["action"] = new JD { ["verb"] = "refund", ["resource"] = "inv/1" } }));
        Assert.False(over.Allow);
        Assert.Contains("forbid: deny by none", over.Reasons);
    }

    [Fact]
    public void ACertificateThatIsNotConsistentOrDoesNotMatchIsRefusedWithItsReason()
    {
        var clauses = new JL { Clause("a", "permit") };
        var ctx = new JD { ["action"] = new JD { ["verb"] = "pay", ["resource"] = "inv/1", ["params"] = Amt() } };
        var good = Forbid.Certify(clauses, ctx);
        var g = Grant();
        var ok = Run(g, i => { i.Forbid = new ForbidOptions((_, _) => clauses, RequireCertificate: true); i.ForbidCertificate = Issue.Norm(good); });
        Assert.True(ok.Allow, ok.Reason);
        Assert.Equal("pass", ok.Checks["forbid"]);
        var g2 = Grant();
        var other = Forbid.Certify(clauses, new JD { ["action"] = new JD { ["verb"] = "pay", ["resource"] = "inv/2" } });
        var bad = Run(g2, i => { i.Forbid = new ForbidOptions((_, _) => clauses, RequireCertificate: true); i.ForbidCertificate = Issue.Norm(other); });
        Assert.Equal("fail", bad.Checks["forbid"]);
        Assert.Contains("forbid: certificate refused (certificate does not match the recomputed decision)", bad.Reasons);
        var g3 = Grant();
        var junk = Run(g3, i => { i.Forbid = new ForbidOptions((_, _) => clauses, RequireCertificate: true); i.ForbidCertificate = new JD { ["x"] = 1L }; });
        Assert.Equal("fail", junk.Checks["forbid"]);
        Assert.Contains("forbid: certificate refused (certificate table does not entail its decision)", junk.Reasons);
        // a certificate is only checked when one is required
        var g4 = Grant();
        var notRequired = Run(g4, i => { i.Forbid = new ForbidOptions((_, _) => clauses); i.ForbidCertificate = new JD { ["x"] = 1L }; });
        Assert.True(notRequired.Allow, notRequired.Reason);
        Assert.Equal("pass", notRequired.Checks["forbid"]);
    }

    // ================= contracts =================

    sealed class Flaky : IAtomicKv
    {
        readonly MemoryAtomicKv _m = new();
        public bool Down;
        public string? Get(string key) => Down ? throw new InvalidOperationException("down") : _m.Get(key);
        public void Update(string key, Func<string?, string?> fn) { if (Down) throw new InvalidOperationException("down"); _m.Update(key, fn); }
    }

    static (JD Contract, EdKey Principal) NeverContract(string verb)
    {
        var principal = EdKey.FromSeed(Enumerable.Repeat((byte)0x96, 32).ToArray());
        var contract = Contracts.Sign(new JD { ["version"] = 1L, ["principal"] = principal.Id, ["clauses"] = new JL { new JD { ["id"] = "no-" + verb, ["kind"] = "never", ["p"] = new JD { ["verb"] = verb } } } }, principal);
        return (contract, principal);
    }

    [Fact]
    public void AContractPassesViolatesAndFailsClosedWithTheirOwnWording()
    {
        var (other, pr) = NeverContract("refund");
        var g = Grant();
        var ok = Run(g, i => i.Contracts = ContractEnforcer.Open(new MemoryAtomicKv(), other, pr.Id, null, () => Now));
        Assert.True(ok.Allow, ok.Reason);
        Assert.Equal("pass", ok.Checks["contract"]);
        var (pay, pr2) = NeverContract("pay");
        var g2 = Grant();
        var bad = Run(g2, i => i.Contracts = ContractEnforcer.Open(new MemoryAtomicKv(), pay, pr2.Id, null, () => Now));
        Assert.False(bad.Allow);
        Assert.Equal("fail", bad.Checks["contract"]);
        Assert.Contains("contract: violated (no-pay)", bad.Reasons);
        var g3 = Grant();
        var kv = new Flaky();
        var enf = ContractEnforcer.Open(kv, other, pr.Id, null, () => Now);
        kv.Down = true;
        var down = Run(g3, i => i.Contracts = enf);
        Assert.False(down.Allow);
        Assert.Contains("contract: store-error", down.Reasons); // no violated ids: no parenthesised list
    }

    // ================= linked template =================

    [Fact]
    public void ALinkedTemplateThatResolvesPassesAndOneThatDoesNotCarryItsReason()
    {
        var v = L(Load("policy-link-vectors.json")["resolve"]).Select(D).First(x => (string)x["name"]! == "a reference resolves to the instantiation");
        var pol = D(D(v["expect"])["policy"]);
        var env = new JD { ["predicates"] = pol["predicates"], ["caveats"] = pol["caveats"], ["risk_policy"] = Issue.DefaultRiskPolicy(), ["template_ref"] = v["ref"] };
        var g = Issue.MintGrant(P, Me.Id!, null, env, "kill d").Grant;
        var ok = Run(g, i => i.RequireLinkedTemplate = () => v["registry"]);
        Assert.Equal("pass", ok.Checks["template"]);
        Assert.DoesNotContain(ok.Reasons, x => x.StartsWith("template:"));
        var missing = Run(g, i => i.RequireLinkedTemplate = () => new JD { ["templates"] = new JD(), ["trusted"] = new JL() });
        Assert.False(missing.Allow);
        Assert.Equal("fail", missing.Checks["template"]);
        Assert.Contains("template: template version is not in the registry", missing.Reasons);
        var thrown = Run(g, i => i.RequireLinkedTemplate = () => throw new InvalidOperationException("down"));
        Assert.Contains("template: the template registry could not be read (fail closed)", thrown.Reasons);
    }

    [Fact]
    public void AGrantWithoutAReadableEnvelopeFailsTheTemplateCheck()
    {
        var g = Issue.MintRoot(P, Me.Id!, null, new JL());
        var r = Run(g, i => i.RequireLinkedTemplate = () => new JD());
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["template"]);
        Assert.Contains("template: the grant has no readable envelope", r.Reasons);
    }

    // ================= the freshness gate =================

    static JD FreshAct(JD grant, long epoch, string beaconRef = "ref") =>
        Act(grant, new JD { ["freshness"] = new JD { ["beacon_ref"] = beaconRef, ["epoch"] = epoch, ["accumulator_witness"] = "" } });

    // gate with one-second epochs: anchor = epoch * 1000
    static AuthorizeResult Gate(FreshnessGate gate, long epoch, string beaconRef = "ref")
    {
        var g = Grant();
        return Run(g, i => i.EnforceFreshness = gate, FreshAct(g, epoch, beaconRef));
    }

    const string Misconfigured = "freshness: freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)";

    [Fact]
    public void TheFreshnessAgeBoundaryIsInclusive()
    {
        long epoch = (Now - 5000) / 1000;
        var atLimit = Gate(new FreshnessGate(5000, 1000), epoch);
        Assert.True(atLimit.Allow, atLimit.Reason);
        Assert.Equal("pass", atLimit.Checks["freshness"]);
        var stale = Gate(new FreshnessGate(4999, 1000), epoch);
        Assert.False(stale.Allow);
        Assert.Equal("fail", stale.Checks["freshness"]);
        Assert.Contains("freshness: freshness anchor is stale (older than 4999 ms)", stale.Reasons);
        var zero = Gate(new FreshnessGate(0, 1000), Now / 1000); // maxAge 0 is valid: an anchor of exactly now
        Assert.True(zero.Allow, zero.Reason);
    }

    [Fact]
    public void TheFutureBoundaryAndTheClockSkewAreHonoured()
    {
        long future = Now / 1000 + 1; // anchor = now + 1000
        var ahead = Gate(new FreshnessGate(10_000, 1000), future);
        Assert.False(ahead.Allow);
        Assert.Contains("freshness: freshness anchor is in the future", ahead.Reasons);
        var tolerated = Gate(new FreshnessGate(10_000, 1000, null, 1000), future); // anchor == now + skew is not the future
        Assert.True(tolerated.Allow, tolerated.Reason);
        var short_ = Gate(new FreshnessGate(10_000, 1000, null, 999), future);
        Assert.Contains("freshness: freshness anchor is in the future", short_.Reasons);
        // a negative or non-finite skew counts as none
        Assert.True(Gate(new FreshnessGate(10_000, 1000, null, -50), Now / 1000).Allow);
        Assert.True(Gate(new FreshnessGate(10_000, 1000, null, double.NaN), Now / 1000).Allow);
        Assert.Contains("freshness: freshness anchor is in the future", Gate(new FreshnessGate(10_000, 1000, null, -50), future).Reasons);
        // the gate's own clock wins over the verifier's
        var older = Gate(new FreshnessGate(10_000, 1000, Now - 100_000), Now / 1000);
        Assert.Contains("freshness: freshness anchor is in the future", older.Reasons);
    }

    [Fact]
    public void AMisconfiguredGateIsRefusedFromEachOperandAlone()
    {
        long epoch = Now / 1000;
        foreach (var gate in new[]
        {
            new FreshnessGate(10_000, 0), new FreshnessGate(10_000, -1), new FreshnessGate(double.NaN, 1000),
            new FreshnessGate(double.PositiveInfinity, 1000), new FreshnessGate(-1, 1000), new FreshnessGate(10_000, double.NaN),
        })
        {
            var r = Gate(gate, epoch);
            Assert.False(r.Allow);
            Assert.Equal("fail", r.Checks["freshness"]);
            Assert.Contains(Misconfigured, r.Reasons);
        }
    }

    [Fact]
    public void AMissingAnchorIsRefusedWhateverThePartThatIsMissing()
    {
        const string Missing = "freshness: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)";
        Assert.Contains(Missing, Gate(new FreshnessGate(10_000, 1000), Now / 1000, "").Reasons); // empty beacon_ref
        Assert.Contains(Missing, Gate(new FreshnessGate(10_000, 1000), 0).Reasons); // epoch 0
        var g = Grant();
        Assert.Contains(Missing, Run(g, i => i.EnforceFreshness = new FreshnessGate(10_000, 1000)).Reasons); // no freshness at all
        Assert.True(Gate(new FreshnessGate(10_000, 1000), Now / 1000).Allow); // both present
    }

    [Fact]
    public void AFailedRevocationStalenessStandsOverAPassingGate()
    {
        var g = Grant();
        var r = Run(g, i =>
        {
            i.RevocationStaleness = new RevocationStalenessPolicy(MaxRevocationAgeMs: 600_000);
            i.RevocationState = (_, _) => null;
            i.EnforceFreshness = new FreshnessGate(10_000, 1000);
        }, FreshAct(g, Now / 1000), new Wrap());
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["freshness"]);
    }

    // ================= principal =================

    [Fact]
    public void AResolvedPrincipalPassesAnUnresolvedOneIsNotEnforcedUnlessRequired()
    {
        string? seen = null;
        var g = Grant();
        var verified = Run(g, i => i.ResolvePrincipal = (iss, _) => { seen = iss; return new PrincipalInfo(true); });
        Assert.True(verified.Allow, verified.Reason);
        Assert.Equal("pass", verified.Checks["principal"]);
        Assert.Equal(P.Id, seen); // the resolver is asked about the grant issuer
        var g2 = Grant();
        var unverified = Run(g2, i => i.ResolvePrincipal = (_, _) => new PrincipalInfo(false));
        Assert.True(unverified.Allow, unverified.Reason);
        Assert.Equal("not-enforced", unverified.Checks["principal"]);
        var g3 = Grant();
        var nothing = Run(g3, i => i.ResolvePrincipal = (_, _) => null);
        Assert.Equal("not-enforced", nothing.Checks["principal"]);
        var g4 = Grant();
        var thrown = Run(g4, i => i.ResolvePrincipal = (_, _) => throw new InvalidOperationException("down"));
        Assert.True(thrown.Allow, thrown.Reason);
        Assert.Equal("not-enforced", thrown.Checks["principal"]);
    }

    [Fact]
    public void RequiringAVerifiedPrincipalRefusesEveryOtherAnswer()
    {
        const string NotVerified = "principal: the grant issuer is not an enrolled, verified principal";
        var g = Grant();
        var ok = Run(g, i => { i.ResolvePrincipal = (_, _) => new PrincipalInfo(true); i.RequireVerifiedPrincipal = true; });
        Assert.True(ok.Allow, ok.Reason);
        Assert.Equal("pass", ok.Checks["principal"]);
        var g2 = Grant();
        var no = Run(g2, i => { i.ResolvePrincipal = (_, _) => new PrincipalInfo(false); i.RequireVerifiedPrincipal = true; });
        Assert.False(no.Allow);
        Assert.Equal("fail", no.Checks["principal"]);
        Assert.Contains(NotVerified, no.Reasons);
        var g3 = Grant();
        var thrown = Run(g3, i => { i.ResolvePrincipal = (_, _) => throw new InvalidOperationException("down"); i.RequireVerifiedPrincipal = true; });
        Assert.Contains(NotVerified, thrown.Reasons);
        var g4 = Grant();
        var absent = Run(g4, i => { i.ResolvePrincipal = (_, _) => null; i.RequireVerifiedPrincipal = true; });
        Assert.Contains(NotVerified, absent.Reasons);
        var g5 = Grant();
        var noResolver = Run(g5, i => i.RequireVerifiedPrincipal = true);
        Assert.False(noResolver.Allow);
        Assert.Contains("principal: requireVerifiedPrincipal needs a resolvePrincipal resolver", noResolver.Reasons);
    }

    // ================= passport =================

    static SuiteKey PassportIssuer => SuiteKey.Ed25519(EdKey.FromSeed(Enumerable.Repeat((byte)0x97, 32).ToArray()));

    static JD SignedPassport(bool hw, string subject)
    {
        var ident = Issue.IssuePassport(new JD { ["model_id"] = "m1", ["operator"] = "acme", ["hardware_rooted"] = hw });
        var evidence = hw ? new JD { ["document"] = new JD { ["nonce"] = "n1" }, ["at"] = Now - 1000 } : null;
        return Issue.SignPassport(ident, PassportIssuer, subject, Now - 1000, Now + 3_600_000, null, evidence);
    }

    static PassportOptions PassOpts() => new()
    {
        TrustedIssuers = new[] { PassportIssuer.Id! }, Revoked = (_, _, _) => false,
        Attest = (_, _) => new PassportAttestation(true, true, new JD { ["model_id"] = "m1", ["operator"] = "acme" }),
    };

    [Fact]
    public void APassportOfTheLeafHolderPassesAndAHardwareRequirementNeedsHardwareEvidence()
    {
        var g = Grant();
        var ok = Run(g, i => { i.RequirePassport = new PassportRequirement(PassOpts()); i.Passport = SignedPassport(false, Me.Id!); });
        Assert.True(ok.Allow, ok.Reason);
        Assert.Equal("pass", ok.Checks["passport"]);
        var g2 = Grant();
        var soft = Run(g2, i => { i.RequirePassport = new PassportRequirement(PassOpts(), Hardware: true); i.Passport = SignedPassport(false, Me.Id!); });
        Assert.False(soft.Allow);
        Assert.Equal("fail", soft.Checks["passport"]);
        Assert.Contains("passport: hardware_evidence_missing", soft.Reasons);
        var g3 = Grant();
        var hard = Run(g3, i => { i.RequirePassport = new PassportRequirement(PassOpts(), Hardware: true); i.Passport = SignedPassport(true, Me.Id!); });
        Assert.True(hard.Allow, hard.Reason);
        Assert.Equal("pass", hard.Checks["passport"]);
        var g4 = Grant();
        var other = Run(g4, i => { i.RequirePassport = new PassportRequirement(PassOpts()); i.Passport = SignedPassport(false, Third.Id!); });
        Assert.False(other.Allow);
        Assert.Contains("passport: subject_mismatch", other.Reasons);
    }

    // ================= attestation, plan root, reversibility =================

    [Fact]
    public void AGrantThatBindsTheAgentNeedsAnAttestationThisSdkCannotVerify()
    {
        var env = Env();
        env["agent_binding"] = new JD { ["operator"] = "acme" };
        var g = Issue.MintGrant(P, Me.Id!, null, env, "kill d").Grant;
        var r = Run(g);
        Assert.False(r.Allow);
        Assert.Equal("fail", r.Checks["attestation"]);
        Assert.Contains("attestation: the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED (no attestation verifier in this SDK: fail closed)", r.Reasons);
    }

    static JL NodesOf(JD p, string? verb = null)
    {
        var a = (JD)p["action"]!;
        var pl = (JD)p["plan"]!;
        return new JL
        {
            new JD
            {
                ["id"] = pl["node_id"], ["verb"] = verb ?? a["verb"], ["resource"] = a["resource"], ["params_digest"] = a["params_digest"],
                ["reversibility_class"] = a.GetValueOrDefault("reversibility_class"),
            },
        };
    }

    [Fact]
    public void ThePlanRootMustMatchTheKnownPlanAndBeAuthorized()
    {
        var g = Grant();
        var ok = Run(g, i => { i.Plan = null; i.Context = p => new JD { ["plan"] = NodesOf(p), ["plan_authorized"] = true }; });
        Assert.True(ok.Allow, ok.Reason);
        Assert.Equal("pass", ok.Checks["plan_root_authorized"]);
        var g2 = Grant();
        var unauth = Run(g2, i => { i.Plan = null; i.Context = p => new JD { ["plan"] = NodesOf(p), ["plan_authorized"] = false }; });
        Assert.False(unauth.Allow);
        Assert.Equal("fail", unauth.Checks["plan_root_authorized"]);
        Assert.Contains("plan_root_authorized: the plan root has not been authorized by the principal", unauth.Reasons);
        var g3 = Grant();
        var otherNode = Run(g3, i => { i.Plan = null; i.Context = p => new JD { ["plan"] = NodesOf(p, "refund"), ["plan_authorized"] = true }; });
        Assert.Contains("plan_root_authorized: known plan does not match plan.root", otherNode.Reasons);
        var g4 = Grant();
        var notAList = Run(g4, i => { i.Plan = null; i.Context = _ => new JD { ["plan"] = "junk", ["plan_authorized"] = true }; });
        Assert.False(notAList.Allow);
        Assert.Contains("plan_root_authorized: known plan does not match plan.root", notAList.Reasons);
        var g5 = Grant();
        var none = Run(g5, i => i.Plan = null);
        Assert.False(none.Allow);
        Assert.Contains(none.Reasons, x => x.StartsWith("plan_root_authorized: default-deny: no authorized plan is configured"));
    }

    [Fact]
    public void ADeclaredClassLessRestrictiveThanTheServersIsRefused()
    {
        var g = Grant();
        var less = Run(g, i => i.Context = _ => new JD { ["reversibility_class"] = "costly" });
        Assert.False(less.Allow);
        Assert.Equal("fail", less.Checks["reversibility"]);
        Assert.Contains("reversibility: declared class 'reversible' is less restrictive than the authoritative 'costly'", less.Reasons);
        var g2 = Grant();
        var same = Run(g2, i => i.Context = _ => new JD { ["reversibility_class"] = "reversible" });
        Assert.True(same.Allow, same.Reason);
        Assert.Equal("pass", same.Checks["reversibility"]);
    }

    static JD CostlyAct(JD grant)
    {
        var a = AgentOf(grant);
        a.CommitPlan(new[] { new JD { ["id"] = "n1", ["verb"] = "pay", ["resource"] = "inv/1", ["params_digest"] = Pca.ParamsDigest(Amt()), ["reversibility_class"] = "rate_limited" } });
        return a.ActNode("n1", Amt());
    }

    [Fact]
    public void TheEffectiveClassIsTheStricterOfTheDeclaredAndTheServers()
    {
        var limit = new JL { new JD { ["type"] = "reversibility_max", ["class"] = "reversible" } };
        var g = Grant(limit);
        Assert.Equal("pass", Run(g).Checks["policy"]); // declared reversible, none from the server
        var g2 = Grant(limit);
        var serverStricter = Run(g2, i => i.Context = _ => new JD { ["reversibility_class"] = "rate_limited" });
        Assert.Equal("fail", serverStricter.Checks["policy"]);
        Assert.Contains("policy: caveat(s) not satisfied: reversibility_max", serverStricter.Reasons);
        var g3 = Grant(limit);
        var declaredStricter = Run(g3, i => i.Context = _ => new JD { ["reversibility_class"] = "reversible" }, CostlyAct(g3));
        Assert.Equal("pass", declaredStricter.Checks["reversibility"]);
        Assert.Equal("fail", declaredStricter.Checks["policy"]);
        Assert.Contains("policy: caveat(s) not satisfied: reversibility_max", declaredStricter.Reasons);
        var g4 = Grant(new JL { new JD { ["type"] = "reversibility_max", ["class"] = "rate_limited" } });
        Assert.Equal("pass", Run(g4, null, CostlyAct(g4)).Checks["policy"]); // an equal class satisfies the limit
    }

    [Fact]
    public void TheEffectiveClassIsNeverReplacedByTheClassOfAServerPlanNode()
    {
        var limit = new JL { new JD { ["type"] = "reversibility_max", ["class"] = "reversible" } };
        var g = Grant(limit);
        var r = Run(g, i =>
        {
            i.Plan = null;
            i.Context = _ => new JD
            {
                ["plan"] = new JL { new JD { ["id"] = "n1", ["verb"] = "pay", ["resource"] = "inv/1", ["params_digest"] = Pca.ParamsDigest(Amt()), ["reversibility_class"] = "reversible" } },
                ["plan_authorized"] = true,
            };
        }, CostlyAct(g)); // the signed action declares rate_limited; the plan node of the same id says reversible
        Assert.Equal("fail", r.Checks["policy"]);
        Assert.Contains("policy: caveat(s) not satisfied: reversibility_max", r.Reasons);
    }

    // ================= the policy context =================

    [Fact]
    public void TheSubjectAndTheEnvAreVisibleToThePredicates()
    {
        JL Preds(string field, string value) => new() { new JD { ["verb"] = "*", ["where"] = new JL { new JD { ["field"] = field, ["op"] = "eq", ["value"] = value } } } };
        var g = Grant(null, Preds("subject.role", "admin"));
        Assert.Equal("pass", Run(g, i => i.Context = _ => new JD { ["subject"] = new JD { ["role"] = "admin" } }).Checks["policy"]);
        var g2 = Grant(null, Preds("subject.role", "admin"));
        var wrong = Run(g2, i => i.Context = _ => new JD { ["subject"] = new JD { ["role"] = "guest" } });
        Assert.Equal("fail", wrong.Checks["policy"]);
        Assert.Contains(wrong.Reasons, x => x.StartsWith("policy: "));
        Assert.Equal("fail", Run(Grant(null, Preds("subject.role", "admin"))).Checks["policy"]); // no subject at all
        var g3 = Grant(null, Preds("env.region", "eu"));
        Assert.Equal("pass", Run(g3, i => i.Context = _ => new JD { ["env"] = new JD { ["region"] = "eu" } }).Checks["policy"]);
        var g4 = Grant(null, Preds("env.region", "eu"));
        Assert.Equal("fail", Run(g4, i => i.Context = _ => new JD { ["env"] = new JD { ["region"] = "us" } }).Checks["policy"]);
        Assert.Equal("fail", Run(Grant(null, Preds("env.region", "eu"))).Checks["policy"]);
    }

    [Fact]
    public void BlastRadiusAndRecentActionTimesReachTheCaveats()
    {
        var blast = new JL { new JD { ["type"] = "max_blast_radius", ["max"] = 5L } };
        var g = Grant(blast);
        Assert.Equal("pass", Run(g, i => i.Context = _ => new JD { ["blast_radius"] = 3L }).Checks["policy"]);
        var g2 = Grant(blast);
        var big = Run(g2, i => i.Context = _ => new JD { ["blast_radius"] = 7L });
        Assert.Contains("policy: caveat(s) not satisfied: max_blast_radius", big.Reasons);
        Assert.Contains("policy: caveat(s) not satisfied: max_blast_radius", Run(Grant(blast)).Reasons); // none supplied: unsatisfied
        var rate = new JL { new JD { ["type"] = "rate", ["max"] = 1L, ["per_secs"] = 60L } };
        var g3 = Grant(rate);
        Assert.Equal("pass", Run(g3, i => i.Context = _ => new JD { ["recent_action_times"] = new JL() }).Checks["policy"]);
        var g4 = Grant(rate);
        var busy = Run(g4, i => i.Context = _ => new JD { ["recent_action_times"] = new JL { Now - 1000 } });
        Assert.Contains("policy: caveat(s) not satisfied: rate", busy.Reasons);
        Assert.Contains("policy: caveat(s) not satisfied: rate", Run(Grant(rate)).Reasons);
    }

    // ================= delegation =================

    [Fact]
    public void TheDelegationDepthIsTheNumberOfHops()
    {
        var depth0 = new JL { new JD { ["type"] = "delegation_depth", ["max"] = 0L } };
        var g = Grant(depth0);
        Assert.Equal("pass", Run(g).Checks["policy"]); // the root holder acts at depth 0
        var g2 = Grant(depth0);
        var hop = AgentOf(g2).Delegate(Sub, null);
        var deep = Run(g2, null, hop.Act("pay", "inv/1", Amt()));
        Assert.Equal("fail", deep.Checks["policy"]);
        Assert.Contains("policy: caveat(s) not satisfied: delegation_depth", deep.Reasons);
        var depth1 = new JL { new JD { ["type"] = "delegation_depth", ["max"] = 1L } };
        var g3 = Grant(depth1);
        var hop3 = AgentOf(g3).Delegate(Sub, null);
        Assert.Equal("pass", Run(g3, null, hop3.Act("pay", "inv/1", Amt())).Checks["policy"]);
    }

    [Fact]
    public void AHopsAddedCaveatsAreEvaluatedAsDelegatedCaveats()
    {
        var g = Grant();
        var bad = Run(g, null, AgentOf(g).Delegate(Sub, new JL { Expires(Now - 1) }).Act("pay", "inv/1", Amt()));
        Assert.False(bad.Allow);
        Assert.Equal("fail", bad.Checks["delegated_caveats"]);
        Assert.Contains("delegated_caveats: delegation caveat(s) not satisfied: expires", bad.Reasons);
        var g2 = Grant();
        var good = Run(g2, null, AgentOf(g2).Delegate(Sub, new JL { Expires(Now + 60_000) }).Act("pay", "inv/1", Amt()));
        Assert.Equal("pass", good.Checks["delegated_caveats"]);
        var g3 = Grant();
        var two = Run(g3, null, AgentOf(g3).Delegate(Sub, new JL { Expires(Now - 1), new JD { ["type"] = "not_before", ["at"] = Now + 1 } }).Act("pay", "inv/1", Amt()));
        Assert.Contains("delegated_caveats: delegation caveat(s) not satisfied: expires, not_before", two.Reasons);
    }

    // ================= K1 =================

    [Fact]
    public void AFailingK1CheckWithoutAnyK1OptionFailsClosed()
    {
        var g = Grant();
        Pca.K1CheckHook = () => throw new InvalidOperationException("down");
        try
        {
            var r = Run(g);
            Assert.False(r.Allow);
            Assert.Equal("fail", r.Checks["k1_caveats"]);
            Assert.Contains("k1_caveats: the K1 caveats could not be checked (fail closed)", r.Reasons);
        }
        finally { Pca.K1CheckHook = null; }
        var g2 = Grant();
        Assert.False(Run(g2).Checks.ContainsKey("k1_caveats")); // the hook did not leak
    }

    // ================= risk wording =================

    [Fact]
    public void ABudgetlessStoreIsNotEnforcedAndItsReasonIsNotPrefixed()
    {
        var g = Grant();
        var r = Run(g, null, null, new ClaimOnly());
        Assert.True(r.Allow, r.Reason); // B=0 still covers a zero-cost action, as the reference
        Assert.Equal("not-enforced", r.Checks["budget"]);
        Assert.Contains(r.Reasons, x => x.StartsWith("budget: no budget supplied"));
        Assert.DoesNotContain(r.Reasons, x => x.StartsWith("policy: budget:"));
        var g2 = Grant();
        var persisted = Run(g2);
        Assert.Equal("pass", persisted.Checks["budget"]);
        var g3 = Grant();
        var risky = Run(g3, i => i.ServerRisk = new Dictionary<string, double>());
        Assert.Contains(risky.Reasons, x => x.StartsWith("policy: risk input(s) missing, assumed worst case:"));
        Assert.Contains(risky.Reasons, x => x.StartsWith("policy: risk ") && x.Contains(" exceeds auto threshold: step-up to t="));
    }

    [Fact]
    public void AHookThatReportsMinusInfinityIsNamedAndOnePlusInfinityPasses()
    {
        var g = Grant();
        var neg = Run(g, i => { i.ServerRisk = new Dictionary<string, double>(); i.ThresholdHook = (_, _) => new ThresholdHookResult(true, true, double.NegativeInfinity); });
        Assert.False(neg.Allow);
        Assert.Contains("threshold: threshold hook enforced t=-Infinity but the server requires t=3 (below the server-derived threshold; derive t from server-held data)", neg.Reasons);
        var g2 = Grant();
        var pos = Run(g2, i => { i.ServerRisk = new Dictionary<string, double>(); i.ThresholdHook = (_, _) => new ThresholdHookResult(true, true, double.PositiveInfinity); });
        Assert.Equal("pass", pos.Checks["threshold"]);
    }

    [Fact]
    public void RiskOptionsWithoutAReadableRiskPolicyAreRefusedEachOnItsOwn()
    {
        const string Unreadable = "risk_inputs: the grant carries no readable risk policy (fail closed)";
        AuthorizeResult Bare(Action<AuthorizeInput> cfg) => Run(Issue.MintRoot(P, Me.Id!, null, new JL()), cfg); // no envelope, so no risk policy
        Assert.Contains(Unreadable, Bare(i => i.RequireRiskInputs = new[] { "taint" }).Reasons);
        Assert.Contains(Unreadable, Bare(i => i.Adaptive = new RiskPolicy(0.25, 0.2, 0.2, 0.2, 0.1, 0.05, 0.25, 0.6, 1, 0.0005, 0.5, 1)).Reasons);
        Assert.Contains(Unreadable, Bare(i => i.AdaptivePolicy = _ => null).Reasons);
        Assert.DoesNotContain(Unreadable, Bare(i => { }).Reasons);
    }

    // ================= the replay read =================

    [Fact]
    public void AReplayedCounterIsNamedByTheReadOfTheStreamsLastCounter()
    {
        var g = Grant();
        var pc = Act(g);
        var store = new MemoryStateStore();
        Assert.True(Run(g, null, pc, store).Allow);
        var again = Run(g, null, pc, store);
        Assert.False(again.Allow);
        Assert.Equal("fail", again.Checks["replay"]);
        Assert.Contains("replay: 1 is not greater than last seen 1 (replay)", again.Reasons);
    }
}
