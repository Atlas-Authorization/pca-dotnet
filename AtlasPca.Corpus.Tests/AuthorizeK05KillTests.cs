using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>k05 Stryker survivors of Authorize.cs: the replay / consume-once stores (default interface method, the memory store's
/// prune edges, the SQL store over a strict in-memory ADO.NET fake that only knows the store's exact statements), the tool_schema
/// firewall bounds and messages (some defensive bounds are unreachable through the public API and are driven through their private
/// seam by reflection), the JSON quoting of argument names, and the agent-caveat evaluator's fail-closed paths.</summary>
public class AuthorizeK05KillTests
{
    const string StoreMsg = "ConsumeOnce needs a non-empty key and retainUntilMs >= nowMs";
    const string SqlOnceMsg = "ConsumeOnce needs a non-empty key and 0 <= nowMs <= retainUntilMs <= 2^53-1";

    // ================= IStateStore default ConsumeOnce =================

    sealed class ClaimOnly : IStateStore
    {
        readonly MemoryStateStore _m = new();
        public ClaimResult? Claim(string key, long counter) => _m.Claim(key, counter);
    }

    [Fact]
    public void DefaultConsumeOnceRefusesAndConsumes()
    {
        IStateStore s = new ClaimOnly();
        Assert.Equal(StoreMsg, Assert.Throws<ArgumentException>(() => s.ConsumeOnce("", 10, 5)).Message);
        Assert.Equal(StoreMsg, Assert.Throws<ArgumentException>(() => s.ConsumeOnce("k", 4, 5)).Message);
        Assert.True(s.ConsumeOnce("k", 5, 5)); // retainUntil == now is allowed
        Assert.False(s.ConsumeOnce("k", 9, 5));
        Assert.True(s.ConsumeOnce("k2", 9, 5));
    }

    // ================= MemoryStateStore =================

    [Fact]
    public void MemoryConsumeOnceMessageAndNullClaim()
    {
        var m = new MemoryStateStore();
        Assert.Equal(StoreMsg, Assert.Throws<ArgumentException>(() => m.ConsumeOnce("", 10, 5)).Message);
        Assert.Equal(StoreMsg, Assert.Throws<ArgumentException>(() => m.ConsumeOnce("k", 4, 5)).Message);
        Assert.Equal(new ClaimResult(false), m.Claim(null!, 1));
    }

    static MemoryStateStore Filled(int n, long retain, long now)
    {
        var m = new MemoryStateStore();
        for (int i = 0; i < n; i++) Assert.True(m.ConsumeOnce("k" + i, retain, now));
        return m;
    }

    // a pruned record is only observable when time runs backwards: an unpruned expired record is live again for an earlier now
    [Fact]
    public void MemoryNoPruneBelow1024Records()
    {
        var m = Filled(1023, 50, 50);
        Assert.True(m.ConsumeOnce("x", 200, 100)); // 1023 records: no prune, k* (50 < 100) stay
        Assert.False(m.ConsumeOnce("k0", 60, 40)); // k0 = 50 >= 40: live
    }

    [Fact]
    public void MemoryPrunesExpiredAt1024Records()
    {
        var m = Filled(1024, 50, 50);
        Assert.True(m.ConsumeOnce("x", 200, 100)); // 1024 records: every k* (50 < 100) is pruned
        Assert.True(m.ConsumeOnce("k0", 60, 40)); // gone, so consumable again
        Assert.False(m.ConsumeOnce("x", 300, 150)); // x (200) was never pruned (only records < now are)
    }

    [Fact]
    public void MemoryPruneKeepsRecordsAtNow()
    {
        var m = Filled(1024, 100, 50);
        Assert.True(m.ConsumeOnce("x", 200, 100)); // prune < 100: the k* (== 100) stay
        Assert.False(m.ConsumeOnce("k0", 60, 40));
    }

    // ================= SqlStateStore over a strict fake =================

    sealed class FakeDb
    {
        public readonly string T, O;
        public readonly Dictionary<string, long> Replay = new(StringComparer.Ordinal), Once = new(StringComparer.Ordinal);
        public readonly List<string> Log = new();
        public bool InsertAffectsNothing;
        public int Opens;

        public FakeDb(string table = SqlStateStore.DefaultTable) { T = table; O = table + "_once"; }

        string CreateReplay => $"CREATE TABLE IF NOT EXISTS {T} (key TEXT NOT NULL PRIMARY KEY, last_counter BIGINT NOT NULL)";
        string CreateOnce => $"CREATE TABLE IF NOT EXISTS {O} (key TEXT NOT NULL PRIMARY KEY, retain_until BIGINT NOT NULL)";
        string Idx => $"CREATE INDEX IF NOT EXISTS {O}_retain ON {O} (retain_until)";
        string Del => $"DELETE FROM {O} WHERE retain_until < @now";
        string InsOnce => $"INSERT INTO {O} (key, retain_until) VALUES (@key, @r) ON CONFLICT(key) DO UPDATE SET retain_until = excluded.retain_until WHERE {O}.retain_until < @now";
        string Ext => $"UPDATE {O} SET retain_until = @r WHERE key = @key AND retain_until < @r";
        string InsReplay => $"INSERT INTO {T} (key, last_counter) VALUES (@key, @counter) ON CONFLICT(key) DO UPDATE SET last_counter = excluded.last_counter WHERE excluded.last_counter > {T}.last_counter";
        string Sel => $"SELECT last_counter FROM {T} WHERE key = @key";

        public List<string> SchemaStatements => new() { CreateReplay, CreateOnce, Idx };

        public int Exec(string sql, FakeCmd c)
        {
            Log.Add(sql);
            if (sql == CreateReplay || sql == CreateOnce || sql == Idx) return 0;
            if (sql == Del)
            {
                var now = c.Lng("@now");
                var gone = Once.Where(kv => kv.Value < now).Select(kv => kv.Key).ToList();
                foreach (var k in gone) Once.Remove(k);
                return gone.Count;
            }
            if (sql == InsOnce)
            {
                var k = c.Str("@key"); long r = c.Lng("@r"), now = c.Lng("@now");
                if (Once.TryGetValue(k, out var cur) && !(cur < now)) return 0;
                Once[k] = r;
                return 1;
            }
            if (sql == Ext)
            {
                var k = c.Str("@key"); long r = c.Lng("@r");
                if (Once.TryGetValue(k, out var cur) && cur < r) { Once[k] = r; return 1; }
                return 0;
            }
            if (sql == InsReplay)
            {
                var k = c.Str("@key"); long n = c.Lng("@counter");
                if (InsertAffectsNothing) return 0;
                if (Replay.TryGetValue(k, out var cur) && !(n > cur)) return 0;
                Replay[k] = n;
                return 1;
            }
            throw new InvalidOperationException("unexpected SQL: " + sql);
        }

        public object? Scalar(string sql, FakeCmd c)
        {
            Log.Add(sql);
            if (sql == Sel) return Replay.TryGetValue(c.Str("@key"), out var v) ? (object)v : null;
            throw new InvalidOperationException("unexpected SQL: " + sql);
        }
    }

    sealed class FakeConn : DbConnection
    {
        readonly FakeDb _db;
        ConnectionState _state = ConnectionState.Closed;
        public FakeConn(FakeDb db) => _db = db;
        [AllowNull] public override string ConnectionString { get; set; } = "";
        public override string Database => "fake";
        public override string DataSource => "fake";
        public override string ServerVersion => "0";
        public override ConnectionState State => _state;
        public override void Open() { _state = ConnectionState.Open; _db.Opens++; }
        public override void Close() => _state = ConnectionState.Closed;
        public override void ChangeDatabase(string databaseName) { }
        protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel) => throw new NotSupportedException();
        protected override DbCommand CreateDbCommand() => new FakeCmd(_db) { Connection = this };
    }

    sealed class FakeCmd : DbCommand
    {
        readonly FakeDb _db;
        readonly FakeParams _ps = new();
        public FakeCmd(FakeDb db) => _db = db;
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
        protected override DbParameter CreateDbParameter() => new FakeParam();
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

    sealed class FakeParam : DbParameter
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

    sealed class FakeParams : DbParameterCollection
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

    static (SqlStateStore Store, FakeDb Db) Sql(string table = SqlStateStore.DefaultTable)
    {
        var db = new FakeDb(table);
        return (new SqlStateStore(() => new FakeConn(db), table), db);
    }

    [Fact]
    public void SqlConstructorValidation()
    {
        Assert.Equal("connectionFactory", Assert.Throws<ArgumentNullException>(() => new SqlStateStore(null!)).ParamName);
        Func<DbConnection> f = () => new FakeConn(new FakeDb());
        foreach (var bad in new[] { "", null, new string('a', 64), "1abc", "a-b", "-ab" })
        {
            var ex = Assert.Throws<ArgumentException>(() => new SqlStateStore(f, bad!));
            Assert.Equal("table", ex.ParamName);
            Assert.StartsWith("table must be a plain SQL identifier ([A-Za-z_][A-Za-z0-9_]*)", ex.Message);
        }
        foreach (var ok in new[] { new string('a', 63), "_x", "T9_z", "Z" }) _ = new SqlStateStore(f, ok);
    }

    [Fact]
    public void SqlEnsureSchemaRunsAllThreeStatements()
    {
        var (s, db) = Sql("tbl");
        s.EnsureSchema();
        Assert.Equal(db.SchemaStatements, db.Log);
    }

    [Fact]
    public void SqlConsumeOnceBounds()
    {
        var (s, db) = Sql();
        Assert.True(s.ConsumeOnce("a", Pca.MaxSafeInt, 5)); // retainUntil == 2^53-1 is allowed
        Assert.True(s.ConsumeOnce("b", 10, 0)); // now == 0 is allowed
        int opens = db.Opens;
        Assert.Equal(SqlOnceMsg, Assert.Throws<ArgumentException>(() => s.ConsumeOnce("c", Pca.MaxSafeInt + 1, 0)).Message);
        Assert.Equal(SqlOnceMsg, Assert.Throws<ArgumentException>(() => s.ConsumeOnce("c", 10, -1)).Message);
        Assert.Equal(SqlOnceMsg, Assert.Throws<ArgumentException>(() => s.ConsumeOnce("", 10, 0)).Message);
        Assert.Equal(SqlOnceMsg, Assert.Throws<ArgumentException>(() => s.ConsumeOnce("c", 4, 5)).Message);
        Assert.Equal(opens, db.Opens);
    }

    [Fact]
    public void SqlConsumeOncePrunesExpiredRows()
    {
        var (s, db) = Sql();
        Assert.True(s.ConsumeOnce("a", 50, 10));
        Assert.True(s.ConsumeOnce("b", 200, 100)); // the prune deletes a (50 < 100)
        Assert.Equal(new[] { "b" }, db.Once.Keys.ToArray());
        Assert.True(s.ConsumeOnce("b", 300, 250)); // expired b revived
        Assert.Equal(300, db.Once["b"]);
    }

    [Fact]
    public void SqlConsumeOnceExtendsALiveRow()
    {
        var (s, db) = Sql();
        Assert.True(s.ConsumeOnce("a", 100, 10));
        Assert.False(s.ConsumeOnce("a", 300, 50));
        Assert.Equal(300, db.Once["a"]); // extended, never shortened
        Assert.False(s.ConsumeOnce("a", 120, 60));
        Assert.Equal(300, db.Once["a"]);
        Assert.False(s.ConsumeOnce("a", 400, 200)); // still live under the extended horizon
    }

    [Fact]
    public void SqlClaimBoundsRefuseWithoutTouchingTheDatabase()
    {
        var (s, db) = Sql();
        Assert.Equal(new ClaimResult(false), s.Claim(null!, 5));
        Assert.Equal(new ClaimResult(false), s.Claim("k", -1));
        Assert.Equal(new ClaimResult(false), s.Claim("k", Pca.MaxSafeInt + 1));
        Assert.Equal(0, db.Opens);
        Assert.Empty(db.Replay);
        Assert.Equal(new ClaimResult(true), s.Claim("k", Pca.MaxSafeInt));
        Assert.Equal(new ClaimResult(true), s.Claim("z", 0));
    }

    [Fact]
    public void SqlClaimRefusalCarriesTheStoredCounter()
    {
        var (s, _) = Sql();
        Assert.Equal(new ClaimResult(true), s.Claim("k", 5));
        Assert.Equal(new ClaimResult(false, 5), s.Claim("k", 5));
        Assert.Equal(new ClaimResult(false, 5), s.Claim("k", 4));
        Assert.Equal(new ClaimResult(true), s.Claim("k", 6));
    }

    [Fact]
    public void SqlClaimRefusalWithoutARowHasNoCounter()
    {
        var (s, db) = Sql();
        db.InsertAffectsNothing = true;
        Assert.Equal(new ClaimResult(false, null), s.Claim("k", 5));
    }

    [Fact]
    public void SqlLast()
    {
        var (s, _) = Sql();
        Assert.Null(s.Last("k"));
        Assert.True(s.Claim("k", 7)!.Ok);
        Assert.Equal(7L, s.Last("k"));
        Assert.Null(s.Last("other"));
    }

    [Fact]
    public void SqlNullConnectionFails()
    {
        var s = new SqlStateStore(() => null!);
        Assert.Equal("the connection factory returned null", Assert.Throws<InvalidOperationException>(() => s.Last("k")).Message);
    }

    // ================= small pure pieces =================

    [Fact] public void StateKeyJoinsWithAColon() => Assert.Equal("g:h", Pca.StateKey("g", "h"));

    static D Risk(object? alpha) => new()
    {
        ["weights"] = new D { ["alpha"] = alpha, ["beta"] = 0, ["gamma"] = 0, ["delta"] = 0, ["epsilon"] = 0, ["zeta"] = 0 },
        ["theta1"] = 0, ["theta2"] = 1, ["kappa"] = 1, ["lambda"] = 0, ["rho"] = 0, ["bMax"] = 0,
    };

    [Fact]
    public void NonFiniteNumbersAreNotNumbers()
    {
        Assert.Null(Pca.ValidateRiskPolicy(Risk(0)));
        const string e = "risk_policy.weights.alpha must be finite and >= 0";
        Assert.Equal(e, Pca.ValidateRiskPolicy(Risk(double.NaN)));
        Assert.Equal(e, Pca.ValidateRiskPolicy(Risk(double.PositiveInfinity)));
        Assert.Equal(e, Pca.ValidateRiskPolicy(Risk(new Num("1e999"))));
    }

    static D Str() => new() { ["type"] = "string" };
    static D Schema(D props) => new() { ["props"] = props };

    [Fact]
    public void PropertyNamesAAndZAreSafe()
    {
        Assert.Null(Pca.ValidateArgSchema(Schema(new D { ["A"] = Str() })));
        Assert.Null(Pca.ValidateArgSchema(Schema(new D { ["Z"] = Str() })));
        Assert.Null(Pca.ValidateArgSchema(Schema(new D { ["a"] = Str(), ["z"] = Str(), ["_0"] = Str(), ["9"] = Str() })));
        Assert.Equal("invalid property name 'a-b'", Pca.ValidateArgSchema(Schema(new D { ["a-b"] = Str() })));
    }

    [Fact]
    public void NumberAndIntegerBoundsAreValidated()
    {
        foreach (var t in new[] { "number", "integer" })
        {
            Assert.Equal("n: bad min", Pca.ValidateArgSchema(Schema(new D { ["n"] = new D { ["type"] = t, ["min"] = "x" } })));
            Assert.Equal("n: bad max", Pca.ValidateArgSchema(Schema(new D { ["n"] = new D { ["type"] = t, ["max"] = "x" } })));
            Assert.Equal("n: min > max", Pca.ValidateArgSchema(Schema(new D { ["n"] = new D { ["type"] = t, ["min"] = 2, ["max"] = 1 } })));
        }
    }

    // nodes: the top object 1, each object spec 1 (counted once), each leaf spec 1
    static D NodeSchema(int topStrings)
    {
        var props = new D();
        for (int i = 0; i < 3; i++)
        {
            var inner = new D();
            for (int j = 0; j < 64; j++) inner["s" + j] = Str();
            props["o" + i] = new D { ["type"] = "object", ["props"] = inner }; // 65 nodes each
        }
        for (int i = 0; i < topStrings; i++) props["t" + i] = Str();
        props["z"] = new D { ["type"] = "object", ["props"] = new D() };
        return Schema(props);
    }

    [Fact]
    public void SchemaNodeBudgetIsInclusive()
    {
        Assert.Null(Pca.ValidateArgSchema(NodeSchema(59))); // 1 + 195 + 59 + 1 = 256 nodes, the last an object spec
        Assert.Equal("z: schema too large", Pca.ValidateArgSchema(NodeSchema(60)));
    }

    // ================= tool_schema evaluation =================

    static D ToolCv(D schema) => new()
    {
        ["type"] = "tool_schema", ["tool"] = "t", ["schema"] = schema, ["schema_digest"] = Pca.HashCanonical(schema),
        ["signature_digest"] = "sig",
        ["binding_digest"] = Pca.HashCanonical(new D { ["tool"] = "t", ["signature_digest"] = "sig", ["schema"] = schema }),
    };

    static string? Reason(D cv, D args, object? sig = null)
    {
        var (ok, reason) = Pca.EvaluateToolSchema(cv, new ToolCall("t", args, null, sig));
        Assert.Equal(reason is null, ok);
        return reason;
    }

    [Fact]
    public void UnexpectedArgumentNamesAreJsonQuoted()
    {
        var cv = ToolCv(Schema(new D { ["x"] = Str() }));
        Assert.Null(Reason(cv, new D { ["x"] = "v" }));
        string U(string k) => Reason(cv, new D { [k] = 1 })!;
        Assert.Equal("args: unexpected argument \"a b\"", U("a b"));
        Assert.Equal("args: unexpected argument \"a\\u001f\"", U("a\u001f"));
        Assert.Equal("args: unexpected argument \"a\uD83D\uDE00\"", U("a\uD83D\uDE00"));
        Assert.Equal("args: unexpected argument \"\uD83D\uDE00b\"", U("\uD83D\uDE00b"));
        Assert.Equal("args: unexpected argument \"a\uD83D\uDE00\uD83D\uDE01\"", U("a\uD83D\uDE00\uD83D\uDE01"));
        Assert.Equal("args: unexpected argument \"a\\ud83d\"", U("a\uD83D"));
        Assert.Equal("args: unexpected argument \"\\ud83dx\"", U("\uD83Dx"));
        Assert.Equal("args: unexpected argument \"\\ude00\"", U("\uDE00"));
    }

    [Fact]
    public void ValueBudgetIsInclusive()
    {
        D Arr() => new() { ["type"] = "array", ["items"] = new D { ["type"] = "integer" }, ["maxItems"] = 4096 };
        var cv = ToolCv(Schema(new D { ["a"] = Arr(), ["b"] = Arr(), ["c"] = Arr() }));
        D Args(int c) => new()
        {
            ["a"] = new L(Enumerable.Repeat<object?>(1, 4096)), ["b"] = new L(Enumerable.Repeat<object?>(1, 4096)),
            ["c"] = new L(Enumerable.Repeat<object?>(1, c)),
        };
        Assert.Null(Reason(cv, Args(1805))); // 4097 + 4097 + 1806 = 10000 values
        Assert.Equal("args.c[1805]: too many values", Reason(cv, Args(1806)));
    }

    [Fact]
    public void AnUncanonicalizableSignatureFailsClosed()
    {
        var cv = ToolCv(Schema(new D { ["x"] = Str() }));
        Assert.Equal("evaluation error (fail closed)", Reason(cv, new D { ["x"] = "v" }, new object()));
    }

    // ---- private bounds unreachable through the public API (the schema validator bounds the value walk), driven directly ----

    const BindingFlags NP = BindingFlags.NonPublic | BindingFlags.Static;
    static object? Call(string name, object?[] args) => typeof(Pca).GetMethod(name, NP)!.Invoke(null, args);
    static object Budget(int n)
    {
        var t = typeof(Pca).GetNestedType("Budget", BindingFlags.NonPublic)!;
        var b = Activator.CreateInstance(t, nonPublic: true)!;
        t.GetField("N")!.SetValue(b, n);
        return b;
    }

    [Fact]
    public void ObjectSchemaErrorBounds()
    {
        Assert.Null(Call("ObjectSchemaError", new object?[] { new D(), false, null, 8, Budget(0) }));
        Assert.Equal("schema too deep", Call("ObjectSchemaError", new object?[] { new D(), false, null, 9, Budget(0) }));
        Assert.Null(Call("ObjectSchemaError", new object?[] { new D(), false, null, 1, Budget(255) }));
        Assert.Equal("schema too large", Call("ObjectSchemaError", new object?[] { new D(), false, null, 1, Budget(256) }));
    }

    [Fact]
    public void CheckValueBounds()
    {
        string? CV(D spec, object? v, int depth, int n = 0) => (string?)Call("CheckValue", new object?[] { spec, v, "p", depth, Budget(n) });
        Assert.Null(CV(Str(), "s", 9));
        Assert.Equal("p: too deep", CV(Str(), "s", 10));
        Assert.Equal("p[0]: too deep", CV(new D { ["type"] = "array", ["items"] = Str() }, new L { "s" }, 9));
        Assert.Equal("p.k: too deep", CV(new D { ["type"] = "object", ["props"] = new D { ["k"] = Str() } }, new D { ["k"] = "s" }, 9));
        Assert.Equal("p: unknown type", CV(new D { ["type"] = "weird" }, 1, 2));
        Assert.Null(CV(Str(), "s", 2, 9999));
        Assert.Equal("p: too many values", CV(Str(), "s", 2, 10000));
    }

    [Fact]
    public void JsEqFallbackIsFalse()
    {
        Assert.False((bool)Call("JsEq", new object?[] { null, null })!);
        Assert.False((bool)Call("JsEq", new object?[] { new D(), new D() })!);
        Assert.True((bool)Call("JsEq", new object?[] { "a", "a" })!);
    }

    // ================= agent-native caveat evaluator =================

    /// <summary>A list whose generic enumeration throws: drives the evaluator's catch (LINQ goes through the interface).</summary>
    sealed class Bomb : List<object?>, IEnumerable<object?>
    {
        IEnumerator<object?> IEnumerable<object?>.GetEnumerator() => throw new InvalidOperationException("bomb");
    }

    static void Fails(Caveats.Result r, params string[] failed)
    {
        Assert.False(r.Ok);
        Assert.Equal(failed, r.Failed.ToArray());
    }

    [Fact]
    public void AgentCaveatsFailClosed()
    {
        Fails(Pca.EvaluateAgentCaveats("x", new D()), "<malformed caveats>");
        Fails(Pca.EvaluateAgentCaveats(new L { "x" }, new D()), "<malformed>");
        Fails(Pca.EvaluateAgentCaveats(new L { new D { ["type"] = "predicates" } }, new D()), "predicates");
        Fails(Pca.EvaluateAgentCaveats(new L { new D { ["type"] = "predicates", ["allow"] = new L() } }, new D()), "predicates");
        Fails(Pca.EvaluateAgentCaveats(new L { new D { ["type"] = "predicates", ["allow"] = new Bomb() } }, new D()), "predicates");
        Fails(Pca.EvaluateAgentCaveats(new L { new D { ["type"] = "x" } }, null), "<evaluation error>");
        var ok = Pca.EvaluateAgentCaveats(new L(), new D());
        Assert.True(ok.Ok);
        Assert.Empty(ok.Failed);
    }
}
