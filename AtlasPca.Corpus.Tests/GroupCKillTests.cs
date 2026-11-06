using System.Collections;
using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using AtlasPca;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Exact answers, boundaries and fail-closed catches of the smaller modules (TS references: packages/pca/src and
/// packages/pca-grants/src, same module names).</summary>
public class GroupCKillTests
{
    sealed class Hostile : IEqualityComparer<string>
    {
        public bool Armed;
        public bool Equals(string? a, string? b) => Armed ? throw new InvalidOperationException("hostile") : a == b;
        public int GetHashCode(string s) => Armed ? throw new InvalidOperationException("hostile") : 0;
    }

    // an empty dictionary answers a lookup without asking its comparer, so it holds one member before it turns hostile
    static D HostileDict(string key = "x")
    {
        var h = new Hostile();
        var d = new D(h) { [key] = null };
        h.Armed = true;
        return d;
    }

    static Num N(long v) => new(v.ToString(System.Globalization.CultureInfo.InvariantCulture));
    static EdKey Key(byte b) => EdKey.FromSeed(Enumerable.Repeat(b, 32).ToArray());
    static readonly EdKey K1 = Key(61), K2 = Key(62);

    // ---- AtomicKv ----------------------------------------------------------------------------------------------------

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
        readonly List<object> l = new();
        public override int Count => l.Count;
        public override object SyncRoot => l;
        public override int Add(object value) { l.Add(value); return l.Count - 1; }
        public override void AddRange(Array values) { foreach (var v in values) l.Add(v!); }
        public override void Clear() => l.Clear();
        public override bool Contains(object value) => l.Contains(value);
        public override bool Contains(string value) => false;
        public override void CopyTo(Array array, int index) => ((ICollection)l).CopyTo(array, index);
        public override IEnumerator GetEnumerator() => l.GetEnumerator();
        public override int IndexOf(object value) => l.IndexOf(value);
        public override int IndexOf(string parameterName) => -1;
        public override void Insert(int index, object value) => l.Insert(index, value);
        public override void Remove(object value) => l.Remove(value);
        public override void RemoveAt(int index) => l.RemoveAt(index);
        public override void RemoveAt(string parameterName) { }
        protected override DbParameter GetParameter(int index) => (DbParameter)l[index];
        protected override DbParameter GetParameter(string parameterName) => throw new NotSupportedException();
        protected override void SetParameter(int index, DbParameter value) => l[index] = value;
        protected override void SetParameter(string parameterName, DbParameter value) => throw new NotSupportedException();
    }

    // every write loses the race: the row is always there, and no conditional statement ever changes a row
    sealed class FakeCmd : DbCommand
    {
        [AllowNull] public override string CommandText { get; set; } = "";
        public override int CommandTimeout { get; set; }
        public override CommandType CommandType { get; set; }
        public override bool DesignTimeVisible { get; set; }
        public override UpdateRowSource UpdatedRowSource { get; set; }
        protected override DbConnection? DbConnection { get; set; }
        protected override DbParameterCollection DbParameterCollection { get; } = new FakeParams();
        protected override DbTransaction? DbTransaction { get; set; }
        public override void Cancel() { }
        public override int ExecuteNonQuery() => 0;
        public override object? ExecuteScalar() => null;
        public override void Prepare() { }
        protected override DbParameter CreateDbParameter() => new FakeParam();
        protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior)
        {
            var t = new DataTable();
            t.Columns.Add("v", typeof(string));
            t.Columns.Add("ver", typeof(long));
            t.Rows.Add("old", 1L);
            return t.CreateDataReader();
        }
    }

    sealed class FakeConn : DbConnection
    {
        [AllowNull] public override string ConnectionString { get; set; } = "";
        public override string Database => "";
        public override string DataSource => "";
        public override string ServerVersion => "";
        public override ConnectionState State => ConnectionState.Open;
        public override void ChangeDatabase(string databaseName) { }
        public override void Close() { }
        public override void Open() { }
        protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel) => throw new NotSupportedException();
        protected override DbCommand CreateDbCommand() => new FakeCmd();
    }

    [Fact]
    public void SqlKvRefusesANullFactoryAndAFactoryThatReturnsNull()
    {
        Assert.Throws<ArgumentNullException>(() => new SqlAtomicKv(null!));
        var e = Assert.Throws<InvalidOperationException>(() => { new SqlAtomicKv(() => null!).Get("k"); });
        Assert.Equal("the connection factory returned null", e.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("1abc")]
    [InlineData("-")]
    [InlineData("a-b")]
    [InlineData("a b")]
    public void SqlKvRefusesATableThatIsNotAPlainIdentifier(string? table)
    {
        var e = Assert.Throws<ArgumentException>(() => new SqlAtomicKv(() => new FakeConn(), table!));
        Assert.Equal("table must be a plain SQL identifier ([A-Za-z_][A-Za-z0-9_]*) (Parameter 'table')", e.Message);
        Assert.Equal("table", e.ParamName);
    }

    [Fact]
    public void SqlKvTableBoundsAre63Characters()
    {
        var e = Assert.Throws<ArgumentException>(() => new SqlAtomicKv(() => new FakeConn(), new string('a', 64)));
        Assert.Equal("table", e.ParamName);
        Assert.NotNull(new SqlAtomicKv(() => new FakeConn(), new string('a', 63)));
        Assert.NotNull(new SqlAtomicKv(() => new FakeConn(), "_"));
        Assert.NotNull(new SqlAtomicKv(() => new FakeConn(), "_abc1"));
        Assert.NotNull(new SqlAtomicKv(() => new FakeConn(), "A1_z"));
    }

    [Fact]
    public void SqlKvGivesUpAfterExactlyMaxAttempts()
    {
        var calls = 0;
        var kv = new SqlAtomicKv(() => new FakeConn());
        var e = Assert.Throws<InvalidOperationException>(() => kv.Update("k", prev =>
        {
            Assert.Equal("old", prev);
            if (++calls > 1000) throw new ArithmeticException("an attempt past the limit");
            return "new";
        }));
        Assert.Equal("SqlAtomicKv: update of 'k' lost the race 1000 times (fail closed)", e.Message);
        Assert.Equal(1000, calls);
    }

    // ---- AttestCommon / AttestFactory --------------------------------------------------------------------------------

    [Fact]
    public void AFailedHardwareResultIsNeitherOkNorBound()
    {
        var r = HardwareResult.Fail("why");
        Assert.False(r.Ok);
        Assert.False(r.Bound);
        Assert.Equal("why", r.Reason);
    }

    [Fact]
    public void BindingEpochBoundIsTheLargestSafeInteger()
    {
        Assert.Equal(64, AttestUtil.BindingBytes(new AttestationBinding("h", "g", Pca.MaxSafeInt, "n")).Length);
        var e = Assert.Throws<AttestError>(() => AttestUtil.BindingBytes(new AttestationBinding("h", "g", 9007199254740992d, "n")));
        Assert.Equal("binding: epoch must be a non-negative safe integer", e.Message);
    }

    [Fact]
    public void JsSpaceIsExactlyTheEcmaScriptSet()
    {
        foreach (var c in "\t\n\v\f\r\u0020\u00A0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u2028\u2029\u202F\u205F\u3000\uFEFF") Assert.True(AttestUtil.IsJsSpace(c), $"U+{(int)c:X4}");
        foreach (var c in "a\u0008\u000E\u1FFF\u200B\u2027\u202A\u3001\uFEFE") Assert.False(AttestUtil.IsJsSpace(c), $"U+{(int)c:X4}");
    }

    [Fact]
    public void JsTrimHandlesEmptyAndAllSpace()
    {
        Assert.Equal("", AttestUtil.JsTrim(""));
        Assert.Equal("", AttestUtil.JsTrim("  "));
        Assert.Equal("a b", AttestUtil.JsTrim("  a b﻿"));
    }

    [Fact]
    public void NodeB64StopsAtPaddingSkipsForeignCharactersAndDecodesEveryByte()
    {
        // answers checked against Node's Buffer.from(s, 'base64')
        Assert.Equal(new byte[] { 0x41 }, AttestUtil.NodeB64("QQ=QQ"));
        Assert.Equal(new byte[] { 0x41 }, AttestUtil.NodeB64("Q!Q"));
        Assert.Equal(new byte[] { 0xff, 0xff, 0xff, 0xff }, AttestUtil.NodeB64("/////w"));
        Assert.Equal(Enumerable.Repeat((byte)0xff, 9).ToArray(), AttestUtil.NodeB64("////////////"));
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, AttestUtil.NodeB64("AQIDBA"));
    }

    [Fact]
    public void AnEmptyStringIsNotHex()
    {
        Assert.False(AttestUtil.IsHexString(""));
        Assert.False(AttestUtil.IsHexString("a"));
        Assert.True(AttestUtil.IsHexString("aB"));
    }

    [Fact]
    public void AzureRuntimeDataWithOneForeignCharacterIsRefused()
    {
        var runtime = Encoding.UTF8.GetBytes("{\"user-data\":\"z" + new string('a', 127) + "\"}");
        var report = new byte[64];
        SHA256.HashData(runtime).CopyTo(report, 0);
        Assert.Equal("runtime data carries no 64-byte hex user-data", AttestUtil.CheckAzureRuntimeDataBinding(report, runtime, new AttestationBinding("h", "g", 1, "n")));
    }

    [Fact]
    public void ErrMsgReadsTheExceptionElseInvalid()
    {
        Assert.Equal("invalid", AttestUtil.ErrMsg(null));
        Assert.Equal("boom", AttestUtil.ErrMsg(new InvalidOperationException("boom")));
    }

    sealed class BoomImpl : IVendorImpl
    {
        public HardwareResult Verify(D? ev, AttestationBinding? expected, long nowMs) => throw new InvalidOperationException("boom");
    }

    sealed class OkImpl : IVendorImpl
    {
        public D Measured = new() { ["model_id"] = "m" };
        public HardwareResult Verify(D? ev, AttestationBinding? expected, long nowMs) => new(true, true, null, Measured);
    }

    [Theory]
    [InlineData("amd-sev-snp", "amd-snp verification error (fail closed): boom")]
    [InlineData("intel-tdx-dcap", "intel-dcap verification error (fail closed): boom")]
    [InlineData("azure-maa", "azure-maa verification error (fail closed): boom")]
    [InlineData("gcp-confidential-space", "gcp-confidential-space verification error (fail closed): boom")]
    [InlineData("nvidia-gpu-spdm", "nvidia-spdm verification error (fail closed): boom")]
    public void AThrowingVendorFailsClosedWithItsPrefix(string vendor, string reason)
    {
        var r = new VendorVerifier(vendor, new BoomImpl(), null).Verify(null, null, 0);
        Assert.False(r.Ok);
        Assert.Equal(reason, r.Reason);
    }

    [Fact]
    public void EmptyOverridesLeaveTheMeasuredIdentityUntouched()
    {
        var impl = new OkImpl();
        Assert.Same(impl.Measured, new VendorVerifier("azure-maa", impl, new D()).Verify(null, null, 0).Measured);
        var merged = new VendorVerifier("azure-maa", impl, new D { ["operator"] = "o" }).Verify(null, null, 0).Measured!;
        Assert.Equal("o", merged["operator"]);
        Assert.Equal("m", merged["model_id"]);
    }

    // ---- BreakGlass --------------------------------------------------------------------------------------------------

    [Fact]
    public void BreakGlassUseInputBoundIs128Characters()
    {
        var reg = new BreakGlassRegistry(new BreakGlassPolicy(new[] { K1.Id }, new[] { K2.Id }));
        Assert.Equal("unknown_break_glass", reg.Use(new string('i', 128), "h", "d", N(1), true).Code);
        Assert.Equal("bad_input", reg.Use(new string('i', 129), "h", "d", N(1), true).Code);
    }

    [Fact]
    public void AnUnjustifiedReviewFreezesTheHolderOfThatGrant()
    {
        var reg = new BreakGlassRegistry(new BreakGlassPolicy(new[] { K1.Id }, new[] { K2.Id }));
        var body = Issue.NormJ(new D
        {
            ["v"] = 1L, ["id"] = "g", ["holder"] = "h", ["grant_ref"] = "r", ["reason_digest"] = "d", ["max_uses"] = 2L, ["issued_at"] = 1L, ["expires_at"] = 1000L,
            ["review_within"] = 1000L, ["notify_to"] = "n", ["authority"] = K1.Id,
        });
        Assert.True(reg.Accept(new D(body) { ["sig"] = Issue.SignBody(K1, BreakGlass.Domain, body) }, N(5)).Ok);
        Assert.Equal("allow", reg.Use("g", "h", "d", N(6), true).Decision);
        var review = Issue.NormJ(new D { ["v"] = 1L, ["id"] = "g", ["outcome"] = "unjustified", ["notes_digest"] = "n", ["at"] = 7L, ["reviewer"] = K2.Id });
        Assert.True(reg.Review(new D(review) { ["sig"] = Issue.SignBody(K2, BreakGlass.ReviewDomain, review) }, "h", N(8)).Ok);
        Assert.Equal(new BreakGlassDecision("deny", "holder_frozen", "g"), reg.Use("g", "h", "d", N(9), true));
    }

    // ---- IntentHistory / IntentJs ------------------------------------------------------------------------------------

    [Fact]
    public void AMissingWindowOrEventThrowsItsOwnMessage()
    {
        var w = Assert.Throws<ArgumentNullException>(() => { IntentHistory.InWindow(null!, N(1), N(2)); });
        Assert.Equal("accumulator window missing (Parameter 'win')", w.Message);
        var e = Assert.Throws<ArgumentNullException>(() => { IntentHistory.MonitorStep(new D(), "idle", null!); });
        Assert.Equal("monitor event missing (Parameter 'e')", e.Message);
    }

    [Fact]
    public void AnEventWithoutAVerbIsNeverSelected()
    {
        // intent-acc.ts:209: verbs.includes(undefined) is false, even when the list holds the empty verb or any other text
        foreach (var name in new[] { "", "Stryker was here!" })
        {
            var a = new D { ["sel"] = new D { ["verbs"] = new L { name } }, ["agg"] = "count", ["win"] = new D { ["kind"] = "task" } };
            var noVerb = new D { ["status"] = "committed", ["t"] = N(1) };
            Assert.Equal(0L, IntentHistory.AccPreState(a, new L { noVerb }, null, N(2), null)!["count"]);
            var named = new D { ["status"] = "committed", ["t"] = N(1), ["verb"] = name };
            Assert.Equal(1L, IntentHistory.AccPreState(a, new L { named }, null, N(2), null)!["count"]);
        }
    }

    static string? PendingAfter(D within)
    {
        var m = new D(within) { ["kind"] = "responds_within", ["p"] = new D { ["verb"] = "v" }, ["q"] = new D { ["verb"] = "other" } };
        return IntentHistory.MonitorStep(m, "idle", new D { ["status"] = "committed", ["verb"] = "v", ["resource"] = "r", ["params"] = new D() });
    }

    [Fact]
    public void APendingCountPrintsAsJavaScriptString()
    {
        Assert.Equal("pending:NaN", PendingAfter(new D()));
        Assert.Equal("pending:Infinity", PendingAfter(new D { ["within"] = double.PositiveInfinity }));
        Assert.Equal("pending:-Infinity", PendingAfter(new D { ["within"] = double.NegativeInfinity }));
        Assert.Equal("pending:3", PendingAfter(new D { ["within"] = N(3) }));
    }

    [Fact]
    public void JsKeysPutCanonicalIndicesFirstIncludingZero() =>
        Assert.Equal(new[] { "0", "2", "10", "b", "05" }, IntentJs.JsKeys(new[] { "b", "10", "05", "0", "2" }).ToArray());

    // ---- JsCanon -----------------------------------------------------------------------------------------------------

    [Fact]
    public void LenientRefusesANonFiniteArrayMember()
    {
        Assert.Null(JsCanon.Lenient(new L { double.NaN }));
        Assert.Null(JsCanon.Lenient(new L { 1L, double.PositiveInfinity, 2L }));
        Assert.Equal("[1,2]", JsCanon.Lenient(new L { 1L, 2L }));
    }

    [Fact]
    public void LenientEscapesControlCharactersByName() =>
        Assert.Equal("\"\\b\\f\\n\\r\\t\\u0001\"", JsCanon.Lenient("\b\f\n\r\t\u0001"));

    [Theory]
    [InlineData(0.5, "0.5")]
    [InlineData(0.001, "0.001")]
    [InlineData(0.0001, "0.0001")]
    [InlineData(0.00001, "0.00001")]
    [InlineData(0.000001, "0.000001")]
    [InlineData(1e-7, "1e-7")]
    [InlineData(-1.5e-7, "-1.5e-7")]
    [InlineData(100d, "100")]
    [InlineData(-1.5, "-1.5")]
    [InlineData(1e20, "100000000000000000000")]
    [InlineData(1e21, "1e+21")]
    [InlineData(1.5e300, "1.5e+300")]
    [InlineData(5e-324, "5e-324")]
    [InlineData(0d, "0")]
    [InlineData(-0d, "0")]
    [InlineData(double.NaN, "NaN")]
    [InlineData(double.PositiveInfinity, "Infinity")]
    [InlineData(double.NegativeInfinity, "-Infinity")]
    public void NumberStringMatchesJavaScript(double d, string s) => Assert.Equal(s, JsCanon.NumberString(d));

    // ---- Lease -------------------------------------------------------------------------------------------------------

    static D LeaseRec(string id, long seq, long renewed, long expires, string just)
    {
        var b = Issue.NormJ(new D
        {
            ["v"] = 1L, ["lease_id"] = id, ["path"] = "svc/" + id, ["grant_ref"] = "g", ["holder"] = "h", ["requester"] = "r", ["approvers"] = new L { "a" },
            ["justification_digest"] = just, ["seq"] = seq, ["issued_at"] = 1000L, ["renewed_at"] = renewed, ["expires_at"] = expires, ["max_ttl"] = 100000L, ["authority"] = K1.Id,
        });
        return new D(b) { ["sig"] = Issue.SignBody(K1, Lease.Domain, b) };
    }

    [Fact]
    public void LeaseSequenceRefusalsCarryTheirReasonsAndARenewalIsRecorded()
    {
        var reg = new LeaseRegistry(new LeasePolicy(new[] { K1.Id }));
        Assert.Equal(new LeaseAccept(false, "bad_seq", Reason: "a new lease starts at seq 1"), reg.Accept(LeaseRec("a", 2, 1000, 2000, "j")));
        Assert.True(reg.Accept(LeaseRec("a", 1, 1000, 2000, "j")).Ok);
        Assert.Equal(new LeaseAccept(false, "bad_seq", Reason: "renewals advance seq by exactly 1"), reg.Accept(LeaseRec("a", 3, 1500, 3000, "j2")));
        Assert.Equal(new LeaseAccept(false, "expired_lease", Reason: "an expired lease cannot be renewed"), reg.Accept(LeaseRec("a", 2, 2000, 3000, "j2")));
        var renewal = LeaseRec("a", 2, 1500, 3000, "j2");
        Assert.True(reg.Accept(renewal).Ok);
        Assert.Equal(new[] { 1L, 2L }, reg.Leases["a"].History.Select(h => h.Seq));
        Assert.Same(renewal, reg.Leases["a"].Current);
    }

    // ---- Ledger ------------------------------------------------------------------------------------------------------

    static readonly EdKey Guardian = Key(63), Witness = Key(64);
    static readonly byte[] LeafA = SHA256.HashData(new byte[] { 1 }), LeafC = SHA256.HashData(new byte[] { 2 });
    static readonly string RootA = Pca.B64u(LeafA);

    static D Sth(long size, string root, object? prev)
    {
        var body = Issue.NormJ(new D { ["instance_id"] = "i", ["principal"] = "p", ["size"] = size, ["root"] = root, ["prev_root"] = prev, ["timestamp"] = 1L });
        return new D(body) { ["guardian"] = Guardian.Id, ["sig"] = Pca.B64u(Guardian.Sign(IntentJs.Message(Ledger.SthDomain, body))) };
    }

    static D Cosig(D sth)
    {
        var body = new D();
        foreach (var k in new[] { "instance_id", "principal", "size", "root", "prev_root" }) body[k] = sth[k];
        body["guardian_epoch"] = N(0);
        return new D { ["key"] = Witness.Id, ["sig"] = Pca.B64u(Witness.Sign(IntentJs.Message(Ledger.SthWitnessDomain, body))) };
    }

    [Fact]
    public void LedgerVerifiersAreFalseOnAThrowingProof()
    {
        Assert.False(Ledger.VerifyLedgerInclusion("r", HostileDict(), "c"));
        Assert.False(Ledger.VerifyLedgerConsistency("a", "b", HostileDict()));
    }

    [Fact]
    public void WitnessCheckStopsAtTheThresholdAndIsFalseBelowIt()
    {
        var sth = Sth(1, RootA, null);
        var policy1 = new D { ["threshold"] = N(1), ["witnessKeys"] = new L { Witness.Id } };
        // the walk ends at the first valid cosignature: the throwing entry after it is never read
        sth["witnesses"] = new L { Cosig(sth), HostileDict() };
        Assert.True(Ledger.VerifyWitnessCosignatures(sth, policy1));
        sth["witnesses"] = new L { Cosig(sth) };
        Assert.False(Ledger.VerifyWitnessCosignatures(sth, new D { ["threshold"] = N(2), ["witnessKeys"] = new L { Witness.Id } }));
    }

    [Fact]
    public void HeadConsistencyNeedsBothProofSizesToMatchTheHeads()
    {
        var older = Sth(1, RootA, null);
        var newer = Sth(2, RootA, RootA);
        foreach (var (o, n) in new[] { (2L, 2L), (1L, 1L) }) // each path checks out on its own (equal sizes, equal roots); one size is off
            Assert.False(Ledger.VerifyHeadConsistency(older, newer, new D { ["oldSize"] = N(o), ["newSize"] = N(n), ["path"] = new L() }, Guardian.Id, null));
        Assert.False(Ledger.VerifyHeadConsistency(older, newer, new D { ["newSize"] = N(2), ["path"] = new L() }, Guardian.Id, null));
        Assert.False(Ledger.VerifyHeadConsistency(older, newer, new D { ["oldSize"] = N(1), ["path"] = new L() }, Guardian.Id, null));
    }

    [Fact]
    public void ACheckpointChainNeedsAProofFromTheSecondHeadOn()
    {
        var newRoot = Pca.B64u(Pca.Sha256Of(new byte[] { 1 }, LeafA, LeafC));
        var older = Sth(1, RootA, null);
        var newer = Sth(2, newRoot, RootA);
        var proof = new D { ["oldSize"] = N(1), ["newSize"] = N(2), ["path"] = new L { Pca.B64u(LeafC) } };
        Assert.Equal(new CheckpointVerdict(true, 0), Ledger.VerifyCheckpointChain(new L { new D { ["sth"] = older }, new D { ["sth"] = newer, ["proof"] = proof } }, Guardian.Id, null));
        Assert.Equal(new CheckpointVerdict(false, 1), Ledger.VerifyCheckpointChain(new L { new D { ["sth"] = older }, new D { ["sth"] = newer } }, Guardian.Id, null));
        Assert.Equal(new CheckpointVerdict(false, 1), Ledger.VerifyCheckpointChain(new L { new D { ["sth"] = older }, new D { ["sth"] = newer, ["proof"] = false } }, Guardian.Id, null));
    }

    // ---- PcaDomainSig ------------------------------------------------------------------------------------------------

    [Fact]
    public void VerifyDigestIsFalseWhenItThrows() => Assert.False(Pca.VerifyDigest("s", null!, "x"));

    // ---- PcaGrant ----------------------------------------------------------------------------------------------------

    [Fact]
    public void GrantUrlBoundsMatchTheReference()
    {
        const string b = "https://a/";
        Assert.True(PcaGrant.IsHttpsUrl(b + new string('x', 2048 - b.Length)));
        Assert.False(PcaGrant.IsHttpsUrl(b + new string('x', 2049 - b.Length)));
        Assert.True(PcaGrant.IsHttpsUrl(b + "!"));
        Assert.True(PcaGrant.IsHttpsUrl(b + "~"));
        Assert.False(PcaGrant.IsHttpsUrl(b + " "));
        Assert.False(PcaGrant.IsHttpsUrl(b + "\u007f"));
    }

    static D Detail(params object?[] locations)
    {
        var d = new D { ["type"] = PcaGrant.Type, ["chain_digest"] = PcaGrant.ChainDigest(new[] { "x" }), ["chain_len"] = N(1) };
        if (locations.Length > 0) d["locations"] = new L(locations);
        return d;
    }

    [Fact]
    public void GrantLocationsMustAllBeUrls()
    {
        Assert.Null(PcaGrant.Validate(Detail("https://a/", "https://b/")));
        Assert.Equal("bad_locations", PcaGrant.Validate(Detail("https://a/", 5L)));
    }

    [Fact]
    public void GrantRefusalsCarryNoIndex()
    {
        var chain = new[] { "x" };
        void Refused(string code, PcaGrantResult r) { Assert.Equal(code, r.Code); Assert.Equal(-1, r.Index); Assert.Empty(r.Details); }
        Refused("not_an_array", PcaGrant.Parse("x"));
        Refused("too_many_details", PcaGrant.Parse(new L(Enumerable.Repeat<object?>(new D(), 17))));
        Refused("bad_entry", PcaGrant.Parse(new L { 5L }));
        Refused("bad_chain_digest", PcaGrant.Parse(new L { new D { ["type"] = PcaGrant.Type } }));
        Refused("no_detail", PcaGrant.Check(new List<D>(), "https://a/", chain, true));
        Refused("proof_required", PcaGrant.Check(new List<D> { Detail() }, "https://a/", chain, false));
        Refused("chain_mismatch", PcaGrant.Check(new List<D> { Detail() }, "https://a/", new[] { "y" }, true));
        Refused("wrong_location", PcaGrant.Check(new List<D> { Detail("https://b/") }, "https://a/", chain, true));
        var ok = PcaGrant.Parse(new L { Detail() });
        Assert.Null(ok.Code);
        Assert.Equal(-1, ok.Index);
        Assert.Single(ok.Details);
    }

    [Fact]
    public void AGrantDetailNeedsOnlyOneMatchingLocation()
    {
        var r = PcaGrant.Check(new List<D> { Detail("https://a/", "https://b/") }, "https://a/", new[] { "x" }, true);
        Assert.Null(r.Code);
        Assert.Equal(0, r.Index);
    }

    // ---- PolicyAuthoring ---------------------------------------------------------------------------------------------

    [Fact]
    public void AnAbsentSignerRanksLastEvenIfPrecedenceHoldsNull()
    {
        var cert = new D
        {
            ["v"] = N(1), ["kind"] = "forbid-wins", ["decision"] = "deny", ["shadowed"] = new L { "b" }, ["winner"] = new D { ["kind"] = "forbid", ["id"] = "a" },
            ["clauses"] = new L
            {
                new D { ["id"] = "a", ["kind"] = "forbid", ["value"] = "true", ["signer"] = "s" },
                new D { ["id"] = "b", ["kind"] = "forbid", ["value"] = "true" },
            },
        };
        Assert.True(PolicyAuthoring.ForbidCertificateConsistent(cert, new string[] { null!, "s" }));
    }

    [Fact]
    public void PolicyAuthoringCatchesAnswerTheirFailClosedTexts()
    {
        var trusted = Array.Empty<string>();
        Assert.False(PolicyAuthoring.ForbidCertificateConsistent(HostileDict()));
        Assert.Equal("template verification error (fail closed)", PolicyAuthoring.VerifyTemplate(HostileDict(), trusted));
        Assert.Equal("overlay verification error (fail closed)", PolicyAuthoring.VerifyTighten(HostileDict(), trusted));
        Assert.Equal("instantiation error (fail closed)", PolicyAuthoring.InstantiateTemplate(HostileDict(), new D()).Reason);
        var r = new D { ["template_id"] = "t", ["version_digest"] = "d", ["slots"] = new D() };
        Assert.Equal("link resolution error (fail closed)", PolicyAuthoring.ResolveLink(r, HostileDict()).Reason);
    }

    static D TemplateDef(string post) => Issue.NormJ(new D
    {
        ["v"] = 1L, ["kind"] = "pca-policy-template", ["id"] = "t", ["version"] = "1", ["slots"] = new D { ["x"] = new D { ["type"] = "string" } },
        ["body"] = new D { ["predicates"] = new L { new D { ["verb"] = "a", ["where"] = new L { new D { ["field"] = "f", ["op"] = "eq", ["value"] = new D { ["$slot"] = "x", ["post"] = post } } } } } },
    });

    [Fact]
    public void ASplicedSlotThatStartsARegexIsRefused()
    {
        Assert.Equal("slot 'x' would inject a regex matcher", PolicyAuthoring.InstantiateTemplate(TemplateDef("z"), new D { ["x"] = "re:abc" }).Reason);
        var (policy, reason) = PolicyAuthoring.InstantiateTemplate(TemplateDef("re:"), new D { ["x"] = "abc" });
        Assert.Null(reason);
        var where = (L)((D)((L)policy!["predicates"]!)[0]!)["where"]!;
        Assert.Equal("abcre:", ((D)where[0]!)["value"]);
    }

    [Fact]
    public void OverlaysThatCannotBeIteratedAreRefused()
    {
        var def = TemplateDef("z");
        var digest = PolicyAuthoring.TemplateDigest(def);
        var msg = Encoding.UTF8.GetBytes("atlas-pca/policy-template/v1\0").Concat(SHA256.HashData(Encoding.UTF8.GetBytes(digest))).ToArray();
        var signed = new D { ["def"] = def, ["signer"] = K1.Id, ["sig"] = Pca.B64u(K1.Sign(msg)) };
        var reference = new D { ["template_id"] = "t", ["version_digest"] = digest, ["slots"] = new D { ["x"] = "v" } };
        D Reg() => new() { ["templates"] = new D { [digest] = signed }, ["trusted"] = new L { K1.Id } };
        Assert.Null(PolicyAuthoring.ResolveLink(reference, Reg()).Reason);
        Assert.Equal("link resolution error (fail closed)", PolicyAuthoring.ResolveLink(reference, new D(Reg()) { ["overlays"] = N(5) }).Reason);
    }

    [Fact]
    public void ASlotWithoutAKnownTypeIsRefused()
    {
        var def = TemplateDef("z");
        ((D)((D)def["slots"]!)["x"]!).Remove("type");
        Assert.Equal("slot 'x'.type must be string, integer or set", PolicyAuthoring.TemplateDefError(def));
    }

    // ---- PolicyClasses -----------------------------------------------------------------------------------------------

    static D ClassRow(object? digest) => new() { ["class"] = "org", ["revision"] = N(1), ["digest"] = digest, ["decision"] = "allow" };

    [Fact]
    public void ClassVerdictErrorsAreExact()
    {
        Assert.Equal("more than 5 policy classes", PolicyClasses.ClassVerdictsError(new L(Enumerable.Repeat<object?>(1L, 6))));
        Assert.Equal("policy_classes[0] must be an object", PolicyClasses.ClassVerdictsError(new L { 5L }));
        Assert.Equal("policy_classes[0] has unknown member 'x'", PolicyClasses.ClassVerdictsError(new L { new D { ["x"] = 1L } }));
        Assert.Equal("policy_classes[0].revision must be a non-negative safe integer", PolicyClasses.ClassVerdictsError(new L { new D(ClassRow("d")) { ["revision"] = "1" } }));
        Assert.Equal("policy_classes[0].decision must be allow, escalate or deny", PolicyClasses.ClassVerdictsError(new L { new D(ClassRow("d")) { ["decision"] = "maybe" } }));
        Assert.Null(PolicyClasses.ClassVerdictsError(new L { ClassRow(new string('d', 128)) }));
        Assert.Equal("policy_classes[0].digest invalid", PolicyClasses.ClassVerdictsError(new L { ClassRow(new string('d', 129)) }));
    }

    [Fact]
    public void ClassEvaluationFailsClosedOnAThrow()
    {
        var r = PolicyClasses.DecideClasses(new L { HostileDict("class") });
        Assert.Equal("deny", r.Decision);
        Assert.Equal("evaluation error (fail closed)", r.Reason);
    }

    // ---- Predicates --------------------------------------------------------------------------------------------------

    [Fact]
    public void ShownBooleansAndNonObjectConditions()
    {
        Assert.Equal("true", Predicates.ShowValue(true));
        Assert.Equal("false", Predicates.ShowValue(false));
        Assert.Equal("<condition>", Predicates.DescribeCondition(5L));
        Assert.Equal("<condition>", Predicates.DescribeCondition(null));
    }

    // ---- ProvenanceGate ----------------------------------------------------------------------------------------------

    static byte[] Node(byte[] l, byte[] r) => SHA256.HashData(new byte[] { 1 }.Concat(l).Concat(r).ToArray());

    sealed class TrackedProof : IReadOnlyList<byte[]>
    {
        public bool Enumerated;
        public int N;
        public byte[] this[int i] => new byte[32];
        public int Count => N;
        public IEnumerator<byte[]> GetEnumerator() { Enumerated = true; for (var i = 0; i < N; i++) yield return new byte[32]; }
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    sealed class ThrowingProof : IReadOnlyList<byte[]>
    {
        public byte[] this[int i] => throw new InvalidOperationException("hostile");
        public int Count => throw new InvalidOperationException("hostile");
        public IEnumerator<byte[]> GetEnumerator() => throw new InvalidOperationException("hostile");
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    [Fact]
    public void InclusionAcceptsTheLargestSafeTreeSize()
    {
        var leaf = new byte[32];
        var p = Enumerable.Repeat((byte)7, 32).ToArray();
        var proof = Enumerable.Repeat(p, 53).ToList(); // size-1 = 2^53-2 has 53 bits: leaf 0 climbs 53 levels
        var root = leaf;
        foreach (var x in proof) root = Node(root, x);
        Assert.True(ProvenanceGate.VerifyRfc9162Inclusion(leaf, 0, ProvenanceGateMaxSafe, proof, root));
        Assert.False(ProvenanceGate.VerifyRfc9162Inclusion(leaf, 0, ProvenanceGateMaxSafe + 1, proof, root));
    }

    const long ProvenanceGateMaxSafe = 9_007_199_254_740_991;

    [Fact]
    public void InclusionRefusesAShortLeafOrProofNodeThatWouldOtherwiseHash()
    {
        var p = new byte[32];
        var shortLeaf = new byte[31];
        Assert.False(ProvenanceGate.VerifyRfc9162Inclusion(shortLeaf, 0, 2, new[] { p }, Node(new byte[32], p)));
        var leaf = new byte[32];
        var shortNode = new byte[31];
        Assert.False(ProvenanceGate.VerifyRfc9162Inclusion(leaf, 0, 2, new[] { shortNode }, Node(leaf, new byte[32])));
        Assert.False(ProvenanceGate.VerifyRfc9162Inclusion(leaf, 0, 2, null!, leaf));
    }

    [Fact]
    public void InclusionProofOverThe64NodeBoundIsRefusedBeforeItIsRead()
    {
        var leaf = new byte[32];
        var over = new TrackedProof { N = 65 };
        Assert.False(ProvenanceGate.VerifyRfc9162Inclusion(leaf, 0, 2, over, leaf));
        Assert.False(over.Enumerated);
        var at = new TrackedProof { N = 64 };
        Assert.False(ProvenanceGate.VerifyRfc9162Inclusion(leaf, 0, 2, at, leaf));
        Assert.True(at.Enumerated);
    }

    [Fact]
    public void InclusionIsFalseWhenTheProofThrows() =>
        Assert.False(ProvenanceGate.VerifyRfc9162Inclusion(new byte[32], 0, 1, new ThrowingProof(), new byte[32]));

    static D Facts(object? alg, object? digest) => new()
    {
        ["v"] = N(1), ["predicate_type"] = ProvenanceGate.SlsaProvenanceV1, ["build_type"] = "b", ["builder_id"] = "bi", ["identity"] = "i", ["oidc_issuer"] = "o",
        ["subjects"] = new L { new D { ["alg"] = alg, ["digest"] = digest } }, ["integrated_time"] = N(1), ["rekor_log_index"] = N(1),
    };

    [Fact]
    public void SubjectDigestsAreBoundToTheirAlgorithm()
    {
        const string bad = "facts.subjects must be 1..64 {alg, digest}";
        Assert.Null(ProvenanceGate.ProvenanceFactsError(Facts("sha256", new string('a', 64))));
        Assert.Null(ProvenanceGate.ProvenanceFactsError(Facts("sha512", new string('a', 128))));
        Assert.Equal(bad, ProvenanceGate.ProvenanceFactsError(Facts("sha256", new string('a', 128))));
        Assert.Equal(bad, ProvenanceGate.ProvenanceFactsError(Facts("sha512", new string('a', 64))));
        Assert.Equal(bad, ProvenanceGate.ProvenanceFactsError(Facts("md5", "a")));
    }

    [Fact]
    public void EveryPolicyBuildTypeMustBeAString()
    {
        var policy = new D
        {
            ["roots"] = new L { new D { ["oidc_issuer"] = "o", ["builder_id"] = "b", ["identity"] = "i", ["level"] = N(1) } }, ["min_level"] = N(1),
            ["build_types"] = new L { "x" },
        };
        Assert.Null(ProvenanceGate.ProvenancePolicyError(policy));
        policy["build_types"] = new L { "x", 5L };
        Assert.Equal("policy.build_types must hold 1..16 strings", ProvenanceGate.ProvenancePolicyError(policy));
    }

    [Fact]
    public void TheGateFailsClosedOnAThrow()
    {
        var r = ProvenanceGate.Gate(HostileDict());
        Assert.False(r.Ok);
        Assert.Equal("malformed_facts", r.Code);
    }

    // ---- ReadSide ----------------------------------------------------------------------------------------------------

    static ReadResult Last4(string value)
    {
        var body = Issue.NormJ(new D
        {
            ["v"] = 1L, ["id"] = "g", ["principal"] = K1.Id, ["issued_at"] = 1L, ["expires_at"] = 100L, ["caps"] = new D(), ["sinks"] = new D(),
            ["reads"] = new L { new D { ["verb"] = "v", ["resource_prefix"] = "r", ["purposes"] = new L { "p" }, ["modes"] = new D { ["c"] = "last4" }, ["default_mode"] = "drop" } },
        });
        var grant = new D { ["body"] = body, ["sig"] = Issue.SignBody(K1, ReadSide.GrantDomain, body) };
        var schema = new D { ["fields"] = new D { ["f"] = "c" }, ["required"] = new L() };
        return ReadSide.RedactRead(new ReadInput(grant, K1.Id, N(10), "v", "r", "p", schema, new D { ["f"] = value }, new D(), "0123456789abcdef", new D()));
    }

    [Fact]
    public void Last4DropsAnythingOutsideTheBmp()
    {
        var astral = Last4("abcde\U00010000");
        Assert.Equal("allow", astral.Decision);
        Assert.Equal("dropped", ((D)astral.Fields["f"]!)["action"]);
        Assert.Empty(astral.View);
        Assert.Equal("****bcde", Last4("abcde").View["f"]);
    }

    static ChainLabels Receipt(string cls)
    {
        var digest = Pca.B64u(new byte[32]);
        var body = Issue.NormJ(new D
        {
            ["v"] = 1L, ["grant"] = digest, ["verb"] = "v", ["resource"] = "r", ["purpose"] = "p", ["seq"] = 0L, ["prev"] = null, ["labels"] = new L(), ["issued_at"] = 1L, ["signer"] = K2.Id,
            ["fields"] = new D { ["f"] = new D { ["class"] = cls, ["action"] = "dropped", ["kind"] = null, ["vd"] = digest } },
        });
        var receipt = new D(body) { ["sig"] = Issue.SignBody(K2, ReadSide.ReceiptDomain, body) };
        return ReadSide.ReadChainLabels(new L { receipt }, K2.Id, digest, 10);
    }

    [Fact]
    public void AReceiptFieldClassIsALabelOrUnclassified()
    {
        foreach (var bad in new[] { "", "BAD" })
        {
            var r = Receipt(bad);
            Assert.Null(r.Labels);
            Assert.Equal("bad_receipt", r.Code);
            Assert.Equal(0, r.At);
        }
        foreach (var good in new[] { "unclassified", "c" })
        {
            var r = Receipt(good);
            Assert.Empty(r.Labels!);
            Assert.Null(r.Code);
            Assert.Equal(-1, r.At);
        }
    }

    [Fact]
    public void AnEmptyChainHasNoFailureIndex()
    {
        var r = ReadSide.ReadChainLabels(new L(), "s", "g", 0);
        Assert.Empty(r.Labels!);
        Assert.Equal(-1, r.At);
    }

    [Fact]
    public void CheckSinkFailsClosedOnAThrow()
    {
        var r = ReadSide.CheckSink(null!);
        Assert.Equal("deny", r.Decision);
        Assert.Equal("bad_request", r.Code);
    }

    // ---- Refusals ----------------------------------------------------------------------------------------------------

    [Fact]
    public void RefusalTableRowsArePinnedToTheReference()
    {
        Assert.Equal(new RefusalHelp("grant_ref_bound", "The proof does not name a grant this server knows.", "Register the principal's grant with the server (its grants list or resolveGrant). The grant comes from your store, never from the request.", Refusals.Ref + "#grant_ref"), Refusals.Explain("grant_ref_bound: x"));
        Assert.Equal(new RefusalHelp("risk_inputs", "A risk input the server must vouch for was not supplied.", "Supply it in the risk option (catalogRisk derives the common ones; protect() uses it).", Refusals.Ref + "#risk_inputs"), Refusals.Explain("risk_inputs: x"));
    }

    [Theory]
    [InlineData("audience mismatch", "audience")]
    [InlineData("authorize refused", "authorize")]
    [InlineData("plan_state revoked", "plan_state")]
    [InlineData("XX audience: y", "audience")]
    [InlineData("XX audience", "unknown")]
    [InlineData("Audience mismatch", "unknown")]
    [InlineData("audience_", "unknown")]
    public void TheLeadingNameWinsAndAnEmbeddedOneNeedsItsColon(string reason, string check) => Assert.Equal(check, Refusals.Explain(reason).Check);

    [Fact]
    public void AnUnknownOrNullReasonGetsTheGenericEntry()
    {
        var generic = new RefusalHelp("unknown", "The guard refused and the reason is not in the table.", "Read the reason as written; every refusal names the check that failed.", Refusals.Ref);
        Assert.Equal(generic, Refusals.Explain(null));
        Assert.Equal(generic, Refusals.Explain("nothing known"));
    }
}
