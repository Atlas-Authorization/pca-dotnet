using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using AtlasPca;
using AtlasPca.Js;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Corpus.Tests
{
    /// <summary>The durable store's file, JSON, lock-file and platform helpers and the operator recovery, each pinned directly (fast, no lock
    /// waits): the name parsers, the fence files, holder records and how they are judged, the recovery's records and every one of its test-only
    /// crash hooks, the in-memory store. The name contains DurableStateTests so the Windows mutation shards run it.</summary>
    public class DurableStateTestsHelpers
    {
        const long Dead = 999999999;
        static readonly string H64 = new('a', 64);
        static readonly string Pid = Environment.ProcessId.ToString(CultureInfo.InvariantCulture);

        static string NewDir() => Directory.CreateTempSubdirectory("pca-dsh-").FullName;
        static void Clean(string dir) { try { Directory.Delete(dir, true); } catch (Exception) { /* best effort */ } }
        static string[] Names(string dir) => Directory.GetFileSystemEntries(dir).Select(p => Path.GetFileName(p)!).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        static object? J(string json) => Pca.ParseJson(json);
        static D Me() => new() { ["pid"] = new Num(Pid), ["host"] = Ds.Host() };

        static void WithEnv(IReadOnlyDictionary<string, string?> vars, Action body)
        {
            var prev = vars.Keys.ToDictionary(k => k, k => Environment.GetEnvironmentVariable(k));
            try
            {
                foreach (var kv in vars) Environment.SetEnvironmentVariable(kv.Key, kv.Value);
                body();
            }
            finally { foreach (var kv in prev) Environment.SetEnvironmentVariable(kv.Key, kv.Value); }
        }

        static void WithHalter(Action halter, Action body)
        {
            var prev = DsNative.CrashHalter;
            DsNative.CrashHalter = halter;
            try { body(); }
            finally { DsNative.CrashHalter = prev; }
        }

        static Dictionary<string, string?> RecoverCrashAt(string point, bool child) =>
            new() { ["PCA_DURABLE_TEST"] = "1", [Ds.RecoverCrashEnv] = point, [DsNative.CrashChildEnv] = child ? "1" : null };

        // ---- options ----

        [Fact]
        public void TheOptionDirectoriesDefaultToEmpty()
        {
            Assert.Equal("", new DurableStateOptions().Dir);
            Assert.Equal("", new RecoverDurableStateOptions().Dir);
        }

        // ---- name and value parsers ----

        [Fact]
        public void Hex64AcceptsExactlySixtyFourLowercaseHexDigits()
        {
            Assert.True(Ds.Hex64("0123456789abcdef" + new string('9', 48)));
            Assert.True(Ds.Hex64(new string('f', 64)));
            Assert.False(Ds.Hex64(new string('g', 64)));
            Assert.False(Ds.Hex64(new string('A', 64)));
            Assert.False(Ds.Hex64(new string(':', 64)));
            Assert.False(Ds.Hex64(new string('`', 64)));
            Assert.False(Ds.Hex64(new string('/', 64)));
            Assert.False(Ds.Hex64(new string('a', 63)));
            Assert.False(Ds.Hex64(new Num("1")));
        }

        [Fact]
        public void AllDigitsChecksExactlyTheRangeAndAnEmptyRangeIsNotDigits()
        {
            Assert.True(Ds.AllDigits("0123456789", 0, 10));
            Assert.True(Ds.AllDigits("0", 0, 1));
            Assert.True(Ds.AllDigits("9", 0, 1));
            Assert.True(Ds.AllDigits("ab12cd", 2, 4));
            Assert.False(Ds.AllDigits("ab12cd", 1, 4));
            Assert.False(Ds.AllDigits("ab12cd", 2, 5));
            Assert.False(Ds.AllDigits("1a3", 0, 3));
            Assert.False(Ds.AllDigits("/", 0, 1));
            Assert.False(Ds.AllDigits(":", 0, 1));
            Assert.False(Ds.AllDigits("123", 1, 1));
            Assert.False(Ds.AllDigits("123", 2, 1));
        }

        [Fact]
        public void SafeIntAcceptsTheWholeSafeRangeAndNothingPastIt()
        {
            Assert.True(Ds.SafeInt(new Num("9007199254740991"), out var v));
            Assert.Equal(9007199254740991L, v);
            Assert.True(Ds.SafeInt(new Num("-9007199254740991"), out v));
            Assert.Equal(-9007199254740991L, v);
            Assert.True(Ds.SafeInt(new Num("1e2"), out v));
            Assert.Equal(100L, v);
            Assert.False(Ds.SafeInt(new Num("9007199254740992"), out _));
            Assert.False(Ds.SafeInt(new Num("1.5"), out _));
            Assert.False(Ds.SafeInt("1", out _));
        }

        [Fact]
        public void NumSuffixParsesOnlyPrefixPlusUpToEighteenDigits()
        {
            const string p = "state.lock.";
            Assert.Equal(7L, Ds.NumSuffix("state.lock.7", p));
            Assert.Equal(0L, Ds.NumSuffix("state.lock.0", p));
            Assert.Equal(123456789012345678L, Ds.NumSuffix("state.lock.123456789012345678", p));
            Assert.Equal(-1L, Ds.NumSuffix("state.lock.1234567890123456789", p));
            Assert.Equal(-1L, Ds.NumSuffix("state.lock.", p));
            Assert.Equal(-1L, Ds.NumSuffix("state.lock.7x", p));
            Assert.Equal(-1L, Ds.NumSuffix("state.lock.x5", p));
            Assert.Equal(-1L, Ds.NumSuffix("state.lock.tmp-1-ab", p));
            Assert.Equal(-1L, Ds.NumSuffix("xstate.lock.7", p));
            Assert.Equal(-1L, Ds.NumSuffix("7.state.lock.", p));
            Assert.Equal(-1L, Ds.NumSuffix("12", p));
        }

        [Fact]
        public void FenceEntryParsesGenerationDashHexOnly()
        {
            Assert.Equal(("state.fence.2-ab", 2L), Ds.FenceEntry("state.fence.2-ab")!.Value);
            Assert.Equal(("state.fence.123456789012345678-0f", 123456789012345678L), Ds.FenceEntry("state.fence.123456789012345678-0f")!.Value);
            Assert.Null(Ds.FenceEntry("state.fence.1234567890123456789-ab"));
            Assert.Null(Ds.FenceEntry("state.fence.12-"));
            Assert.Null(Ds.FenceEntry("state.fence.12"));
            Assert.Null(Ds.FenceEntry("state.fence.-ab"));
            Assert.Null(Ds.FenceEntry("state.fence.1x-ab"));
            Assert.Null(Ds.FenceEntry("state.fence.1-ag"));
            Assert.Null(Ds.FenceEntry("state.fence.1-AB"));
            Assert.Null(Ds.FenceEntry("state.fence"));
            Assert.Null(Ds.FenceEntry("xstate.fence.1-ab"));
        }

        [Fact]
        public void TopGenerationIsTheLargestNumberedLockFile()
        {
            var dir = NewDir();
            try
            {
                Assert.Equal(0L, Ds.TopGeneration(dir));
                foreach (var f in new[] { "state.lock.3", "state.lock.12", "state.lock.x", "state.lock.tmp-1-ab", "state.lock", "state.journal", "99" })
                    File.WriteAllText(Path.Combine(dir, f), "{}");
                Assert.Equal(12L, Ds.TopGeneration(dir));
            }
            finally { Clean(dir); }
        }

        // ---- test-only crash hooks ----

        [Fact]
        public void TheRecoveryCrashHookFiresOnlyAtTheArmedPointUnderTheTestSwitch()
        {
            WithEnv(RecoverCrashAt("p1", false), () =>
            {
                var e = Assert.Throws<InvalidOperationException>(() => Ds.TestCrashPoint("p1"));
                Assert.Equal("crash hook fired outside a crash child (p1)", e.Message);
                Ds.TestCrashPoint("p2");
                Ds.TestCrashPoint("");
            });
            WithEnv(new Dictionary<string, string?> { ["PCA_DURABLE_TEST"] = null, [Ds.RecoverCrashEnv] = "p1", [DsNative.CrashChildEnv] = null }, () => Ds.TestCrashPoint("p1"));
            WithEnv(new Dictionary<string, string?> { ["PCA_DURABLE_TEST"] = "0", [Ds.RecoverCrashEnv] = "p1", [DsNative.CrashChildEnv] = null }, () => Ds.TestCrashPoint("p1"));
            var halted = new List<string>();
            WithEnv(RecoverCrashAt("p1", true), () => WithHalter(() => halted.Add("p1"), () => { Ds.TestCrashPoint("p1"); Ds.TestCrashPoint("p2"); }));
            Assert.Equal(new[] { "p1" }, halted);
        }

        // ---- file helpers ----

        [Fact]
        public void AtomicWriteRunsTheHookBeforeTheRenameAndAFailingHookLeavesNothing()
        {
            var dir = NewDir();
            try
            {
                var p = Path.Combine(dir, "t.json");
                var calls = 0;
                Ds.AtomicWrite(p, "x", false, () => { Assert.False(File.Exists(p)); calls++; });
                Assert.Equal(1, calls);
                Assert.Equal("x", File.ReadAllText(p));
                Assert.Equal(new[] { "t.json" }, Names(dir));

                var q = Path.Combine(dir, "u.json");
                var e = Assert.Throws<InvalidOperationException>(() => Ds.AtomicWrite(q, "y", false, () => throw new InvalidOperationException("stop")));
                Assert.Equal("stop", e.Message);
                Assert.Equal(new[] { "t.json" }, Names(dir));
            }
            finally { Clean(dir); }
        }

        [Fact]
        public void AtomicWriteCrashingAfterTheTempLeavesTheNamedTempOnly()
        {
            var dir = NewDir();
            try
            {
                var p = Path.Combine(dir, "t.json");
                WithEnv(new Dictionary<string, string?> { [DsNative.CrashChildEnv] = null }, () =>
                {
                    var e = Assert.Throws<InvalidOperationException>(() => Ds.AtomicWrite(p, "x", true, null));
                    Assert.Equal("crash hook fired outside a crash child (after-temp-write)", e.Message);
                });
                var names = Names(dir);
                Assert.Single(names);
                Assert.Matches("^t\\.json\\.tmp-" + Pid + "-[0-9a-f]{12}$", names[0]);
                Assert.Equal("x", File.ReadAllText(Path.Combine(dir, names[0])));
            }
            finally { Clean(dir); }
        }

        // ---- fences ----

        static string FenceJson(long gen, long seq) => "{\"gen\":" + gen + ",\"seq\":" + seq + ",\"h\":\"" + H64 + "\"}";

        [Fact]
        public void ParseFenceRejectsEachInvalidFieldAlone()
        {
            Assert.Equal(new DurableFence(2, 0, H64), Ds.ParseFence(J(FenceJson(2, 0)), "W"));
            Assert.Equal(new DurableFence(1, 7, H64), Ds.ParseFence(J(FenceJson(1, 7)), "W"));
            var bad = new[]
            {
                "5", "[]", "null",
                "{\"seq\":0,\"h\":\"" + H64 + "\"}", FenceJson(0, 0), FenceJson(-1, 0), "{\"gen\":1.5,\"seq\":0,\"h\":\"" + H64 + "\"}", "{\"gen\":\"2\",\"seq\":0,\"h\":\"" + H64 + "\"}",
                "{\"gen\":2,\"h\":\"" + H64 + "\"}", FenceJson(2, -1), "{\"gen\":2,\"seq\":-0,\"h\":\"" + H64 + "\"}", "{\"gen\":2,\"seq\":0.5,\"h\":\"" + H64 + "\"}",
                "{\"gen\":2,\"seq\":0}", "{\"gen\":2,\"seq\":0,\"h\":\"zz\"}",
            };
            foreach (var b in bad)
            {
                var e = Assert.Throws<DurableStateError>(() => Ds.ParseFence(J(b), "W"));
                Assert.Equal("corrupt: W has an invalid entry", e.Message);
            }
        }

        [Fact]
        public void ReadFencesListsTheFenceListThenEachEntryByGenerationThenName()
        {
            var dir = NewDir();
            try
            {
                Assert.Empty(Ds.ReadFences(dir));
                File.WriteAllText(Path.Combine(dir, "state.fence"), "{\"v\":1,\"fences\":[" + FenceJson(1, 0) + "]}");
                File.WriteAllText(Path.Combine(dir, "state.fence.10-bb"), "{\"v\":1,\"fence\":" + FenceJson(10, 3) + "}\n");
                File.WriteAllText(Path.Combine(dir, "state.fence.2-aa"), "{\"v\":1,\"fence\":" + FenceJson(2, 1) + "}\n");
                File.WriteAllText(Path.Combine(dir, "state.fence.10-aa"), "{\"v\":1,\"fence\":" + FenceJson(10, 2) + "}\n");
                File.WriteAllText(Path.Combine(dir, "state.fence.x-aa"), "not json"); // not an entry name: ignored
                Assert.Equal(new[] { new DurableFence(1, 0, H64), new DurableFence(2, 1, H64), new DurableFence(10, 2, H64), new DurableFence(10, 3, H64) }, Ds.ReadFences(dir));
            }
            finally { Clean(dir); }
        }

        [Fact]
        public void ReadFencesRefusesEveryMalformedFenceFile()
        {
            void Case(string file, string text, string msg)
            {
                var dir = NewDir();
                try
                {
                    File.WriteAllText(Path.Combine(dir, file), text);
                    Assert.Equal(msg, Assert.Throws<DurableStateError>(() => Ds.ReadFences(dir)).Message);
                }
                finally { Clean(dir); }
            }
            const string shape = "corrupt: state.fence has an invalid shape";
            Case("state.fence", "nope", "corrupt: state.fence is not valid JSON");
            Case("state.fence", "[]", shape);
            Case("state.fence", "{\"fences\":[]}", shape);
            Case("state.fence", "{\"v\":2,\"fences\":[]}", shape);
            Case("state.fence", "{\"v\":\"1\",\"fences\":[]}", shape);
            Case("state.fence", "{\"v\":1}", shape);
            Case("state.fence", "{\"v\":1,\"fences\":{}}", shape);
            Case("state.fence", "{\"v\":1,\"fences\":[" + FenceJson(0, 0) + "]}", "corrupt: state.fence has an invalid entry");
            Case("state.fence.3-ab", "nope", "corrupt: state.fence.3-ab is not valid JSON");
            Case("state.fence.3-ab", "[1]", "corrupt: state.fence.3-ab has an invalid shape");
            Case("state.fence.3-ab", "{\"fence\":" + FenceJson(3, 0) + "}", "corrupt: state.fence.3-ab has an invalid shape");
            Case("state.fence.3-ab", "{\"v\":2,\"fence\":" + FenceJson(3, 0) + "}", "corrupt: state.fence.3-ab has an invalid shape");
            Case("state.fence.3-ab", "{\"v\":1,\"fence\":" + FenceJson(0, 0) + "}", "corrupt: state.fence.3-ab has an invalid entry");
            Case("state.fence.3-ab", "{\"v\":1,\"fence\":" + FenceJson(4, 0) + "}", "corrupt: state.fence.3-ab names generation 3 but holds 4");
        }

        [Fact]
        public void WriteFenceCutsAtTheJournalTailInItsOwnFile()
        {
            var dir = NewDir();
            try
            {
                var c = new string('c', 64);
                File.WriteAllText(Path.Combine(dir, "state.journal"), "{\"seq\":1,\"h\":\"" + new string('b', 64) + "\"}\n{\"seq\":3,\"h\":\"" + c + "\"}\n\n");
                Ds.WriteFence(dir, 4, null);
                var f = Names(dir).Where(n => n != "state.journal").ToArray();
                Assert.Single(f);
                Assert.Matches("^state\\.fence\\.5-[0-9a-f]{12}$", f[0]);
                var text = File.ReadAllText(Path.Combine(dir, f[0]));
                Assert.Matches("^" + Regex.Escape("{\"v\":1,\"fence\":{\"gen\":5,\"seq\":3,\"h\":\"" + c + "\",\"from\":4,\"t\":") + "-?[0-9]+\\}\\}\\n\\z", text);
                Assert.Equal(new[] { new DurableFence(5, 3, c) }, Ds.ReadFences(dir));
            }
            finally { Clean(dir); }
        }

        [Fact]
        public void WriteFenceRefusesAnUnreadableFenceSetBeforeWriting()
        {
            var dir = NewDir();
            try
            {
                File.WriteAllText(Path.Combine(dir, "state.fence"), "garbage");
                Assert.Equal("corrupt: state.fence is not valid JSON", Assert.Throws<DurableStateError>(() => Ds.WriteFence(dir, 1, null)).Message);
                Assert.Equal(new[] { "state.fence" }, Names(dir));
            }
            finally { Clean(dir); }
        }

        // ---- lock files and holders ----

        [Fact]
        public void ClassifyLockFileNeedsANumericPidAHostAndANonEmptyNonce()
        {
            var dir = NewDir();
            try
            {
                Ds.Classified C(string text) { var p = Path.Combine(dir, "l"); File.WriteAllText(p, text); return Ds.ClassifyLockFile(p); }
                Assert.Equal(Ds.Kind.Unreadable, Ds.ClassifyLockFile(Path.Combine(dir, "missing")).Kind);
                Assert.Equal(new Ds.Classified(Ds.Kind.Unreadable, null, null), C("not json"));
                Assert.Equal(new Ds.Classified(Ds.Kind.Unreadable, null, null), C("5"));
                Assert.Equal(new Ds.Classified(Ds.Kind.Free, null, null), C("{\"st\":\"free\",\"pid\":1,\"host\":\"h\",\"nonce\":\"n\"}"));
                var list = C("[1]");
                Assert.Equal(Ds.Kind.Incomplete, list.Kind);
                Assert.IsType<List<object?>>(list.Raw);
                Assert.Null(list.Body);
                var full = C("{\"pid\":1,\"host\":\"h\",\"nonce\":\"n\"}");
                Assert.Equal(Ds.Kind.Complete, full.Kind);
                Assert.Same(full.Raw, full.Body);
                Assert.Equal("n", full.Body!["nonce"]);
                foreach (var t in new[] { "{\"st\":\"held\",\"nonce\":\"x\"}", "{\"pid\":1,\"host\":\"h\",\"nonce\":\"\"}", "{\"pid\":\"1\",\"host\":\"h\",\"nonce\":\"n\"}",
                             "{\"pid\":1,\"nonce\":\"n\"}", "{\"pid\":1,\"host\":\"h\"}", "{\"pid\":1,\"host\":\"h\",\"nonce\":5}", "{\"st\":\"held\"}" })
                {
                    var k = C(t);
                    Assert.Equal(Ds.Kind.Incomplete, k.Kind);
                    Assert.Equal(t, JsJson.Stringify(k.Raw));
                    Assert.Null(k.Body);
                }
            }
            finally { Clean(dir); }
        }

        [Fact]
        public void AHolderIsAliveHereOnlyWhenItsNamespaceOrHostAndStartTimeMatch()
        {
            Assert.True(Ds.HolderAliveHere(Me()));
            Assert.False(Ds.HolderAliveHere(new D { ["host"] = Ds.Host() }));
            Assert.False(Ds.HolderAliveHere(new D { ["pid"] = Pid, ["host"] = Ds.Host() }));
            Assert.False(Ds.HolderAliveHere(new D { ["pid"] = new Num(Pid), ["host"] = "not-" + Ds.Host() }));
            Assert.False(Ds.HolderAliveHere(new D { ["pid"] = new Num(Pid) }));
            Assert.False(Ds.HolderAliveHere(new D { ["pid"] = new Num(Dead.ToString(CultureInfo.InvariantCulture)), ["host"] = Ds.Host() }));
            // a recorded namespace decides, the host is then ignored: a foreign one (or none to compare with) is never judged alive
            Assert.False(Ds.HolderAliveHere(new D { ["pid"] = new Num(Pid), ["host"] = Ds.Host(), ["ns"] = "pid:[0]" }));
            var me = Me();
            me["start"] = DsNative.ProcStartOf(Environment.ProcessId) ?? "unknown-here";
            Assert.True(Ds.HolderAliveHere(me));
            if (OperatingSystem.IsLinux())
            {
                Assert.True(Ds.HolderAliveHere(new D { ["pid"] = new Num(Pid), ["ns"] = DsNative.MyNs() }));
                Assert.True(Ds.HolderAliveHere(new D { ["pid"] = new Num(Pid), ["host"] = "not-" + Ds.Host(), ["ns"] = DsNative.MyNs() }));
                me["start"] = "1";
                Assert.False(Ds.HolderAliveHere(me)); // the pid was reused by a process started at another time
            }
        }

        [Fact]
        public void JsFieldPrintsAFieldAsStringDoesAndAMissingOneAsUndefined()
        {
            Assert.Equal("undefined", Ds.JsField(new D(), "pid"));
            Assert.Equal("undefined", Ds.JsField(null, "pid"));
            Assert.Equal("7", Ds.JsField(new D { ["pid"] = new Num("7") }, "pid"));
            Assert.Equal("h", Ds.JsField(new D { ["host"] = "h" }, "host"));
        }

        [Fact]
        public void ConfirmHolderQuotesAnIncompleteRecordUpTo160CharactersAndRefusesALiveOne()
        {
            var longRaw = new D { ["st"] = "held", ["pad"] = new string('x', 200) };
            var s = JsJson.Stringify(longRaw);
            var e = Assert.Throws<DurableStateError>(() => Ds.ConfirmHolder(new Ds.Classified(Ds.Kind.Incomplete, longRaw, null), null, "P"));
            Assert.Equal("invalid: P has an incomplete holder record (" + s[..160] + "); after confirming its holder is gone, pass expectedHolder: 'unreadable' to release it", e.Message);
            var shortRaw = new D { ["st"] = "held" };
            e = Assert.Throws<DurableStateError>(() => Ds.ConfirmHolder(new Ds.Classified(Ds.Kind.Incomplete, shortRaw, null), null, "P"));
            Assert.Equal("invalid: P has an incomplete holder record ({\"st\":\"held\"}); after confirming its holder is gone, pass expectedHolder: 'unreadable' to release it", e.Message);
            e = Assert.Throws<DurableStateError>(() => Ds.ConfirmHolder(new Ds.Classified(Ds.Kind.Incomplete, Me(), null), "unreadable", "P"));
            Assert.Equal("invalid: the holder of P (pid " + Pid + ") is alive in this PID namespace; refusing to release a live holder", e.Message);
            Ds.ConfirmHolder(new Ds.Classified(Ds.Kind.Incomplete, new D { ["pid"] = new Num(Dead.ToString(CultureInfo.InvariantCulture)), ["host"] = Ds.Host() }, null), "unreadable", "P");
        }

        // ---- operator recovery ----

        static string DeadHolderDir(string lockFile = "state.lock.1")
        {
            var dir = NewDir();
            File.WriteAllText(Path.Combine(dir, lockFile), JsJson.Stringify(new D { ["st"] = "held", ["pid"] = Dead, ["host"] = Ds.Host(), ["nonce"] = "n1" }));
            return dir;
        }

        static RecoverDurableStateOptions Opts(string dir, bool legacy = false) =>
            new() { Dir = dir, Force = true, ExpectedHolder = new ExpectedLockHolder(Ds.Host(), Dead, "n1"), LegacyLock = legacy };

        const string LockTmp = "^state\\.lock\\.tmp-";
        static string FenceName(string dir) => Assert.Single(Names(dir), n => Regex.IsMatch(n, "^state\\.fence\\.2-[0-9a-f]{12}$"));

        [Fact]
        public void RecoverTakesAMarkedGenerationFencesAndReleases()
        {
            var dir = DeadHolderDir();
            try
            {
                Assert.Equal(new RecoverDurableStateResult(true, "released", Path.Combine(dir, "state.lock.1")), Ds.Recover(Opts(dir)));
                var fence = FenceName(dir);
                Assert.Equal(new[] { fence, "state.lock.1", "state.lock.2", "state.lock.3" }.OrderBy(x => x, StringComparer.Ordinal), Names(dir));
                Assert.Equal(new[] { new DurableFence(2, 0, Ds.Genesis) }, Ds.ReadFences(dir));

                var held = (D)J(File.ReadAllText(Path.Combine(dir, "state.lock.2")))!;
                var ns = DsNative.MyNs();
                var start = DsNative.ProcStartOf(Environment.ProcessId);
                var keys = new List<string> { "st", "pid", "host", "nonce", "boot" };
                if (ns != null) keys.Add("ns");
                if (start != null) keys.Add("start");
                keys.AddRange(new[] { "recovering", "t" });
                Assert.Equal(keys, held.Keys.ToList());
                Assert.Equal("held", held["st"]);
                Assert.Equal(new Num(Pid), held["pid"]);
                Assert.Equal(Ds.Host(), held["host"]);
                Assert.Matches("^[0-9a-f]{24}$", (string)held["nonce"]!);
                Assert.Equal(Ds.BootId, held["boot"]);
                if (ns != null) Assert.Equal(ns, held["ns"]);
                if (start != null) Assert.Equal(start, held["start"]);
                Assert.Equal(new Num("1"), held["recovering"]);
                Assert.IsType<Num>(held["t"]);

                var free = (D)J(File.ReadAllText(Path.Combine(dir, "state.lock.3")))!;
                Assert.Equal(new[] { "st", "t", "recoveredFrom" }, free.Keys.ToArray());
                Assert.Equal("free", free["st"]);
                Assert.IsType<Num>(free["t"]);
                Assert.Equal(new Num("1"), free["recoveredFrom"]);
            }
            finally { Clean(dir); }
        }

        [Fact]
        public void RecoverStopsAtEachArmedCrashPointWithExactlyTheStepsBeforeItOnDisk()
        {
            // point -> (takeover lock, release lock, fence, takeover/release temp) on disk when the hook fires
            var points = new (string Point, bool Lock2, bool Lock3, bool Fence, bool Tmp)[]
            {
                ("before-lock", false, false, false, false), ("after-lock-temp", false, false, false, true), ("after-lock", true, false, false, false),
                ("after-fence-temp", true, false, false, false), ("after-fence", true, false, true, false), ("after-release-temp", true, false, true, true),
                ("after-release", true, true, true, false),
            };
            foreach (var x in points)
            {
                var dir = DeadHolderDir();
                try
                {
                    WithEnv(RecoverCrashAt(x.Point, false), () =>
                    {
                        var e = Assert.Throws<InvalidOperationException>(() => Ds.Recover(Opts(dir)));
                        Assert.Equal("crash hook fired outside a crash child (" + x.Point + ")", e.Message);
                    });
                    var names = Names(dir);
                    Assert.True(x.Lock2 == names.Contains("state.lock.2"), x.Point + ": state.lock.2");
                    Assert.True(x.Lock3 == names.Contains("state.lock.3"), x.Point + ": state.lock.3");
                    Assert.True(x.Fence == names.Any(n => Regex.IsMatch(n, "^state\\.fence\\.2-[0-9a-f]{12}$")), x.Point + ": fence");
                    var tmps = names.Where(n => n.Contains("tmp")).ToArray();
                    Assert.Equal(x.Tmp ? 1 : 0, tmps.Length);
                    if (x.Tmp) Assert.Matches(LockTmp + Pid + "-[0-9a-f]{12}$", tmps[0]);
                    Assert.Equal(1 + (x.Lock2 ? 1 : 0) + (x.Lock3 ? 1 : 0) + (x.Fence ? 1 : 0) + (x.Tmp ? 1 : 0), names.Length);
                }
                finally { Clean(dir); }
            }
        }

        [Fact]
        public void RecoverSupersededWhileTakingOverFailsAndLeavesNoTemp()
        {
            var dir = DeadHolderDir();
            try
            {
                var rival = Path.Combine(dir, "state.lock.2");
                WithEnv(RecoverCrashAt("after-lock-temp", true), () => WithHalter(() => File.WriteAllText(rival, "{\"st\":\"free\"}"), () =>
                {
                    var e = Assert.Throws<DurableStateError>(() => Ds.Recover(Opts(dir)));
                    Assert.Equal("invalid: " + Path.Combine(dir, "state.lock.1") + " was superseded while recovering; re-read the lock state and retry", e.Message);
                }));
                Assert.Equal(new[] { "state.lock.1", "state.lock.2" }, Names(dir));
                Assert.Equal("{\"st\":\"free\"}", File.ReadAllText(rival));
            }
            finally { Clean(dir); }
        }

        [Fact]
        public void RecoverReportsAFailedLinkByItsErrno()
        {
            var dir = DeadHolderDir();
            try
            {
                // the temp vanishes before the link: link(2) / CreateHardLink fails with not-found, not with exists
                void DropTemps() { foreach (var f in Directory.GetFiles(dir, "state.lock.tmp-*")) File.Delete(f); }
                WithEnv(RecoverCrashAt("after-lock-temp", true), () => WithHalter(DropTemps, () =>
                {
                    var e = Assert.Throws<IOException>(() => Ds.Recover(Opts(dir)));
                    if (OperatingSystem.IsWindows()) { Assert.StartsWith("link: ", e.Message); Assert.DoesNotContain("EEXIST", e.Message); }
                    else Assert.Equal("link: ENOENT", e.Message);
                }));
                Assert.Equal(new[] { "state.lock.1" }, Names(dir));
            }
            finally { Clean(dir); }
        }

        [Fact]
        public void RecoverMovesALegacyLockAsideUnderAFence()
        {
            var dir = DeadHolderDir("state.lock");
            try
            {
                Assert.Equal(new RecoverDurableStateResult(true, "released", Path.Combine(dir, "state.lock")), Ds.Recover(Opts(dir, true)));
                var names = Names(dir);
                Assert.Equal(2, names.Length);
                Assert.Single(names, n => Regex.IsMatch(n, "^state\\.fence\\.1-[0-9a-f]{12}$"));
                Assert.Single(names, n => Regex.IsMatch(n, "^state\\.lock\\.legacy-recovered-[0-9]+-[0-9a-f]{6}$"));
                Assert.Equal(new[] { new DurableFence(1, 0, Ds.Genesis) }, Ds.ReadFences(dir));
            }
            finally { Clean(dir); }
        }

        // ---- in-memory store ----

        [Fact]
        public void TheMemoryStoreGetValueIsUndefinedWhenAbsentAndTheTreeWhenPresent()
        {
            var m = new MemoryDurableKv();
            Assert.Same(DurableState.Undefined, m.GetValue("a"));
            m.SetValue("a", new Num("7"));
            Assert.Equal(new Num("7"), m.GetValue("a"));
            m.SetValue("n", null);
            Assert.Null(m.GetValue("n"));
        }

        // ---- platform layer ----

        [Fact]
        public void PidAliveRefusesAFractionalPidEvenWhenItsWholePartIsAlive()
        {
            Assert.False(DsNative.PidAlive(Environment.ProcessId + 0.5));
            Assert.False(DsNative.PidAlive(-(Environment.ProcessId + 0.5)));
            if (OperatingSystem.IsLinux()) Assert.True(DsNative.PidAlive(1)); // init: alive, possibly not ours (EPERM)
        }

        static int FdsOn(string dir)
        {
            var n = 0;
            var name = Path.GetFileName(dir);
            foreach (var fd in Directory.GetFileSystemEntries("/proc/self/fd"))
            {
                try { if (new FileInfo(fd).LinkTarget is string t && Path.GetFileName(t) == name) n++; }
                catch (Exception) { /* closed while listing */ }
            }
            return n;
        }

        [Fact]
        public void FsyncDirNamesTheFailingCallAndClosesItsDescriptor()
        {
            if (!OperatingSystem.IsLinux()) return; // the directory fsync is libc-only (Windows has none to fail)
            var dir = NewDir();
            try
            {
                var missing = Path.Combine(dir, "missing");
                Assert.Equal("open(" + missing + "): ENOENT", Assert.Throws<IOException>(() => DsNative.FsyncDir(missing)).Message);
                // procfs directories have no fsync: open succeeds, fsync fails with EINVAL
                Assert.Equal("fsync(/proc): errno 22", Assert.Throws<IOException>(() => DsNative.FsyncDir("/proc")).Message);
                for (var i = 0; i < 3; i++) DsNative.FsyncDir(dir);
                Assert.Equal(0, FdsOn(dir));
            }
            finally { Clean(dir); }
        }

        static string StatStart(int pid)
        {
            var st = File.ReadAllText("/proc/" + pid.ToString(CultureInfo.InvariantCulture) + "/stat");
            return st[(st.LastIndexOf(')') + 2)..].Split(' ')[19];
        }

        [Fact]
        public void ProcStartAndPidNamespaceComeFromProcOnLinuxOnly()
        {
            if (!OperatingSystem.IsLinux())
            {
                Assert.Null(DsNative.ProcStartOf(Environment.ProcessId));
                Assert.Null(DsNative.MyNs());
                return;
            }
            Assert.Equal(StatStart(Environment.ProcessId), DsNative.ProcStartOf(Environment.ProcessId));
            Assert.Null(DsNative.ProcStartOf(Dead));
            Assert.Matches("^pid:\\[[0-9]+\\]$", DsNative.MyNs()!);
            // a command name holding ") " must not shift the fields (the name is cut at the LAST parenthesis)
            var dir = NewDir();
            try
            {
                var link = Path.Combine(dir, "x) y z");
                File.CreateSymbolicLink(link, File.Exists("/usr/bin/sleep") ? "/usr/bin/sleep" : "/bin/sleep");
                using var p = Process.Start(new ProcessStartInfo(link, "30") { UseShellExecute = false })!;
                try
                {
                    Assert.Contains("(x) y z)", File.ReadAllText("/proc/" + p.Id.ToString(CultureInfo.InvariantCulture) + "/stat"));
                    Assert.Equal(StatStart(p.Id), DsNative.ProcStartOf(p.Id));
                }
                finally { p.Kill(); p.WaitForExit(); }
            }
            finally { Clean(dir); }
        }

        [Fact]
        public void KillSelfEndsTheProcessAtOnce()
        {
            // a child test host whose startup hook calls KillSelf: killed it exits by SIGKILL (137) / TerminateProcess (-1), a no-op returns 3
            var asm = typeof(DurableStateTestsHelpers).Assembly.Location;
            var psi = new ProcessStartInfo { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            var host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
            if (string.IsNullOrEmpty(host) || !File.Exists(host))
                host = Path.GetFileNameWithoutExtension(Environment.ProcessPath) == "dotnet" ? Environment.ProcessPath : null;
            if (host != null) { psi.FileName = host; psi.ArgumentList.Add(asm); }
            else psi.FileName = Path.ChangeExtension(asm, OperatingSystem.IsWindows() ? ".exe" : null);
            psi.Environment["DOTNET_STARTUP_HOOKS"] = asm;
            psi.Environment[StartupHook.ChildEnv] = "1";
            using var p = Process.Start(psi)!;
            var err = p.StandardError.ReadToEndAsync();
            var output = p.StandardOutput.ReadToEnd();
            Assert.True(p.WaitForExit(120_000), "the child did not exit");
            Assert.True(output == "hook\n" && p.ExitCode == (OperatingSystem.IsWindows() ? -1 : 137),
                "exit " + p.ExitCode.ToString(CultureInfo.InvariantCulture) + ", stdout [" + output + "], stderr [" + err.Result + "]");
        }
    }
}

/// <summary>Startup hook of the child test host <c>KillSelfEndsTheProcessAtOnce</c> starts (DOTNET_STARTUP_HOOKS = this assembly): the
/// runtime looks it up by this exact name in the global namespace. Inert unless its environment switch is set.</summary>
internal class StartupHook
{
    internal const string ChildEnv = "PCA_DS_TEST_KILL_SELF_CHILD";

    public static void Initialize()
    {
        if (Environment.GetEnvironmentVariable(ChildEnv) != "1") return;
        Console.Out.Write("hook\n");
        Console.Out.Flush();
        AtlasPca.DsNative.KillSelf();
        Environment.Exit(3);
    }
}
