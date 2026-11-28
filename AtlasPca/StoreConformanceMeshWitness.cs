// Conformance cases for an IMeshWitnessStore: the durable memory of a mesh log witness. A witness cosigns a head only if it extends the last head THIS
// witness cosigned. A store that forgets across a restart, or that loses a save and still lets the cosignature out, lets a domain walk the witness back
// and show two verifiers different histories. The cases check the store by itself (round trip, replace, copy semantics, atomicity, reopen) and through a
// real MeshWitness (every cosignature is persisted first; a restarted witness refuses rollback and forks; a failed save refuses the cosignature and
// changes nothing; damaged storage is not read as empty):
//
//     var report = MeshWitnessStoreConformance.Run(new MyAdapter());
//     Assert.True(report.Ok, report.Format());
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

/// <summary>The adapter a mesh witness store author implements.</summary>
public abstract class MeshWitnessStoreAdapter
{
    public abstract string Name { get; }

    /// <summary>A fresh, empty store.</summary>
    public abstract IMeshWitnessStore Make();

    /// <summary>True when <see cref="Reopen"/> is implemented (a store that can persist).</summary>
    public virtual bool CanReopen => false;

    /// <summary>A new store object over the same backing storage as <paramref name="previous"/> (a restart).</summary>
    public virtual IMeshWitnessStore Reopen(IMeshWitnessStore previous) => throw new NotSupportedException("reopen");

    /// <summary>True when <see cref="Damage"/> is implemented (a store that can detect damage).</summary>
    public virtual bool CanDamage => false;

    /// <summary>Damage the backing storage of <paramref name="store"/> so that <c>Load</c> must fail.</summary>
    public virtual void Damage(IMeshWitnessStore store) => throw new NotSupportedException("damage");
}

/// <summary>The environment of one mesh witness store case.</summary>
public sealed class MeshWitnessEnv(MeshWitnessStoreAdapter adapter) : ISuiteHandle
{
    public MeshWitnessStoreAdapter Adapter { get; } = adapter;
}

public static class MeshWitnessStoreConformance
{
    static byte[] Seed(string label)
    {
        var s = new byte[32];
        for (int i = 0; i < 32; i++) s[i] = (byte)((label[i % label.Length] + i) & 0xff);
        return s;
    }

    static EdKey Key(string label) => EdKey.FromSeed(Seed(label));

    static D Cap(string label) => new()
    {
        ["id"] = label,
        ["caveats"] = new L { new D { ["type"] = "scope", ["actions"] = new L { label } } },
    };

    /// <summary>Same domain key, different history: the second is a fork of the first from entry 0 on.</summary>
    static (MeshDomain Honest, MeshDomain Fork) TwoLogs()
    {
        var honest = new MeshDomain("d", Key("domain"));
        var fork = new MeshDomain("d", Key("domain"));
        honest.Record(Cap("a"));
        fork.Record(Cap("x"));
        return (honest, fork);
    }

    static D State(long n)
    {
        var head = new D
        {
            ["domain"] = "d" + n,
            ["size"] = IntentJs.OfLong(0),
            ["root"] = "",
            ["rev_root"] = "r",
            ["rev_size"] = IntentJs.OfLong(0),
            ["timestamp"] = IntentJs.OfLong(n),
        };
        return new D { ["seen"] = new L { new D { ["head"] = head, ["rev_ids"] = new L() } } };
    }

    static int Cosigs(D ch) => ((L)ch["cosigs"]!).Count;

    static MeshWitness Witness(string label, IMeshWitnessStore store) => new(Key(label), new MeshWitness.Options { Store = store });

    /// <summary>A store whose saves can be made to fail.</summary>
    sealed class Flaky(IMeshWitnessStore inner) : IMeshWitnessStore
    {
        public readonly IMeshWitnessStore Inner = inner;
        public volatile bool Failing;
        public D? Load() => Inner.Load();

        public void Save(D state)
        {
            if (Failing) throw new InvalidOperationException("disk full");
            Inner.Save(state);
        }
    }

    /// <summary>The cases that apply to <paramref name="a"/> (reopen and damage cases only when the adapter implements them).</summary>
    public static List<SuiteCheck<MeshWitnessEnv>> Cases(MeshWitnessStoreAdapter a)
    {
        var cases = new List<SuiteCheck<MeshWitnessEnv>>
        {
            new("a fresh store loads nothing", "a store that was never written loads null", e => StoreSuite.Ok(a.Make().Load() == null, "a fresh store must load null")),
            new("save then load returns the same state", "what was saved is what loads", e =>
            {
                var s = a.Make();
                s.Save(State(1));
                StoreSuite.Eq(State(1), s.Load());
            }),
            new("a later save replaces the earlier one", "the last save wins", e =>
            {
                var s = a.Make();
                s.Save(State(1));
                s.Save(State(2));
                StoreSuite.Eq(State(2), s.Load());
            }),
            new("load returns a copy: changing it does not change the store", "mutating a loaded state leaves the store alone", e =>
            {
                var s = a.Make();
                s.Save(State(1));
                var got = s.Load()!;
                ((L)got["seen"]!).Clear();
                StoreSuite.Eq(State(1), s.Load());
            }),
            new("save keeps its own copy: changing the argument afterwards does not change the store", "mutating a saved state leaves the store alone", e =>
            {
                var s = a.Make();
                var st = State(1);
                s.Save(st);
                ((L)st["seen"]!).Clear();
                StoreSuite.Eq(State(1), s.Load());
            }),
            new("a witness persists every cosignature before returning it", "the stored state is the witness's state after each cosignature", e =>
            {
                var s = a.Make();
                var w = Witness("w", s);
                var honest = TwoLogs().Honest;
                var ch = honest.PublishHead(new[] { w }, 1_000);
                StoreSuite.Eq(w.ExportState(), s.Load());
                var heads = new L();
                foreach (var x in (L)s.Load()!["seen"]!) heads.Add(((D)x!)["head"]);
                StoreSuite.Eq(new L { ch["head"] }, heads);
            }),
            new("a failed save refuses the cosignature and leaves the witness unchanged", "the cosignature is released only after the state is saved", e =>
            {
                var flaky = new Flaky(a.Make());
                var w = Witness("w", flaky);
                var honest = TwoLogs().Honest;
                honest.PublishHead(new[] { w }, 1_000);
                var before = JsCanon.Lenient(w.ExportState())!;
                honest.Record(Cap("b"));
                flaky.Failing = true;
                var threw = StoreSuite.Thrown(() => honest.PublishHead(new[] { w }, 2_000));
                StoreSuite.Eq("witness: could not persist state; refusing to cosign", threw);
                StoreSuite.Eq(before, JsCanon.Lenient(w.ExportState()));
                StoreSuite.Eq(Pca.ParseJson(before), flaky.Inner.Load());
                flaky.Failing = false;
                StoreSuite.Ok(Cosigs(honest.PublishHead(new[] { w }, 2_000)) == 1, "the same head is cosigned once the disk recovers");
            }),
        };
        if (a.CanReopen)
        {
            cases.Add(new("state survives reopening the store", "a new store object over the same storage loads the saved state", e =>
            {
                var s = a.Make();
                s.Save(State(3));
                StoreSuite.Eq(State(3), a.Reopen(s).Load());
            }));
            cases.Add(new("a restarted witness remembers what it cosigned: it refuses a fork and a rollback", "restart safety: a witness never cosigns a fork of what it saw", e =>
            {
                var s = a.Make();
                var w1 = Witness("w", s);
                var (honest, fork) = TwoLogs();
                honest.PublishHead(new[] { w1 }, 1_000);
                honest.Record(Cap("b"));
                honest.PublishHead(new[] { w1 }, 2_000);
                var w2 = Witness("w", a.Reopen(s));
                StoreSuite.Eq(2, w2.LastSeen(honest.Id)!["size"]);
                fork.Record(Cap("y"));
                fork.Record(Cap("z"));
                StoreSuite.Ok(StoreSuite.Thrown(() => fork.PublishHead(new[] { w2 }, 3_000)).Length > 0, "a fork that grew past the remembered size must be refused");
                var rollback = new MeshDomain("d", Key("domain"));
                rollback.Record(Cap("a"));
                StoreSuite.Ok(StoreSuite.Thrown(() => rollback.PublishHead(new[] { w2 }, 3_000)).Length > 0, "a rollback to the first head must be refused");
                StoreSuite.Ok(Cosigs(honest.PublishHead(new[] { w2 }, 3_000)) == 1, "the honest log is still cosigned");
            }));
        }
        if (a.CanDamage)
        {
            cases.Add(new("damaged storage makes load throw, so a witness never starts empty over it", "damaged storage is refused, never read as empty", e =>
            {
                var s = a.Make();
                // a state a witness accepts, so that only the damage can make construction fail
                var w0 = new MeshWitness(Key("w"));
                var d0 = new MeshDomain("d", Key("domain"));
                d0.Record(Cap("a"));
                d0.PublishHead(new[] { w0 }, 1_000);
                s.Save(w0.ExportState());
                a.Damage(s);
                StoreSuite.Ok(StoreSuite.Thrown(() => s.Load()).Length > 0, "load must throw on damaged storage");
                StoreSuite.Ok(StoreSuite.Thrown(() => Witness("w", s)).Length > 0, "constructing a witness over damaged storage must throw");
            }));
        }
        return cases;
    }

    /// <summary>Run the cases that apply to <paramref name="adapter"/>.</summary>
    public static SuiteReport Run(MeshWitnessStoreAdapter adapter) =>
        StoreSuite.Run("mesh witness store", adapter.Name, true, () => new MeshWitnessEnv(adapter), Cases(adapter));

    /// <summary>GOOD, in process: the memory store (no reopen, no damage).</summary>
    public static MeshWitnessStoreAdapter MemoryAdapter() => new MemoryAdapterImpl();

    /// <summary>BAD: a store that forgets everything (load nothing, save nothing). The suite MUST flag it.</summary>
    public static MeshWitnessStoreAdapter ForgetfulAdapter() => new ForgetfulAdapterImpl();

    /// <summary>BAD: a store that accepts a save but returns a stale copy (a lost update); flagged by the round-trip and persistence cases.</summary>
    public static MeshWitnessStoreAdapter StaleAdapter() => new StaleAdapterImpl();

    /// <summary>The reference adapters by name (the bad ones are positive controls).</summary>
    public static IReadOnlyDictionary<string, Func<MeshWitnessStoreAdapter>> ReferenceAdapters() => new Dictionary<string, Func<MeshWitnessStoreAdapter>>
    {
        ["mesh-witness-memory"] = MemoryAdapter,
        ["bad-mesh-witness-forgetful"] = ForgetfulAdapter,
        ["bad-mesh-witness-stale"] = StaleAdapter,
    };

    sealed class MemoryAdapterImpl : MeshWitnessStoreAdapter
    {
        public override string Name => "MemoryMeshWitnessStore";
        public override IMeshWitnessStore Make() => new MemoryMeshWitnessStore();
    }

    sealed class ForgetfulStore : IMeshWitnessStore
    {
        public D? Load() => null;
        public void Save(D state) { /* forgets */ }
    }

    sealed class ForgetfulAdapterImpl : MeshWitnessStoreAdapter
    {
        readonly ForgetfulStore _forget = new();
        public override string Name => "BAD forgetful (loads nothing, saves nothing)";
        public override IMeshWitnessStore Make() => _forget;
        public override bool CanReopen => true;
        public override IMeshWitnessStore Reopen(IMeshWitnessStore previous) => _forget;
    }

    sealed class StaleStore : IMeshWitnessStore
    {
        D? _first;
        readonly object _lock = new();

        public D? Load()
        {
            lock (_lock) return _first == null ? null : (D)StoreJs.DeepCopy(_first)!;
        }

        public void Save(D state)
        {
            lock (_lock) _first ??= (D)StoreJs.DeepCopy(state)!;
        }
    }

    sealed class StaleAdapterImpl : MeshWitnessStoreAdapter
    {
        public override string Name => "BAD stale (keeps the first state it was given)";
        public override IMeshWitnessStore Make() => new StaleStore();
    }
}
