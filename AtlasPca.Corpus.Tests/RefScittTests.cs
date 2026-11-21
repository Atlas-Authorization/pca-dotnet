using System.Globalization;
using System.Numerics;
using AtlasPca.Scitt;
using Xunit;
using ScittApi = AtlasPca.Scitt.Scitt;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of the SCITT surface (deterministic CBOR codec, RFC 9162 tree, Signed Statements, COSE Receipts, the in-memory and
/// durable transparency services, the file-backed store) against the TypeScript reference (test-data/ref-scitt.json.gz). ES256 signatures are
/// randomised, so the ES256 cases compare verification outcomes only; every EdDSA signature is compared byte for byte.</summary>
public class RefScittTests
{
    const string M = "ref-scitt";

    // ---- cj <-> CBOR model ----
    static object? FromCj(object? v)
    {
        switch (v)
        {
            case null or string or bool or Num: return v;
            case L l: return l.Select(FromCj).ToList();
            case D d when Base.IsBytes(d): return Base.Bytes(d);
            case D d when d.ContainsKey("$map"):
                {
                    var m = new CborMap();
                    foreach (var kv in (L)d["$map"]!) { var p = (L)kv!; m.Set(p[0]!, FromCj(p[1])); }
                    return m;
                }
            case D d when d.ContainsKey("$tag"): return new CborTag(d["$tag"]!, FromCj(d["v"]));
            default: throw new InvalidDataException("bad cj");
        }
    }

    static object? ToCj(object? v) => v switch
    {
        byte[] b => new D { ["$bytes"] = Pca.B64u(b) },
        CborMap m => new D { ["$map"] = m.Items.Select(e => (object?)new L { e.Key, ToCj(e.Value) }).ToList() },
        CborTag t => new D { ["$tag"] = t.Tag, ["v"] = ToCj(t.Value) },
        List<object?> l => l.Select(ToCj).ToList(),
        _ => v,
    };

    // ---- argument helpers ----
    static bool Int(object? a, out long v)
    {
        v = 0;
        return a is Num n && long.TryParse(n.Raw, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out v);
    }

    // a non-integer index / size is an out-of-range one in every reference check
    static long Idx(object? a) => Int(a, out var v) ? v : long.MinValue;

    static List<byte[]> Bytes(object? a) => ((L)a!).Select(Base.Bytes).ToList();

    static CoseKey Key(D k, bool priv)
    {
        byte[] B(string name) => Pca.B64uDecode(k[name]) ?? throw new InvalidDataException("bad key " + name);
        if ((string)k["alg"]! == "EdDSA") return priv ? CoseKey.Ed25519Private(B("seed")) : CoseKey.Ed25519Public(B("pub"));
        return priv ? CoseKey.Es256Private(B("d"), B("x"), B("y")) : CoseKey.Es256Public(B("x"), B("y"));
    }

    static SignStatementOpts SOpts(D s) =>
        new((string)s["alg"]!, Key((D)s["key"]!, true), (string)s["issuer"]!, s.GetValueOrDefault("subject") as string, s.GetValueOrDefault("contentType") as string);

    static ReceiptSignerOpts ROpts(D s) => new((string)s["alg"]!, Key((D)s["key"]!, true), s.GetValueOrDefault("issuer") as string);

    static VerifyReceiptOpts VOpts(D? o) => o == null ? new() : new(
        o.GetValueOrDefault("treeRoot") as string,
        o.GetValueOrDefault("verificationKey") is D vk ? Key(vk, false) : null,
        o.GetValueOrDefault("statementKey") is D sk ? Key(sk, false) : null,
        o.GetValueOrDefault("allowHighS") is true);

    static bool AllowHigh(L a) => a.Count > 2 && a[2] is D o && o.GetValueOrDefault("allowHighS") is true;

    static object? Check(StatementCheck r) => r.Ok ? new D { ["ok"] = true } : new D { ["ok"] = false, ["reason"] = r.Reason };

    static InclusionProof Proof(D p) => new(Idx(p["index"]), Idx(p["size"]),
        ((L)p["path"]!).Select(s => new ProofStep((string)((D)s!)["side"]!, (string)((D)s)["hash"]!)).ToList());

    static string? Err(Exception e) => e.GetType().GetProperty("Code")?.GetValue(e) as string;

    // ---------------------------------------------------------------- tests

    [Fact]
    public void CborCodec()
    {
        Base.Check(M, "cborEncode", a => Cbor.Encode(FromCj(a[0])));
        Base.Check(M, "cborDecode", a => ToCj(Cbor.Decode(Base.Bytes(a[0]))));
    }

    [Fact]
    public void Rfc9162Tree()
    {
        Base.Check(M, "emptyRoot", a => Rfc9162.EmptyRoot());
        Base.Check(M, "leafHash", a => Rfc9162.LeafHash(Base.Bytes(a[0])));
        Base.Check(M, "nodeHash", a => Rfc9162.NodeHash(Base.Bytes(a[0]), Base.Bytes(a[1])));
        Base.Check(M, "treeHash", a => Rfc9162.TreeHash(Bytes(a[0])));
        Base.Check(M, "inclusionPath", a => Int(a[1], out var i) ? Rfc9162.InclusionPath(Bytes(a[0]), i) : Base.Refused);
        Base.Check(M, "rootFromInclusionPath", a => Int(a[1], out var i) && Int(a[2], out var n) ? Rfc9162.RootFromInclusionPath(Base.Bytes(a[0]), i, n, Bytes(a[3])) : null);
        Base.Check(M, "verifyInclusionPath", a => Int(a[1], out var i) && Int(a[2], out var n) && Rfc9162.VerifyInclusionPath(Base.Bytes(a[0]), i, n, Bytes(a[3]), Base.Bytes(a[4])));
        Base.Check(M, "consistencyPath", a => Int(a[1], out var m) ? Rfc9162.ConsistencyPath(Bytes(a[0]), m) : Base.Refused);
        Base.Check(M, "verifyConsistencyPath", a => Int(a[0], out var f) && Int(a[1], out var s) && Rfc9162.VerifyConsistencyPath(f, s, Base.Bytes(a[2]), Base.Bytes(a[3]), Bytes(a[4])));
        Base.Check(M, "siblingSides", a => ScittApi.SiblingSides(Base.Long(a[0]), Base.Long(a[1])));
    }

    [Fact]
    public void InclusionProofCodec()
    {
        Base.Check(M, "encodeInclusionProof", a => ScittApi.EncodeInclusionProof((D)a[0]!));
        Base.Check(M, "decodeInclusionProof", a =>
        {
            var p = ScittApi.DecodeInclusionProof(Base.Bytes(a[0]));
            return new D { ["index"] = p.Index, ["size"] = p.Size, ["path"] = p.Path.Select(s => (object?)new D { ["side"] = s.Side, ["hash"] = s.Hash }).ToList() };
        });
    }

    [Fact]
    public void SignedStatements()
    {
        Base.Check(M, "signStatement", a => ScittApi.SignStatement(a[0], SOpts((D)a[1]!)));
        Base.Check(M, "decodeCoseSign1", a =>
        {
            var c = ScittApi.DecodeCoseSign1(Base.Bytes(a[0]));
            return new D { ["protectedBytes"] = c.ProtectedBytes, ["protectedMap"] = ToCj(c.ProtectedMap), ["unprotected"] = ToCj(c.Unprotected), ["payload"] = c.Payload, ["signature"] = c.Signature };
        });
        Base.Check(M, "checkStatement", a => Check(ScittApi.CheckStatement(Base.Bytes(a[0]), Key((D)a[1]!, false), AllowHigh(a))));
        Base.Check(M, "verifyStatement", a => ScittApi.VerifyStatement(Base.Bytes(a[0]), Key((D)a[1]!, false), AllowHigh(a)));
        Base.Check(M, "statementPayload", a => ScittApi.StatementPayload(Base.Bytes(a[0])));
        Base.Check(M, "statementLeaf", a => ScittApi.StatementLeaf(Base.Bytes(a[0])));
    }

    [Fact]
    public void Receipts()
    {
        Base.Check(M, "buildReceipt", a => ScittApi.BuildReceipt((string)a[0]!, Proof((D)a[1]!), ROpts((D)a[2]!)));
        Base.Check(M, "verifyReceipt", a => ScittApi.VerifyReceipt(Base.Bytes(a[0]), Base.Bytes(a[1]), VOpts(a.Count > 2 ? a[2] as D : null)));
        Base.Check(M, "verifyConsistencyProof", a => ScittApi.VerifyConsistencyProof(Base.Bytes(a[0]), (string)a[1]!, (string)a[2]!));
    }

    [Fact]
    public void Es256()
    {
        var half = ScittApi.P256HalfN;
        Base.Check(M, "es256SignVerify", a =>
        {
            var k = (D)a[0]!;
            var st = ScittApi.SignStatement(a[1], new SignStatementOpts("ES256", Key(k, true), (string)a[2]!));
            var c = ScittApi.DecodeCoseSign1(st);
            var s = new BigInteger(c.Signature.AsSpan(32), isUnsigned: true, isBigEndian: true);
            return new D
            {
                ["check"] = Check(ScittApi.CheckStatement(st, Key(new D { ["alg"] = "ES256", ["x"] = k["x"], ["y"] = k["y"] }, false))),
                ["payload"] = ScittApi.StatementPayload(st),
                ["lowS"] = s <= half,
                ["protectedBytes"] = c.ProtectedBytes,
            };
        });
        Base.Check(M, "es256Receipt", a =>
        {
            var k = (D)a[0]!;
            int n = (int)Base.Long(a[1]);
            long index = Base.Long(a[2]);
            var ed = (D)a[3]!;
            var ts = new TransparencyService("ES256", Key(k, true), "ts");
            var sts = new List<byte[]>();
            for (int i = 0; i < n; i++) sts.Add(ts.AppendAndReceipt(new D { ["i"] = i }, new SignStatementOpts("EdDSA", Key(ed, true), "iss")).Statement);
            var pub = CoseKey.Es256Public(Pca.B64uDecode(k["x"])!, Pca.B64uDecode(k["y"])!);
            var r = ts.GetReceipt(index);
            var wrong = Key((D)a[4]!, false);
            using var edKey = EdKey.FromSeed(Pca.B64uDecode(ed["seed"])!);
            var edPub = CoseKey.Ed25519Public(edKey.Pub);
            var st = sts[(int)index];
            return new D
            {
                ["key"] = ScittApi.VerifyReceipt(r.Receipt, st, new(VerificationKey: pub)),
                ["root"] = ScittApi.VerifyReceipt(r.Receipt, st, new(TreeRoot: r.Root)),
                ["both"] = ScittApi.VerifyReceipt(r.Receipt, st, new(r.Root, pub, edPub)),
                ["wrongKey"] = ScittApi.VerifyReceipt(r.Receipt, st, new(VerificationKey: wrong)),
                ["otherStatement"] = ScittApi.VerifyReceipt(r.Receipt, sts[(int)((index + 1) % n)], new(VerificationKey: pub)),
                ["none"] = ScittApi.VerifyReceipt(r.Receipt, st, new()),
            };
        });
    }

    /// <summary>The store wrapper of the oracle's storeFault scenarios.</summary>
    sealed class FaultStore(IScittLogStore inner, D f) : IScittLogStore
    {
        public long Size() => f.ContainsKey("negSize") ? -1 : inner.Size();
        public byte[]? GetEntry(long index) => inner.GetEntry(index);

        public byte[]? GetNode(int level, long index)
        {
            if (f.GetValueOrDefault("dropNode") is L d && Base.Long(d[0]) == level && Base.Long(d[1]) == index) return null;
            if (f.GetValueOrDefault("shortNode") is L s && Base.Long(s[0]) == level && Base.Long(s[1]) == index) return new byte[31];
            return inner.GetNode(level, index);
        }

        public bool Append(long expectedSize, byte[] entry, IReadOnlyList<StoredNode> nodes) => !f.ContainsKey("stale") && inner.Append(expectedSize, entry, nodes);
    }

    static D Reg(long index, byte[] receipt, string root) => new() { ["index"] = index, ["receipt"] = receipt, ["root"] = root };

    static D Cons(ConsistencyProofResult c) => new() { ["oldSize"] = c.OldSize, ["newSize"] = c.NewSize, ["oldRoot"] = c.OldRoot, ["newRoot"] = c.NewRoot, ["proof"] = c.Proof };

    static object? RunService(D spec)
    {
        var kd = (D)spec["key"]!;
        var alg = (string)kd["alg"]!;
        var key = Key(kd, true);
        var issuer = spec.GetValueOrDefault("issuer") as string;
        var memory = (string)spec["kind"]! == "memory";
        var ms = memory ? new TransparencyService(alg, key, issuer) : null;
        DurableTransparencyService? ds = null;
        if (!memory)
        {
            IScittLogStore store = new MemoryScittLogStore();
            if (spec.GetValueOrDefault("storeFault") is D f) store = new FaultStore(store, f);
            ds = new DurableTransparencyService(store, alg, key, issuer);
        }
        SignStatementOpts StmtOpts(D op) =>
            new("EdDSA", Key((D)spec["stmtKey"]!, true), "https://issuer.example", op.GetValueOrDefault("subject") as string, op.GetValueOrDefault("contentType") as string);

        var res = new L();
        foreach (var o in (L)spec["ops"]!)
        {
            var op = (D)o!;
            try
            {
                object? v;
                switch ((string)op["op"]!)
                {
                    case "append":
                        if (ms != null) { var r = ms.AppendAndReceipt(op["payload"], StmtOpts(op)); v = new D { ["statement"] = r.Statement, ["index"] = r.Index, ["receipt"] = r.Receipt, ["root"] = r.Root }; }
                        else { var r = ds!.AppendAndReceipt(op["payload"], StmtOpts(op)); v = new D { ["statement"] = r.Statement, ["index"] = r.Index, ["receipt"] = r.Receipt, ["root"] = r.Root }; }
                        break;
                    case "register":
                        {
                            var st = Base.Bytes(op["statement"]);
                            if (ms != null) { var r = ms.Register(st); v = Reg(r.Index, r.Receipt, r.Root); }
                            else { var r = ds!.Register(st); v = Reg(r.Index, r.Receipt, r.Root); }
                            break;
                        }
                    case "receipt":
                        if (ms != null) { var r = ms.GetReceipt(Idx(op["i"])); v = Reg(r.Index, r.Receipt, r.Root); }
                        else { var r = ds!.GetReceipt(Idx(op["i"])); v = Reg(r.Index, r.Receipt, r.Root); }
                        break;
                    case "consistency":
                        v = Cons(ms != null ? ms.ConsistencyProof(Idx(op["m"])) : ds!.ConsistencyProof(Idx(op["m"])));
                        break;
                    case "entry":
                        // the in-memory reference service has no getEntry: the call is a TypeError there
                        v = ms != null ? throw new InvalidOperationException("svc.getEntry is not a function") : ds!.GetEntry(Idx(op["i"]));
                        break;
                    case "snapshot":
                        v = ms != null ? ms.Snapshot() : throw new InvalidOperationException("svc.snapshot is not a function");
                        break;
                    case "root": v = ms != null ? ms.Root : ds!.Root(); break;
                    case "size": v = ms != null ? ms.Size : ds!.Size(); break;
                    default: throw new InvalidOperationException("op");
                }
                res.Add(new D { ["ok"] = v });
            }
            catch (Exception e)
            {
                res.Add(new D { ["err"] = (object?)Err(e) ?? true });
            }
        }
        return res;
    }

    [Fact]
    public void Services() => Base.Check(M, "service", a => RunService((D)a[0]!));

    static string TempFile() => Path.Combine(Path.GetTempPath(), "scitt-" + Guid.NewGuid().ToString("N") + ".log");

    [Fact]
    public void FileStore()
    {
        Base.Check(M, "fileStoreBytes", a =>
        {
            var p = TempFile();
            try
            {
                using (var s = FileScittLogStore.Open(p))
                {
                    foreach (var o in (L)a[0]!)
                    {
                        var op = (D)o!;
                        var nodes = ((L)op["nodes"]!).Select(n =>
                        {
                            var t = (L)n!;
                            return new StoredNode((int)Base.Long(t[0]), Base.Long(t[1]), Pca.B64uDecode(t[2]) ?? throw new InvalidDataException("bad hash"));
                        }).ToList();
                        try { s.Append(Base.Long(op["expected"]), Base.Bytes(op["entry"]), nodes); }
                        catch (Exception) { /* a refused / malformed append: nothing is written */ }
                    }
                }
                return File.ReadAllBytes(p);
            }
            finally { File.Delete(p); }
        });
        Base.Check(M, "fileStoreOpen", a =>
        {
            var p = TempFile();
            try
            {
                File.WriteAllBytes(p, Base.Bytes(a[0]));
                var entries = new L();
                var nodes0 = new L();
                long size;
                using (var s = FileScittLogStore.Open(p))
                {
                    size = s.Size();
                    for (long i = 0; i < size; i++) { entries.Add(s.GetEntry(i)); nodes0.Add(s.GetNode(0, i)); }
                }
                // read once the store is closed (any torn tail was truncated while opening)
                return new D { ["size"] = size, ["entries"] = entries, ["nodes0"] = nodes0, ["after"] = File.ReadAllBytes(p) };
            }
            finally { File.Delete(p); }
        });
        Base.Check(M, "checkScittLogStore", a =>
        {
            if ((string)a[0]! == "memory") return DurableTransparencyService.CheckScittLogStore(() => new MemoryScittLogStore());
            var opened = new List<FileScittLogStore>();
            var paths = new List<string>();
            try
            {
                return DurableTransparencyService.CheckScittLogStore(() =>
                {
                    var p = TempFile();
                    paths.Add(p);
                    var s = FileScittLogStore.Open(p);
                    opened.Add(s);
                    return s;
                });
            }
            finally
            {
                foreach (var s in opened) s.Dispose();
                foreach (var p in paths) File.Delete(p);
            }
        });
    }

    [Fact]
    public void Constants() => Base.Check(M, "constants", a => new D
    {
        ["COSE_SIGN1_TAG"] = ScittApi.CoseSign1Tag,
        ["HDR_ALG"] = ScittApi.HdrAlg,
        ["HDR_CONTENT_TYPE"] = ScittApi.HdrContentType,
        ["HDR_CWT_CLAIMS"] = ScittApi.HdrCwtClaims,
        ["CWT_ISS"] = ScittApi.CwtIss,
        ["CWT_SUB"] = ScittApi.CwtSub,
        ["HDR_VDS"] = ScittApi.HdrVds,
        ["HDR_VDS_PROOFS"] = ScittApi.HdrVdsProofs,
        ["VDS_RFC9162_SHA256"] = ScittApi.VdsRfc9162Sha256,
        ["PROOF_TYPE_INCLUSION"] = ScittApi.ProofTypeInclusion,
        ["DEFAULT_CONTENT_TYPE"] = ScittApi.DefaultContentType,
    });

    [Fact]
    public void AllFunctionsCovered() { Base.Covers(M, new[]
    {
        "cborEncode", "cborDecode", "emptyRoot", "leafHash", "nodeHash", "treeHash", "inclusionPath", "rootFromInclusionPath", "verifyInclusionPath",
        "consistencyPath", "verifyConsistencyPath", "siblingSides", "encodeInclusionProof", "decodeInclusionProof", "signStatement", "decodeCoseSign1",
        "checkStatement", "verifyStatement", "statementPayload", "statementLeaf", "buildReceipt", "verifyReceipt", "verifyConsistencyProof",
        "es256SignVerify", "es256Receipt", "service", "fileStoreBytes", "fileStoreOpen", "checkScittLogStore", "constants",
    }); Assert.Equal(8036, Base.Total(M)); }
}
