using System.Security.Cryptography;
using System.Text;
using Xunit;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca.Corpus.Tests;

/// <summary>Differential replay of bond settlement against the reference: the slash split and money arithmetic, bond sizing, the evidence digests, settlement records and anchors, the claim,
/// fraud-proof and dispute verdicts, and scripted op sequences over a <see cref="StoreBondLedger"/> on a memory store.</summary>
public class RefCoreBondSettlementTests
{
    const string M = "ref-core-bond-settlement-java";

    static double Dbl(object? o) => IntentJs.NumOf(o) ?? throw new ArgumentException("not a number");

    static double? DblOrNull(object? o) => IntentJs.NumOf(o);

    static byte[] Seed(string label) => SHA256.HashData(Encoding.UTF8.GetBytes("atlas-pca-conformance/" + label));

    static IReadOnlyDictionary<string, string>? Pins(object? o) =>
        // the reference API takes {pqPins}; a bare identity-to-key map is the older spelling of the same pins
        o is D d ? (d.GetValueOrDefault("pqPins") is D pp ? pp : d).Where(kv => kv.Value is string).ToDictionary(kv => kv.Key, kv => (string)kv.Value!) : null;

    static ChallengeWindowPolicy? PolicyOf(object? o) =>
        o is D p ? new ChallengeWindowPolicy(Dbl(p["minWindowMs"]), Dbl(p["maxWindowMs"]), Dbl(p["maxSkewMs"])) : null;

    static ObjectiveOracle? OracleOf(object? table) => table is D t ? (input, _) => t.GetValueOrDefault(input) as D : null;

    [Fact] public void ComputeSlashSplit() => Base.Check(M, "computeSlashSplit", a => BondSettlement.ComputeSlashSplit(Dbl(a[0]), (D)a[1]!, (D)a[2]!).ToJson());
    [Fact] public void QuantizeUp() => Base.Check(M, "quantizeUp", a => BondSettlement.QuantizeUp(Dbl(a[0])));
    [Fact]
    public void ToMicros() => Base.Check(M, "toMicros", a => BondSettlement.ToMicros(Dbl(a[0])) is long v ? new D { ["$bigint"] = v.ToString(System.Globalization.CultureInfo.InvariantCulture) } : null);
    [Fact] public void ExactAdd() => Base.Check(M, "exactAdd", a => BondSettlement.ExactAdd(Dbl(a[0]), Dbl(a[1]), (int)Dbl(a[2])));

    [Fact]
    public void ApplyBondMoves() => Base.Check(M, "applyBondMoves", a =>
    {
        var bal = (D)a[0]!;
        return BondDoc.ApplyBondMoves(acct => bal.ContainsKey(acct) ? IntentJs.NumOf(bal[acct]) ?? 0 : 0, (L)a[1]!);
    });

    [Fact] public void BondAmount() => Base.Check(M, "bondAmount", a => BondSettlement.BondAmount((D)a[0]!, Dbl(a[1])));

    [Fact]
    public void EvidenceDigests()
    {
        Base.Check(M, "settlementEvidenceDigest", a => BondSettlement.SettlementEvidenceDigest((D)a[0]!, (D)a[1]!));
        Base.Check(M, "revocationEvidenceDigest", a => BondSettlement.RevocationEvidenceDigest((D)a[0]!, (string)a[1]!));
        Base.Check(M, "disputeEvidenceDigest", a => BondSettlement.DisputeEvidenceDigest((D)a[0]!, (D)a[1]!));
    }

    [Fact]
    public void Records()
    {
        Base.Check(M, "verifySettlement", a => BondSettlement.VerifySettlement(a[0], (string)a[1]!, Pins(a[2])));
        Base.Check(M, "settlementRecordDigest", a => BondSettlement.SettlementRecordDigest((D)a[0]!));
        Base.Check(M, "settlementCommit", a => BondSettlement.SettlementCommit((string)a[0]!, (D)a[1]!));
        Base.Check(M, "verifySettlementCommit", a => BondSettlement.VerifySettlementCommit(a[0] as string, a[1] as string, a[2] as D));
    }

    [Fact] public void VerifyClaim() => Base.Check(M, "verifyClaim", a => Optimistic.VerifyClaim(a[0], a[1], (string)a[2]!, Dbl(a[3]), PolicyOf(a[4])));
    [Fact] public void VerifyFraudProof() => Base.Check(M, "verifyFraudProof", a => Optimistic.VerifyFraudProof((D)a[0]!, a[1], a[2], a[3]));
    [Fact] public void AdjudicateDispute() => Base.Check(M, "adjudicateDispute", a => Optimistic.AdjudicateDispute((D)a[0]!, a[1], a[2], a[3], OracleOf(a[4]), DblOrNull(a[5])));

    // ---- scripted ledger sequences ----

    /// <summary>Replaces every "@name" string by a copy of the fixture (an unknown name is an absent value).</summary>
    static object? Resolve(D fx, object? v)
    {
        if (v is string s && s.StartsWith('@')) return StoreJs.DeepCopy(fx.GetValueOrDefault(s[1..]));
        if (v is L l) return l.Select(x => Resolve(fx, x)).ToList();
        if (v is D m) return m.ToDictionary(e => e.Key, e => Resolve(fx, e.Value));
        return v;
    }

    static D? Params(D fx, object? raw)
    {
        var q = Resolve(fx, raw) as D;
        if (q != null && q.ContainsKey("oracleTable"))
        {
            var table = q["oracleTable"];
            q.Remove("oracleTable");
            q["oracle"] = OracleOf(table);
        }
        return q;
    }

    static string CodeOf(Exception t) => t is BondStoreError b ? b.Code : t is ArgumentException ? "RangeError" : "Error";

    static L Run(L args)
    {
        var fx = (D)args[0]!;
        var cfg = (D)args[1]!;
        var kv = new MemoryAtomicKv();
        double[] clock = { 1_800_000_000_000.0 };
        var o = new StoreBondLedgerOptions { Store = new KvBondStore(kv), GuardianKey = EdKey.FromSeed(Seed("bond/guardian")), Clock = () => clock[0] };
        if (cfg.ContainsKey("epoch")) o.GuardianEpoch = (long)Dbl(cfg["epoch"]);
        if (cfg.ContainsKey("escrow")) o.EscrowAccount = (string)cfg["escrow"]!;
        if (cfg.ContainsKey("bondPolicy")) o.BondPolicy = (D)cfg["bondPolicy"]!;
        if (cfg.ContainsKey("splitPolicy")) o.SlashSplitPolicy = (D)cfg["splitPolicy"]!;
        if (cfg.ContainsKey("windowMs"))
        {
            var w = (D)cfg["windowMs"]!;
            o.WindowPolicy = new ChallengeWindowPolicy(Dbl(w["min"]), Dbl(w["max"]), Dbl(w["skew"]));
        }
        var ledger = new StoreBondLedger(o);
        var outp = new L();
        foreach (var oo in (L)args[2]!)
        {
            var op = (L)oo!;
            try
            {
                object? v;
                switch ((string)op[0]!)
                {
                    case "clock": clock[0] = DblOrNull(op[1]) ?? double.NaN; v = null; break;
                    case "deposit": v = ledger.Deposit((string)op[1]!, Dbl(op[2])); break;
                    case "balance": v = ledger.BalanceOf((string)op[1]!); break;
                    case "status": v = ledger.BondStatus((string)op[1]!); break;
                    case "bond": v = ledger.GetBond((string)op[1]!); break;
                    case "challenge": v = ledger.ChallengeStatus((string)op[1]!); break;
                    case "pub": v = ledger.GuardianPublicKey; break;
                    case "openClaim":
                        {
                            var p = Params(fx, op[1])!;
                            v = ledger.OpenClaim(p["claim"] as D, p.GetValueOrDefault("pcactn"), (string)p["signerPublic"]!, Dbl(p["amount"]), (string)p["depositor"]!, DblOrNull(p.GetValueOrDefault("exposure")));
                            break;
                        }
                    case "openBond":
                        {
                            var p = Params(fx, op[1])!;
                            v = ledger.OpenBond((string)p["claimId"]!, Dbl(p["amount"]), (string)p["depositor"]!, DblOrNull(p.GetValueOrDefault("exposure")));
                            break;
                        }
                    case "release": v = ledger.Release((string)op[1]!); break;
                    case "releaseUnreg": v = ledger.ReleaseUnregistered((string)op[1]!); break;
                    case "slash": v = ledger.SlashBond(Params(fx, op[1])!); break;
                    case "slashDispute": v = ledger.SlashBondOnDispute(Params(fx, op[1])!); break;
                    case "slashRevoke": v = ledger.SlashBondOnRevocation(Params(fx, op[1])!); break;
                    case "slashCounter": v = ledger.SlashCounterBond(Params(fx, op[1])!); break;
                    case "kvSet": { var text = JsCanon.Lenient(StoreJs.DeepCopy(op[1]))!; kv.Update(KvBondStore.DocKey, _ => text); v = null; break; }
                    case "kvGet": v = kv.Get(KvBondStore.DocKey) is { } t ? Pca.ParseJson(t) : null; break;
                    default: throw new InvalidOperationException("op");
                }
                outp.Add(v);
            }
            catch (Exception t) { outp.Add(new D { ["$err"] = CodeOf(t) }); }
        }
        return outp;
    }

    [Fact] public void Ledger() => Base.Check(M, "ledger", Run);

    [Fact]
    public void Covers() { Base.Covers(M, new[]
    {
        "computeSlashSplit", "quantizeUp", "toMicros", "exactAdd", "applyBondMoves", "bondAmount", "settlementEvidenceDigest", "revocationEvidenceDigest", "disputeEvidenceDigest",
        "verifySettlement", "settlementRecordDigest", "settlementCommit", "verifySettlementCommit", "verifyClaim", "verifyFraudProof", "adjudicateDispute", "ledger",
    }); Assert.Equal(1451, Base.Total(M)); }
}
