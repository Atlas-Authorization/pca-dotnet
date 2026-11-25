// Zero-knowledge proof of compliance (the reference zk module), part 2: the Groth16 envelopes. The one canonical encoding of an envelope, the public
// signals of the Policy VM circuits (pca-policyvm-v1 on BN254 and BLS12-381, the risk-bound pca-policyvm-v2 on BN254) and their decoding, the struct
// hashes the circuits expose and the quantization of an action, a plan and a policy to the hashed structs, the context pins, the offline verification
// of a Policy VM proof and the four SNARK backends. Everything here runs in front of the pairing check, which the registered engine answers.
using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Numerics;
using System.Text;
using AtlasPca.Analyzer;
using AtlasPca.InteropJs;
using D = System.Collections.Generic.Dictionary<string, object?>;
using L = System.Collections.Generic.List<object?>;

namespace AtlasPca;

public static partial class ZkCompliance
{
    static ReadOnlyDictionary<string, int> Layout(params string[] names)
    {
        var d = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int i = 0; i < names.Length; i++) d[names[i]] = i;
        return new ReadOnlyDictionary<string, int>(d);
    }

    /// <summary>Index of each public signal of <c>pca-policyvm-v1</c>: the three struct-hash halves, the risk r, the threshold t and the admit bit (outputs), then
    /// the asserted allow bit and the decision context (public inputs).</summary>
    public static readonly IReadOnlyDictionary<string, int> PolicyVmPublicSignal =
        Layout("actionHi", "actionLo", "policyHi", "policyLo", "planHi", "planLo", "r", "t", "admit", "allow", "now", "blast", "delegationDepth", "recentCount", "allocChild");
    public const int PolicyVmPublicSignalCount = 15;

    /// <summary>Index of each public signal of the risk-bound <c>pca-policyvm-v2</c>: the v1 statement plus the risk commitment halves.</summary>
    public static readonly IReadOnlyDictionary<string, int> PolicyVmBoundPublicSignal =
        Layout("actionHi", "actionLo", "policyHi", "policyLo", "planHi", "planLo", "r", "t", "admit", "riskHi", "riskLo", "allow", "now", "blast", "delegationDepth", "recentCount", "allocChild");
    public const int PolicyVmBoundPublicSignalCount = 17;

    /// <summary>The risk magnitudes the v2 circuit commits to, in struct order.</summary>
    public static readonly IReadOnlyList<string> PolicyVmBoundRiskFields = Array.AsReadOnly(new[] { "revScore", "taint", "conf", "age", "rFloorIn" });

    static readonly string[] ReversibilityOrder = { "reversible", "rate_limited", "irreversible" };

    /// <summary>The reversibility classes in the order the circuit's class index encodes (reversible = 0).</summary>
    public static readonly IReadOnlyList<string> PolicyVmReversibilityOrder = Array.AsReadOnly(ReversibilityOrder);

    static readonly BigInteger Bn254Fq = BigInteger.Parse("21888242871839275222246405745257275088696311157297823662689037894645226208583", CultureInfo.InvariantCulture);
    static readonly BigInteger Bls12381Fq = BigInteger.Parse("01a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
    static readonly BigInteger Bls12381Fr = BigInteger.Parse("073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
    static readonly BigInteger ContextBound = BigInteger.One << 64;

    // ---- the canonical envelope ----

    /// <summary>The whole text is a decimal integer with no sign and no leading zero.</summary>
    static bool CanonDec(string s)
    {
        if (s.Length == 0 || (s[0] == '0' && s.Length > 1)) return false;
        foreach (var c in s)
            if (c is < '0' or > '9') return false;
        return true;
    }

    static bool CanonDecBelow(object? v, BigInteger bound) =>
        v is string s && s.Length <= 120 && CanonDec(s) && BigInteger.Parse(s, CultureInfo.InvariantCulture) < bound;

    static bool SameKeys(D o, params string[] keys) => o.Count == keys.Length && keys.All(o.ContainsKey);

    /// <summary>True when <paramref name="env"/> is exactly the one canonical Groth16 envelope for <paramref name="curve"/> (<c>bn254</c>, anything else is read as
    /// <c>bls12-381</c>): the members system, circuit, proof and publicSignals and no other; every signal and coordinate a canonical decimal below its field;
    /// the proof {pi_a, pi_b, pi_c, protocol, curve} with affine points (z = 1). The pairing library would accept many other spellings of one proof.</summary>
    public static bool IsCanonicalGroth16Envelope(object? env, object? curve)
    {
        if (env is not D e || !SameKeys(e, "system", "circuit", "proof", "publicSignals")) return false;
        bool bn = curve is "bn254";
        var fq = bn ? Bn254Fq : Bls12381Fq;
        var fr = bn ? Bn254Fr : Bls12381Fr;
        if (e["publicSignals"] is not L signals || !signals.All(x => CanonDecBelow(x, fr))) return false;
        if (e["proof"] is not D pr || !SameKeys(pr, "pi_a", "pi_b", "pi_c", "protocol", "curve")) return false;
        if (pr["protocol"] is not "groth16" || pr["curve"] is not string named || named != (bn ? "bn128" : "bls12381")) return false;
        bool G1(object? a) => a is L { Count: 3 } p && CanonDecBelow(p[0], fq) && CanonDecBelow(p[1], fq) && p[2] is "1";
        if (!G1(pr["pi_a"]) || !G1(pr["pi_c"])) return false;
        if (pr["pi_b"] is not L { Count: 3 } b) return false;
        for (int i = 0; i < 2; i++)
            if (b[i] is not L { Count: 2 } row || !CanonDecBelow(row[0], fq) || !CanonDecBelow(row[1], fq)) return false;
        return b[2] is L { Count: 2 } z && z[0] is "1" && z[1] is "0";
    }

    // ---- integers as the reference reads them ----

    static BigInteger TextToBig(string text)
    {
        var s = JsX.JsTrim(text);
        if (s.Length == 0) return BigInteger.Zero;
        int radix = 0;
        if (s.Length > 2 && s[0] == '0')
        {
            char prefix = (char)(s[1] | 0x20);
            radix = prefix == 'x' ? 16 : prefix == 'o' ? 8 : prefix == 'b' ? 2 : 0;
        }
        if (radix != 0)
        {
            var acc = BigInteger.Zero;
            for (int i = 2; i < s.Length; i++)
            {
                char c = s[i], lower = (char)(c | 0x20);
                int digit = c is >= '0' and <= '9' ? c - '0' : lower is >= 'a' and <= 'f' ? lower - 'a' + 10 : 99;
                if (digit >= radix) throw new ArgumentException("cannot convert the text to an integer");
                acc = acc * radix + digit;
            }
            return acc;
        }
        int start = s[0] is '+' or '-' ? 1 : 0;
        if (start == s.Length) throw new ArgumentException("cannot convert the text to an integer");
        for (int i = start; i < s.Length; i++)
            if (s[i] is < '0' or > '9') throw new ArgumentException("cannot convert the text to an integer");
        return BigInteger.Parse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
    }

    /// <summary>The integer a struct field or a pin stands for: an integer type, an integral number, a boolean, or integer text (decimal with an optional
    /// sign, or 0x / 0o / 0b; surrounding white space ignored, empty = 0). Anything else throws.</summary>
    static BigInteger ToBig(object? v)
    {
        switch (v)
        {
            case BigInteger b: return b;
            case ulong u: return u;
            case long l: return l;
            case int i: return i;
            case bool t: return t ? BigInteger.One : BigInteger.Zero;
            case string s: return TextToBig(s);
            case L a: return TextToBig(JsX.Str(a));
            case Num or double:
                {
                    if (IntentJs.NumOf(v) is not double x || !double.IsFinite(x) || x != Math.Floor(x)) throw new ArgumentException("the number is not an integer");
                    return new BigInteger(x);
                }
            default: throw new ArgumentException("cannot convert the value to an integer");
        }
    }

    /// <summary>An explicit code or a numeric field as a uint64: an integer type or an integral number in range. Anything else throws (fail closed).</summary>
    static ulong U64(object? v, string what)
    {
        BigInteger? b = v switch
        {
            BigInteger x => (BigInteger?)x,
            ulong x => x,
            long x => x,
            int x => x,
            Num or double when IntentJs.NumOf(v) is double x && double.IsFinite(x) && x == Math.Floor(x) => new BigInteger(x),
            _ => null,
        };
        if (b is not { } n || n < 0 || n > ulong.MaxValue) throw new ArgumentException($"policyvm quantize: {what} is not a uint64");
        return (ulong)n;
    }

    // ---- struct hashes ----

    static string Half(ReadOnlySpan<byte> half) => new BigInteger(half, isUnsigned: true, isBigEndian: true).ToString(CultureInfo.InvariantCulture);

    /// <summary>The digest the circuit exposes for a fixed-layout struct: every field as a 64-bit unsigned big-endian integer, concatenated, SHA-256, split into
    /// the two 128-bit big-endian halves {hi, lo} as decimal text. A field is an integer type, an integral number, or integer text; one outside the uint64
    /// range throws.</summary>
    public static D PolicyVmStructHash(IEnumerable<object?> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        var list = fields.ToList();
        var bytes = new byte[list.Count * 8];
        for (int i = 0; i < list.Count; i++)
        {
            var v = ToBig(list[i]);
            if (v < 0 || v > ulong.MaxValue) throw new ArgumentException("policyVmStructHash: field out of uint64 range");
            BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(i * 8), (ulong)v);
        }
        var digest = Pca.Sha(bytes);
        return new D { ["hi"] = Half(digest.AsSpan(0, 16)), ["lo"] = Half(digest.AsSpan(16, 16)) };
    }

    /// <summary><see cref="PolicyVmStructHash(IEnumerable{object})"/> over quantized fields.</summary>
    public static D PolicyVmStructHash(IEnumerable<ulong> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        return PolicyVmStructHash(fields.Select(f => (object?)f));
    }

    /// <summary>The risk commitment of the v2 circuit, as the public halves riskHi / riskLo: exactly the five risk magnitudes (revScore, taint, conf, age,
    /// rFloorIn; fixed point, scale 1e6) in <see cref="PolicyVmBoundRiskFields"/> order.</summary>
    public static D PolicyVmRiskHash(IEnumerable<object?>? fields)
    {
        if (fields is not IReadOnlyCollection<object?> { Count: 5 }) throw new ArgumentException("policyVmRiskHash: need exactly 5 risk fields");
        return PolicyVmStructHash(fields);
    }

    // ---- quantization: the live action, plan and policy as the structs the circuit hashes ----
    // Options (the reference's members): verbCodes and resourceCodes (text to uint64 code, the catalog shared with the prover), strictCatalog (a text
    // missing from the catalog throws instead of being content-addressed), paramScalarField (the action parameter that is the circuit's param scalar).

    /// <summary>The uint64 a text has without a catalog: the first 8 bytes, big-endian, of the SHA-256 of its domain-tagged form.</summary>
    static ulong ContentAddress(string domain, string value) =>
        BinaryPrimitives.ReadUInt64BigEndian(Pca.Sha(Encoding.UTF8.GetBytes($"atlas-pca/policyvm-quantize/{domain}:{value}")));

    static ulong Code(string domain, object? value, object? catalog, bool strict)
    {
        if (value is not string s) throw new ArgumentException($"policyvm quantize: {domain} must be a string");
        if (catalog is D map && map.TryGetValue(s, out var code)) return U64(code, domain + " code");
        if (strict) throw new ArgumentException($"policyvm quantize: {domain} \"{s}\" is not in the catalog (strict)");
        return ContentAddress(domain, s);
    }

    // names every object of the reference runtime inherits: read as a parameter they are a function or an object there, never a number
    static readonly HashSet<string> Inherited = new(StringComparer.Ordinal)
    {
        "constructor", "__proto__", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString", "toString", "valueOf",
        "__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__",
    };

    /// <summary>The param scalar: 0 when no field is named or the parameter is unset, else its value, which must be a non-negative integer in the uint64 range
    /// (a number, an integer type, or text of decimal digits only).</summary>
    static ulong ParamScalar(object? parameters, object? field)
    {
        if (!Jx.Truthy(field)) return 0;
        var name = JsX.Str(field);
        var v = M(parameters, name);
        if (Jx.IsUndef(v) && Jx.Truthy(parameters) && Inherited.Contains(name)) throw new ArgumentException("policyvm quantize: paramScalar is not a non-negative integer");
        if (v == null || Jx.IsUndef(v)) return 0;
        if (v is BigInteger or ulong or long or int) return U64(v, "paramScalar");
        if (v is Num or double)
        {
            if (IntentJs.NumOf(v) is not double x || !double.IsFinite(x) || x != Math.Floor(x) || x < 0 || IntentJs.IsNegZero(x))
                throw new ArgumentException("policyvm quantize: paramScalar must be a non-negative integer");
            return U64(v, "paramScalar");
        }
        if (v is string s && s.Length > 0 && s.All(c => c is >= '0' and <= '9')) return U64(BigInteger.Parse(s, CultureInfo.InvariantCulture), "paramScalar");
        throw new ArgumentException("policyvm quantize: paramScalar is not a non-negative integer");
    }

    static ulong ReversibilityIndex(object? rc, string what)
    {
        int idx = rc is string s ? Array.IndexOf(ReversibilityOrder, s) : -1;
        if (idx < 0) throw new ArgumentException($"policyvm quantize: unknown {what} class \"{JsX.Str(rc)}\"");
        return (ulong)idx;
    }

    /// <summary>The action {verb, resource, reversibility_class?, params?} as the circuit's 4-field struct: verb code, resource code, reversibility class index
    /// (an omitted class is <c>reversible</c>), param scalar. Throws on anything that cannot be quantized: a verb or resource that is not text, an unknown
    /// class, a strict-catalog miss, a param scalar outside the uint64 range.</summary>
    public static ulong[] QuantizeActionStruct(object? action, D? opts = null)
    {
        if (action is not (D or L)) throw new ArgumentException("policyvm quantize: action is missing");
        bool strict = M(opts, "strictCatalog") is true;
        var verb = Code("verb", M(action, "verb"), M(opts, "verbCodes"), strict);
        var resource = Code("resource", M(action, "resource"), M(opts, "resourceCodes"), strict);
        var rc = M(action, "reversibility_class");
        var rev = ReversibilityIndex(rc == null || Jx.IsUndef(rc) ? "reversible" : rc, "reversibility");
        return new[] { verb, resource, rev, ParamScalar(M(action, "params"), M(opts, "paramScalarField")) };
    }

    /// <summary>The plan node {verb, resource, semanticDist, planSalt} as the circuit's 4-field plan struct. The salt is the prover's: a verifier binds the action.</summary>
    public static ulong[] QuantizePlanStruct(object? plan, D? opts = null)
    {
        ArgumentNullException.ThrowIfNull(plan);
        bool strict = M(opts, "strictCatalog") is true;
        return new[]
        {
            Code("verb", M(plan, "verb"), M(opts, "verbCodes"), strict),
            Code("resource", M(plan, "resource"), M(opts, "resourceCodes"), strict),
            U64(M(plan, "semanticDist"), "semanticDist"),
            U64(M(plan, "planSalt"), "planSalt"),
        };
    }

    /// <summary>The policy {weights {alpha, beta, gamma, delta, epsilon, zeta}, theta1, theta2, kappa, budgetB, policyVerb, policyResource, policyParamBound,
    /// expiresAt, notBefore, maxBlast, maxDepth, revMax, rateMax, allocParent} as the circuit's 20-field policy struct (the numbers are the policy's own
    /// fixed-point integers).</summary>
    public static ulong[] QuantizePolicyStruct(object? policy, D? opts = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        bool strict = M(opts, "strictCatalog") is true;
        var w = M(policy, "weights");
        if (w == null || Jx.IsUndef(w)) throw new ArgumentException("policyvm quantize: the policy has no weights");
        return new[]
        {
            U64(M(w, "alpha"), "wAlpha"),
            U64(M(w, "beta"), "wBeta"),
            U64(M(w, "gamma"), "wGamma"),
            U64(M(w, "delta"), "wDelta"),
            U64(M(w, "epsilon"), "wEpsilon"),
            U64(M(w, "zeta"), "wZeta"),
            U64(M(policy, "theta1"), "theta1"),
            U64(M(policy, "theta2"), "theta2"),
            U64(M(policy, "kappa"), "kappa"),
            U64(M(policy, "budgetB"), "budgetB"),
            Code("verb", M(policy, "policyVerb"), M(opts, "verbCodes"), strict),
            Code("resource", M(policy, "policyResource"), M(opts, "resourceCodes"), strict),
            U64(M(policy, "policyParamBound"), "policyParamBound"),
            U64(M(policy, "expiresAt"), "expiresAt"),
            U64(M(policy, "notBefore"), "notBefore"),
            U64(M(policy, "maxBlast"), "maxBlast"),
            U64(M(policy, "maxDepth"), "maxDepth"),
            ReversibilityIndex(M(policy, "revMax"), "revMax"),
            U64(M(policy, "rateMax"), "rateMax"),
            U64(M(policy, "allocParent"), "allocParent"),
        };
    }

    /// <summary>{action, plan?, policy?} quantized: <c>action</c> always, <c>plan</c> and <c>policy</c> when given. The values are the uint64 field arrays.</summary>
    public static D QuantizePolicyVmInputs(object? inp, D? opts = null)
    {
        ArgumentNullException.ThrowIfNull(inp);
        var o = new D { ["action"] = QuantizeActionStruct(M(inp, "action"), opts) };
        var plan = M(inp, "plan");
        if (Jx.Truthy(plan)) o["plan"] = QuantizePlanStruct(plan, opts);
        var policy = M(inp, "policy");
        if (Jx.Truthy(policy)) o["policy"] = QuantizePolicyStruct(policy, opts);
        return o;
    }

    /// <summary>The circuit's action commitment (the public halves actionHi / actionLo) recomputed from the live action. A verifier binds a Policy VM proof to
    /// this action by requiring those halves (<c>expectActionHash</c>): a proof made for another action does not match.</summary>
    public static D PolicyVmCommitmentFromAction(object? action, D? opts = null) => PolicyVmStructHash(QuantizeActionStruct(action, opts));

    // ---- public signals ----

    static D Decode(L publicSignals, IReadOnlyDictionary<string, int> layout, bool risk)
    {
        ArgumentNullException.ThrowIfNull(publicSignals);
        D Halves(string name)
        {
            var h = new D();
            Jx.Set(h, "hi", At(publicSignals, layout[name + "Hi"]));
            Jx.Set(h, "lo", At(publicSignals, layout[name + "Lo"]));
            return h;
        }
        var o = new D { ["actionHash"] = Halves("action"), ["policyHash"] = Halves("policy"), ["planHash"] = Halves("plan") };
        if (risk) o["riskHash"] = Halves("risk");
        foreach (var k in new[] { "r", "t", "admit", "allow", "now", "blast", "delegationDepth", "recentCount", "allocChild" }) Jx.Set(o, k, At(publicSignals, layout[k]));
        return o;
    }

    /// <summary>The statement a v1 proof makes, read from its public signals: {actionHash, policyHash, planHash} as {hi, lo}, r, t, admit, allow, now, blast,
    /// delegationDepth, recentCount, allocChild. A signal the list lacks is left out.</summary>
    public static D DecodePolicyVmPublic(L publicSignals) => Decode(publicSignals, PolicyVmPublicSignal, false);

    /// <summary>The statement a v2 proof makes: the v1 statement plus <c>riskHash</c>.</summary>
    public static D DecodePolicyVmBoundPublic(L publicSignals) => Decode(publicSignals, PolicyVmBoundPublicSignal, true);

    // ---- context pins ----

    /// <summary>A pin as an integer, or null when it is not one (a number must be a safe integer).</summary>
    static BigInteger? PinValue(object? v)
    {
        try
        {
            if (v is Num or double && !IntentJs.IsSafeInteger(v)) return null;
            return ToBig(v);
        }
        catch (ArgumentException) { return null; }
    }

    static bool SignalMatchesPin(object? signal, object? pin)
    {
        if (Jx.IsUndef(signal) || !CanonDec(JsX.Str(signal))) return false;
        var x = signal is string s ? BigInteger.Parse(s, CultureInfo.InvariantCulture) : ToBig(signal);
        if (pin == null) throw JsX.TypeError("cannot read properties of null (reading 'min')");
        if (pin is D or L)
        {
            BigInteger? lo = PinValue(M(pin, "min")), hi = PinValue(M(pin, "max"));
            return lo != null && hi != null && lo <= hi && x >= lo && x <= hi;
        }
        var want = PinValue(pin);
        return want != null && x == want;
    }

    static readonly string[] ContextSignals = { "now", "blast", "delegationDepth", "recentCount", "allocChild" };
    static readonly string[] PinnedSignals = { "now", "blast", "delegationDepth", "recentCount", "allocChild", "r", "t" };

    static bool ContextMatches(L? ps, object? expectSource, bool bound)
    {
        if (ps == null) return false;
        var layout = bound ? PolicyVmBoundPublicSignal : PolicyVmPublicSignal;
        foreach (var k in ContextSignals)
        {
            // 2^64 has 20 digits: a longer canonical decimal is above it
            if (At(ps, layout[k]) is not string sig || !CanonDec(sig) || sig.Length > 20 || BigInteger.Parse(sig, CultureInfo.InvariantCulture) >= ContextBound) return false;
        }
        if (Jx.IsUndef(expectSource)) return true;
        object? e;
        try { e = expectSource is Func<object?> thunk ? thunk() : expectSource; }
        catch (Exception) { return false; }
        if (e is not (D or L)) return false;
        foreach (var k in PinnedSignals)
        {
            var pin = M(e, k);
            if (!Jx.IsUndef(pin) && !SignalMatchesPin(At(ps, layout[k]), pin)) return false;
        }
        if (Jx.Truthy(M(e, "requireAdmit")) && At(ps, layout["admit"]) is not "1") return false;
        if (Jx.Truthy(M(e, "requireTier1")) && At(ps, layout["t"]) is not "1") return false;
        return true;
    }

    /// <summary>With no pins: every context signal (now, blast, delegationDepth, recentCount, allocChild) is a canonical decimal below 2^64. The circuit compares
    /// public inputs it does not range-check, so a field-negative <c>now</c> would otherwise pass its expiry test. <paramref name="bound"/> reads the v2 layout.</summary>
    public static bool PolicyVmContextMatches(L publicSignals, bool bound = false) => ContextMatches(publicSignals, JsX.Undef, bound);

    /// <summary>The range rule of the other overload, and the public signals satisfy <paramref name="expect"/>: the context the verifier requires the proof to
    /// have been made for, {now?, blast?, delegationDepth?, recentCount?, allocChild?, r?, t?, requireAdmit?, requireTier1?}, or a function returning it (so
    /// <c>now</c> can follow a clock; one that throws denies). A pin is an exact value (decimal text, a number, an integer type) or an inclusive {min, max}
    /// window. Anything else given as the expectation denies; a pin that is null throws.</summary>
    public static bool PolicyVmContextMatches(L publicSignals, object? expect, bool bound = false) => ContextMatches(publicSignals, expect, bound);

    // ---- verification ----

    static object? Expect(D opts) => opts.TryGetValue("expect", out var e) ? e : JsX.Undef;

    /// <summary>
    /// Verifies a Policy VM Groth16 proof offline: the envelope {system: "groth16-bn254" | "groth16-bls12-381", circuit: "pca-policyvm-v1" | "pca-policyvm-v2",
    /// proof, publicSignals}. False (fail closed) on anything malformed. In order: shape, circuit and system tags (the risk-bound circuit is BN254 only), the
    /// signal count, allow = 1, the risk-hash pin, the canonical envelope, the context pins, then the pairing check under the verification key.
    /// <paramref name="opts"/> = {verificationKey?, verificationKeyPath?, expect?, expectRiskHash?, strict?}: the key defaults to the embedded key of the
    /// proof's curve (the risk-bound circuit has none: its build product is read, and a missing file throws); <c>expect</c> is the expectation of
    /// <see cref="PolicyVmContextMatches(L, object, bool)"/>; <c>expectRiskHash</c> {hi, lo} is only met by a v2 proof carrying those halves;
    /// <c>strict: true</c> also refuses a key whose protocol, nPublic or IC length disagree with the proof. Without a registered engine the answer is false.
    /// </summary>
    public static bool VerifyPolicyVmProof(object? env, D? opts = null)
    {
        opts ??= new D();
        if (env is not D p) return false;
        bool bound = p.GetValueOrDefault("circuit") is "pca-policyvm-v2";
        if (p.GetValueOrDefault("circuit") is not "pca-policyvm-v1" && !bound) return false;
        bool bls = p.GetValueOrDefault("system") is "groth16-bls12-381";
        if (p.GetValueOrDefault("system") is not "groth16-bn254" && !(bls && !bound)) return false; // the risk-bound circuit is BN254 only
        var layout = bound ? PolicyVmBoundPublicSignal : PolicyVmPublicSignal;
        if (p.GetValueOrDefault("publicSignals") is not L ps || ps.Count != (bound ? PolicyVmBoundPublicSignalCount : PolicyVmPublicSignalCount) || p.GetValueOrDefault("proof") is not { } proof) return false;
        if (ps[layout["allow"]] is not "1") return false;
        if (opts.TryGetValue("expectRiskHash", out var risk))
        {
            if (!bound) return false;
            if (!Ledger.Same(ps[PolicyVmBoundPublicSignal["riskHi"]], JsX.At(risk, "hi")) || !Ledger.Same(ps[PolicyVmBoundPublicSignal["riskLo"]], JsX.At(risk, "lo"))) return false;
        }
        if (!IsCanonicalGroth16Envelope(p, bls ? "bls12-381" : "bn254")) return false;
        if (!ContextMatches(ps, Expect(opts), bound)) return false;
        var vkey = opts.GetValueOrDefault("verificationKey")
            ?? LoadKey(opts.GetValueOrDefault("verificationKeyPath"), bound ? null : bls ? PolicyVmBls12381Key.Value : PolicyVmKey.Value, PolicyVmBoundVkeyPath);
        try { return Groth16Verify(vkey, ps, proof, opts.GetValueOrDefault("strict") is true); }
        catch (Exception) { return false; } // no engine, or a key or proof the engine cannot read: a refusal
    }

    // ---- SNARK backends ----

    sealed class Backend(Func<object?, ZkPublicInputs, bool> verify) : ISnarkBackend
    {
        public bool Verify(object? proof, ZkPublicInputs publicInputs, PcaCore.CoreContext? ctx) => verify(proof, publicInputs);
    }

    static ISnarkBackend Labelled(AssuranceLabel label, Func<object?, ZkPublicInputs, bool> verify) => AssuranceLabels.Set<ISnarkBackend>(new Backend(verify), label);

    /// <summary><c>multi-party</c> only for an explicit verification key backed by pinned ceremony evidence naming this circuit; the embedded keys are single-party.</summary>
    static string CeremonyLabel(D opts, string circuit) =>
        ZkCeremony.CeremonyOf(opts.GetValueOrDefault("verificationKey"), opts.GetValueOrDefault("ceremony") is D evidence ? new D(evidence) { ["circuit"] = circuit } : null);

    /// <summary>The two halves at the given signals equal the expected digest {hi, lo}, or no digest is expected.</summary>
    static bool HalvesMatch(L ps, int hi, int lo, object? want) =>
        !Jx.Truthy(want) || (Ledger.Same(At(ps, hi), JsX.At(want, "hi")) && Ledger.Same(At(ps, lo), JsX.At(want, "lo")));

    static void Carry(D from, D to, string member)
    {
        if (from.TryGetValue(member, out var v)) to[member] = v;
    }

    /// <summary>
    /// The Groth16 backend of the first circuit (<c>pca-compliance-v1</c>, BN254): a well-formed envelope, allow = 1, the circuit's binding tags equal to
    /// <see cref="CommitmentField"/> of the verifier's own policy, plan and action commitments (a proof for other commitments is refused), the canonical
    /// encoding, then the pairing check. <paramref name="opts"/> = {verificationKey?, verificationKeyPath?, ceremony?, strict?}; no key is embedded, so
    /// without one the circuit's build product is read. A commitment that is not base64url throws, as does a missing engine or key file.
    /// </summary>
    public static ISnarkBackend CreateGroth16SnarkBackend(D? opts = null)
    {
        var o = opts ?? new D();
        var key = LazyKey(o, null, DefaultVkeyPath);
        return Labelled(new AssuranceLabel("groth16", Ceremony: CeremonyLabel(o, "pca-compliance-v1")), (proof, publicInputs) =>
        {
            if (proof is not D env) return false;
            if (env.GetValueOrDefault("system") is not "groth16-bn254" || env.GetValueOrDefault("circuit") is not "pca-compliance-v1") return false;
            if (env.GetValueOrDefault("publicSignals") is not L ps || ps.Count != 7 || env.GetValueOrDefault("proof") is not { } g16) return false;
            if (ps[6] is not "1") return false;
            if (ps[3] as string != CommitmentField(publicInputs.PolicyCommit)) return false;
            if (ps[4] as string != CommitmentField(publicInputs.PlanCommit)) return false;
            if (ps[5] as string != CommitmentField(publicInputs.ActionCommit)) return false;
            if (!IsCanonicalGroth16Envelope(env, "bn254")) return false;
            return Groth16Verify(key(), ps, g16, o.GetValueOrDefault("strict") is true);
        });
    }

    static ISnarkBackend PolicyVmBackend(D? opts, Lazy<D> bundled, string defaultPath)
    {
        var o = opts ?? new D();
        var key = LazyKey(o, bundled.Value, defaultPath);
        var ceremony = CeremonyLabel(o, "pca-policyvm-v1");
        bool pinned = Jx.Truthy(M(o, "expectActionHash")) && Jx.Truthy(M(o, "expectPolicyHash")) && Jx.Truthy(M(o, "expectPlanHash"));
        // without all three pins a valid proof may be for another compliant action: the label says so
        var label = pinned ? new AssuranceLabel("policyvm_snark", Ceremony: ceremony) : new AssuranceLabel("unknown", "policyvm-unbound", Ceremony: ceremony);
        return Labelled(label, (proof, _) =>
        {
            if (proof is not D env || env.GetValueOrDefault("circuit") is not "pca-policyvm-v1") return false;
            if (env.GetValueOrDefault("publicSignals") is L ps
                && !(HalvesMatch(ps, 0, 1, M(o, "expectActionHash")) && HalvesMatch(ps, 2, 3, M(o, "expectPolicyHash")) && HalvesMatch(ps, 4, 5, M(o, "expectPlanHash")))) return false;
            var inner = new D { ["verificationKey"] = key() };
            Carry(o, inner, "expect");
            Carry(o, inner, "strict");
            return VerifyPolicyVmProof(env, inner);
        });
    }

    /// <summary>
    /// The backend of the full Policy VM circuit on BN254: the checks of <see cref="VerifyPolicyVmProof"/>, and the proof's public hash halves equal to the
    /// expected struct hashes when given. <paramref name="opts"/> = {verificationKey?, verificationKeyPath?, expect?, ceremony?, expectActionHash?,
    /// expectPolicyHash?, expectPlanHash?, strict?}; the key defaults to the embedded one. The label is <c>policyvm_snark</c> only with all three hashes
    /// pinned, else <c>unknown</c> (vendor <c>policyvm-unbound</c>). The commitments the hook passes are not used: the circuit commits to the quantized
    /// structs (see <see cref="PolicyVmCommitmentFromAction"/>).
    /// </summary>
    public static ISnarkBackend CreatePolicyVmSnarkBackend(D? opts = null) => PolicyVmBackend(opts, PolicyVmKey, PolicyVmVkeyPath);

    /// <summary><see cref="CreatePolicyVmSnarkBackend"/> on BLS12-381: the embedded key is the BLS12-381 one.</summary>
    public static ISnarkBackend CreatePolicyVmSnarkBackendBls12381(D? opts = null) => PolicyVmBackend(opts, PolicyVmBls12381Key, PolicyVmBls12381VkeyPath);

    /// <summary>
    /// The backend of the risk-bound circuit (<c>pca-policyvm-v2</c>, BN254): the checks of <see cref="CreatePolicyVmSnarkBackend"/> plus the risk commitment
    /// (<c>expectRiskHash</c>, see <see cref="PolicyVmRiskHash"/>). The label is <c>policyvm_snark</c> only with all four commitments pinned. No key is
    /// embedded: pass <c>verificationKey</c> or <c>verificationKeyPath</c>, else the circuit's build product is read (a missing file throws).
    /// </summary>
    public static ISnarkBackend CreatePolicyVmBoundSnarkBackend(D? opts = null)
    {
        var o = opts ?? new D();
        var key = LazyKey(o, null, PolicyVmBoundVkeyPath);
        var ceremony = CeremonyLabel(o, "pca-policyvm-v2");
        bool pinned = Jx.Truthy(M(o, "expectActionHash")) && Jx.Truthy(M(o, "expectPolicyHash")) && Jx.Truthy(M(o, "expectPlanHash")) && Jx.Truthy(M(o, "expectRiskHash"));
        var label = pinned ? new AssuranceLabel("policyvm_snark", Ceremony: ceremony) : new AssuranceLabel("unknown", "policyvm-unbound", Ceremony: ceremony);
        return Labelled(label, (proof, _) =>
        {
            if (proof is not D env || env.GetValueOrDefault("circuit") is not "pca-policyvm-v2" || env.GetValueOrDefault("publicSignals") is not L ps) return false;
            if (!HalvesMatch(ps, 0, 1, M(o, "expectActionHash")) || !HalvesMatch(ps, 2, 3, M(o, "expectPolicyHash")) || !HalvesMatch(ps, 4, 5, M(o, "expectPlanHash"))
                || !HalvesMatch(ps, 9, 10, M(o, "expectRiskHash"))) return false;
            var inner = new D { ["verificationKey"] = key() };
            Carry(o, inner, "expect");
            Carry(o, inner, "expectRiskHash");
            Carry(o, inner, "strict");
            return VerifyPolicyVmProof(env, inner);
        });
    }
}
