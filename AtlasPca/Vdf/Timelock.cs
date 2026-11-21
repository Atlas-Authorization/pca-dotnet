// PCA timelock on the Wesolowski VDF (mirrors @atlasauth/pca-vdf timelock): the delay is bound to one action and to a post-action beacon, so a
// proof cannot be reused for another action or precomputed before the beacon existed. Verification re-derives the VDF input itself and fails closed.
using System.Numerics;
using System.Text;
using D = System.Collections.Generic.Dictionary<string, object?>;

namespace AtlasPca.Vdf;

/// <summary>A derived timelock requirement: the VDF input, the step count and the modulus.</summary>
public sealed record TimelockRequirement(string Kind, BigInteger X, long Steps, BigInteger N, string ActionDigest);

/// <summary>A timelock proof: the canonical output, the Wesolowski proof and the step count it attests to.</summary>
public sealed record TimelockProof(string Kind, BigInteger Y, BigInteger Pi, long Steps);

/// <summary>Options shared by the timelock entry points. AllowInsecureDevModulus is DEV/TEST ONLY: a timelock on a modulus whose factors are known delays nobody who holds them.</summary>
public sealed class TimelockOptions
{
    public double Steps { get; init; }
    public BigInteger N { get; init; }
    /// <summary>The beacon the delay starts from: a non-empty string or byte[].</summary>
    public object? Beacon { get; init; }
    public bool? AllowInsecureDevModulus { get; init; }
}

public static class Timelock
{
    const string XDerivationDomain = "atlas-pca/vdf/timelock/input/v2\0";
    public const string RequirementKind = "vdf-timelock";
    public const string ProofKind = "vdf-timelock-proof";

    /// <summary>The result of <see cref="CalibrateSteps"/>: the step count and the squaring rates it rests on.</summary>
    public sealed record Calibration(long Steps, double MeasuredSquaringsPerSecond, double AssumedAdversarySquaringsPerSecond);

    /// <summary>Turn a desired cooling-off duration into a step count. A VDF measures sequential WORK, not seconds: this times <paramref name="sampleSquarings"/> squarings
    /// modulo <paramref name="n"/> on this machine, assumes the fastest adversary is <paramref name="adversaryAdvantage"/> times faster, and returns
    /// <c>steps = ceil(adversaryRate * desiredSeconds)</c> (at least 1), so the real delay can only be LONGER. Treat the wall-clock as a floor, never an exact timer.
    /// <paramref name="nowMs"/> is the clock in milliseconds (default: a monotonic stopwatch); for tests.</summary>
    public static Calibration CalibrateSteps(BigInteger n, double desiredSeconds, long sampleSquarings = 50_000, double adversaryAdvantage = 10, Func<double>? nowMs = null)
    {
        if (n <= 3) throw new ArgumentOutOfRangeException(nameof(n), "calibrateSteps: modulus N must be > 3");
        if (!double.IsFinite(desiredSeconds) || desiredSeconds <= 0) throw new ArgumentOutOfRangeException(nameof(desiredSeconds), "calibrateSteps: desiredSeconds must be > 0");
        if (sampleSquarings < 1) throw new ArgumentOutOfRangeException(nameof(sampleSquarings), "calibrateSteps: sampleSquarings must be an integer >= 1");
        if (!double.IsFinite(adversaryAdvantage) || adversaryAdvantage < 1) throw new ArgumentOutOfRangeException(nameof(adversaryAdvantage), "calibrateSteps: adversaryAdvantage must be >= 1");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Func<double> clock = nowMs ?? (() => sw.Elapsed.TotalMilliseconds);
        var y = new BigInteger(2) % n;
        var t0 = clock();
        for (long i = 0; i < sampleSquarings; i++) y = y * y % n;
        var elapsedMs = Math.Max(clock() - t0, 2.220446049250313e-16);
        if (y == BigInteger.MinusOne) throw new InvalidOperationException("unreachable"); // keeps the optimiser from eliminating the loop
        var measured = sampleSquarings / elapsedMs * 1000;
        var assumed = measured * adversaryAdvantage;
        return new Calibration(Math.Max(1, (long)Math.Ceiling(assumed * desiredSeconds)), measured, assumed);
    }

    static byte[] Lp(byte[] b)
    {
        var o = new byte[4 + b.Length];
        o[0] = (byte)(b.Length >> 24); o[1] = (byte)(b.Length >> 16); o[2] = (byte)(b.Length >> 8); o[3] = (byte)b.Length;
        Array.Copy(b, 0, o, 4, b.Length);
        return o;
    }

    static byte[] BeaconBytes(object? beacon)
    {
        var b = beacon is string s ? Encoding.UTF8.GetBytes(s) : beacon as byte[];
        if (b == null || b.Length == 0) throw new ArgumentOutOfRangeException(nameof(beacon), "timelock: a non-empty beacon (unpredictable, post-action value) is required");
        return b;
    }

    /// <summary>The digest a timelock binds to: a string is an opaque precomputed digest; a PCActn (JSON tree) is hashCanonical(pcactn).</summary>
    public static string ActionDigest(object? action) => action is string s ? s : Pca.HashCanonical(action);

    /// <summary>x = sha256(domain || lp(utf8(digest)) || lp(beacon)) mod N, nudged into [2, N).</summary>
    public static BigInteger DeriveTimelockInput(object? action, BigInteger N, object? beacon)
    {
        if (N <= 3) throw new ArgumentOutOfRangeException(nameof(N), "deriveTimelockInput: modulus N must be a bigint > 3");
        var digest = Encoding.UTF8.GetBytes(ActionDigest(action));
        var msg = Pca.Cat(Encoding.UTF8.GetBytes(XDerivationDomain), Lp(digest), Lp(BeaconBytes(beacon)));
        var raw = Vdf.BytesToBigInt(Pca.Sha(msg)) % N;
        return raw <= 1 ? raw + 2 : raw;
    }

    static void RequireProductionModulus(BigInteger N, bool? allowInsecureDevModulus)
    {
        if (allowInsecureDevModulus == true) return;
        var (ok, reason) = Vdf.CheckProductionModulus(N);
        if (!ok)
            throw new ArgumentOutOfRangeException(nameof(N), $"timelock: refusing this modulus: {reason}. Use RSA_2048_CHALLENGE_MODULUS or a ceremony modulus; tests may pass allowInsecureDevModulus: true.");
    }

    static long RequireSteps(double steps)
    {
        if (!(double.IsFinite(steps) && steps == Math.Round(steps) && Math.Abs(steps) <= 9007199254740991.0 && steps >= 1))
            throw new ArgumentOutOfRangeException(nameof(steps), $"timelock: steps must be a safe integer >= 1, got {steps}");
        return (long)steps;
    }

    /// <summary>Derive the requirement for an action: the VDF input bound to the action and beacon, plus steps and N.</summary>
    public static TimelockRequirement RequireTimelock(object? action, TimelockOptions opts)
    {
        var steps = RequireSteps(opts.Steps);
        RequireProductionModulus(opts.N, opts.AllowInsecureDevModulus);
        var x = DeriveTimelockInput(action, opts.N, opts.Beacon);
        return new TimelockRequirement(RequirementKind, x, steps, opts.N, ActionDigest(action));
    }

    /// <summary>Run the VDF for an action: the sequential squarings ARE the cooling-off, so this call is deliberately slow.</summary>
    public static TimelockProof ProveTimelockElapsed(object? action, double steps, BigInteger N, object? beacon, bool? allowInsecureDevModulus = null)
    {
        var s = RequireSteps(steps);
        RequireProductionModulus(N, allowInsecureDevModulus);
        var x = DeriveTimelockInput(action, N, beacon);
        var p = Vdf.VdfEvalCanonical(x, s, N);
        return new TimelockProof(ProofKind, p.Y, p.Pi, s);
    }

    public static bool VerifyTimelock(object? action, TimelockProof proof, TimelockOptions opts) =>
        VerifyTimelock(action, new D { ["kind"] = proof.Kind, ["y"] = proof.Y, ["pi"] = proof.Pi, ["steps"] = proof.Steps }, opts);

    /// <summary>Gate release on a valid proof for the RIGHT input and step count. Fail closed: re-derives x from the action, requires proof.steps to equal the
    /// required steps, then runs the O(log) canonical verify. The proof is a loose record: kind (string), steps (number), y and pi (BigInteger). Never throws.</summary>
    public static bool VerifyTimelock(object? action, object? proof, TimelockOptions opts)
    {
        try
        {
            var required = RequireSteps(opts.Steps);
            RequireProductionModulus(opts.N, opts.AllowInsecureDevModulus);
            if (proof is not D p) return false;
            if (!(p.GetValueOrDefault("kind") is string k && k == ProofKind)) return false;
            var st = p.GetValueOrDefault("steps");
            if (!IntentJs.IsSafeInteger(st) || IntentJs.NumOf(st) != required) return false;
            if (p.GetValueOrDefault("y") is not BigInteger y || p.GetValueOrDefault("pi") is not BigInteger pi) return false;
            var x = DeriveTimelockInput(action, opts.N, opts.Beacon);
            return Vdf.VdfVerifyCanonical(x, y, pi, required, opts.N);
        }
        catch { return false; }
    }
}
