using Xunit;

namespace AtlasPca.Corpus.Tests;

public class SnapshotTests
{
    const int Chunks = 16;

    static void Check(IEnumerable<(string, string)> computed)
    {
        var exp = Snapshot.Load();
        foreach (var (k, v) in computed)
            if (exp.TryGetValue(Snapshot.Esc(k), out var want)) Assert.True(want == v, $"{k}: want [{want}] got [{v}]");
    }

    [Fact] public void WriteSnapshot()
    {
        var p = Environment.GetEnvironmentVariable("PCA_SNAPSHOT_WRITE");
        if (string.IsNullOrEmpty(p)) return;
        Snapshot.Write(p);
    }

    [Fact] public void CoreSnapshot() => BigStack.Run(() => Check(Snapshot.ComputeVectors(Snapshot.Core(), "core", 0, 1)));

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)]
    [InlineData(8)] [InlineData(9)] [InlineData(10)] [InlineData(11)] [InlineData(12)] [InlineData(13)] [InlineData(14)] [InlineData(15)]
    public void AdvSnapshot(int k) => BigStack.Run(() => Check(Snapshot.ComputeVectors(Snapshot.Adv(), "adv", k, Chunks)));

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)] [InlineData(6)] [InlineData(7)]
    [InlineData(8)] [InlineData(9)] [InlineData(10)] [InlineData(11)] [InlineData(12)] [InlineData(13)] [InlineData(14)] [InlineData(15)]
    public void InputsSnapshot(int k) => BigStack.Run(() => Check(Snapshot.ComputeInputs(k, Chunks)));
}
