using System;
using System.IO;
using AtlasPca;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AtlasPca.AspNetCore.Tests;

// The reusable store-conformance helper over the SQL-backed stores: several connections to one SQLite database file.
public class StoreConformanceSqlTests : IDisposable
{
    readonly string _path = Path.Combine(Path.GetTempPath(), "pca-conf-" + Guid.NewGuid().ToString("N") + ".db");
    SqliteConnection Connect() => new("Data Source=" + _path + ";Pooling=False");

    public void Dispose() { try { File.Delete(_path); } catch (IOException) { /* best effort */ } }

    [Fact]
    public void SqlStateStorePasses()
    {
        new SqlStateStore(Connect).EnsureSchema();
        var r = StoreConformance.RunStateStore(new StateStoreConformance { Name = "sqlite", Open = () => new SqlStateStore(Connect), Shared = true, Durable = true, Rounds = 5, Copies = 8, Handles = 3 });
        Assert.True(r.Ok, r.ToString());
    }

    [Fact]
    public void SqlOperationStorePasses()
    {
        new SqlAtomicKv(Connect).EnsureSchema();
        var r = StoreConformance.RunOperationStore(new OperationStoreConformance { Name = "sqlite", Open = () => new KvOperationStore(new SqlAtomicKv(Connect)), Shared = true, Durable = true, Copies = 8 });
        Assert.True(r.Ok, r.ToString());
    }
}
