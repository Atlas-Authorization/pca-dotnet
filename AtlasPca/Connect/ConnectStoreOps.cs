// The reference pca-connect store helper: a defensive copy of a stored connection.
namespace AtlasPca.Connect;

public static class ConnectStore
{
    /// <summary>A defensive copy of a stored connection (the scopes and the authority are copied, never shared).</summary>
    public static StoredConnection CloneConnection(StoredConnection c) => c.Copy();
}
