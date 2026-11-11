namespace AtlasPca;

// Access to the Merkle path shape of Pca for the extension-layer verifiers (mesh).
public static partial class Pca
{
    internal static List<char> PathShapeOf(long index, long size) => PathShape(index, size);
}
