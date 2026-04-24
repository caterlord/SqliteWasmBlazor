using MessagePack;
using System.Security.Cryptography;

namespace SqliteWasmBlazor;

/// <summary>
/// Envelope carrying a user-supplied password from C# to the worker for
/// password-based VFS encryption. The worker reads-or-creates the per-DB
/// salt block in SAHPool's header region, derives a 32-byte ChaCha20-Poly1305
/// key via Argon2id (<see cref="@blazorprf/crypto-core"/>), and opens the DB
/// via the encrypted VFS path.
///
/// <para>
/// Mirrors the shape of <see cref="VfsKeyHeader"/> — versioned MessagePack
/// with a <see cref="Clear"/> symmetric zeroization helper. Password bytes
/// never land on disk; they live only in the worker for the duration of the
/// derivation call, then are zeroed before the derived key is persisted to
/// the registry.
/// </para>
/// </summary>
[MessagePackObject]
public sealed class VfsPasswordHeader
{
    /// <summary>Wire format version. Bumped on schema changes.</summary>
    [Key(0)]
    public int Version { get; set; } = 1;

    /// <summary>
    /// UTF-8 encoded password bytes. Sensitive — zeroize via <see cref="Clear"/>.
    /// </summary>
    [Key(1)]
    public byte[] Password { get; set; } = [];

    /// <summary>
    /// AAD prefix version expected by the worker. Same semantics as
    /// <see cref="VfsKeyHeader.AadVersion"/>.
    /// </summary>
    [Key(2)]
    public string AadVersion { get; set; } = "v1";

    /// <summary>
    /// Zero the password buffer. Call in a <c>finally</c> block after the
    /// worker call returns.
    /// </summary>
    public void Clear()
    {
        if (Password.Length > 0)
        {
            CryptographicOperations.ZeroMemory(Password);
        }
    }
}
