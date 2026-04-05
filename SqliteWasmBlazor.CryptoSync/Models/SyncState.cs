namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Local-only sync tracking metadata. Not synced.
/// </summary>
public sealed class SyncState
{
    public Guid Id { get; set; }
    public DateTime LastSyncAt { get; set; }
    public string? LastDeltaHash { get; set; }
}
