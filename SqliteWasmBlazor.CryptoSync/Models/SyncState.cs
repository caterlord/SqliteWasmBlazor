namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Local-only sync tracking metadata. Not synced.
///
/// <para>
/// Currently a single deterministic row keyed by <see cref="EngineCursorId"/>
/// holding <see cref="SyncEngine"/>'s export cursor — the high-water mark
/// timestamp through which local changes have been shipped. The row's
/// presence + value lets a SyncEngine survive process restarts without
/// re-shipping rows already exported.
/// </para>
/// </summary>
public sealed class SyncState
{
    /// <summary>
    /// Deterministic id used by <see cref="SyncEngine"/> for its single
    /// per-DB export-cursor row. Value chosen via
    /// <c>CryptoSyncContextBase.DeterministicGuid("SyncEngine.ExportCursor:v1")</c>.
    /// </summary>
    public static readonly Guid EngineCursorId =
        CryptoSyncContextBase.DeterministicGuid("SyncEngine.ExportCursor:v1");

    public Guid Id { get; set; }

    /// <summary>
    /// High-water mark timestamp through which the engine has exported.
    /// On first push the engine seeds a fresh row with this value;
    /// subsequent pushes update it.
    /// </summary>
    public DateTime LastExportedAt { get; set; }

    /// <summary>Reserved for future delta-hash tracking. Currently unused.</summary>
    public string? LastDeltaHash { get; set; }
}
