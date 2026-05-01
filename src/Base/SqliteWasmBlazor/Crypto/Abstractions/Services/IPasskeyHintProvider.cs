namespace SqliteWasmBlazor.Crypto.Abstractions.Services;

/// <summary>
/// Persists the most-recently-registered passkey credential id so the next
/// sign-in can target it via WebAuthn <c>allowCredentials</c> and skip the
/// account-picker UI. The hint is advisory: wrong / stale / cross-device
/// values must fall back to a discoverable ceremony.
/// </summary>
/// <remarks>
/// Hosts that want cross-device hint replication (transferable iCloud /
/// Google passkeys) can implement this against a synced storage backend
/// (e.g. a CryptoSync-replicated table). The default browser implementation
/// is keyed by <c>PrfOptions.Salt</c> in <c>localStorage</c>.
/// </remarks>
public interface IPasskeyHintProvider
{
    /// <summary>
    /// Return the cached credentialId hint, or <c>null</c> if no hint is
    /// stored or the backing storage is unavailable.
    /// </summary>
    ValueTask<string?> GetCredentialIdAsync(CancellationToken ct = default);

    /// <summary>
    /// Persist a credentialId as the next-sign-in hint. Overwrites any
    /// existing value.
    /// </summary>
    ValueTask SetCredentialIdAsync(string credentialId, CancellationToken ct = default);

    /// <summary>
    /// Drop the stored hint. Called on revocation or when a hint-targeted
    /// ceremony returns <c>UNKNOWN_CREDENTIAL</c>.
    /// </summary>
    ValueTask ClearAsync(CancellationToken ct = default);
}
