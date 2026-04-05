using System.ComponentModel.DataAnnotations;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Local-only device identity and configuration. Not synced.
/// </summary>
public sealed class DeviceSettings
{
    public Guid Id { get; set; }

    [MaxLength(64)]
    public required string ClientGuid { get; set; }

    [MaxLength(128)]
    public required string DeviceName { get; set; }

    /// <summary>WebAuthn credential ID hint for auto-fill.</summary>
    [MaxLength(256)]
    public string? CredentialId { get; set; }
}
