namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Trust level for a contact (PGP-style).
/// </summary>
public enum TrustLevel
{
    None = 0,
    Marginal = 1,
    Full = 2
}

/// <summary>
/// Direction of trust establishment.
/// </summary>
public enum TrustDirection
{
    Sent = 0,
    Received = 1
}

/// <summary>
/// Status of a sent invitation.
/// </summary>
public enum InviteStatus
{
    Pending = 0,
    Accepted = 1,
    Expired = 2,
    Revoked = 3
}

/// <summary>
/// Roles for sync participants.
/// </summary>
public enum SyncRole
{
    Admin = 0,
    User = 1,
    Guest = 2
}
