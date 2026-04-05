namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Standard audit fields for syncable entities.
/// Every domain table in a CryptoSync app implements this.
/// </summary>
public interface ISyncableEntity
{
    Guid Id { get; set; }
    DateTime UpdatedAt { get; set; }
    bool IsDeleted { get; set; }
    DateTime? DeletedAt { get; set; }
}
