using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor;

/// <summary>
/// Base DbContext for any application using encrypted delta sync.
/// Provides the _deltaMetadata table for permission persistence and encrypted table configuration.
///
/// Consumer apps inherit this and add their domain-specific entities:
/// <code>
/// public class MyAppContext : EncryptedDeltaContextBase
/// {
///     public DbSet&lt;ShoppingItem&gt; ShoppingItems =&gt; Set&lt;ShoppingItem&gt;();
///
///     public MyAppContext(DbContextOptions&lt;MyAppContext&gt; options) : base(options) { }
/// }
/// </code>
///
/// The _deltaMetadata table is managed by the worker (raw SQL).
/// C# reads it via EF Core for UI-level permission enforcement.
/// </summary>
public abstract class EncryptedDeltaContextBase : DbContext
{
    protected EncryptedDeltaContextBase(DbContextOptions options) : base(options)
    {
    }

    /// <summary>
    /// Delta metadata key-value store. Worker manages this table;
    /// C# reads for UI enforcement and configuration.
    /// </summary>
    public DbSet<DeltaMetadata> DeltaMetadata => Set<DeltaMetadata>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<DeltaMetadata>(entity =>
        {
            entity.ToTable("_deltaMetadata");
            entity.HasKey(e => e.Key);
        });
    }
}
