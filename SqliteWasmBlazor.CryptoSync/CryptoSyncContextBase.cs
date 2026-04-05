using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Base DbContext for any CryptoSync-enabled application.
/// Provides system tables for contacts, invitations, permissions, and sync tracking.
/// Domain apps inherit this and add their own DbSets.
///
/// <code>
/// public class ShoppingListContext : CryptoSyncContextBase
/// {
///     public DbSet&lt;ShoppingList&gt; ShoppingLists =&gt; Set&lt;ShoppingList&gt;();
///     public DbSet&lt;ShoppingItem&gt; ShoppingItems =&gt; Set&lt;ShoppingItem&gt;();
///     public ShoppingListContext(DbContextOptions options) : base(options) { }
/// }
/// </code>
/// </summary>
public abstract class CryptoSyncContextBase : DbContext
{
    protected CryptoSyncContextBase(DbContextOptions options) : base(options)
    {
    }

    // Contacts & trust (synced system table)
    public DbSet<TrustedContact> Contacts => Set<TrustedContact>();
    public DbSet<SentInvitation> SentInvitations => Set<SentInvitation>();
    public DbSet<ReceivedInvitation> ReceivedInvitations => Set<ReceivedInvitation>();

    // Permissions (synced system table, admin-only write)
    public DbSet<SyncPermission> Permissions => Set<SyncPermission>();

    // Local-only
    public DbSet<SyncState> SyncStates => Set<SyncState>();
    public DbSet<DeviceSettings> DeviceSettings => Set<DeviceSettings>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Contacts
        modelBuilder.Entity<TrustedContact>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Ed25519PublicKey).IsUnique();
            entity.HasIndex(e => e.X25519PublicKey).IsUnique();
        });

        // Sent invitations
        modelBuilder.Entity<SentInvitation>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.InviteCode).IsUnique();
            entity.HasOne(e => e.TrustedContact)
                .WithMany()
                .HasForeignKey(e => e.TrustedContactId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        // Received invitations
        modelBuilder.Entity<ReceivedInvitation>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.InviteCode);
            entity.HasOne(e => e.TrustedContact)
                .WithMany()
                .HasForeignKey(e => e.TrustedContactId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        // Permissions
        modelBuilder.Entity<SyncPermission>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => new { e.Role, e.TableName }).IsUnique();
            entity.HasIndex(e => e.IsDeleted);
            entity.HasIndex(e => e.UpdatedAt);
            entity.HasQueryFilter(e => !e.IsDeleted);
        });

        // Sync state (local only)
        modelBuilder.Entity<SyncState>(entity =>
        {
            entity.HasKey(e => e.Id);
        });

        // Device settings (local only, singleton)
        modelBuilder.Entity<DeviceSettings>(entity =>
        {
            entity.HasKey(e => e.Id);
        });
    }
}
