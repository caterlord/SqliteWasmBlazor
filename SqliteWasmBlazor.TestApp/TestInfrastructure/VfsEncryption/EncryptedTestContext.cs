using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor.TestApp.TestInfrastructure.VfsEncryption;

/// <summary>
/// Plain entity used exclusively by the PRF-VFS integration tests. Uses
/// recognizable literal strings in its columns so the on-disk-ciphertext
/// test can scan raw bytes and confirm the plaintext never surfaces.
/// </summary>
public class VfsTestItem
{
    public int Id { get; set; }
    public string Marker { get; set; } = string.Empty;
    public string Payload { get; set; } = string.Empty;
}

/// <summary>
/// Dedicated DbContext for the PRF-VFS test suite. Intentionally a plain
/// <see cref="DbContext"/> — not a <c>CryptoSyncContextBase</c> — so the
/// tests exercise the VFS in isolation from the full sync stack.
/// </summary>
public sealed class EncryptedTestContext : DbContext
{
    public EncryptedTestContext(DbContextOptions<EncryptedTestContext> options) : base(options) { }

    public DbSet<VfsTestItem> Items => Set<VfsTestItem>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.Entity<VfsTestItem>(e =>
        {
            e.HasKey(x => x.Id);
            e.ToTable("VfsTestItems");
        });
    }
}
