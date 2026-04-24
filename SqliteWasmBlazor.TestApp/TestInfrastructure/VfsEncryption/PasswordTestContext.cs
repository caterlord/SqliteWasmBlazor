using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor.TestApp.TestInfrastructure.VfsEncryption;

/// <summary>
/// DbContext used by the password-form integration page. Distinct from
/// <see cref="EncryptedTestContext"/> so the two test flows can coexist
/// (one with a fixed key, one driven by the user's typed password).
/// </summary>
public class PasswordNote
{
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Body { get; set; } = string.Empty;
}

public sealed class PasswordTestContext : DbContext
{
    public PasswordTestContext(DbContextOptions<PasswordTestContext> options) : base(options) { }

    public DbSet<PasswordNote> Notes => Set<PasswordNote>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.Entity<PasswordNote>(e =>
        {
            e.HasKey(x => x.Id);
            e.ToTable("PasswordNotes");
        });
    }
}
