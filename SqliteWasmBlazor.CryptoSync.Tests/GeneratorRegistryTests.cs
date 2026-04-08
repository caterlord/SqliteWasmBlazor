using Xunit;

namespace SqliteWasmBlazor.CryptoSync.Tests;

/// <summary>
/// Validates the source generator's output against the test project's
/// <see cref="TestSyncContext"/> (defined in <c>ContextTests.cs</c>). The generator
/// is wired in this project's csproj as an Analyzer reference, so on build it
/// emits <c>CryptoTableRegistry</c>, <c>SystemTableRegistry</c>,
/// <c>SensitiveEntityRegistry</c>, plus <c>Crypto_&lt;Entity&gt;</c> shadow classes
/// — the same outputs every consumer of CryptoSync gets.
///
/// The minimum context to test is <see cref="TestSyncContext"/>: one domain
/// entity (<see cref="TestItem"/>) inheriting <see cref="SyncableEntity"/>, plus the
/// base-context system tables (<see cref="TrustedContact"/>, <see cref="SyncPermission"/>)
/// which inherit SyncableEntity AND carry <c>[SystemTable]</c>. After commit 1
/// (system-table shadow generation) the registries should contain all three.
/// </summary>
public class GeneratorRegistryTests
{
    [Fact]
    public void CryptoTableRegistry_IncludesDomainEntity()
    {
        Assert.Contains(CryptoTableRegistry.Tables,
            t => t.EntityName == "TestItem"
                 && t.CryptoTableName == "_crypto_TestItems"
                 && t.OpenTableName == "TestItems");
    }

    [Fact]
    public void CryptoTableRegistry_IncludesSystemTrustedContact()
    {
        // Pre-commit-1: this assertion FAILED because the generator skipped
        // [SystemTable] entities entirely. Post-commit-1: the system shadow
        // is generated and registered.
        Assert.Contains(CryptoTableRegistry.Tables,
            t => t.EntityName == "TrustedContact"
                 && t.CryptoTableName == "_crypto_Contacts"
                 && t.OpenTableName == "Contacts");
    }

    [Fact]
    public void CryptoTableRegistry_IncludesSystemSyncPermission()
    {
        Assert.Contains(CryptoTableRegistry.Tables,
            t => t.EntityName == "SyncPermission"
                 && t.CryptoTableName == "_crypto_Permissions"
                 && t.OpenTableName == "Permissions");
    }

    [Fact]
    public void CryptoTableRegistry_DoesNotIncludeStandaloneNonSyncableEntities()
    {
        // SentInvitation, ReceivedInvitation, DeviceSettings, SyncState are all
        // standalone (non-SyncableEntity) classes — they are local-only by design
        // and must NOT get shadow tables.
        Assert.DoesNotContain(CryptoTableRegistry.Tables, t => t.EntityName == "SentInvitation");
        Assert.DoesNotContain(CryptoTableRegistry.Tables, t => t.EntityName == "ReceivedInvitation");
        Assert.DoesNotContain(CryptoTableRegistry.Tables, t => t.EntityName == "DeviceSettings");
        Assert.DoesNotContain(CryptoTableRegistry.Tables, t => t.EntityName == "SyncState");
    }

    [Fact]
    public void SystemTableRegistry_IncludesAllSystemEntities()
    {
        // Both system entities present (note: SharingKey is currently NOT a
        // SyncableEntity in the codebase, so it's deliberately excluded —
        // it'll join when the ShareGroup+ShareTarget refactor lands).
        Assert.Contains(SystemTableRegistry.Tables, t => t.EntityName == "TrustedContact" && t.TableName == "Contacts");
        Assert.Contains(SystemTableRegistry.Tables, t => t.EntityName == "SyncPermission" && t.TableName == "Permissions");
    }

    [Fact]
    public void SystemTableRegistry_IsSystem_True_ForKnownSystemTables()
    {
        Assert.True(SystemTableRegistry.IsSystem("Contacts"));
        Assert.True(SystemTableRegistry.IsSystem("Permissions"));
    }

    [Fact]
    public void SystemTableRegistry_IsSystem_False_ForDomainTable()
    {
        Assert.False(SystemTableRegistry.IsSystem("TestItems"));
    }

    [Fact]
    public void SystemTableRegistry_IsSystem_False_ForUnknownTable()
    {
        Assert.False(SystemTableRegistry.IsSystem("RandomTable"));
    }

    [Fact]
    public void SensitiveEntityRegistry_Empty_WhenNoSensitiveEntities()
    {
        // None of TestItem / TrustedContact / SyncPermission carry [Sensitive].
        Assert.Empty(SensitiveEntityRegistry.Tables);
    }

    [Fact]
    public void Crypto_TestItem_ShadowClass_IsGenerated()
    {
        // Smoke check that the generated shadow class is present and instantiable.
        // Failing this means the generator didn't emit the type — a sign the
        // analyzer reference isn't wired or the generator's entity walker is broken.
        var shadow = new Crypto_TestItem
        {
            Id = Guid.NewGuid(),
            SharingScope = 0,
            SharingId = "test",
            EncryptedRow = [1, 2, 3],
            Nonce = [4, 5, 6]
        };
        Assert.Equal("test", shadow.SharingId);
    }

    [Fact]
    public void Crypto_TrustedContact_ShadowClass_IsGenerated()
    {
        // The system-table shadow class is the new thing in commit 1.
        // Pre-commit-1: this type didn't exist. Post-commit-1: it's emitted.
        var shadow = new Crypto_TrustedContact
        {
            Id = Guid.NewGuid(),
            SharingScope = 0,
            SharingId = "system",
            EncryptedRow = [1, 2, 3],
            Nonce = [4, 5, 6]
        };
        Assert.Equal("system", shadow.SharingId);
    }

    [Fact]
    public void Crypto_SyncPermission_ShadowClass_IsGenerated()
    {
        var shadow = new Crypto_SyncPermission
        {
            Id = Guid.NewGuid(),
            SharingScope = 0,
            SharingId = "system",
            EncryptedRow = [1, 2, 3],
            Nonce = [4, 5, 6]
        };
        Assert.Equal("system", shadow.SharingId);
    }
}
