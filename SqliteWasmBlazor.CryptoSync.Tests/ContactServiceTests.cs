using Microsoft.EntityFrameworkCore;
using SqliteWasmBlazor.CryptoSync.Tests.Fixtures;
using Xunit;

namespace SqliteWasmBlazor.CryptoSync.Tests;

/// <summary>
/// Tests for the surviving <see cref="ContactService"/> read/admin helpers.
/// Contact creation + trust establishment moved to
/// <see cref="ContactInvitationService"/> — those tests live in
/// <c>ContactInvitationServiceTests</c>.
/// </summary>
public class ContactServiceTests : IAsyncLifetime
{
    private TwoActorBootstrap _scenario = null!;

    public async Task InitializeAsync()
    {
        _scenario = await TwoActorBootstrap.CreateAsync();
    }

    public async Task DisposeAsync()
    {
        await _scenario.DisposeAsync();
    }

    [Fact]
    public async Task GetByEd25519PublicKey_ReturnsMatchingContact()
    {
        var found = await _scenario.Admin.Contacts
            .GetByEd25519PublicKeyAsync(_scenario.User.Keys.Ed25519PublicKey);

        Assert.NotNull(found);
        Assert.Equal(_scenario.User.Keys.Ed25519PublicKey, found.Ed25519PublicKey);
    }

    [Fact]
    public async Task GetByEd25519PublicKey_ReturnsNull_ForUnknownKey()
    {
        var found = await _scenario.Admin.Contacts
            .GetByEd25519PublicKeyAsync("unknown-key");

        Assert.Null(found);
    }

    [Fact]
    public async Task GetAllAsync_ReturnsAdminAndUser()
    {
        var all = await _scenario.Admin.Contacts.GetAllAsync();
        Assert.Equal(2, all.Count);
    }

    [Fact]
    public async Task GetRecipientPublicKeys_ReturnsBothActorX25519Keys()
    {
        var keys = await _scenario.Admin.Contacts.GetRecipientPublicKeysAsync();

        Assert.Equal(2, keys.Length);
        Assert.Contains(_scenario.Admin.Keys.X25519PublicKey, keys);
        Assert.Contains(_scenario.User.Keys.X25519PublicKey, keys);
    }

    [Fact]
    public async Task Delete_SoftDeletesContact()
    {
        var userContact = await _scenario.Admin.Contacts
            .GetByEd25519PublicKeyAsync(_scenario.User.Keys.Ed25519PublicKey);
        Assert.NotNull(userContact);

        await _scenario.Admin.Contacts.DeleteAsync(userContact.Id);

        var all = await _scenario.Admin.Contacts.GetAllAsync();
        Assert.Single(all); // admin remains visible

        var raw = await _scenario.Admin.Context.Contacts
            .IgnoreQueryFilters()
            .SingleOrDefaultAsync(c => c.Id == userContact.Id);
        Assert.NotNull(raw);
        Assert.True(raw.IsDeleted);
        Assert.NotNull(raw.DeletedAt);
    }

    [Fact]
    public async Task Delete_NonExistentContact_NoOp()
    {
        await _scenario.Admin.Contacts.DeleteAsync(Guid.NewGuid());
    }
}
