using MessagePack;
using Microsoft.EntityFrameworkCore;
using SqliteWasmBlazor.Crypto.Testing;
using SqliteWasmBlazor.CryptoSync.Tests.Fixtures;
using Xunit;

namespace SqliteWasmBlazor.CryptoSync.Tests;

/// <summary>
/// Tests for <see cref="SyncEngine"/> — the wiring between
/// <see cref="SyncOrchestrator"/> and <see cref="ISyncTransport"/>. Crypto
/// round-trip is faked via <see cref="FakeDatabaseService"/>; these tests
/// verify recipient enumeration, cursor advance, empty-envelope skip, and
/// inbox drain. The actual encrypted pipeline is exercised in browser-side
/// CryptoSyncRoundTripTest.
/// </summary>
public class SyncEngineTests : IAsyncLifetime
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
    public async Task PushChanges_NoChanges_DoesNotSendEnvelope()
    {
        var relay = new InMemorySyncRelay();
        var transport = new InMemorySyncTransport(relay, _scenario.Admin.Keys.X25519PublicKey);
        var fakeDb = new FakeDatabaseService
        {
            CannedExportBytes = MessagePackSerializer.Serialize(new DeltaEnvelope
            {
                SenderEd25519PublicKey = _scenario.Admin.Keys.Ed25519PublicKey,
                Groups = []
            })
        };
        var engine = new SyncEngine(
            _scenario.Admin.Context, fakeDb, transport,
            NullImportNotifier.Instance, "admin.db");

        var sent = await engine.PushChangesAsync(_scenario.Admin.Keys);

        Assert.False(sent);
    }

    [Fact]
    public async Task PushChanges_WithRows_AddressesAllOtherContacts()
    {
        var relay = new InMemorySyncRelay();
        var adminTransport = new InMemorySyncTransport(relay, _scenario.Admin.Keys.X25519PublicKey);
        var userTransport = new InMemorySyncTransport(relay, _scenario.User.Keys.X25519PublicKey);

        var nonEmpty = MessagePackSerializer.Serialize(new DeltaEnvelope
        {
            SenderEd25519PublicKey = _scenario.Admin.Keys.Ed25519PublicKey,
            Groups =
            [
                new ShadowRowGroup
                {
                    TableName = "TestItems",
                    IsSystemTable = false,
                    Rows = [new ShadowRow { Id = Guid.NewGuid() }]
                }
            ]
        });
        var fakeDb = new FakeDatabaseService { CannedExportBytes = nonEmpty };

        var engine = new SyncEngine(
            _scenario.Admin.Context, fakeDb, adminTransport,
            NullImportNotifier.Instance, "admin.db");

        var sent = await engine.PushChangesAsync(_scenario.Admin.Keys);

        Assert.True(sent);
        // The user has the envelope in their inbox; admin does not.
        var received = await userTransport.TryReceiveAsync();
        Assert.NotNull(received);
        Assert.Null(await adminTransport.TryReceiveAsync());
    }

    [Fact]
    public async Task PushChanges_AdvancesCursor()
    {
        var relay = new InMemorySyncRelay();
        var transport = new InMemorySyncTransport(relay, _scenario.Admin.Keys.X25519PublicKey);
        var nonEmpty = MessagePackSerializer.Serialize(new DeltaEnvelope
        {
            SenderEd25519PublicKey = _scenario.Admin.Keys.Ed25519PublicKey,
            Groups =
            [
                new ShadowRowGroup
                {
                    TableName = "TestItems",
                    IsSystemTable = false,
                    Rows = [new ShadowRow { Id = Guid.NewGuid() }]
                }
            ]
        });
        var fakeDb = new FakeDatabaseService { CannedExportBytes = nonEmpty };
        var engine = new SyncEngine(
            _scenario.Admin.Context, fakeDb, transport,
            NullImportNotifier.Instance, "admin.db");

        Assert.Equal(default, engine.LastExportedAt);
        var before = DateTime.UtcNow;
        await engine.PushChangesAsync(_scenario.Admin.Keys);
        var after = DateTime.UtcNow;

        Assert.InRange(engine.LastExportedAt, before.AddSeconds(-1), after.AddSeconds(1));
    }

    [Fact]
    public async Task PullChanges_DrainsAllEnvelopes_AndAccumulatesRows()
    {
        var relay = new InMemorySyncRelay();
        var adminTransport = new InMemorySyncTransport(relay, _scenario.Admin.Keys.X25519PublicKey);
        var userTransport = new InMemorySyncTransport(relay, _scenario.User.Keys.X25519PublicKey);

        // Admin posts two envelopes addressed to user.
        await adminTransport.SendAsync([0x01], [_scenario.User.Keys.X25519PublicKey]);
        await adminTransport.SendAsync([0x02], [_scenario.User.Keys.X25519PublicKey]);

        var fakeDb = new FakeDatabaseService
        {
            CannedImportReport = new ImportReport { RowsImported = 5 }
        };
        var notifier = new RecordingImportNotifier();
        var engine = new SyncEngine(
            _scenario.User.Context, fakeDb, userTransport,
            notifier, "user.db");

        var totalApplied = await engine.PullChangesAsync(_scenario.User.Keys);

        Assert.Equal(10, totalApplied); // 5 + 5
        Assert.Equal(2, notifier.Reports.Count);
        Assert.Null(await userTransport.TryReceiveAsync());
    }

    [Fact]
    public async Task PullChanges_EmptyInbox_ReturnsZero()
    {
        var relay = new InMemorySyncRelay();
        var transport = new InMemorySyncTransport(relay, _scenario.User.Keys.X25519PublicKey);
        var fakeDb = new FakeDatabaseService();
        var engine = new SyncEngine(
            _scenario.User.Context, fakeDb, transport,
            NullImportNotifier.Instance, "user.db");

        var applied = await engine.PullChangesAsync(_scenario.User.Keys);

        Assert.Equal(0, applied);
    }

    [Fact]
    public async Task SyncOnce_PushesThenPulls()
    {
        var relay = new InMemorySyncRelay();
        var adminTransport = new InMemorySyncTransport(relay, _scenario.Admin.Keys.X25519PublicKey);
        var userTransport = new InMemorySyncTransport(relay, _scenario.User.Keys.X25519PublicKey);

        // Pre-seed an envelope addressed to admin so the pull side has work.
        await userTransport.SendAsync([0xFF], [_scenario.Admin.Keys.X25519PublicKey]);

        var nonEmpty = MessagePackSerializer.Serialize(new DeltaEnvelope
        {
            SenderEd25519PublicKey = _scenario.Admin.Keys.Ed25519PublicKey,
            Groups =
            [
                new ShadowRowGroup
                {
                    TableName = "TestItems",
                    IsSystemTable = false,
                    Rows = [new ShadowRow { Id = Guid.NewGuid() }]
                }
            ]
        });
        var fakeDb = new FakeDatabaseService
        {
            CannedExportBytes = nonEmpty,
            CannedImportReport = new ImportReport { RowsImported = 7 }
        };
        var engine = new SyncEngine(
            _scenario.Admin.Context, fakeDb, adminTransport,
            NullImportNotifier.Instance, "admin.db");

        var applied = await engine.SyncOnceAsync(_scenario.Admin.Keys);

        Assert.Equal(7, applied);
        // Admin's push went to user.
        Assert.NotNull(await userTransport.TryReceiveAsync());
        // Admin's pull drained the pre-seeded envelope.
        Assert.Null(await adminTransport.TryReceiveAsync());
    }

    [Fact]
    public async Task PushChanges_OneActor_NoOtherContacts_SkipsSendButAdvancesCursor()
    {
        // Stand up a fresh admin-only actor — no other contacts.
        var crypto = new BouncyCastleCryptoProvider();
        var solo = await TestActor.CreateAsync("Solo", isAdmin: true, seedByte: 1, crypto);
        try
        {
            var relay = new InMemorySyncRelay();
            var transport = new InMemorySyncTransport(relay, solo.Keys.X25519PublicKey);
            var nonEmpty = MessagePackSerializer.Serialize(new DeltaEnvelope
            {
                SenderEd25519PublicKey = solo.Keys.Ed25519PublicKey,
                Groups =
                [
                    new ShadowRowGroup
                    {
                        TableName = "TestItems",
                        IsSystemTable = false,
                        Rows = [new ShadowRow { Id = Guid.NewGuid() }]
                    }
                ]
            });
            var fakeDb = new FakeDatabaseService { CannedExportBytes = nonEmpty };
            var engine = new SyncEngine(
                solo.Context, fakeDb, transport,
                NullImportNotifier.Instance, "solo.db");

            // Bootstrap solo's DeviceSettings so BuildHeaderAsync can resolve OwnContactId.
            var seed = await solo.Bootstrap.CreateAdminSeedAsync(solo.Keys);
            await solo.Context.Database.ExecuteSqlRawAsync("DELETE FROM DeviceSettings");
            solo.Context.DeviceSettings.Add(seed.Device);
            await solo.Context.SaveChangesAsync();

            var sent = await engine.PushChangesAsync(solo.Keys);

            Assert.False(sent); // No recipients
            Assert.NotEqual(default, engine.LastExportedAt); // Cursor advances
        }
        finally
        {
            await solo.DisposeAsync();
        }
    }
}
