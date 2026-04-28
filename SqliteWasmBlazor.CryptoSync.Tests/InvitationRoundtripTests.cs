using SqliteWasmBlazor.Crypto.Testing;
using SqliteWasmBlazor.CryptoSync.Tests.Fixtures;
using Xunit;

namespace SqliteWasmBlazor.CryptoSync.Tests;

/// <summary>
/// End-to-end invitation flow coverage. Most tests here are stubbed out for
/// commit 1 of the invitation pivot — the real bodies are written in
/// commits 3 and 4 once <c>RespondToInvitationAsync</c> /
/// <c>PromoteInvitationAsync</c> are in place.
/// </summary>
public class InvitationRoundtripTests
{
    [Fact(Skip = "rewritten in stage-4 commit 3")]
    public Task Roundtrip_ContactRespondsAdminAccepts_ViaSyncTransport() => Task.CompletedTask;

    [Fact(Skip = "rewritten in stage-4 commit 3")]
    public Task Roundtrip_TamperedBundleSignature_Rejected() => Task.CompletedTask;

    [Fact(Skip = "rewritten in stage-4 commit 3")]
    public Task Roundtrip_ExpiredBundle_Rejected() => Task.CompletedTask;

    [Fact(Skip = "rewritten in stage-4 commit 3")]
    public Task Roundtrip_WireOpacity_NoPlaintextLeak() => Task.CompletedTask;

    [Fact(Skip = "rewritten in stage-4 commit 4")]
    public Task PrivacyInvariant_AdminCannotUnwrapContactSelfGroupCek() => Task.CompletedTask;

    [Fact]
    public async Task Roundtrip_ImportFiresNotifier()
    {
        var crypto = new BouncyCastleCryptoProvider();
        var actor = await TestActor.CreateAsync("Solo", isAdmin: true, seedByte: 230, crypto);
        try
        {
            var notifier = new RecordingImportNotifier();
            var fakeDatabase = new FakeDatabaseService
            {
                CannedImportReport = new ImportReport { RowsImported = 3 }
            };

            var orchestrator = new SyncOrchestrator(fakeDatabase, actor.Context, notifier);
            var header = new V2CryptoHeader
            {
                Version = 2,
                SystemTables = ["Contacts", "ShareGroups", "ShareTargets"],
                GroupContext = CryptoSyncBootstrap.SystemGroupContext,
                KeyVersion = 1
            };

            var report = await orchestrator.ImportAsync("test.db", header, envelopeBytes: [0x01]);

            Assert.Equal(3, report.RowsImported);
            Assert.Single(notifier.Reports);
            Assert.Equal(3, notifier.Reports.Single().RowsImported);
        }
        finally
        {
            await actor.DisposeAsync();
        }
    }
}
