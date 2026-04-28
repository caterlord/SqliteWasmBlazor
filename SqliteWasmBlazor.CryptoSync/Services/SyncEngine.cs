using SqliteWasmBlazor.Crypto.Abstractions.Models;
using MessagePack;
using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Glue between <see cref="SyncOrchestrator"/> (export/import via the worker)
/// and <see cref="ISyncTransport"/> (recipient-addressed relay delivery).
/// One instance per <see cref="CryptoSyncContextBase"/> + relay pair. Holds
/// the per-DB cursor (last exported timestamp) so subsequent pushes ship only
/// rows the sender hasn't shipped before.
///
/// <para>
/// <b>Recipient enumeration policy (Phase A1):</b> push sends the envelope
/// addressed to every <see cref="TrustedContact.X25519PublicKey"/> in the
/// local DB except the sender's own. Crypto naturally filters at the
/// receiver: rows whose scope CEK the recipient lacks decrypt-fail and are
/// dropped. Per-scope envelope splitting (one envelope per CEK) is a
/// follow-up; today the model matches the existing snapshot tests.
/// </para>
///
/// <para>
/// <b>Identity seam:</b> caller passes <see cref="DualKeyPairFull"/> per call
/// for now. Phase B replaces this with a PRF-derived signing capability so
/// raw priv bytes don't live on the SyncEngine surface.
/// </para>
/// </summary>
public class SyncEngine(
    CryptoSyncContextBase context,
    ISqliteWasmDatabaseService databaseService,
    ISyncTransport transport,
    IImportNotifier importNotifier,
    string databaseName)
{
    private DateTime _lastExportedAt;

    /// <summary>
    /// The high-water mark this engine has exported up to. Persisted only
    /// in process memory for now — Phase A3 moves it to OPFS so reload
    /// doesn't reship envelopes.
    /// </summary>
    public DateTime LastExportedAt => _lastExportedAt;

    /// <summary>
    /// Push then pull. Returns the number of rows applied locally from
    /// the inbox drain.
    /// </summary>
    public async ValueTask<int> SyncOnceAsync(
        DualKeyPairFull ownKeys,
        CancellationToken cancellationToken = default)
    {
        await PushChangesAsync(ownKeys, cancellationToken).ConfigureAwait(false);
        return await PullChangesAsync(ownKeys, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Export local changes since <see cref="LastExportedAt"/>, address the
    /// envelope to every TrustedContact except self, and ship via the
    /// transport. No-op if there are no changes or no other contacts.
    /// </summary>
    public async ValueTask<bool> PushChangesAsync(
        DualKeyPairFull ownKeys,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ownKeys);

        var orchestrator = new SyncOrchestrator(databaseService, context, importNotifier);
        var since = _lastExportedAt == default ? (DateTime?)null : _lastExportedAt;
        var now = DateTime.UtcNow;

        var header = await BuildHeaderAsync(ownKeys, cancellationToken).ConfigureAwait(false);
        // ExportAsync calls header.Clear() in its finally, so we don't need to.
        var envelopeBytes = await orchestrator.ExportAsync(
            databaseName, header, since, cancellationToken).ConfigureAwait(false);

        if (envelopeBytes.Length == 0)
        {
            return false;
        }

        // Skip empty-body envelopes — nothing changed since the last cursor.
        var parsed = MessagePackSerializer.Deserialize<DeltaEnvelope>(envelopeBytes);
        var rowCount = 0;
        foreach (var group in parsed.Groups)
        {
            rowCount += group.Rows.Count;
        }
        if (rowCount == 0)
        {
            _lastExportedAt = now;
            return false;
        }

        var recipients = await EnumerateRecipientsAsync(
            ownKeys.X25519PublicKey, cancellationToken).ConfigureAwait(false);
        if (recipients.Count == 0)
        {
            // Nobody else listening yet — still advance the cursor so we
            // don't keep re-encoding the same rows on the next push.
            _lastExportedAt = now;
            return false;
        }

        await transport.SendAsync(envelopeBytes, recipients, cancellationToken).ConfigureAwait(false);
        _lastExportedAt = now;
        return true;
    }

    /// <summary>
    /// Drain the inbox and apply each envelope via
    /// <see cref="SyncOrchestrator.ImportAsync"/>. Envelopes from unknown
    /// senders surface as <see cref="SyncRejectedException"/> in the
    /// underlying import pipeline — currently propagated to the caller; a
    /// future variant could swallow + log per-envelope.
    /// </summary>
    /// <returns>Total rows applied across all drained envelopes.</returns>
    public async ValueTask<int> PullChangesAsync(
        DualKeyPairFull ownKeys,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ownKeys);

        var orchestrator = new SyncOrchestrator(databaseService, context, importNotifier);
        var totalApplied = 0;

        while (true)
        {
            var envelopeBytes = await transport.TryReceiveAsync(cancellationToken).ConfigureAwait(false);
            if (envelopeBytes is null)
            {
                break;
            }

            // ImportAsync calls header.Clear() in its finally; rebuild per call.
            var header = await BuildHeaderAsync(ownKeys, cancellationToken).ConfigureAwait(false);
            var report = await orchestrator.ImportAsync(
                databaseName, header, envelopeBytes, cancellationToken).ConfigureAwait(false);
            totalApplied += report.RowsImported;
        }

        return totalApplied;
    }

    /// <summary>
    /// Build the V2 header for an export or import call against the local
    /// system group. Materializes own contact id from
    /// <see cref="DeviceSettings.OwnContactId"/>, system group context +
    /// version + own wrapped CEK from the local <see cref="ShareGroup"/> /
    /// <see cref="ShareTarget"/> rows.
    /// </summary>
    private async Task<V2CryptoHeader> BuildHeaderAsync(
        DualKeyPairFull ownKeys, CancellationToken cancellationToken)
    {
        var ownContactId = await context.DeviceSettings
            .AsNoTracking()
            .Select(d => d.OwnContactId)
            .FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                "SyncEngine: DeviceSettings.OwnContactId is null. Bootstrap must set this before sync runs.");

        var systemGroup = await context.ShareGroups
            .AsNoTracking()
            .FirstOrDefaultAsync(g => g.GroupContext == CryptoSyncBootstrap.SystemGroupContext, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                "SyncEngine: system ShareGroup not found in local DB.");

        var ownTarget = await context.ShareTargets
            .AsNoTracking()
            .FirstOrDefaultAsync(t =>
                t.ShareGroupId == systemGroup.Id
                && t.MemberPublicKey == ownKeys.X25519PublicKey
                && t.KeyVersion == systemGroup.KeyVersion, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                "SyncEngine: this device's own system ShareTarget not found. " +
                "Either bootstrap is incomplete or ownKeys does not match the local actor.");

        return new V2CryptoHeader
        {
            Version = 2,
            SystemTables = ["Contacts", "ShareGroups", "ShareTargets", "Invitations"],
            ClientContactId = ownContactId,
            ClientX25519PrivateKey = Convert.FromBase64String(ownKeys.X25519PrivateKey),
            AdminX25519PublicKey = Convert.FromBase64String(systemGroup.GroupAdminPublicKey),
            GroupContext = systemGroup.GroupContext,
            KeyVersion = systemGroup.KeyVersion,
            WrappedCek = ownTarget.WrappedContentKey,
            ClientEd25519PrivateKey = Convert.FromBase64String(ownKeys.Ed25519PrivateKey),
            ClientEd25519PublicKey = Convert.FromBase64String(ownKeys.Ed25519PublicKey)
        };
    }

    /// <summary>
    /// Enumerate the addressee list for a push: every TrustedContact's
    /// X25519 pubkey except the sender's own.
    /// </summary>
    private async Task<List<string>> EnumerateRecipientsAsync(
        string ownX25519PublicKey, CancellationToken cancellationToken)
    {
        return await context.Contacts
            .AsNoTracking()
            .Where(c => c.X25519PublicKey != ownX25519PublicKey)
            .Select(c => c.X25519PublicKey)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
    }
}
