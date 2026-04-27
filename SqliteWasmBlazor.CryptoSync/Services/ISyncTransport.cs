namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Byte-opaque, recipient-addressed delivery for the sync layer. Carries
/// whatever the orchestrator (or a peer-bootstrap flow like contact
/// invitations) hands it — typically a MessagePack-serialized
/// <see cref="DeltaEnvelope"/>, but the contract is just bytes.
///
/// <para>
/// <b>Relay semantics.</b> Implementations target a "dumb delta deliverer":
/// the relay stores opaque envelopes indexed by recipient public key,
/// delivers per pubkey + since-cursor, and GCs old entries. The relay never
/// inspects payload contents — every confidentiality / integrity guarantee
/// comes from the layer above (V2 envelope crypto for deltas, Ed25519
/// signatures for invitations).
/// </para>
///
/// <para>
/// <b>Identity.</b> The receive side knows its own pubkey from session
/// state, so <see cref="TryReceiveAsync"/> takes no recipient parameter —
/// the implementation pulls from "this device's" inbox. The send side
/// addresses one or more recipients explicitly.
/// </para>
/// </summary>
public interface ISyncTransport
{
    /// <summary>
    /// Hand <paramref name="envelope"/> to the relay for delivery to every
    /// recipient in <paramref name="recipientPublicKeys"/>. Returns once the
    /// relay has accepted the bytes — <b>not</b> once recipients have
    /// downloaded them.
    /// </summary>
    ValueTask SendAsync(
        byte[] envelope,
        IReadOnlyList<string> recipientPublicKeys,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Try to pull the next pending envelope addressed to this device.
    /// Returns <c>null</c> when the inbox is empty — callers poll or await a
    /// higher-level signal (e.g. push notification) to learn when to retry.
    /// </summary>
    ValueTask<byte[]?> TryReceiveAsync(CancellationToken cancellationToken = default);
}
