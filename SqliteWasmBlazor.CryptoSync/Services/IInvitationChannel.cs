namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Byte-opaque transport for a <see cref="ContactAcceptancePayload"/> moving
/// between two devices during the contact-invitation handshake. The channel
/// never inspects payload contents — callers MessagePack-serialize a payload
/// themselves before <see cref="SendAsync"/> and deserialize it after
/// <see cref="TryReceiveAsync"/>.
///
/// <para>
/// Implementations are free to choose the delivery medium (QR scan, file
/// drop, push gateway, BLE, …). The contract is one-way per call: the
/// contact's device sends, the admin's device receives. A complete
/// invitation flow uses two channels (one per direction) or one bidirectional
/// channel pair — whichever the implementation prefers.
/// </para>
/// </summary>
public interface IInvitationChannel
{
    /// <summary>
    /// Hand <paramref name="payloadBytes"/> to the transport. Returns once the
    /// transport has accepted the bytes for delivery — <b>not</b> once the
    /// other side has received them.
    /// </summary>
    /// <param name="payloadBytes">MessagePack-serialized
    /// <see cref="ContactAcceptancePayload"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    ValueTask SendAsync(byte[] payloadBytes, CancellationToken cancellationToken = default);

    /// <summary>
    /// Try to receive the next payload. Returns <c>null</c> when nothing has
    /// arrived yet — callers poll or await a higher-level signal. Returns the
    /// raw bytes on success; the caller MessagePack-deserializes into a
    /// <see cref="ContactAcceptancePayload"/>.
    /// </summary>
    ValueTask<byte[]?> TryReceiveAsync(CancellationToken cancellationToken = default);
}
