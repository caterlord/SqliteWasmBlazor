using System.Collections.Concurrent;

namespace SqliteWasmBlazor.CryptoSync.Tests.Fixtures;

/// <summary>
/// In-memory FIFO <see cref="IInvitationChannel"/> that buffers payloads in
/// process. <see cref="SendAsync"/> enqueues; <see cref="TryReceiveAsync"/>
/// dequeues. Used as the channel for both directions in roundtrip tests.
/// </summary>
internal sealed class FakeInvitationChannel : IInvitationChannel
{
    private readonly ConcurrentQueue<byte[]> _queue = new();

    public ValueTask SendAsync(byte[] payloadBytes, CancellationToken cancellationToken = default)
    {
        _queue.Enqueue(payloadBytes);
        return ValueTask.CompletedTask;
    }

    public ValueTask<byte[]?> TryReceiveAsync(CancellationToken cancellationToken = default)
        => _queue.TryDequeue(out var bytes)
            ? ValueTask.FromResult<byte[]?>(bytes)
            : ValueTask.FromResult<byte[]?>(null);
}
