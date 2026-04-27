using System.Collections.Concurrent;

namespace SqliteWasmBlazor.CryptoSync.Tests.Fixtures;

/// <summary>
/// Process-local backplane for <see cref="InMemorySyncTransport"/>. Each
/// recipient pubkey gets its own FIFO inbox; sends fan out by cloning the
/// envelope per recipient so a per-recipient mutation can't contaminate
/// another's copy.
///
/// <para>
/// The optional <see cref="Tamper"/> hook mutates the envelope as it flows
/// through — used by forgery / negative tests to flip a ciphertext bit,
/// strip a signature, etc. Mutation runs once per send, before the per-recipient
/// clone fan-out, so all recipients see the same tampered bytes (mirrors a
/// real relay where the malicious actor sits between sender and relay).
/// </para>
/// </summary>
internal sealed class InMemorySyncRelay
{
    private readonly ConcurrentDictionary<string, ConcurrentQueue<byte[]>> _inboxes
        = new(StringComparer.Ordinal);

    public Func<byte[], byte[]>? Tamper { get; set; }

    public void Enqueue(byte[] envelope, IReadOnlyList<string> recipientPublicKeys)
    {
        var delivered = Tamper is null ? envelope : Tamper(envelope);
        foreach (var pubKey in recipientPublicKeys)
        {
            var queue = _inboxes.GetOrAdd(pubKey, _ => new ConcurrentQueue<byte[]>());
            queue.Enqueue((byte[])delivered.Clone());
        }
    }

    public byte[]? TryDequeue(string ownPublicKey)
    {
        if (_inboxes.TryGetValue(ownPublicKey, out var queue) && queue.TryDequeue(out var bytes))
        {
            return bytes;
        }
        return null;
    }

    public int PendingCount(string ownPublicKey)
        => _inboxes.TryGetValue(ownPublicKey, out var queue) ? queue.Count : 0;
}
