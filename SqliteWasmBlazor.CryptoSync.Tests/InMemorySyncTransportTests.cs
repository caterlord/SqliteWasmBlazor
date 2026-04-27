using SqliteWasmBlazor.CryptoSync.Tests.Fixtures;
using Xunit;

namespace SqliteWasmBlazor.CryptoSync.Tests;

/// <summary>
/// Behaviour coverage for <see cref="InMemorySyncTransport"/> /
/// <see cref="InMemorySyncRelay"/>. The pair stand in for a real dumb
/// delta relay in xUnit scenarios — same byte-opaque, recipient-addressed
/// contract.
/// </summary>
public class InMemorySyncTransportTests
{
    private const string Alice = "alice-pub";
    private const string Bob = "bob-pub";
    private const string Carol = "carol-pub";

    [Fact]
    public async Task SendAsync_SingleRecipient_Delivers()
    {
        var relay = new InMemorySyncRelay();
        var aliceTx = new InMemorySyncTransport(relay, Alice);
        var bobTx = new InMemorySyncTransport(relay, Bob);

        await aliceTx.SendAsync([0xAA, 0xBB], [Bob]);

        var received = await bobTx.TryReceiveAsync();
        Assert.NotNull(received);
        Assert.Equal([0xAA, 0xBB], received!);
        Assert.Null(await aliceTx.TryReceiveAsync());
    }

    [Fact]
    public async Task SendAsync_MultipleRecipients_EveryoneGetsACopy()
    {
        var relay = new InMemorySyncRelay();
        var aliceTx = new InMemorySyncTransport(relay, Alice);
        var bobTx = new InMemorySyncTransport(relay, Bob);
        var carolTx = new InMemorySyncTransport(relay, Carol);

        await aliceTx.SendAsync([0x01], [Bob, Carol]);

        Assert.Equal([0x01], (await bobTx.TryReceiveAsync())!);
        Assert.Equal([0x01], (await carolTx.TryReceiveAsync())!);
    }

    [Fact]
    public async Task SendAsync_FifoPerRecipient()
    {
        var relay = new InMemorySyncRelay();
        var aliceTx = new InMemorySyncTransport(relay, Alice);
        var bobTx = new InMemorySyncTransport(relay, Bob);

        await aliceTx.SendAsync([0x01], [Bob]);
        await aliceTx.SendAsync([0x02], [Bob]);
        await aliceTx.SendAsync([0x03], [Bob]);

        Assert.Equal([0x01], (await bobTx.TryReceiveAsync())!);
        Assert.Equal([0x02], (await bobTx.TryReceiveAsync())!);
        Assert.Equal([0x03], (await bobTx.TryReceiveAsync())!);
        Assert.Null(await bobTx.TryReceiveAsync());
    }

    [Fact]
    public async Task SendAsync_UnrelatedRecipient_GetsNothing()
    {
        var relay = new InMemorySyncRelay();
        var aliceTx = new InMemorySyncTransport(relay, Alice);
        var carolTx = new InMemorySyncTransport(relay, Carol);

        await aliceTx.SendAsync([0xFF], [Bob]);

        Assert.Null(await carolTx.TryReceiveAsync());
        Assert.Equal(0, relay.PendingCount(Carol));
        Assert.Equal(1, relay.PendingCount(Bob));
    }

    [Fact]
    public async Task TamperHook_AppliesBeforeFanOut()
    {
        var relay = new InMemorySyncRelay
        {
            Tamper = bytes => [.. bytes.Select(b => (byte)(b ^ 0xFF))]
        };
        var aliceTx = new InMemorySyncTransport(relay, Alice);
        var bobTx = new InMemorySyncTransport(relay, Bob);
        var carolTx = new InMemorySyncTransport(relay, Carol);

        await aliceTx.SendAsync([0x00, 0x01, 0x02], [Bob, Carol]);

        Assert.Equal([0xFF, 0xFE, 0xFD], (await bobTx.TryReceiveAsync())!);
        Assert.Equal([0xFF, 0xFE, 0xFD], (await carolTx.TryReceiveAsync())!);
    }

    [Fact]
    public async Task SendAsync_ClonesPerRecipient_NoCrossContamination()
    {
        var relay = new InMemorySyncRelay();
        var aliceTx = new InMemorySyncTransport(relay, Alice);
        var bobTx = new InMemorySyncTransport(relay, Bob);
        var carolTx = new InMemorySyncTransport(relay, Carol);

        await aliceTx.SendAsync([0x10, 0x20, 0x30], [Bob, Carol]);

        var bobBytes = (await bobTx.TryReceiveAsync())!;
        bobBytes[0] = 0xFF;

        var carolBytes = (await carolTx.TryReceiveAsync())!;
        Assert.Equal([0x10, 0x20, 0x30], carolBytes);
    }

    [Fact]
    public async Task PendingCount_TracksInbox()
    {
        var relay = new InMemorySyncRelay();
        var aliceTx = new InMemorySyncTransport(relay, Alice);
        var bobTx = new InMemorySyncTransport(relay, Bob);

        Assert.Equal(0, relay.PendingCount(Bob));
        await aliceTx.SendAsync([0x01], [Bob]);
        await aliceTx.SendAsync([0x02], [Bob]);
        Assert.Equal(2, relay.PendingCount(Bob));

        await bobTx.TryReceiveAsync();
        Assert.Equal(1, relay.PendingCount(Bob));
    }
}
