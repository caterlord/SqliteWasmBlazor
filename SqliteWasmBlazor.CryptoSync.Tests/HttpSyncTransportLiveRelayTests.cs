using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using SqliteWasmBlazor.Crypto.Testing;
using Xunit;

namespace SqliteWasmBlazor.CryptoSync.Tests;

/// <summary>
/// Live-relay integration tests for the whitelist-broadcast wire contract.
/// Drives a Herd-served PHP relay at <c>http://delta-relay.test/</c> through
/// <see cref="HttpSyncTransport"/> + <see cref="WhitelistPushService"/>. Each
/// test resets <c>relay-config.php</c> + <c>relay.db</c> to a known seeded
/// state, so the suite is deterministic but write-heavy on the relay
/// directory.
///
/// <para>
/// Opt-in via <c>dotnet test --filter "Category=LiveRelay"</c>. The default
/// <c>dotnet test</c> run skips this category so CI without Herd doesn't
/// break.
/// </para>
///
/// <para>
/// <b>Test seeds.</b> Synthetic Ed25519 keypairs generated per-run from
/// <see cref="RandomNumberGenerator"/>, hardcoded host. No PRF, no WebAuthn —
/// per the Stage A scope in <c>~/.claude/plans/whitelist-broadcast-rewrite.md</c>.
/// Stage B replaces the seeds with PRF-backed identities; the wire contract
/// is identical so these tests stay valid.
/// </para>
/// </summary>
[Collection("LiveRelay")]
[Trait("Category", "LiveRelay")]
public sealed class HttpSyncTransportLiveRelayTests : IAsyncLifetime
{
    private static readonly Uri RelayBase = new("http://delta-relay.test/");
    private const int Ed25519SeedLength = 32;

    private string _deltaRelayDir = null!;
    private byte[] _adminSeed = null!;
    private byte[] _adminPub = null!;
    private byte[] _senderSeed = null!;
    private byte[] _senderPub = null!;
    private byte[] _deploymentSalt = null!;
    private DeclarationSigner _declarationSigner = null!;

    public async Task InitializeAsync()
    {
        _deltaRelayDir = LocateDeltaRelayDir();
        await ProbeRelayOrThrowAsync();

        _adminSeed = RandomNumberGenerator.GetBytes(Ed25519SeedLength);
        _adminPub = DerivePub(_adminSeed);
        _senderSeed = RandomNumberGenerator.GetBytes(Ed25519SeedLength);
        _senderPub = DerivePub(_senderSeed);
        _deploymentSalt = RandomNumberGenerator.GetBytes(32);

        var crypto = new BouncyCastleCryptoProvider();
        _declarationSigner = new DeclarationSigner(crypto);

        var adminHashHex = HashHex(_deploymentSalt, _adminPub);
        WriteRelayConfig(_deploymentSalt, adminHashHex);
        ResetRelayDb();

        // Baseline whitelist: add the sender, version 1.
        await PushAsync(
            version: 1,
            ops:
            [
                WhitelistOp.Add(HashHex(_deploymentSalt, _senderPub)),
            ]);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task PostEnvelope_RoundTripsThroughLivePhpRelay()
    {
        using var http = new HttpClient();
        var transport = NewSenderTransport(http);

        var envelope = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50 };
        await transport.SendAsync(envelope);

        var received = await transport.TryReceiveAsync();
        Assert.NotNull(received);
        Assert.Equal(envelope, received!);

        Assert.Null(await transport.TryReceiveAsync());
    }

    [Fact]
    public async Task WhitelistPush_AddSecondMember_BothCanPostAndPullThroughTransport()
    {
        // Add a second sender via an incremental Add op at v2. Sender from
        // the baseline (v1) stays whitelisted.
        var secondSeed = RandomNumberGenerator.GetBytes(Ed25519SeedLength);
        var secondPub = DerivePub(secondSeed);

        var result = await PushAsync(
            version: 2,
            ops:
            [
                WhitelistOp.Add(HashHex(_deploymentSalt, secondPub)),
            ]);
        Assert.Equal(2L, result.Version);
        Assert.Equal(1, result.OperationCount);

        using var http = new HttpClient();
        var firstTransport = NewSenderTransport(http);
        var secondTransport = NewTransportFor(http, secondSeed, secondPub);

        var envFromFirst = new byte[] { 0xA1, 0xA2 };
        var envFromSecond = new byte[] { 0xB1, 0xB2, 0xB3 };
        await firstTransport.SendAsync(envFromFirst);
        await secondTransport.SendAsync(envFromSecond);

        // Either side polls and the broadcast queue serves both envelopes.
        var pulled = new List<byte[]>();
        for (int i = 0; i < 2; i++)
        {
            var bytes = await secondTransport.TryReceiveAsync();
            Assert.NotNull(bytes);
            pulled.Add(bytes!);
        }
        Assert.Contains(envFromFirst, pulled);
        Assert.Contains(envFromSecond, pulled);
        Assert.Null(await secondTransport.TryReceiveAsync());
    }

    [Fact]
    public async Task WhitelistPush_ReplayVersion_ThrowsWhitelistVersionConflict()
    {
        // Baseline (v1) was pushed in InitializeAsync. Pushing v1 again must
        // surface as a typed replay-defense exception with the relay's
        // current_version.
        var ex = await Assert.ThrowsAsync<WhitelistVersionConflictException>(async () =>
            await PushAsync(
                version: 1,
                ops:
                [
                    WhitelistOp.Add(HashHex(_deploymentSalt, _senderPub)),
                ]));
        Assert.Equal(1L, ex.AttemptedVersion);
        Assert.Equal(1L, ex.CurrentVersion);
    }

    [Fact]
    public async Task WhitelistPush_RevokeFlipsActiveSenderTo403()
    {
        // Sender is active on the baseline. Revoke at v2; subsequent POSTs
        // must hit 403 (status='revoked' is denied for POST per design §6.2).
        var result = await PushAsync(
            version: 2,
            ops:
            [
                WhitelistOp.Revoke(
                    HashHex(_deploymentSalt, _senderPub),
                    revokedAt: DateTimeOffset.UtcNow.ToUnixTimeSeconds()),
            ]);
        Assert.Equal(2L, result.Version);

        using var http = new HttpClient();
        var transport = NewSenderTransport(http);

        var ex = await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await transport.SendAsync([0xDE, 0xAD]));
        Assert.Equal(HttpStatusCode.Forbidden, ex.StatusCode);
    }

    [Fact]
    public async Task PostEnvelope_NonWhitelistedSender_Returns403()
    {
        // Generate a third sender NOT on the whitelist.
        var rogueSeed = RandomNumberGenerator.GetBytes(Ed25519SeedLength);
        var roguePub = DerivePub(rogueSeed);

        using var http = new HttpClient();
        var transport = NewTransportFor(http, rogueSeed, roguePub);

        var ex = await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await transport.SendAsync([0xCC]));
        Assert.Equal(HttpStatusCode.Forbidden, ex.StatusCode);
    }

    [Fact]
    public async Task ThreeActors_AdminUser1User2_AllPostAndPullAllEnvelopes()
    {
        // Stage A's canonical "everyone broadcasts" coverage. Baseline (v1) has
        // user1 (== _senderPub) on the whitelist; v2 adds the system admin
        // pubkey + a fresh user2 so all three can POST. Per actor: each pulls
        // the whole queue from cursor 0 (each transport has its own
        // InMemoryReceiveCursorStore).
        var user2Seed = RandomNumberGenerator.GetBytes(Ed25519SeedLength);
        var user2Pub = DerivePub(user2Seed);

        await PushAsync(
            version: 2,
            ops:
            [
                WhitelistOp.Add(HashHex(_deploymentSalt, _adminPub)),
                WhitelistOp.Add(HashHex(_deploymentSalt, user2Pub)),
            ]);

        using var http = new HttpClient();
        var adminTransport = NewTransportFor(http, _adminSeed, _adminPub);
        var user1Transport = NewSenderTransport(http);
        var user2Transport = NewTransportFor(http, user2Seed, user2Pub);

        var adminEnv = new byte[] { 0xAA, 0x01 };
        var user1Env = new byte[] { 0xBB, 0x02 };
        var user2Env = new byte[] { 0xCC, 0x03 };
        await adminTransport.SendAsync(adminEnv);
        await user1Transport.SendAsync(user1Env);
        await user2Transport.SendAsync(user2Env);

        foreach (var transport in new[] { adminTransport, user1Transport, user2Transport })
        {
            var pulled = new List<byte[]>();
            for (var i = 0; i < 3; i++)
            {
                var bytes = await transport.TryReceiveAsync();
                Assert.NotNull(bytes);
                pulled.Add(bytes!);
            }
            Assert.Contains(adminEnv, pulled);
            Assert.Contains(user1Env, pulled);
            Assert.Contains(user2Env, pulled);
            Assert.Null(await transport.TryReceiveAsync());
        }
    }

    [Fact]
    public async Task WhitelistPush_NonAdminSigner_Returns401()
    {
        // A "rogue admin" — valid Ed25519 keypair but NOT matching the
        // deployment's hardwired admin_pubkey_hash. Their signed v2 push must
        // hit 401 ("admin pubkey hash does not match deployment") before any
        // signature verification, surfacing as plain HttpRequestException
        // (not WhitelistVersionConflictException — that's the 409 path).
        var rogueAdminSeed = RandomNumberGenerator.GetBytes(Ed25519SeedLength);
        var rogueAdminPub = DerivePub(rogueAdminSeed);

        using var http = new HttpClient();
        var service = new WhitelistPushService(http, RelayBase, _declarationSigner);

        var ex = await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await service.PushAsync(
                [WhitelistOp.Add(HashHex(_deploymentSalt, rogueAdminPub))],
                adminEd25519PublicKeyBase64: Convert.ToBase64String(rogueAdminPub),
                adminEd25519PrivateKey: rogueAdminSeed,
                version: 2));
        Assert.Equal(HttpStatusCode.Unauthorized, ex.StatusCode);
    }

    [Fact]
    public async Task RevokedSender_GraceWindowExpired_GetReturns403()
    {
        // Tighten the grace window, then revoke with a backdated revoked_at
        // beyond it. The relay's check is `now - revoked_at >= grace`, so
        // revoked_at = now - 200 with grace=60 lands in the post-grace zone
        // without sleeping — no test-clock machinery needed.
        var adminHashHex = HashHex(_deploymentSalt, _adminPub);
        WriteRelayConfig(_deploymentSalt, adminHashHex, readGraceSeconds: 60);

        var revokedAtPastGrace = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 200;
        await PushAsync(
            version: 2,
            ops:
            [
                WhitelistOp.Revoke(
                    HashHex(_deploymentSalt, _senderPub),
                    revokedAt: revokedAtPastGrace),
            ]);

        using var http = new HttpClient();
        var transport = NewSenderTransport(http);

        var ex = await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await transport.TryReceiveAsync());
        Assert.Equal(HttpStatusCode.Forbidden, ex.StatusCode);
    }

    [Fact]
    public async Task RevokedSender_WithinGraceWindow_GetStillSucceeds()
    {
        // Friendly handoff: a member who's been revoked seconds ago can still
        // drain the inbox while the grace window holds — "you've been
        // revoked, here's everything that arrived before you were kicked".
        // Use revoked_at = now (just-revoked) + grace = 60 → comfortably inside.
        var adminHashHex = HashHex(_deploymentSalt, _adminPub);
        WriteRelayConfig(_deploymentSalt, adminHashHex, readGraceSeconds: 60);

        // POST one envelope while still active so the post-revoke GET has
        // something to drain.
        using var http = new HttpClient();
        var transport = NewSenderTransport(http);
        await transport.SendAsync([0x42]);

        await PushAsync(
            version: 2,
            ops:
            [
                WhitelistOp.Revoke(
                    HashHex(_deploymentSalt, _senderPub),
                    revokedAt: DateTimeOffset.UtcNow.ToUnixTimeSeconds()),
            ]);

        var pulled = await transport.TryReceiveAsync();
        Assert.NotNull(pulled);
        Assert.Equal(new byte[] { 0x42 }, pulled!);
    }

    [Fact]
    public async Task PostEnvelope_ExceedsBodyCap_Returns413()
    {
        // C-2 audit fix verified end-to-end: relay enforces max_body_bytes
        // before any signature work and returns 413. Keep the cap small so
        // the offending body stays small too — no megabyte uploads in tests.
        var adminHashHex = HashHex(_deploymentSalt, _adminPub);
        WriteRelayConfig(_deploymentSalt, adminHashHex, maxBodyBytes: 4096);

        using var http = new HttpClient();
        var transport = NewSenderTransport(http);

        var bigEnvelope = RandomNumberGenerator.GetBytes(8000);

        var ex = await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await transport.SendAsync(bigEnvelope));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, ex.StatusCode);
    }

    [Fact]
    public async Task PostEnvelope_StaleTimestamp_Returns401()
    {
        // RECEIVE_WINDOW_SECONDS = 300 in the relay, so 600s in the past is
        // safely outside. Hand-craft the POST instead of going through
        // HttpSyncTransport — the transport always uses `now`, which is the
        // contract; this test pokes at the relay's window directly.
        using var http = new HttpClient();

        var staleTs = (DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 600)
            .ToString(CultureInfo.InvariantCulture);
        var envelope = new byte[] { 0x77 };
        var envelopeHashHex = Convert.ToHexString(SHA256.HashData(envelope))
            .ToLowerInvariant();
        var signingInput = $"deltapost-v1|{staleTs}|{envelopeHashHex}";
        var sig = Convert.ToBase64String(
            SignEd25519(_senderSeed, Encoding.UTF8.GetBytes(signingInput)));

        using var request = new HttpRequestMessage(
            HttpMethod.Post, new Uri(RelayBase, "api/delta"))
        {
            Content = JsonContent.Create(new
            {
                envelope = Convert.ToBase64String(envelope),
            }),
        };
        request.Headers.Add("X-Timestamp", staleTs);
        request.Headers.Add("X-Sender-PubKey", Convert.ToBase64String(_senderPub));
        request.Headers.Add("X-Sender-Sig", sig);

        using var response = await http.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private HttpSyncTransport NewSenderTransport(HttpClient http)
        => NewTransportFor(http, _senderSeed, _senderPub);

    private static HttpSyncTransport NewTransportFor(HttpClient http, byte[] seed, byte[] pub)
    {
        var senderSigner = new BcEd25519SenderSigner(seed, pub);
        var receiveSigner = new BcEd25519ReceiveSigner(seed, pub);
        return new HttpSyncTransport(http, RelayBase, senderSigner, receiveSigner);
    }

    private async Task<WhitelistPushResult> PushAsync(long version, IReadOnlyList<WhitelistOp> ops)
    {
        using var http = new HttpClient();
        var service = new WhitelistPushService(http, RelayBase, _declarationSigner);
        return await service.PushAsync(
            ops,
            adminEd25519PublicKeyBase64: Convert.ToBase64String(_adminPub),
            adminEd25519PrivateKey: _adminSeed,
            version: version);
    }

    private static string LocateDeltaRelayDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "DeltaRelay", "delta-relay.php");
            if (File.Exists(candidate))
            {
                return Path.Combine(dir.FullName, "DeltaRelay");
            }
            dir = dir.Parent;
        }
        throw new InvalidOperationException(
            "LiveRelay setup: cannot locate DeltaRelay directory by walking up from "
            + $"'{AppContext.BaseDirectory}'. Run tests from inside the SqliteWasmBlazor checkout.");
    }

    private static async Task ProbeRelayOrThrowAsync()
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        try
        {
            using var resp = await http.GetAsync(RelayBase);
            if (resp.StatusCode == HttpStatusCode.NotFound)
            {
                throw new InvalidOperationException(
                    $"LiveRelay setup: GET {RelayBase} returned 404 — Herd/Valet "
                    + "is running but the delta-relay.test site is not linked. "
                    + "Run 'herd link delta-relay' (or 'valet link delta-relay') from "
                    + "the DeltaRelay directory before running LiveRelay tests.");
            }
        }
        catch (HttpRequestException ex)
        {
            throw new InvalidOperationException(
                $"LiveRelay setup: GET {RelayBase} failed — Herd/Valet not "
                + "running. Start it before running LiveRelay tests.", ex);
        }
    }

    private void WriteRelayConfig(
        byte[] salt,
        string adminHashHex,
        int readGraceSeconds = 604800,
        int maxBodyBytes = 1048576)
    {
        var saltB64 = Convert.ToBase64String(salt);
        var contents = $$"""
            <?php
            // Generated by HttpSyncTransportLiveRelayTests. Do not commit.
            return [
                'deployment_salt'    => '{{saltB64}}',
                'admin_pubkey_hash'  => '{{adminHashHex}}',
                'read_grace_seconds' => {{readGraceSeconds}},
                'max_body_bytes'     => {{maxBodyBytes}},
                'rate_limit_window'  => 60,
                'rate_limit_count'   => 60,
                'retention_seconds'  => 2592000,
            ];
            """;
        var path = Path.Combine(_deltaRelayDir, "relay-config.php");
        File.WriteAllText(path, contents);
    }

    private void ResetRelayDb()
    {
        TryDelete(Path.Combine(_deltaRelayDir, "relay.db"));
        TryDelete(Path.Combine(_deltaRelayDir, "relay.db-wal"));
        TryDelete(Path.Combine(_deltaRelayDir, "relay.db-shm"));
    }

    private static void TryDelete(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private static string HashHex(byte[] salt, byte[] pubKey)
    {
        var buffer = new byte[salt.Length + pubKey.Length];
        Buffer.BlockCopy(salt, 0, buffer, 0, salt.Length);
        Buffer.BlockCopy(pubKey, 0, buffer, salt.Length, pubKey.Length);
        return Convert.ToHexString(SHA256.HashData(buffer)).ToLowerInvariant();
    }

    private static byte[] DerivePub(byte[] seed)
    {
        var priv = new Ed25519PrivateKeyParameters(seed, 0);
        return priv.GeneratePublicKey().GetEncoded();
    }

    private static byte[] SignEd25519(byte[] seed, byte[] message)
    {
        var signer = new Ed25519Signer();
        signer.Init(forSigning: true, new Ed25519PrivateKeyParameters(seed, 0));
        signer.BlockUpdate(message, 0, message.Length);
        return signer.GenerateSignature();
    }

    private sealed class BcEd25519SenderSigner(byte[] seed, byte[] pub) : ISenderAuthSigner
    {
        public string OwnEd25519PublicKeyBase64 { get; } = Convert.ToBase64String(pub);

        public ValueTask<string> SignSendChallengeAsync(string message, CancellationToken cancellationToken = default)
        {
            var sig = SignEd25519(seed, Encoding.UTF8.GetBytes(message));
            return ValueTask.FromResult(Convert.ToBase64String(sig));
        }
    }

    private sealed class BcEd25519ReceiveSigner(byte[] seed, byte[] pub) : IReceiveAuthSigner
    {
        public string OwnEd25519PublicKeyBase64 { get; } = Convert.ToBase64String(pub);

        public ValueTask<string> SignReceiveChallengeAsync(string message, CancellationToken cancellationToken = default)
        {
            var sig = SignEd25519(seed, Encoding.UTF8.GetBytes(message));
            return ValueTask.FromResult(Convert.ToBase64String(sig));
        }
    }
}
