using System.Globalization;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace SqliteWasmBlazor.CryptoSync.Tests;

/// <summary>
/// Live-relay integration tests for <see cref="HttpSyncTransport"/>. Drives a
/// Herd-served PHP relay at <c>http://delta-relay.test/</c> through the same
/// wire contract a production deployment exposes. Each test resets
/// <c>relay-config.php</c> and <c>relay.db</c> to a known seeded state, so
/// the suite is deterministic but write-heavy on the relay directory.
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

    public async Task InitializeAsync()
    {
        _deltaRelayDir = LocateDeltaRelayDir();
        await ProbeRelayOrThrowAsync();

        _adminSeed = RandomNumberGenerator.GetBytes(Ed25519SeedLength);
        _adminPub = DerivePub(_adminSeed);
        _senderSeed = RandomNumberGenerator.GetBytes(Ed25519SeedLength);
        _senderPub = DerivePub(_senderSeed);
        _deploymentSalt = RandomNumberGenerator.GetBytes(32);

        var adminHashHex = HashHex(_deploymentSalt, _adminPub);
        WriteRelayConfig(_deploymentSalt, adminHashHex);
        ResetRelayDb();

        await PushWhitelistAsync(
            version: 1,
            members:
            [
                new WhitelistEntry(
                    PubkeyHash: HashHex(_deploymentSalt, _senderPub),
                    Status: "active",
                    RevokedAt: null),
            ]);
    }

    public Task DisposeAsync()
    {
        // Leave the seeded state in place — InitializeAsync resets on the
        // next run. Skipping cleanup keeps the relay directory inspectable
        // after a failed test for post-mortem.
        return Task.CompletedTask;
    }

    [Fact]
    public async Task PostEnvelope_RoundTripsThroughLivePhpRelay()
    {
        using var http = new HttpClient();
        var senderSigner = new BcEd25519SenderSigner(_senderSeed, _senderPub);
        var receiveSigner = new BcEd25519ReceiveSigner(_senderSeed, _senderPub);
        var transport = new HttpSyncTransport(http, RelayBase, senderSigner, receiveSigner);

        var envelope = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50 };
        await transport.SendAsync(envelope);

        var received = await transport.TryReceiveAsync();
        Assert.NotNull(received);
        Assert.Equal(envelope, received!);

        // Stream is empty after the single envelope is drained.
        Assert.Null(await transport.TryReceiveAsync());
    }

    // ------------------------------------------------------------------
    // Setup helpers
    // ------------------------------------------------------------------

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
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                throw new InvalidOperationException(
                    $"LiveRelay setup: GET {RelayBase} returned 404 — Herd/Valet "
                    + "is running but the delta-relay.test site is not linked. "
                    + "Run 'valet link delta-relay' (or 'herd link') from the "
                    + "DeltaRelay directory before running LiveRelay tests.");
            }
        }
        catch (HttpRequestException ex)
        {
            throw new InvalidOperationException(
                $"LiveRelay setup: GET {RelayBase} failed — Herd/Valet not "
                + "running. Start it before running LiveRelay tests.", ex);
        }
    }

    private void WriteRelayConfig(byte[] salt, string adminHashHex)
    {
        var saltB64 = Convert.ToBase64String(salt);
        var contents = $$"""
            <?php
            // Generated by HttpSyncTransportLiveRelayTests. Do not commit.
            return [
                'deployment_salt'    => '{{saltB64}}',
                'admin_pubkey_hash'  => '{{adminHashHex}}',
                'read_grace_seconds' => 604800,
                'max_body_bytes'     => 1048576,
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

    private async Task PushWhitelistAsync(int version, IReadOnlyList<WhitelistEntry> members)
    {
        var canonical = BuildWhitelistSigningString(version, members);
        var sig = SignEd25519(_adminSeed, Encoding.UTF8.GetBytes(canonical));

        var body = new WhitelistPushBody
        {
            Version = version,
            Members =
            [
                .. members.Select(m => new WhitelistMemberWire
                {
                    PubkeyHash = m.PubkeyHash,
                    Status = m.Status,
                    RevokedAt = m.RevokedAt,
                }),
            ],
            AdminPubkey = Convert.ToBase64String(_adminPub),
            AdminSignature = Convert.ToBase64String(sig),
        };

        using var http = new HttpClient();
        using var resp = await http.PostAsJsonAsync(
            new Uri(RelayBase, "api/whitelist"),
            body,
            LiveRelayJsonContext.Default.WhitelistPushBody);

        if (!resp.IsSuccessStatusCode)
        {
            var responseBody = await resp.Content.ReadAsStringAsync();
            throw new InvalidOperationException(
                $"LiveRelay setup: whitelist push failed: HTTP {(int)resp.StatusCode} — {responseBody}");
        }
    }

    private static string BuildWhitelistSigningString(int version, IReadOnlyList<WhitelistEntry> members)
    {
        var rows = members
            .Select(m => $"{m.PubkeyHash}:{m.Status}:{m.RevokedAt ?? 0}")
            .OrderBy(s => s, StringComparer.Ordinal)
            .ToArray();
        return $"whitelist-v1|{version.ToString(CultureInfo.InvariantCulture)}|{string.Join("|", rows)}";
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

    private sealed record WhitelistEntry(string PubkeyHash, string Status, long? RevokedAt);

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

    internal sealed class WhitelistMemberWire
    {
        [JsonPropertyName("pubkey_hash")]
        public required string PubkeyHash { get; init; }

        [JsonPropertyName("status")]
        public required string Status { get; init; }

        [JsonPropertyName("revoked_at")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public long? RevokedAt { get; init; }
    }

    internal sealed class WhitelistPushBody
    {
        [JsonPropertyName("version")]
        public required int Version { get; init; }

        [JsonPropertyName("members")]
        public required WhitelistMemberWire[] Members { get; init; }

        [JsonPropertyName("admin_pubkey")]
        public required string AdminPubkey { get; init; }

        [JsonPropertyName("admin_signature")]
        public required string AdminSignature { get; init; }
    }
}

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(HttpSyncTransportLiveRelayTests.WhitelistPushBody))]
internal partial class LiveRelayJsonContext : JsonSerializerContext;
