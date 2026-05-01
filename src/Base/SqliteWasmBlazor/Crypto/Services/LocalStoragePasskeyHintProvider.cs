using System.Runtime.InteropServices.JavaScript;
using System.Runtime.Versioning;
using Microsoft.Extensions.Options;
using SqliteWasmBlazor.Crypto.Abstractions.Services;
using SqliteWasmBlazor.Crypto.Configuration;

namespace SqliteWasmBlazor.Crypto.Services;

/// <summary>
/// Default <see cref="IPasskeyHintProvider"/> backed by browser
/// <c>localStorage</c>, keyed by <c>"prf-hint:{salt}"</c>. Loads the
/// underlying JS module lazily on first call so initialization order with
/// <see cref="PrfService"/> is irrelevant — both share the same
/// <c>sqliteWasmBlazorCryptoPrf</c> module.
/// </summary>
[SupportedOSPlatform("browser")]
public sealed partial class LocalStoragePasskeyHintProvider : IPasskeyHintProvider
{
    private readonly SqliteWasmBlazorCryptoOptions _cryptoOptions;
    private readonly string _storageKey;
    private readonly SemaphoreSlim _initLock = new(1, 1);
    private bool _initialized;

    public LocalStoragePasskeyHintProvider(
        IOptions<PrfOptions> prfOptions,
        IOptions<SqliteWasmBlazorCryptoOptions> cryptoOptions)
    {
        _cryptoOptions = cryptoOptions.Value;
        _storageKey = $"prf-hint:{prfOptions.Value.Salt}";
    }

    public async ValueTask<string?> GetCredentialIdAsync(CancellationToken ct = default)
    {
        await EnsureInitializedAsync();
        var raw = JsInterop.GetPasskeyHint(_storageKey);
        return string.IsNullOrEmpty(raw) ? null : raw;
    }

    public async ValueTask SetCredentialIdAsync(string credentialId, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(credentialId);
        await EnsureInitializedAsync();
        JsInterop.SetPasskeyHint(_storageKey, credentialId);
    }

    public async ValueTask ClearAsync(CancellationToken ct = default)
    {
        await EnsureInitializedAsync();
        JsInterop.ClearPasskeyHint(_storageKey);
    }

    private async ValueTask EnsureInitializedAsync()
    {
        if (_initialized)
        {
            return;
        }

        await _initLock.WaitAsync();
        try
        {
            if (_initialized)
            {
                return;
            }

            var modulePath = $"{_cryptoOptions.BaseHref}{_cryptoOptions.AssetRoot}noble-prf.js";
            await JSHost.ImportAsync("sqliteWasmBlazorCryptoPrf", modulePath);
            _initialized = true;
        }
        finally
        {
            _initLock.Release();
        }
    }

    private static partial class JsInterop
    {
        [JSImport("getPasskeyHint", "sqliteWasmBlazorCryptoPrf")]
        public static partial string? GetPasskeyHint(string key);

        [JSImport("setPasskeyHint", "sqliteWasmBlazorCryptoPrf")]
        public static partial void SetPasskeyHint(string key, string value);

        [JSImport("clearPasskeyHint", "sqliteWasmBlazorCryptoPrf")]
        public static partial void ClearPasskeyHint(string key);
    }
}
