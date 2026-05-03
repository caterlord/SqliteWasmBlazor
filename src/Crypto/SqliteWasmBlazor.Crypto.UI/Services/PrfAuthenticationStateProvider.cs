using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace SqliteWasmBlazor.Crypto.UI.Services;

/// <summary>
/// Blazor <see cref="AuthenticationStateProvider"/> backed by two
/// independent inputs:
/// <list type="bullet">
///   <item>The PRF session held in
///         <see cref="Components.Authentication.AuthenticationModel"/> —
///         drives <see cref="ClaimTypes.Name"/> /
///         <see cref="ClaimTypes.NameIdentifier"/> identity claims.</item>
///   <item><see cref="IDbInitializationStatus.State"/> — drives the
///         <c>DatabaseState</c> claim that consumer pages gate on via
///         <c>Policy="DatabaseOpen"</c>.</item>
/// </list>
///
/// <para>
/// <b>Policies (registered by AddCryptoUI):</b>
/// <list type="bullet">
///   <item><c>DatabaseOpen</c> — requires <c>DatabaseState=OPEN</c>. Pages
///         that touch the DB wrap their content in
///         <c>&lt;AuthorizeView Policy="DatabaseOpen"&gt;</c>; the
///         NotAuthorized branch typically renders
///         <c>&lt;AuthenticationPanel/&gt;</c> so the user can sign in to
///         unlock an encrypted DB. Plain DBs always satisfy this policy
///         (boot init reports READY immediately).</item>
/// </list>
/// </para>
///
/// <para>
/// <b>Update path.</b>
/// <see cref="Components.Authentication.AuthenticationModel"/> declares
/// <c>[ObservableTrigger(nameof(UpdateAuthenticationState))]</c> on
/// <see cref="Components.Authentication.AuthenticationModel.PublicKey"/>
/// / <c>CredentialId</c>; the trigger calls
/// <see cref="UpdateAuthenticationState"/> here. The DB-state side
/// subscribes to <see cref="IDbInitializationStatus.Changed"/> in the
/// constructor and fires its own
/// <see cref="NotifyAuthenticationStateChanged"/> so every
/// <c>AuthorizeView</c> in the tree re-evaluates on either input
/// changing.
/// </para>
/// </summary>
public sealed class PrfAuthenticationStateProvider : AuthenticationStateProvider, IDisposable
{
    /// <summary>Claim type carrying the boot DB state for the
    /// <c>DatabaseOpen</c> policy.</summary>
    public const string DatabaseStateClaim = "DatabaseState";

    /// <summary>Claim value for <see cref="DbInitState.READY"/> — the only
    /// state that satisfies the <c>DatabaseOpen</c> policy.</summary>
    public const string DatabaseStateOpen = "OPEN";

    /// <summary>Claim value for <see cref="DbInitState.ENCRYPTED_LOCKED"/>
    /// — surfaced for completeness; the absence of <c>OPEN</c> is what the
    /// policy actually rejects.</summary>
    public const string DatabaseStateLocked = "LOCKED";

    private readonly IDbInitializationStatus _dbStatus;
    private string? _credentialId;
    private string? _publicKey;
    private bool _disposed;

    public PrfAuthenticationStateProvider(IDbInitializationStatus dbStatus)
    {
        _dbStatus = dbStatus;
        _dbStatus.Changed += OnDbStateChanged;
    }

    /// <summary>
    /// Pushes the latest credential id + X25519 pubkey snapshot from
    /// <see cref="Components.Authentication.AuthenticationModel"/> and
    /// fires <see cref="NotifyAuthenticationStateChanged"/>. Called from
    /// the model's <c>UpdateAuthenticationState</c> trigger method.
    /// </summary>
    public void UpdateAuthenticationState(string? credentialId, string? publicKey)
    {
        _credentialId = credentialId;
        _publicKey = publicKey;
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    private void OnDbStateChanged()
    {
        // DB state moved (boot probe finished, lifecycle service installed
        // K, user wiped, etc.) — re-evaluate every AuthorizeView so the
        // DatabaseOpen policy gating flips with reality.
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var claims = new List<Claim>();

        // DB-state claim — drives the DatabaseOpen policy. Plain DBs report
        // READY out of boot; encrypted DBs report ENCRYPTED_LOCKED until
        // EncryptedDatabaseLifecycle installs K and promotes back to READY.
        switch (_dbStatus.State)
        {
            case DbInitState.READY:
                claims.Add(new Claim(DatabaseStateClaim, DatabaseStateOpen));
                break;
            case DbInitState.ENCRYPTED_LOCKED:
                claims.Add(new Claim(DatabaseStateClaim, DatabaseStateLocked));
                break;
            // NOT_STARTED / INITIALIZING / TAB_LOCKED / SCHEMA_INCOMPATIBLE /
            // TIMEOUT / FAILED — no DatabaseState claim. DatabaseOpen policy
            // fails; the standard DatabaseErrorAlert path covers the visual.
        }

        // PRF identity claims — only when a session is active.
        if (!string.IsNullOrEmpty(_publicKey))
        {
            claims.Add(new Claim(ClaimTypes.Name, "PRF user"));
            claims.Add(new Claim(ClaimTypes.NameIdentifier, _publicKey));
            claims.Add(new Claim("CredentialId", _credentialId ?? string.Empty));
        }

        if (claims.Count == 0)
        {
            return Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));
        }

        // Auth type non-null only when there's an identity (PublicKey set);
        // otherwise the principal is anonymous-but-claim-bearing so policy
        // checks can still pass on the DB-state claim alone.
        var authType = !string.IsNullOrEmpty(_publicKey) ? "PRF" : null;
        var identity = new ClaimsIdentity(claims, authType);
        return Task.FromResult(new AuthenticationState(new ClaimsPrincipal(identity)));
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _dbStatus.Changed -= OnDbStateChanged;
    }
}
