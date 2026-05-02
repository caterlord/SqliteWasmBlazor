using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace SqliteWasmBlazor.Crypto.UI.Services;

/// <summary>
/// Blazor <see cref="AuthenticationStateProvider"/> backed by the PRF
/// session state held in <see cref="Components.Authentication.AuthenticationModel"/>.
/// Every host that calls <c>AddCryptoUI()</c> gets this registered as the
/// app-wide auth-state seam so consumer pages can use the standard Blazor
/// pattern (<c>&lt;AuthorizeView&gt;</c>, <c>[CascadingParameter] Task&lt;AuthenticationState&gt;</c>,
/// <c>AuthenticationStateProvider</c> direct injection) instead of
/// hand-rolling cross-model R3 subscriptions in page partials — the
/// anti-pattern this provider exists to eliminate.
///
/// <para>
/// <b>Update path.</b> <see cref="Components.Authentication.AuthenticationModel"/>
/// declares <c>[ObservableTrigger(nameof(UpdateAuthenticationState))]</c> on
/// the properties whose changes should propagate to consumers
/// (<see cref="Components.Authentication.AuthenticationModel.PublicKey"/>,
/// <see cref="Components.Authentication.AuthenticationModel.CredentialId"/>);
/// the trigger calls <see cref="UpdateAuthenticationState"/> here, which in
/// turn fires Blazor's <see cref="NotifyAuthenticationStateChanged"/> so
/// every <c>AuthorizeView</c> in the tree re-renders.
/// </para>
///
/// <para>
/// <b>State semantics.</b> Authenticated when
/// <see cref="Components.Authentication.AuthenticationModel.PublicKey"/> is
/// non-empty (a successful PRF derivation has happened); anonymous before
/// the first derive and after a Lock / TTL expiry. Claims include the
/// credential id and X25519 pubkey for downstream gating.
/// </para>
/// </summary>
public sealed class PrfAuthenticationStateProvider : AuthenticationStateProvider
{
    private string? _credentialId;
    private string? _publicKey;

    private static readonly AuthenticationState Anonymous =
        new(new ClaimsPrincipal(new ClaimsIdentity()));

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

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        if (string.IsNullOrEmpty(_publicKey))
        {
            return Task.FromResult(Anonymous);
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, "PRF user"),
            new(ClaimTypes.NameIdentifier, _publicKey),
            new("CredentialId", _credentialId ?? string.Empty),
        };

        var identity = new ClaimsIdentity(claims, authenticationType: "PRF");
        var principal = new ClaimsPrincipal(identity);
        return Task.FromResult(new AuthenticationState(principal));
    }
}
