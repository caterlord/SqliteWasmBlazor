using Microsoft.Extensions.DependencyInjection;

namespace SqliteWasmBlazor.CryptoSync.UI;

/// <summary>
/// Host-side DI registration for <c>SqliteWasmBlazor.CryptoSync.UI</c>.
/// Call after <c>AddCryptoSync&lt;TContext&gt;</c> on the host's
/// <see cref="IServiceCollection"/>.
///
/// <para>
/// Registers the RxBlazorV2 <c>ObservableModel</c> instances backing each
/// panel in the library at <see cref="ServiceLifetime.Scoped"/> (matching
/// the per-circuit Blazor convention and the lifetime of the EF context
/// the underlying CryptoSync services consume).
/// </para>
///
/// <para>
/// <b>Caller responsibilities.</b> The host registers the host-supplied
/// seams separately — <c>AddCryptoSyncUI</c> deliberately does not touch
/// them so a non-WebAuthn host (e.g. test fixture) can wire stubs:
/// <list type="bullet">
///   <item><see cref="Services.IPrfAuthenticator"/> — backs the
///         <see cref="AuthenticationPanel"/> and
///         <see cref="RegistrationPanel"/>. Production impl arrives in the
///         post-Stage-2 demo step.</item>
///   <item><see cref="Services.IAdminInvitationContext"/> — supplied per
///         page or as a <c>[CascadingParameter]</c>; the
///         <see cref="InvitationPanel"/> renders an informational
///         placeholder when not supplied.</item>
///   <item><see cref="ISenderAuthSigner"/>, <see cref="IReceiveAuthSigner"/>,
///         <see cref="IPushNotifier"/> — the CryptoSync transport seams.
///         The library does not register defaults; the host wires them
///         (and may register <see cref="NullPushNotifier.Instance"/> as a
///         no-op for hosts that don't ship push).</item>
/// </list>
/// </para>
/// </summary>
public static class CryptoSyncUiServiceCollectionExtensions
{
    /// <summary>
    /// Register every panel-backing model exposed by
    /// <c>SqliteWasmBlazor.CryptoSync.UI</c>. Idempotent — safe to call
    /// multiple times.
    /// </summary>
    public static IServiceCollection AddCryptoSyncUI(this IServiceCollection services)
    {
        ObservableModels.Initialize(services);
        return services;
    }
}
