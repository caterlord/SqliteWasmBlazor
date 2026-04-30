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
/// the underlying CryptoSync services consume), plus the singleton
/// <see cref="RxBlazorV2.MudBlazor.Components.StatusModel"/> from the
/// MudBlazor pkg — the centralized error/status sink every command in
/// this library routes to. Hosts render
/// <c>&lt;RxBlazorV2.MudBlazor.Components.Razor.StatusDisplay/&gt;</c>
/// in their layout to surface those messages.
/// </para>
///
/// <para>
/// <b>Caller responsibilities.</b> The host registers the host-supplied
/// seams separately — <c>AddCryptoSyncUI</c> deliberately does not touch
/// them so a non-WebAuthn host (e.g. test fixture) can wire stubs:
/// <list type="bullet">
///   <item><see cref="Services.IPrfAuthenticator"/> — backs the
///         <see cref="Components.Authentication.AuthenticationPanel"/> and
///         <see cref="Components.Authentication.RegistrationPanel"/>.
///         Production impl arrives in the post-Stage-2 demo step.</item>
///   <item><see cref="Services.IAdminInvitationContext"/> — supplied per
///         page or as a <c>[CascadingParameter]</c>; the
///         <see cref="Components.Invitation.InvitationPanel"/> renders an
///         informational placeholder when not supplied.</item>
///   <item><see cref="Services.IDatabaseResetService"/> — boot-status
///         recovery callback; register
///         <see cref="Services.NullDatabaseResetService.Instance"/> for
///         hosts that don't ship a reset path.</item>
///   <item><see cref="Services.ISessionAuthenticator"/> — backs the
///         re-authenticate / dismiss flow on
///         <see cref="Components.Shared.SessionExpiredPopover"/>.</item>
///   <item><see cref="ISenderAuthSigner"/>, <see cref="IReceiveAuthSigner"/>,
///         <see cref="IPushNotifier"/> — the CryptoSync transport seams.
///         The library does not register defaults; the host wires them
///         (and may register <see cref="NullPushNotifier.Instance"/> as a
///         no-op for hosts that don't ship push).</item>
/// </list>
/// </para>
///
/// <para>
/// <b>Localization.</b> Each panel-backing model resolves
/// <see cref="Microsoft.Extensions.Localization.IStringLocalizer{T}"/> for
/// its user-facing strings. The host MUST call
/// <c>services.AddLocalization()</c> and SHOULD set
/// <c>&lt;BlazorWebAssemblyLoadAllGlobalizationData&gt;true&lt;/&gt;</c> in
/// its csproj so the WASM runtime ships every satellite resource assembly
/// and respects <c>navigator.language</c> at boot.
/// </para>
/// </summary>
public static class CryptoSyncUiServiceCollectionExtensions
{
    /// <summary>
    /// Register every panel-backing model exposed by
    /// <c>SqliteWasmBlazor.CryptoSync.UI</c> plus the
    /// <see cref="RxBlazorV2.MudBlazor.Components.StatusModel"/> singleton
    /// the library's commands route exceptions and status messages to.
    /// Idempotent — safe to call multiple times.
    /// </summary>
    public static IServiceCollection AddCryptoSyncUI(this IServiceCollection services)
    {
        ObservableModels.Initialize(services);
        RxBlazorV2.MudBlazor.ObservableModels.Initialize(services);
        return services;
    }
}
