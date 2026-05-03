using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using SqliteWasmBlazor.Crypto.UI.Services;

namespace SqliteWasmBlazor.Crypto.UI;

/// <summary>
/// Host-side DI registration for <c>SqliteWasmBlazor.Crypto.UI</c>, the
/// base-plane Razor library carved out of <c>SqliteWasmBlazor.CryptoSync.UI</c>
/// in plane-separation Phase 1.1. Hosts that only need the base-plane
/// surface (encrypted VFS via PRF, boot-status, session re-auth) call
/// <see cref="AddCryptoUI"/>; hosts that also need delta-sync / contacts /
/// invitations / push call
/// <see cref="UI.CryptoSyncUiServiceCollectionExtensions.AddCryptoSyncUI"/>
/// in <c>SqliteWasmBlazor.CryptoSync.UI</c>, which calls
/// <see cref="AddCryptoUI"/> first.
///
/// <para>
/// Registers the <see cref="ServiceLifetime.Scoped"/> <c>ObservableModel</c>
/// instances backing each base-plane panel
/// (<see cref="Components.Authentication.AuthenticationModel"/>,
/// <see cref="Components.Shared.DatabaseErrorAlertModel"/>,
/// <see cref="Components.Shared.SessionExpiredPopoverModel"/>) plus the
/// singleton <see cref="RxBlazorV2.MudBlazor.Components.StatusModel"/>
/// status sink every command in this library routes to. Hosts render
/// <c>&lt;RxBlazorV2.MudBlazor.Components.Razor.StatusDisplay/&gt;</c>
/// in their layout to surface those messages.
/// </para>
///
/// <para>
/// <b>Caller responsibilities.</b> The host registers the host-supplied
/// seams separately — <see cref="AddCryptoUI"/> deliberately does not
/// touch them so a non-WebAuthn host (e.g. test fixture) can wire stubs:
/// <list type="bullet">
///   <item><see cref="Services.IPrfAuthenticator"/> — backs the
///         <see cref="Components.Authentication.AuthenticationPanel"/>.
///         Production impl arrives via
///         <see cref="AddCryptoUIPrfAuthenticator"/>.</item>
///   <item><see cref="Services.IDatabaseResetService"/> — boot-status
///         recovery callback; register
///         <see cref="Services.NullDatabaseResetService.Instance"/> for
///         hosts that don't ship a reset path.</item>
///   <item><see cref="Services.ISessionAuthenticator"/> — backs the
///         re-authenticate / dismiss flow on
///         <see cref="Components.Shared.SessionExpiredPopover"/>.</item>
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
public static class CryptoUiServiceCollectionExtensions
{
    /// <summary>
    /// Register every panel-backing model exposed by
    /// <c>SqliteWasmBlazor.Crypto.UI</c> plus the
    /// <see cref="RxBlazorV2.MudBlazor.Components.StatusModel"/> singleton
    /// the library's commands route exceptions and status messages to.
    /// Idempotent — safe to call multiple times.
    /// </summary>
    public static IServiceCollection AddCryptoUI(this IServiceCollection services)
    {
        ObservableModels.Initialize(services);
        RxBlazorV2.MudBlazor.ObservableModels.Initialize(services);

        // PrfAuthenticationStateProvider is the single source of truth for
        // "is a PRF session active?" — registered both as itself (so the
        // panel-backing AuthenticationModel can inject it via partial
        // ctor) and as Blazor's standard AuthenticationStateProvider seam
        // (so consumer hosts get <AuthorizeView> + [CascadingParameter]
        // Task<AuthenticationState> for free, no hand-rolled R3
        // subscriptions in page partials).
        services.AddAuthorizationCore(options =>
        {
            // DatabaseOpen policy — gates pages that touch the DB. Satisfied
            // when the boot DB state is READY (plain DB OR encrypted DB with
            // worker K installed). NotAuthorized branch typically renders
            // <AuthenticationPanel/> so the user can sign in to unlock an
            // encrypted DB; once EncryptedDatabaseLifecycle promotes state
            // back to READY, the AuthorizeView flips automatically.
            options.AddPolicy("DatabaseOpen", policy =>
                policy.RequireClaim(
                    PrfAuthenticationStateProvider.DatabaseStateClaim,
                    PrfAuthenticationStateProvider.DatabaseStateOpen));
        });
        services.AddSingleton<PrfAuthenticationStateProvider>();
        services.AddSingleton<AuthenticationStateProvider>(
            sp => sp.GetRequiredService<PrfAuthenticationStateProvider>());

        return services;
    }

    /// <summary>
    /// Opt-in registration of the production <see cref="IPrfAuthenticator"/>
    /// implementation backed by the base-plane <see cref="Crypto.Services.IPrfService"/>.
    /// Hosts that ship a real WebAuthn-PRF UX (the demo, downstream consumer
    /// apps) call this after <c>AddSqliteWasmBlazorCrypto</c> to wire the seam
    /// consumed by <see cref="Components.Authentication.AuthenticationPanel"/>;
    /// test fixtures
    /// that want a stub skip this call and register their own
    /// <see cref="IPrfAuthenticator"/>. Mirrors the
    /// <c>AddCryptoSyncPrfSigners</c> shape from
    /// <c>SqliteWasmBlazor.CryptoSync</c>.
    ///
    /// <para>
    /// Registered as <see cref="ServiceLifetime.Scoped"/> so it composes with
    /// either base-plane <see cref="Crypto.Services.IPrfService"/> registration
    /// (singleton via the
    /// <c>AddSqliteWasmBlazorCrypto(IConfiguration?, ...)</c> overload, scoped
    /// via the <c>AddSqliteWasmBlazorCrypto(Action&lt;PrfOptions&gt;, ...)</c>
    /// overload).
    /// </para>
    /// </summary>
    public static IServiceCollection AddCryptoUIPrfAuthenticator(this IServiceCollection services)
    {
        services.AddSingleton<IPrfAuthenticator, PrfAuthenticator>();
        return services;
    }

    /// <summary>
    /// Register a database name with the
    /// <see cref="EncryptedDatabaseLifecycle"/> auto-unlock service. The
    /// lifecycle service closes the worker DB on auth-state-cleared (TTL /
    /// Lock) and installs the freshly-derived X25519 pubkey on
    /// auth-state-set, promoting any boot-time
    /// <see cref="DbInitState.ENCRYPTED_LOCKED"/> back to
    /// <see cref="DbInitState.READY"/> on
    /// <see cref="VfsKeyInstallResult.MATCH"/>.
    ///
    /// <para>
    /// Idempotent on the database name; safe to call multiple times for
    /// the same name. The service registration itself is also idempotent
    /// — first call wires the singleton, subsequent calls reuse it.
    /// </para>
    ///
    /// <para>
    /// <b>Eager activation.</b> The lifecycle subscribes to the
    /// <see cref="AuthenticationStateProvider.AuthenticationStateChanged"/>
    /// event in its constructor; the host MUST resolve the service after
    /// <c>builder.Build()</c> for the subscription to be live before any
    /// page renders. Typical:
    /// <code>
    /// var host = builder.Build();
    /// host.Services.GetRequiredService&lt;EncryptedDatabaseLifecycle&gt;();
    /// </code>
    /// </para>
    /// </summary>
    public static IServiceCollection AddCryptoUIEncryptedDatabase(
        this IServiceCollection services,
        string databaseName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databaseName);

        // First-call registration of the singleton; later calls reuse it.
        services.AddSingleton<EncryptedDatabaseLifecycle>();

        // Defer the per-database register call until the singleton is
        // resolved. Decorating the singleton via ImplementationFactory
        // would complicate test substitution; instead use a startup-style
        // configurator service that runs once on first lifecycle activation.
        services.AddSingleton(new EncryptedDatabaseRegistration(databaseName));

        return services;
    }
}

/// <summary>
/// Marker registration consumed by <see cref="EncryptedDatabaseLifecycle"/>
/// during eager activation: each instance corresponds to one database name
/// the host wants auto-managed. Multiple registrations resolve to a list
/// the lifecycle drains into <see cref="EncryptedDatabaseLifecycle.RegisterDatabase"/>.
/// </summary>
public sealed record EncryptedDatabaseRegistration(string DatabaseName);
