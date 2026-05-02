using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Options;
using R3;
using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using RxBlazorV2.MudBlazor.Components;
using SqliteWasmBlazor.Crypto.Abstractions.Models;
using SqliteWasmBlazor.Crypto.Configuration;
using SqliteWasmBlazor.Crypto.Services;
using SqliteWasmBlazor.Crypto.UI.Models;
using SqliteWasmBlazor.Crypto.UI.Services;

namespace SqliteWasmBlazor.Crypto.UI.Components.Authentication;

/// <summary>
/// Drives the authentication / key-derivation panel and is the
/// single source of truth for "is a PRF session active?" — every
/// consumer (panels, demo-page guards, host-supplied logic) reads
/// <see cref="PublicKey"/> / <see cref="HasKeys"/> here, and
/// <see cref="PrfAuthenticationStateProvider"/> mirrors the same
/// state into Blazor's standard <c>AuthenticationStateProvider</c>
/// seam so <c>&lt;AuthorizeView&gt;</c> works out of the box.
///
/// <para>
/// <b>State propagation (declarative).</b>
/// <see cref="PublicKey"/> + <see cref="CredentialId"/> carry
/// <c>[ObservableTrigger(nameof(UpdateAuthenticationState))]</c>: every
/// successful set fires <see cref="UpdateAuthenticationState"/> which
/// pushes the new state into <see cref="PrfAuthenticationStateProvider"/>
/// + raises Blazor's <c>NotifyAuthenticationStateChanged</c>. No host
/// code needs to subscribe to R3 streams or call <c>InvokeAsync</c>
/// from page partials — those are anti-patterns this model exists to
/// eliminate.
/// </para>
///
/// <para>
/// <b>Session-end reactivity.</b>
/// <see cref="OnContextReadyAsync"/> registers an R3 subscription on
/// <see cref="IPrfService.KeyExpired"/> filtered to the seed-cache key
/// (<c>"prf-seed:{Salt}"</c>) — the canonical signal that a TTL elapsed
/// or a manual <c>ClearKeys</c> happened. The handler atomically clears
/// <see cref="PublicKey"/> / <see cref="CredentialId"/> / <see cref="Metadata"/>
/// inside <c>SuspendNotifications</c>, so observers see one coherent
/// transition instead of three intermediate states. The lifetime is
/// owned by <c>Subscriptions</c> on <see cref="ObservableModel"/>.
/// </para>
///
/// <para>
/// <b>Cache bridge.</b> <see cref="OnContextReadyAsync"/> also reads
/// <see cref="IPrfService.HasCachedKeys"/> + <see cref="IPrfService.GetCachedPublicKey"/>
/// once at construction so a still-warm cache (e.g. user navigated back to
/// a panel-hosting page within TTL) re-hydrates the model without forcing
/// a fresh WebAuthn ceremony.
/// </para>
///
/// <para>
/// <b>Error / status routing.</b> The injected <see cref="StatusBaseModel"/>
/// is the centralized sink: command exceptions are auto-routed there
/// through the per-command formatter (third <c>[ObservableCommand]</c>
/// argument); explicit graceful-flow status (cancellation, success) is
/// pushed via <see cref="StatusBaseModel.AddWarning"/> /
/// <see cref="StatusBaseModel.AddSuccess"/> with a <c>source</c> tag.
/// The host renders a <c>&lt;StatusDisplay/&gt;</c> shell-level component
/// that consumes that sink.
/// </para>
/// </summary>
[ObservableModelScope(ModelScope.Scoped)]
[ObservableComponent]
public partial class AuthenticationModel : ObservableModel
{
    public partial AuthenticationModel(
        IPrfAuthenticator authenticator,
        IPrfService prfService,
        IOptions<PrfOptions> prfOptions,
        PrfAuthenticationStateProvider stateProvider,
        StatusModel statusModel,
        IStringLocalizer<AuthenticationModel> localizer);

    [ObservableTrigger(nameof(UpdateAuthenticationState))]
    public partial string? CredentialId { get; set; }

    [ObservableTrigger(nameof(UpdateAuthenticationState))]
    public partial string? PublicKey { get; set; }

    public partial PublicKeyMetadata? Metadata { get; set; }
    public partial bool? IsPrfSupported { get; set; }

    public partial bool DialogVisible { get; set; }
    public partial string? EditName { get; set; }
    public partial string? EditEmail { get; set; }
    public partial string? EditComment { get; set; }

    /// <summary>
    /// Copy-to-clipboard signal. The component-trigger override does the
    /// JS interop + snackbar, then clears the signal so a subsequent click
    /// re-fires the trigger.
    /// </summary>
    [ObservableComponentTriggerAsync]
    public partial string? PendingCopy { get; set; }

    public bool HasKeys => !string.IsNullOrEmpty(PublicKey);
    public bool IsExecuting => DeriveKeys.Executing;

    [ObservableCommand(nameof(CheckPrfSupportAsync))]
    public partial IObservableCommandAsync CheckPrfSupport { get; }

    [ObservableCommand(nameof(DeriveKeysAsync), null, nameof(FormatDeriveKeysError))]
    public partial IObservableCommandAsync DeriveKeys { get; }

    [ObservableCommand(nameof(ClearKeys))]
    public partial IObservableCommand ClearKeysCommand { get; }

    [ObservableCommand(nameof(OpenMetadataDialog), nameof(CanInteractWithKey))]
    public partial IObservableCommand OpenMetadataDialogCommand { get; }

    [ObservableCommand(nameof(CancelMetadataDialog))]
    public partial IObservableCommand CancelMetadataDialogCommand { get; }

    [ObservableCommand(nameof(SaveMetadata))]
    public partial IObservableCommand SaveMetadataCommand { get; }

    [ObservableCommand(nameof(RequestCopy), nameof(CanInteractWithKey))]
    public partial IObservableCommand RequestCopyCommand { get; }

    private bool CanInteractWithKey() => HasKeys;

    protected override async Task OnContextReadyAsync()
    {
        // PRF-support probe is cheap and idempotent. Drives the panel's
        // gate between "checking..." / "supported" / "unsupported" branches.
        IsPrfSupported = await PrfService.IsPrfSupportedAsync();

        // Cache bridge: PRF service may already hold a derived bundle from
        // an earlier ceremony (TTL still warm, user navigated within app).
        // Re-hydrate so panels that mount fresh see the same state instead
        // of forcing a redundant WebAuthn round-trip.
        if (PrfService.HasCachedKeys() && PrfService.GetCachedPublicKey() is { Length: > 0 } cachedPub)
        {
            using (SuspendNotifications("AuthState"))
            {
                PublicKey = cachedPub;
                // CredentialId is the prior-ceremony hint targeting this
                // session — populating it lets the panel render the "switch
                // credential" entry point without a re-derive.
            }
        }

        // Session-end subscription: the seed-cache key id is the canonical
        // expiry signal. Filter in the R3 pipeline so the handler runs once
        // per relevant emission; Subscriptions.Add tears down with the model.
        var seedKey = $"prf-seed:{PrfOptions.Value.Salt}";
        Subscriptions.Add(
            PrfService.KeyExpired
                .Where(cacheKey => cacheKey == seedKey)
                .Subscribe(_ => OnSessionExpired()));
    }

    /// <summary>
    /// Atomic session reset: clearing the three properties inside
    /// <c>SuspendNotifications</c> means observers see one coherent
    /// "session ended" transition instead of three intermediate states.
    /// </summary>
    private void OnSessionExpired()
    {
        using (SuspendNotifications("AuthState"))
        {
            PublicKey = null;
            CredentialId = null;
            Metadata = null;
        }
    }

    private void UpdateAuthenticationState()
    {
        StateProvider.UpdateAuthenticationState(CredentialId, PublicKey);
    }

    private async Task CheckPrfSupportAsync()
    {
        // Pessimistic init — if the probe throws, IsPrfSupported stays false
        // and the panel renders the "PRF not supported" branch.
        IsPrfSupported = false;
        IsPrfSupported = await Authenticator.CheckPrfSupportAsync();
    }

    private async Task DeriveKeysAsync(CancellationToken cancellationToken)
    {
        var hint = string.IsNullOrWhiteSpace(CredentialId) ? null : CredentialId;
        var result = await Authenticator.AuthenticateAsync(hint, cancellationToken);
        if (result is null)
        {
            StatusModel.AddWarning(
                Localizer["Status_AuthenticationCancelled"],
                nameof(DeriveKeys));
            return;
        }
        using (SuspendNotifications("AuthState"))
        {
            CredentialId = result.CredentialId;
            PublicKey = result.PublicKeyBase64;
        }
        StatusModel.AddSuccess(
            Localizer["Status_KeysDerived"],
            nameof(DeriveKeys));
    }

    private void ClearKeys()
    {
        // Clears both the JS-side cache and the model state. PrfService.ClearKeys
        // fires KeyExpired which our subscription would otherwise also handle —
        // pre-emptively wiping the model state here keeps the local transition
        // observable; the subscription handler then becomes a no-op.
        PrfService.ClearKeys();
        using (SuspendNotifications("AuthState"))
        {
            PublicKey = null;
            CredentialId = null;
            Metadata = null;
        }
    }

    private void OpenMetadataDialog()
    {
        EditName = Metadata?.Name;
        EditEmail = Metadata?.Email;
        EditComment = Metadata?.Comment;
        DialogVisible = true;
    }

    private void CancelMetadataDialog()
    {
        DialogVisible = false;
    }

    private void SaveMetadata()
    {
        var hasData = !string.IsNullOrWhiteSpace(EditName)
            || !string.IsNullOrWhiteSpace(EditEmail)
            || !string.IsNullOrWhiteSpace(EditComment);

        Metadata = hasData
            ? new PublicKeyMetadata
            {
                Name = string.IsNullOrWhiteSpace(EditName) ? null : EditName.Trim(),
                Email = string.IsNullOrWhiteSpace(EditEmail) ? null : EditEmail.Trim(),
                Comment = string.IsNullOrWhiteSpace(EditComment) ? null : EditComment.Trim(),
                Created = Metadata?.Created ?? DateOnly.FromDateTime(DateTime.Today),
            }
            : null;

        DialogVisible = false;
    }

    private void RequestCopy()
    {
        PendingCopy = PublicKey;
    }

    private string FormatDeriveKeysError(Exception ex) => ex switch
    {
        PrfAuthenticatorException { Operation: PrfAuthenticatorOperation.Authenticate, Code: var code } =>
            Localizer[$"Error_Authenticate_{code}"],
        _ => Localizer["Error_DeriveKeys_Unknown", ex.Message],
    };
}
