using RxBlazorV2.Interface;
using RxBlazorV2.Model;
using RxBlazorV2.MudBlazor.Components;
using SqliteWasmBlazor.CryptoSync.UI.Models;
using SqliteWasmBlazor.CryptoSync.UI.Services;

namespace SqliteWasmBlazor.CryptoSync.UI.Components.Authentication;

/// <summary>
/// Drives the authentication / key-derivation panel. Owns the derived
/// public key, optional metadata, the metadata-edit dialog state, and
/// the copy-to-clipboard signal. RxBlazor hosts that need to react to a
/// successful key derivation observe <see cref="CredentialId"/> +
/// <see cref="PublicKey"/> on this model — no callback bridges.
///
/// <para>
/// <b>Why everything lives on this model.</b> RXBG061 forbids same-assembly
/// composition of two <c>*ModelComponent</c> panels (a child <c>*ModelComponent</c>
/// rendered inside a parent <c>*ModelComponent</c> in the same assembly).
/// The Stage-2 scaffolding folds the previously-separate <c>PublicKeyDisplay</c>
/// surface into <see cref="AuthenticationPanel"/> directly. If a future
/// scenario needs a public-key display outside the auth flow, it's
/// promoted to its own downstream-consumer panel then.
/// </para>
/// </summary>
[ObservableModelScope(ModelScope.Scoped)]
[ObservableComponent]
public partial class AuthenticationModel : ObservableModel
{
    public partial AuthenticationModel(IPrfAuthenticator authenticator);

    public partial string? CredentialId { get; set; }
    public partial string? PublicKey { get; set; }
    public partial PublicKeyMetadata? Metadata { get; set; }
    public partial bool? IsPrfSupported { get; set; }
    public partial string? ErrorMessage { get; set; }
    public partial string? SuccessMessage { get; set; }

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

    [ObservableCommand(nameof(DeriveKeysAsync))]
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

    private async Task CheckPrfSupportAsync()
    {
        try
        {
            IsPrfSupported = await Authenticator.CheckPrfSupportAsync();
        }
        catch (Exception ex)
        {
            IsPrfSupported = false;
            ErrorMessage = $"PRF support check failed: {ex.Message}";
        }
    }

    private async Task DeriveKeysAsync(CancellationToken cancellationToken)
    {
        ErrorMessage = null;
        SuccessMessage = null;
        try
        {
            var hint = string.IsNullOrWhiteSpace(CredentialId) ? null : CredentialId;
            var result = await Authenticator.AuthenticateAsync(hint, cancellationToken);
            if (result is null)
            {
                ErrorMessage = "Authentication was cancelled.";
                return;
            }
            CredentialId = result.CredentialId;
            PublicKey = result.PublicKeyBase64;
            SuccessMessage = "Keys derived from passkey.";
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Key derivation failed: {ex.Message}";
        }
    }

    private void ClearKeys()
    {
        PublicKey = null;
        Metadata = null;
        ErrorMessage = null;
        SuccessMessage = null;
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
}
